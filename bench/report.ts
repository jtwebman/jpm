#!/usr/bin/env node
import {
  aggregate,
  caption,
  isBest,
  key,
  load,
  MEASURE,
  MEASURES,
  parseArgs,
  PHASE_BLURB,
  range,
  sampleCounts,
  warnings,
} from "./results.ts";
import type { Benchmark, Measure, Run } from "./results.ts";

function md(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replaceAll("*", "\\*")
    .replaceAll("_", "\\_")
    .replaceAll("`", "\\`")
    .replace(/[\r\n]/g, " ");
}

const MEASURE_NOTE: Record<Measure, string> = {
  time: "",
  memory: "peak resident memory of the install's whole process tree",
  cpu: "user + sys, summed over the install's whole process tree",
};

// Memory and CPU come after the times, for each of them the results have. Pass them in `more`.
export function buildReport(data: Benchmark, more: Benchmark[] = []): string {
  const lines = [
    `## Install benchmark — ${data.metric}`,
    "",
    `Samples per measured group: ${sampleCounts(data)}.`,
    "",
    "Timings use successful runs only. Bold marks the lowest result per phase / fixture, excluding failures and cache warnings.",
    "",
  ];
  const header = () => {
    lines.push(`| manager | version | ${data.fixtures.map(md).join(" | ")} |`);
    lines.push(`| --- | --- | ${data.fixtures.map(() => "---:").join(" | ")} |`);
  };
  for (const set of [data, ...more]) {
    const { label, format } = MEASURE[set.measure];
    for (const phase of set.phases) {
      const title = set.measure === "time" ? PHASE_BLURB[phase] : label;
      lines.push(`### ${phase} — ${title}`, "");
      if (set.measure !== "time") lines.push(`${MEASURE_NOTE[set.measure]}, successful runs.`, "");
      header();
      for (const runner of set.runners) {
        const cells = set.fixtures.map((fixture) => {
          const entry = set.groups.get(key(phase, runner, fixture));
          const text = md(caption(entry, format));
          return entry && isBest(set, phase, fixture, entry) ? `**${text}**` : text;
        });
        lines.push(`| ${md(runner.name)} | ${md(runner.version)} | ${cells.join(" | ")} |`);
      }
      lines.push("");
    }
  }
  lines.push("### Packages installed (successful runs)", "");
  header();
  for (const runner of data.runners) {
    const cells = data.fixtures.map((fixture) =>
      range(
        data.phases.flatMap(
          (phase) => data.groups.get(key(phase, runner, fixture))?.packages ?? [],
        ),
      ),
    );
    lines.push(`| ${md(runner.name)} | ${md(runner.version)} | ${cells.join(" | ")} |`);
  }
  const notes = warnings(data);
  if (notes.length) lines.push("", "### Warnings", "", ...notes.map((note) => `- ${md(note)}`));
  return lines.join("\n") + "\n";
}

function hasMeasure(rows: Run[], measure: Measure): boolean {
  return rows.some((row) => MEASURE[measure].value(row) !== undefined);
}

export function main(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  if (options.help) {
    console.log(
      "Usage: node bench/report.ts results.jsonl [...] [--metric min|max|median|mean] [--phase cold|warm|repeat] [--measure time|memory|cpu]\nWithout --measure it prints every measure the results have.",
    );
    return;
  }
  if (!options.results.length)
    throw new Error("provide at least one results.jsonl file (see --help)");
  const rows = load(options.results);
  const sets = (options.measure ? [options.measure] : MEASURES)
    .filter((measure) => measure === options.measure || hasMeasure(rows, measure))
    .map((measure) => aggregate(rows, options.metric, options.phases, measure));
  console.log(buildReport(sets[0]!, sets.slice(1)));
}

if (import.meta.main) {
  try {
    main();
  } catch (error) {
    console.error(`report: ${(error as Error).message}`);
    process.exitCode = 1;
  }
}
