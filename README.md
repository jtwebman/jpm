# jpm

A fast, small, secure-by-default package manager for JavaScript, written in Rust.

**I didn't write a line of jpm.** Claude Code, running Claude Opus 5.5, wrote every one of
them, including its own TLS and crypto: the two things every engineer knows you never write
yourself.

I've been a professional software engineer for 27 years, mostly three-tier business software:
C# until 2012, then Elixir and Node.js. The last time I wrote low-level code was in C, as a kid.
I'm not the engineer you'd pick to write a package manager. That's the point.

## How it started

I was watching [an episode of the Syntax podcast](https://www.youtube.com/watch?v=Z412bnUNiDI&t=71s)
when they held up
[upm](https://github.com/unjs/upm) as a package manager that was faster and smaller than the
rest. Fast, yes. But small? I called foul: it's small because it runs on Node.js. They were
also asking the AI questions everyone is asking right now. Can it build real software, or just
demos? Should engineers be worried, or excited? Most people believe AI can one-shot anything.
It can. The result just usually isn't very good.

So I asked my own questions: what if we ported upm to Rust and made it faster and smaller for
real? And what would it take to turn an AI's one-shot into something you'd trust in CI? On
September 28, 2026, at 3:38 in the afternoon, the first commit landed: *Port upm to Rust as
jpm.* By that evening it had its own HTTP client, JSON reader, crypto and TLS 1.3.

That was the easy part. The afternoon was the one-shot. The next days were the part nobody
posts about:

- hundreds of bugs fixed;
- a security review;
- install scripts locked down;
- reading upm's, pnpm's, bun's and aube's source to understand how they did things fast;
- profiling until the numbers moved.

## What directing looked like

I made maybe a hundred calls, asking things like:

- What should the security defaults be?
- Should we follow npm here, or pnpm?
- What if we tried this?

Sometimes the answer was "that doesn't feel right", and sometimes "don't do that".

Twice Claude pushed back: when I wanted our own TLS, and our own HTTP stack. I insisted, on one
condition: test it like we didn't trust it. Writing it ourselves meant we could leave out
everything a general-purpose library has to carry, like logging, options and special cases. We
needed one thing: a fast, safe GET. So it came out smaller and faster.

Once, I was wrong. I pushed for HTTP/2. We built our own HTTP/2 client and benchmarked it on
GitHub's runners and my own machine. It used more CPU and was slower in some cases, so we
deleted it. The numbers decided, not me.

## Why you can trust code nobody typed

Because none of it is trusted on its word. Every "it works" in jpm is checked against someone
else's tests:

- **Crypto:** Google's Project Wycheproof crypto vectors and the RFCs' test vectors.
- **npm:** node-semver's, npm-package-arg's and hosted-git-info's own test cases, and npm
  arborist's lockfiles.
- **pnpm:** its registry-mock scenarios, diffed against what pnpm itself installs.
- **yarn:** berry's acceptance scenarios, the "dragon tests" included.
- **bun:** its install tests and lockfiles.
- **Real projects:** 98 large ones, installed on Windows from both cmd and PowerShell. 92
  install, and the other six fail on purpose or would fail with any package manager.

None of the speed is mine either. It came from reading the code that great engineers shared
with the world (upm, pnpm, bun and aube) and asking how they did it.

Is jpm perfect? No. Neither is anything I've written by hand in 27 years, or anything any human
has written. Perfect doesn't exist. There's good enough, there's great, and there's tested
enough to know which one you have.

## Where it stands

Wall time to install [`nuxt`](docs/benchmarks.md) (591 packages). The best in each column is
bold.

**GitHub Actions, Linux** (`ubuntu-latest`, 4 cores, median of 5):

| manager | cold | warm (cache restored) | ci (no cache) | repeat |
| --- | ---: | ---: | ---: | ---: |
| **jpm** | **1.22 s** | 206 ms | 734 ms | **2 ms** |
| bun 1.4 | 1.28 s | 234 ms | **676 ms** | 18 ms |
| aube 2.6 | 3.00 s | **186 ms** | 896 ms | 7 ms |
| pnpm 12.8 | 1.72 s | 435 ms | 1.53 s | 11 ms |
| deno 2.9 | 7.64 s | 338 ms | 1.20 s | 28 ms |
| upm 1.3 | 3.52 s | 447 ms | 2.06 s | 44 ms |
| yarn 4.18 | 9.63 s | 3.13 s | 5.58 s | 1.02 s |
| npm 12.1 | 18.5 s | 4.69 s | 6.62 s | 794 ms |

**Windows 11**, Defender on (i9-12900K, median of 3):

| manager | cold | warm (cache restored) | ci (no cache) |
| --- | ---: | ---: | ---: |
| **jpm** | 8.53 s | 1.45 s | 8.01 s |
| upm 1.3 | **7.40 s** | 4.41 s | 6.80 s |
| npm 12.1 | 11.9 s | 4.84 s | **5.15 s** |
| pnpm 12.8 | 9.14 s | 3.75 s | 8.81 s |
| aube 2.6 | 17.4 s | **491 ms** | 16.0 s |

**macOS** (M4 Max, median of 5):

| manager | cold | warm (cache restored) | ci (no cache) | repeat |
| --- | ---: | ---: | ---: | ---: |
| **jpm** | **3.02 s** | 594 ms | **2.81 s** | **12 ms** |
| bun 1.4 | **3.02 s** | 472 ms | 2.92 s | 117 ms |
| aube 2.6 | 8.37 s | **335 ms** | 6.61 s | 186 ms |
| pnpm 12.8 | 5.92 s | 900 ms | 6.22 s | 22 ms |
| deno 2.9 | 8.88 s | 697 ms | 4.35 s | 26 ms |
| upm 1.3 | 6.43 s | 3.04 s | 5.77 s | 60 ms |
| yarn 4.18 | 6.18 s | 2.71 s | 4.18 s | 462 ms |
| npm 12.1 | 9.23 s | 3.15 s | 3.65 s | 514 ms |

- **Linux:** across three projects, jpm is the fastest of eight managers in 9 of 12 cells,
  uses the least memory in 11 of 12, and the least disk in all three.
- **macOS:** across three projects, jpm is the fastest of eight managers in 9 of 12 cells and
  uses the least memory in 11 of 12. A warm install is not the fastest yet: bun and aube
  beat it on `nuxt`.
- **Windows:** jpm is the fastest on `next`, but not on `nuxt` yet. Defender scans every file an
  install writes, and it scans files written by `node.exe` (npm, upm) far more cheaply than
  files written by native tools like jpm, aube or pnpm.
- **The binary:** about 2 MB. bun is about 80 MB, pnpm 60 MB and aube 150 MB.

Every table, with CPU, memory, disk and cache: [docs/benchmarks.md](docs/benchmarks.md).

## Try it

```sh
curl -fsSL https://getjpm.sh | sh                  # macOS and Linux
```

```powershell
irm https://getjpm.sh/install.ps1 | iex              # Windows
```

Then, in a project that uses npm, pnpm, yarn or bun:

```sh
jpm install          # reads your lockfile, writes jpm.lock with the same versions
jpm run build
```

jpm is secure by default:

- A dependency's install scripts, the way most npm malware runs, don't run until you approve
  that package and version (`jpm approve`).
- New versions are held back for a day.
- A published package can't pull in git or tarball dependencies.
- Every package is checked against its lockfile integrity before it is visible.

More: [install](docs/install.md), [usage](docs/usage.md),
[migrating](docs/migrating.md), [configuration](docs/configuration.md),
[install scripts](docs/install-scripts.md), [the lockfile](docs/lockfile.md),
[overrides](docs/overrides.md), [patches](docs/patches.md),
[directory](docs/directory-dependencies.md) and [git](docs/git-dependencies.md) dependencies,
[runtimes](docs/runtimes.md), [how it works](docs/how-it-works.md),
[development](docs/development.md).

## Why "jpm"?

I wondered why the JavaScript package manager wasn't called the JavaScript Package Manager.
Then I remembered JavaScript is a trademark. So: jpm.

## The end, and your turn

I didn't write a line of jpm. I asked a lot of questions, said no a few times, was wrong at
least once, and made it prove everything. Give the same idea to ten engineers and you'd get ten
different package managers, some of them better than this one. What's changed is that the
TLS stack you'd have talked yourself out of, because it was two weeks of work, is now an
afternoon. And a few more days, once you've hardened it and chased out the bugs.

So: try jpm in your CI. Then go build the thing you didn't think you had time for.

## License

MIT, Copyright (c) 2026 JT Turner. jpm started as a port of upm, Copyright (c) Pooya Parsa, also
MIT. See [LICENSE](LICENSE). [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) credits the code,
crates and test data jpm builds on, and ships with every release.
