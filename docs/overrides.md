# Overrides

An override replaces the range an edge asks for, before it is resolved, in every package and
for peers too. jpm reads each manager's field:

| Field | Keys |
| --- | --- |
| npm's `overrides` (bun's too) | `name`, `name@range`, `{ "parent": { "name": … } }`, `.` for the parent itself |
| yarn's `resolutions` (bun's too) | `name`, `**/name`, `parent/name` |
| `pnpm.overrides`, `pnpm-workspace.yaml` `overrides` | `name`, `name@range`, `parent@range>name`, `name@` |

A value is a range, an `npm:` alias, `$name` for the root's own range of `name`, `catalog:`, or
for pnpm `-`, which takes the edge out. A `name@range` key matches as its manager does: npm's
where the two ranges meet, pnpm's where the edge's range is inside it, yarn's where they are
the same. jpm resolves each version of a package once, so a nested rule applies to the
parent's own dependencies wherever the parent is; a rule nested deeper applies to its nearest
parent's, with a warning. When two rules match, the one with a parent wins, then one with a
range, then a name alone; pnpm's rules go before npm's, and npm's before yarn's.
