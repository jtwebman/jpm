# Contributing

Pull requests are welcome, including ones written with AI. jpm itself was written by Claude
Code. Who or what wrote a change doesn't matter; what it proves does.

## What a pull request needs

- **A test that fails without the change and passes with it.** For a bug fix, the test
  reproduces the bug. For a feature, the tests show it working, including its edge cases. A
  change with no test that proves it is closed.
- **One change per pull request.** Small and focused gets reviewed and merged; a sweeping
  rewrite does not.
- **A description in your own words:** what was wrong or missing, how you found it, and how the
  test shows it is fixed. If the change touches speed or size, include before and after numbers
  (see [docs/benchmarks.md](docs/benchmarks.md)).
- **Green CI.** Before you push:

  ```sh
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  ```

  [docs/development.md](docs/development.md) has the rest: the crates, the test switches, and
  the network tests.

## Pull requests written with AI

The same rules apply, and they matter more:

- Read the change and run the tests yourself before opening the pull request. You are the one
  answering review questions, not the tool.
- Don't open pull requests for problems you haven't seen. A "fix" for a bug no test or real
  project shows is closed.
- Keep the diff to what the fix needs. Unrelated renames, reformatting and comment rewrites get
  it closed.
- Leave out co-author trailers for AI tools. CI fails a pull request whose commits have a
  `Co-Authored-By` trailer for Claude or Anthropic.

## Security issues

Don't open a public issue or pull request for a security problem. Report it privately through
[GitHub's security advisories](https://github.com/jtwebman/jpm/security/advisories/new).
