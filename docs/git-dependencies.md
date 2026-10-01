# Git dependencies

```json
"dependencies": {
  "a": "github:user/repo#v1.2.0",
  "b": "user/repo#semver:^2",
  "c": "git+ssh://git@example.com/team/c.git#main",
  "d": "gitlab:group/d#9f2c4e1b7a0d3c5e8f6a2b4c1d3e5f7a9b0c2d4e"
}
```

`github:`, `gitlab:`, `bitbucket:` and `user/repo` shorthands are read, and `git+https://`,
`git+ssh://` (and scp-like `git@host:path`) and `git://` urls, each with `#<commit>`,
`#<branch or tag>` or `#semver:<range>` (the highest tag in the range; none means the default
branch). `git+http://` is refused, as are credentials in a url: they would be written to
jpm.lock, and belong in git's credential helper or ssh. `gist:` is not read yet.

- **Resolving.** A ref becomes a commit through `git ls-remote`, so git must be installed. A
  commit is given as its full id; a short one is refused. jpm.lock keys the package by its
  commit (`a@git+https://github.com/user/repo.git#<commit>`), and keeps that commit until
  package.json names another ref: a branch is not followed by a later install.
- **Fetching.** A GitHub, GitLab or Bitbucket repository over https is downloaded as the host's
  archive of the commit, through jpm's own client; if there is none (a private repository), and
  for every other url, jpm fetches the one commit into a temporary repository
  (`git fetch --depth 1`) and reads it with `git archive`. Only the files `npm pack` would keep
  under package.json's `files` are stored, with package.json, the readme, the licence, `main`
  and the bins always kept and `node_modules` never; `.npmignore` and `.gitignore` are not read.
- **Integrity.** A host's archive is not the same bytes from one year to the next (GitHub's
  compression changed in 2023), so the integrity jpm locks is not of the archive: it is the
  sha512 of the stored tree, each file's path, mode, size and bytes in path order. A download
  that unpacks to other files under the locked commit fails, however it was compressed.
- **Scripts.** A git package's `prepare`, which npm runs to build it, counts as an install
  script: it runs only once approved (`jpm approve <name>`), before its other install scripts,
  in the package's copy. Its devDependencies are not installed for it.
- **Lockfile.** A git or tarball edge of the root or a workspace in jpm.lock must be what
  package.json names: the same url, or the same repository at the commit package.json pins, if
  it pins one. A package's own git or tarball edge must be what its package.json (or the
  registry's copy of it) names. An edit to jpm.lock alone cannot put another repository, commit
  or url in its place: `--frozen-lockfile` fails, and `jpm install` resolves package.json again.
- **Dependencies' repositories.** Only the root and workspaces may take a package from a git
  repository or a tarball url: a registry package that depends on one is refused, as pnpm 10.26
  and later refuse it (`block-exotic-subdeps`, on by default). `block-exotic-subdeps=false` in
  `~/.npmrc`, `npm_config_block_exotic_subdeps=false` or `--no-block-exotic-subdeps` allows it,
  as npm does; a project's own .npmrc cannot. Either way, for a repository no package.json of
  the project names, git asks nothing: no credential prompt, askpass program or
  Git Credential Manager window, and ssh runs in batch mode (no passphrase or host-key question)
  unless `GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand` runs it another way. For the
  project's own repositories, git asks on a terminal as it always does.
- **Security.** git runs with only https, ssh and git:// allowed (`GIT_ALLOW_PROTOCOL`: never a
  transport helper such as `ext::`, nor `file://`), with every url after `--`, and without the
  repository variables (`GIT_DIR` and the like) of a git that ran jpm. It runs in an empty
  directory of jpm's own with `GIT_CEILING_DIRECTORIES` set, so it reads no repository's config:
  not the project's, and not one a checkout carries as plain files. A url, host or user starting
  with `-`, a host other than letters, digits, `.` and `-` (or an IPv6 address in brackets), a
  one-letter scp host (a drive to git on Windows), a `::` (git's transport-helper syntax), a ref
  starting with `-`, or a url with a space or a control character in it is refused when
  package.json or jpm.lock is read. Registry tokens are never sent to a git host.

Another manager's lockfile with a git dependency is brought over by resolving package.json
with its versions preferred.
