# Configuration

`.npmrc` is read from the project, the user's home and npm's global location, plus
`npm_config_*` variables. jpm reads `registry`, `@scope:registry`, credentials
(`//host/:_authToken`, `_auth`, `username` and `_password`), `save-exact`, `offline`,
`prefer-offline`, `min-release-age`, `before`, `min-release-age-exclude`,
`block-exotic-subdeps` (see [Git dependencies](git-dependencies.md)) and the network settings below.

jpm's own environment variables: `JPM_STORE` (where the store is, `~/.jpm/store` by default),
`JPM_GLOBAL_STORE` (`0`, `false` or `off` turns the global virtual store off, see below),
`JPM_REGISTRY` (the registry, where `npm_config_registry` is not set) and `JPM_CONCURRENCY`
(threads for network work, 32 by default).

The project's `.npmrc` comes with the repository, so it cannot weaken what the others check:
`ca`, `cafile`, `proxy`, `https-proxy`, `http-proxy`, `strict-ssl=false`,
`block-exotic-subdeps=false`, `verify-node-signature=false`, a `min-release-age` or `before` that lets in newer versions
than the user's setting (or the default) does, a `min-release-age-exclude` pattern wider than one
package or `@scope/*`, and a `registry` or `@scope:registry` over `http://` on a host the user's
files (or the default registry) reach over https, are ignored there with a warning naming them.
Set them in `~/.npmrc`, the global npmrc, `npm_config_*` or a flag. A cloned repository could
otherwise send the user's registry token through a proxy of its choosing, or in the clear.
`registry`, scoped registries, `noproxy` and `node-mirror:release` still work from the project.

jpm has its own TLS and trusts Mozilla's root certificates and the operating system's: the
Windows certificate store (the current user's `ROOT`, which includes the machine's and group
policy's), or on Linux the distribution's CA bundle (`SSL_CERT_FILE` names another). A company
proxy that inspects TLS usually installs its root there, so it works without settings. For a
registry with a private CA, or a root only in a file, tell jpm which certificates to trust, as
with npm:

- `NODE_EXTRA_CA_CERTS=/path/ca.pem` adds the certificates in a PEM file to Mozilla's roots, as
  Node does.
- `cafile=/path/ca.pem` in `.npmrc` trusts the certificates in the file *instead of* Mozilla's
  and the system's roots (and of `NODE_EXTRA_CA_CERTS`), as it does in npm. `ca="-----BEGIN CERTIFICATE-----\n…"`
  does the same with the PEM text on one line, `\n` for its line breaks; `ca[]=` once per
  certificate lists several. `cafile` wins when both are set.
- `strict-ssl=false` turns the certificate checks off, and jpm warns on every run that it is
  off. The connection is still encrypted, but anyone on the network can pose as the registry.

A file that cannot be read, or holds no certificate, is an error that names it.

`https-proxy` (else `proxy`) in `.npmrc` sends requests through a proxy, `http://user:pass@host:port`
for one that wants credentials (jpm reaches a proxy over plain http, so an `https://` proxy is
refused rather than sent credentials in the clear), and `noproxy` lists the hosts (and domains under them) that go
direct. They take the place of `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, which jpm reads when
`.npmrc` names none. https goes through the proxy by CONNECT, so TLS runs end to end.

New versions are held back for one day by default (`min-release-age`). Set it to `0` to
turn this off. It holds for an exact version a package pins too, so a compromised package's new
release cannot come in by a dependency pinning it; `min-release-age-exclude` (or
`minimumReleaseAgeExclude` in `pnpm-workspace.yaml`) lets a name in however new. A version the
project pins itself, in a package.json of its own or in its overrides, is taken as asked for.
The age applies when a version is picked: what a lockfile already holds is kept as it is.

The global virtual store is on by default. Turn it off with `global-store=false` in `.npmrc`,
`JPM_GLOBAL_STORE=0` or `--no-global-store`. It is off inside containers (`/.dockerenv` or
`/run/.containerenv`), where a mounted project would not see the store, and when the store
cannot be written. It is also off, with a note, for a project that depends on `next` or `nuxt`:
Next's Turbopack compiles nothing outside the project, and Nuxt imports packages it does not
declare. `global-store=true` overrides that.

Every project also gets a hidden hoist, `node_modules/.jpm/node_modules`: the highest version
of every package the root does not link itself, which Node reaches when a package imports
something it did not declare, as pnpm does with `.pnpm/node_modules`. Packages in the global
store resolve from the store and cannot reach it on their own, so under the global store
`jpm run`, `jpm exec` and install scripts point Node at it: `NODE_PATH` gets the hoist and the
project's `node_modules` (for `require`), and `NODE_OPTIONS` gets
`--require node_modules/.jpm/hoist.cjs`, a resolve hook that retries a missing `import` from
the project. The hook needs Node 22.15 or later; older Node gets only `NODE_PATH`, so an
undeclared `require` works there and an undeclared `import` does not. Both add to what is
already set. Plain
`node app.js`, outside jpm, gets neither: an undeclared import fails there unless the project
is installed with `--no-global-store`.

Some packages of the hidden hoist are also linked in the root's `node_modules`, as pnpm's
`public-hoist-pattern` does: where tsc (`"types": ["node"]`), an editor's eslint and prettier,
and tools that npm's and yarn's flat layout let find anything, look. By default those are
`@types/*`, `*eslint*` and `*prettier*`; `*` matches any characters, a scope's `/` too, and a
`!` pattern leaves names out. `public-hoist-pattern[]=<pattern>` in `.npmrc` (one line each)
takes the default's place, an empty `public-hoist-pattern[]=` links none, and
`shamefully-hoist=true` links every one, close to npm's and yarn's layout.
`publicHoistPattern` and `shamefullyHoist` in `pnpm-workspace.yaml` are read the same way when
`.npmrc` says nothing. Workspaces are linked at the root the same way, as npm and yarn link every
one: a workspace a pattern names (all of them under `shamefully-hoist`), in place of a registry
package of its name. A package the root declares is always its own, never the hoist's.

`jpm prune` removes what no project uses. Every install registers its project with the store
(`v1/projects`), and a prune keeps the global entries and packages that registered projects
still use. A project that is gone, or on a drive that is not mounted, is dropped from the
register; its next install rebuilds what it needs. Installs and prunes take a lock on the store
(`v1/lock`), so a prune waits for installs to finish and removes what is unused at once. On a
filesystem without working file locks, such as some network mounts, an install running
alongside a prune can lose entries; installing again repairs it.
