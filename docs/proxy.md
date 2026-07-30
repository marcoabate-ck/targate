# Registry proxy (experimental)

```bash
targate proxy setup
```

The proxy is a transparent enforcement point: instead of remembering to run
`targate add`, you point your package manager's registry at a local proxy, and
**every** `npm install` / `npm ci` (and yarn / pnpm / bun) is vetted before a
tarball's bytes ever reach your machine. It closes the gap left by CLI-only
gating — a raw `npm install`, a script, or a CI job that never calls `targate`
is still checked — without a shell wrapper and without depending on lifecycle
scripts (so `--ignore-scripts` cannot switch it off).

> **Status: experimental.** Flags and output may change in a minor release. It
> vets **public** packages out of the box; private/scoped registries are
> supported via manually configured [uplinks](#private-scopes) (the automatic
> `.npmrc` migration is still a follow-up). The full design, including the
> trade-offs, is in [docs/design/proxy.md](design/proxy.md).

## Quick start

```bash
targate proxy setup          # generate a local CA, start the proxy, configure .npmrc
export NODE_EXTRA_CA_CERTS="$(targate proxy cert path)"   # trust the CA for this shell
npm install                  # every package is now vetted before it lands
targate proxy teardown       # stop the proxy and undo the .npmrc + CA changes
```

`setup` writes a small managed block into the project `.npmrc`:

```ini
# >>> targate proxy (managed — `targate proxy teardown` removes this)
registry=https://127.0.0.1:4873
replace-registry-host=npmjs
# <<< targate proxy
```

This `.npmrc` points at a machine-local proxy — **add it to `.gitignore`; do not
commit it.** `teardown` removes the block again.

## How it works

- **Packument requests pass through unmodified.** The proxy does *not* rewrite
  `dist.tarball`; npm's `replace-registry-host=npmjs` (the default on npm ≥ 9)
  routes the tarball fetch through the proxy while your lockfile keeps canonical
  `registry.npmjs.org` URLs — so a lockfile authored behind the proxy stays
  portable for teammates and CI that do not run it. Do **not** set
  `replace-registry-host=never`; that bypasses the proxy.
- **Every tarball is vetted before it is served.** The proxy fetches the exact
  bytes it is about to serve, runs the same deterministic analysis as
  `targate add` (lifecycle scripts, tarball contents, native surface, OSV /
  reputation, artifact identity, team policy), and either streams the bytes
  (`allow` / `allow_with_warnings`) or returns **HTTP 403** with the reason
  (`block` / `require_approval`). npm surfaces that reason in its error output.
- **Verdicts are cached by artifact digest.** The cache key is the tarball's
  SHA-512 SRI digest (the same identity the [artifact ledger](team-workflow.md)
  uses), persisted under `~/.targate/proxy-verdicts.json`. Each artifact is
  analyzed once — ever, across daemon restarts — so the first install of a
  version pays ~1s and every install after is a sub-millisecond cache hit. A
  republished or mutated tarball has a different digest and is re-analyzed rather
  than served from a stale verdict.

## Commands

| Command | Purpose |
|---|---|
| `targate proxy setup` | Generate a local CA + certificate, start the HTTPS daemon, and configure the project `.npmrc`. |
| `targate proxy teardown` | Stop the daemon, strip the `.npmrc` block, and remove the local TLS material. |
| `targate proxy start` \| `stop` \| `status` | Manage the daemon directly. `--foreground` runs it in the current process (CI / debugging). |
| `targate proxy ensure` | Start the daemon only if it is not already running. |
| `targate proxy cert path` \| `export` | Print the CA path, or a ready-to-source `export NODE_EXTRA_CA_CERTS=…` line. |

State and logs live under `~/.targate/` (`proxy.json`, `proxy.log`,
`proxy-verdicts.json`, `proxy-tls/`). `targate doctor` reports whether the proxy
is running and whether the current project routes through it.

## Trusting the CA

npm only sends registry credentials over HTTPS, so the proxy serves TLS with a
locally generated CA. Trust it once, one of two ways:

- **CI / a single shell** — `export NODE_EXTRA_CA_CERTS="$(targate proxy cert path)"`.
  Nothing touches the system trust store; ideal for ephemeral environments.
- **System trust store** — `setup` prints the per-OS command (macOS `security`,
  Windows `certutil`, Debian `update-ca-certificates`) to trust the CA machine-
  wide. This is a privileged, one-time step; run it yourself.

## Private scopes

`targate proxy setup` reads your existing `.npmrc`, and for every private
per-scope registry (`@acme:registry=https://npm.acme.example`) it:

- writes an **uplink** to `~/.targate/proxy-uplinks.json` capturing the scope's
  real upstream **and its credential** (the same token already in your `.npmrc`),
  written `0600`;
- rewrites that scope in the managed `.npmrc` block to point at the proxy, so
  `@acme/*` now flows through it.

At request time the proxy routes `@acme/*` to its real upstream and authenticates
with the captured credential (it never stores anything the client did not already
have; if no credential was captured it relays the client's header pass-through).
It rewrites the private packument's `dist.tarball` so the tarball comes back
through the proxy for vetting, and runs the same analysis as for public packages
— including the same-version-mutation ledger and content scanning, the byte-level
defenses that matter for a compromised internal package (external databases
cannot know private names). A scoped package with **no** uplink resolves as public
and gets the full public analysis, so a dependency-confusion attempt surfaces
rather than sliding through.

Registries whose scopes share one token (one Artifactory serving several scopes)
migrate cleanly. `teardown` removes the uplinks file along with the rest.

## Limitations

- **The package manager's own cache sits in front of the proxy.** A package
  already in `~/.npm/_cacache` (or yarn/pnpm/bun's store) is served locally and
  never reaches the proxy. When adopting the proxy in an existing project, run
  `npm cache clean --force` for a clean floor.
- **No interactive approval yet.** A `require_approval` verdict is treated as a
  block (fail-closed) in this phase; an out-of-band approval flow is planned.
- **Per-package verdicts.** The proxy sees one tarball at a time and has no
  whole-tree view; use `targate install --deep` for a tree-aware, holistic gate.

See [docs/design/proxy.md](design/proxy.md) for the reasoning behind each of
these and the plan to close them.
