# Registry proxy

```bash
targate proxy setup
```

The proxy is a transparent enforcement point: instead of remembering to run
`targate add`, you point your package manager's registry at a local proxy, and
every install is vetted before a tarball's bytes ever reach your machine. It
closes the gap left by CLI-only gating — a raw `npm install`, a script, or a CI
job that never calls `targate` is still checked — without a shell wrapper and
without depending on lifecycle scripts (so `--ignore-scripts` cannot switch it
off).

> **Works with npm, pnpm, yarn, and bun** (all verified to route through the
> proxy and be blocked on a bad package). Only npm rewrites a tarball's host to
> the configured registry itself, so the proxy leaves npm's `dist.tarball`
> canonical (keeping the lockfile portable) and rewrites it to the proxy for the
> other managers — transparently, by detecting the client. Each manager's own
> content cache still sits in front of the proxy (see [Limitations](#limitations)).

> **Scope.** Vets **public** packages out of the box; **private/scoped**
> registries are auto-migrated from your `.npmrc` on `targate proxy setup`, with
> the credential relayed upstream (see [private scopes](#private-scopes)). It runs
> as a **local, single-user** daemon — a network-shared proxy is out of scope (a
> non-loopback bind is refused unless you opt in). The full design and trade-offs
> are in [docs/design/proxy.md](design/proxy.md).

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

- **The tarball fetch is routed per client.** For **npm**, the packument passes
  through unmodified: npm's `replace-registry-host=npmjs` (the default on npm ≥ 9)
  routes the tarball through the proxy while the lockfile keeps canonical
  `registry.npmjs.org` URLs, so a lockfile authored behind the proxy stays
  portable for teammates and CI that do not run it (do **not** set
  `replace-registry-host=never` — that bypasses the proxy). **pnpm, yarn, and
  bun** don't rewrite the host themselves, so the proxy rewrites `dist.tarball`
  to a **clean** proxy URL (no query string) for those clients (detected by
  user-agent) — their tarball still comes back for vetting, and the real upstream
  URL is resolved from the packument server-side (not baked into the URL).
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
| `targate proxy cert install` \| `uninstall` | Trust / untrust the CA in the system store (`--dry-run` to preview). |
| `targate proxy approvals` | List packages currently held awaiting approval. |
| `targate proxy approve` \| `deny` `<pkg>@<version>` | Release a held `require_approval` request — serve it, or refuse it. |

State and logs live under `~/.targate/` (`proxy.json`, `proxy.log`,
`proxy-verdicts.json`, `proxy-tls/`). `targate doctor` reports whether the proxy
is running and whether the current project routes through it.

## Trusting the CA

npm only sends registry credentials over HTTPS, so the proxy serves TLS with a
locally generated CA. Trust it:

- **Required for the package managers — `NODE_EXTRA_CA_CERTS`.** npm, pnpm, and
  yarn run on Node, and **Node does not read the OS trust store by default**
  (only Node ≥ 22.15 with `--use-system-ca`). So the reliable, cross-platform way
  to make them accept the proxy is the env var:
  `export NODE_EXTRA_CA_CERTS="$(targate proxy cert path)"`. Put it in your shell
  profile or CI env.
- **System trust store — `targate proxy cert install`** (optional). Adds the CA
  to the OS store: macOS login keychain, Windows per-user `Root` (no admin), or
  the printed `sudo update-ca-certificates` on Linux. This is what browsers,
  `curl`, and Node ≥ 22.15 (`--use-system-ca`) read — but on its own it does
  **not** make default-Node npm/pnpm/yarn trust the proxy; pair it with
  `--use-system-ca` or use `NODE_EXTRA_CA_CERTS`. `--dry-run` previews;
  `targate proxy cert uninstall` reverses it.

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
  never reaches the proxy. When adopting the proxy in an existing project, clear
  the cache once for a clean floor (`npm cache clean --force`, `yarn cache clean`,
  or `pnpm store prune`). `targate proxy setup` prints the right command for your
  package manager, and `targate doctor` flags a non-empty cache while the proxy is
  routing the project.
- **Approval holds the install.** A `require_approval` verdict holds the client's
  request open (npm waits up to its `fetch-timeout`) while you decide out of band
  with `targate proxy approve|deny`; if no decision arrives before the hold cap
  (or the approval queue is full), it fails closed. Approved artifacts are then
  cached, so a later install of the same bytes does not prompt again.
- **Per-package verdicts.** The proxy sees one tarball at a time and has no
  whole-tree view; use `targate install --deep` for a tree-aware, holistic gate.
- **yarn-classic and bun lockfiles authored behind the proxy are not portable.**
  npm, pnpm, and yarn-berry omit or canonicalize the tarball URL, so a lockfile
  generated behind the proxy still works for teammates/CI without it. **yarn v1
  and bun bake the absolute fetched URL** (`http://127.0.0.1:<port>/…`) into their
  lockfiles, so that lockfile only resolves while the proxy is up on that port.
  Installs work for all four; only lockfile *authoring* is affected — author and
  commit lockfiles with npm/pnpm/yarn-berry, or don't commit a yarn-v1/bun
  lockfile produced behind the proxy. `targate proxy setup` warns when it detects
  one of these clients, and `targate doctor` flags it while the proxy routes the
  project.

See [docs/design/proxy.md](design/proxy.md) for the reasoning behind each of
these and the plan to close them.

## Verifying the proxy

Two end-to-end checks cover the parts that need a real environment:

- **TLS + system trust, per OS** — [`scripts/e2e-proxy-cert.mts`](../scripts/e2e-proxy-cert.mts):
  `setup` → trust the CA → HTTPS install *without* `NODE_EXTRA_CA_CERTS` →
  untrust. Run it locally with `node --import tsx scripts/e2e-proxy-cert.mts`, or
  via the manual `proxy cert e2e` GitHub Actions workflow which runs it on macOS,
  Windows, and Linux.
- **A real private registry, no credentials** — [`scripts/e2e-proxy-verdaccio.sh`](../scripts/e2e-proxy-verdaccio.sh)
  spins up a real Verdaccio with an auth-required scope, publishes a package to
  it, and installs that package through the proxy — asserting it was routed,
  the credential was relayed to Verdaccio, approved, and installed. Needs only
  `npx` (no external token). `bash scripts/e2e-proxy-verdaccio.sh`.
- **A hosted private registry** — [`scripts/e2e-proxy-github-packages.mts`](../scripts/e2e-proxy-github-packages.mts)
  installs a private package from GitHub Packages through the proxy. Set
  `GITHUB_TOKEN` (with `read:packages`) and `GH_PKG_SPEC=@scope/pkg@version`, then
  run the script; it asserts the package both installs and shows up in the proxy
  log (i.e. it was vetted, not fetched around the proxy).

For a **local** private registry (e.g. Verdaccio, or any registry on
localhost/a private IP), the SSRF guard normally refuses non-public hosts. Set
`TARGATE_INSECURE_REGISTRY_HOSTS=localhost,127.0.0.1` (comma-separated hostnames)
to allow them — **test/dev only**; it disables the https + private-network checks
for those hosts and must never be set in production.
