# Registry proxy

```bash
targate proxy setup
```

The proxy is an enforcement point that needs no per-install command: you route
your package manager through a local proxy, and every install is vetted before a
tarball's bytes ever reach your machine. It closes the gap left by CLI-only
gating — a raw `npm install`, a script, or a CI job that never calls `targate` is
still checked — without a shell wrapper and without depending on lifecycle
scripts (so `--ignore-scripts` cannot switch it off).

> **Supported: npm, pnpm, and yarn-berry (Yarn 2+).** With these three the
> lockfile is **byte-for-byte identical** whether or not the proxy is in play
> (npm records the canonical upstream URL, pnpm the integrity, yarn-berry the
> checksum — none records the proxy). **yarn-classic (v1) and bun are refused**
> by `setup`: they bake the absolute fetched URL into the lockfile, which would
> modify it — unacceptable. Use npm/pnpm/yarn-berry for proxy-gated installs.

> **No project files are touched.** Routing is via **environment variables**, not
> your committed `.npmrc` — `setup` writes a machine-local, sourceable
> `~/.targate/proxy.env`. Public packages are gated out of the box. Private/scoped
> registries are captured from your `.npmrc` (credential relayed upstream) and
> gated via `targate proxy exec` (see [private scopes](#private-scopes)). It runs
> as a **local, single-user** daemon — a network-shared proxy is out of scope (a
> non-loopback bind is refused unless you opt in).

## Quick start

> **Requires `openssl`** on `PATH` — `setup` uses it to generate the local CA and
> leaf certificate.

```bash
targate proxy setup                 # generate a local CA, start the proxy, write ~/.targate/proxy.env
source ~/.targate/proxy.env         # route this shell's installs through the proxy (+ trust the CA)
npm install                         # every public package is now vetted before it lands
targate proxy teardown              # stop the proxy and remove the env file, CA, and uplinks
```

`setup` **never edits your project `.npmrc`** (it is a committed file). Instead it
writes a machine-local `~/.targate/proxy.env` you source:

```sh
export npm_config_registry="https://127.0.0.1:4873"      # npm + pnpm
export NPM_CONFIG_REGISTRY="https://127.0.0.1:4873"      # npm
export YARN_NPM_REGISTRY_SERVER="https://127.0.0.1:4873" # yarn-berry
export NODE_EXTRA_CA_CERTS="/…/.targate/proxy-tls/ca.pem"
```

Add that `source` line to your shell profile to make it persistent. Nothing is
written to the repo, and the lockfile is unchanged.

For a **private scope** pinned in a committed `.npmrc` (npm/pnpm), a sourced env
cannot re-route it (shell cannot export a `@scope:registry` variable) — run those
installs through the proxy with:

```bash
targate proxy exec -- npm install    # sets the per-scope override for this one command
```

## How it works

- **Routing is via the environment, per client.** Package managers are pointed at
  the proxy through env vars (`npm_config_registry` for npm/pnpm,
  `YARN_NPM_REGISTRY_SERVER` for yarn-berry) — never the project `.npmrc`. For
  **npm**, the packument passes through unmodified: `replace-registry-host=npmjs`
  (the default on npm ≥ 9) routes the tarball through the proxy while the lockfile
  keeps canonical `registry.npmjs.org` URLs (do **not** set
  `replace-registry-host=never` — that bypasses the proxy). **pnpm and yarn-berry**
  don't rewrite the host themselves, so the proxy rewrites `dist.tarball` to a
  **clean** proxy URL (no query string) — the tarball still comes back for
  vetting, the real upstream URL is resolved server-side, and the lockfile they
  write is byte-identical to a no-proxy run.
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
| `targate proxy setup` | Generate a local CA + certificate, start the HTTPS daemon, and write the sourceable `~/.targate/proxy.env` (no project files touched). Refuses yarn-classic/bun. |
| `targate proxy teardown` | Stop the daemon and remove the env file, TLS material, and uplinks. |
| `targate proxy exec -- <cmd>` | Run `<cmd>` with the full proxy environment, including per-scope overrides a sourced file cannot express — the way to gate a private scope on npm/pnpm. Requires `--`. |
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

`targate proxy setup` reads your existing `.npmrc` and, for every private
per-scope registry (`@acme:registry=https://npm.acme.example`), writes an
**uplink** to `~/.targate/proxy-uplinks.json` capturing the scope's real upstream
**and its credential** (the same token already in your `.npmrc`), `0600`. It does
**not** touch your `.npmrc`.

Routing a private scope through the proxy needs an override that outranks the
scope pinned in your committed `.npmrc`. On **yarn-berry** the sourced env handles
it. On **npm/pnpm** it cannot — the override variable `npm_config_@scope:registry`
is not a valid shell identifier, so it cannot live in a sourced file. Run those
installs through:

```bash
targate proxy exec -- npm install       # or: pnpm install / pnpm add @acme/thing
```

`exec` spawns your command with the per-scope override applied (a child-process
env may hold that key even though `export` cannot), so `@acme/*` flows through the
proxy for that command only — no project or lockfile changes.

At request time the proxy routes `@acme/*` to its real upstream and authenticates
with the captured credential (it never stores anything the client did not already
have; if no credential was captured it relays the client's header pass-through),
rewrites the private packument's `dist.tarball` so the tarball comes back for
vetting, and runs the same analysis as for public packages — the
same-version-mutation ledger and content scanning that matter for a compromised
internal package (external databases cannot know private names). A scoped package
with **no** uplink resolves as public, so a dependency-confusion attempt surfaces
rather than sliding through.

Registries whose scopes share one token (one Artifactory serving several scopes)
are captured cleanly. `teardown` removes the uplinks file along with the rest.

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
- **yarn-classic (v1) and bun are not supported.** They bake the absolute fetched
  URL into their lockfiles, so routing them through the proxy would modify the
  lockfile — so `targate proxy setup` **refuses** them rather than poison it. Use
  npm, pnpm, or yarn-berry, whose lockfiles are byte-identical with or without the
  proxy.
- **Private scopes on npm/pnpm need `targate proxy exec`.** A sourced env cannot
  re-route a scope pinned in a committed `.npmrc` (the `@scope:registry` env var
  is not a valid shell identifier), so public installs are transparent but private
  ones go through `exec`. yarn-berry needs no exec (its per-scope env var is
  identifier-safe).

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
