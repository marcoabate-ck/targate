---
title: Registry proxy
description: Gate every install through a local proxy — no wrapper, no lockfile changes, no edits to your committed .npmrc.
---

The registry proxy is an install-time gate that needs no per-install command. You
route your package manager through a local proxy, and **every** install — even a
raw `npm install`, a postinstall script, or CI — is analyzed with the same
deterministic pipeline as `targate add` before a tarball's bytes ever touch your
machine. No shell wrapper, and no dependency on lifecycle scripts (so
`--ignore-scripts` cannot switch it off).

It **never touches your repo**: it does not edit your `.npmrc` and it does not
change the lockfile. Routing is done through environment variables.

## Supported package managers

Use **npm, pnpm, or yarn-berry (Yarn 2+)** — with these three the lockfile is
byte-for-byte identical whether or not the proxy is in play. **yarn-classic (v1)
and bun are refused** by `setup`: they bake the absolute fetched URL into the
lockfile, which would modify it.

## Setup (once per project)

Requires `openssl` on your `PATH` (`setup` uses it to mint a local CA).

```bash
targate proxy setup            # local CA, start the proxy, write ~/.targate/proxy.env
source ~/.targate/proxy.env    # route this shell through the proxy (+ trust the CA)
```

`setup` writes a machine-local, sourceable `~/.targate/proxy.env` — **nothing is
written to the repo**:

```sh
export npm_config_registry="https://127.0.0.1:4873"      # npm + pnpm
export YARN_NPM_REGISTRY_SERVER="https://127.0.0.1:4873" # yarn-berry
export NODE_EXTRA_CA_CERTS="/…/.targate/proxy-tls/ca.pem"
```

Add the `source` line to your shell profile to make it persistent. On adoption,
clear your package manager's cache once so already-cached packages get re-vetted
(`npm cache clean --force`, `pnpm store prune`, or `yarn cache clean`).

## Everyday use

```bash
targate proxy ensure    # start the proxy if it is not already up
npm install             # or pnpm add / yarn add — everything is vetted; lockfile unchanged
```

The proxy is **fail-closed**: if it is not running, installs fail by design.
`targate proxy ensure` brings it back up.

## Private scopes

Private/scoped registries in your `.npmrc` are captured on `setup` (credential
relayed upstream, stored `0600`). A sourced env cannot re-route a scope **pinned
in a committed `.npmrc`** on npm/pnpm (the `@scope:registry` variable is not a
valid shell identifier), so run those installs through:

```bash
targate proxy exec -- npm install    # or: pnpm install / pnpm add @scope/pkg
```

`exec` applies the per-scope override for that one command only. With yarn-berry
you do not need `exec` (its per-scope env var is identifier-safe).

## When it stops you

Some packages are held for human review — a known **critical** vulnerability,
suspicious install scripts, a very young package, or incomplete analysis. The
install waits; decide out of band in another terminal:

```bash
targate proxy approvals                    # what is waiting
targate proxy approve <pkg>@<version>      # release and serve it
targate proxy deny    <pkg>@<version>      # refuse it
```

If no decision arrives before the hold cap, it fails closed.

## How it works

- **Analyze-what-you-serve.** The proxy fetches the exact bytes it is about to
  serve, runs the full deterministic analysis, and either streams the bytes
  (`allow` / `allow_with_warnings`) or returns HTTP 403 with the reason
  (`block` / `require_approval`).
- **Verdict cache.** Keyed by the tarball's SHA-512 digest and persisted, so each
  artifact is analyzed once — a republished/mutated tarball has a different digest
  and is re-analyzed.
- **Local and single-user.** It binds loopback only by default; a non-loopback
  bind is refused unless you explicitly opt in.

## Manage

```bash
targate proxy status     # is it running? does this project route through it?
targate doctor           # environment checks (proxy, cache-bypass, …)
targate proxy teardown   # stop and remove the env file, CA, and uplinks
```
