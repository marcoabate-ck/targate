# Private registries

targate reads the same `.npmrc` configuration npm does, so packages served by a private registry — GitHub Packages, Verdaccio, Artifactory, an npmjs mirror, or npm's own private scoped packages — are analyzed exactly like public ones: metadata and tarball come from *your* registry, authenticated with *your* credentials, and the analysis itself (quarantine, scripts, contents, native surface) is unchanged.

## What is read

The user `~/.npmrc` and the project `.npmrc` are merged (project wins), and three kinds of entries matter:

```ini
# which registry serves a scope
@acme:registry=https://npm.pkg.github.com

# a global registry override (typically a mirror/proxy like Verdaccio)
registry=https://verdaccio.internal:4873

# credentials, in npm's own "nerf-dart" format — matched by host + path,
# most specific first; ${ENV} references are expanded
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
//verdaccio.internal:4873/:_authToken=...
```

Resolution per package: a `@scope:registry` rule wins, then a global `registry=` override, then the npmjs default. The chosen registry appears in the report header (`registry: https://… (scoped)`) and in the JSON as `metadata.registryUrl` / `metadata.registrySource`, so a review always shows **which infrastructure was trusted**.

Supported credential forms: `_authToken` (sent as `Bearer`), `_auth` (pre-encoded `Basic`), and `username` + `_password` (base64-encoded password, npm's format). The tarball download reuses the registry's credential when the tarball URL lives under the same nerf-dart — again matching npm. An entry referencing an **unset** environment variable is dropped (npm would error; targate degrades to an anonymous request, and the registry's 401 is reported with a hint pointing at the `.npmrc` entry). Token values are used as request headers only — never logged, printed, or persisted.

## What changes in the analysis

targate's external intelligence sources only know **public npmjs packages**, so lookups degrade honestly rather than producing junk:

| Package served by | OSV / OpenSSF | npm downloads | Maintainer intel | GitHub repo status | Typosquat check |
|---|---|---|---|---|---|
| npmjs (default) | ✓ | ✓ | ✓ | ✓ | ✓ |
| global `registry=` override (mirror) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `@scope:registry` (private registry) | ✓ | skipped | skipped | ✓ | ✓ |
| scope in policy `internalScopes` | **skipped** | **skipped** | **skipped** | **skipped** | **skipped** |

- A **global override** is treated as a mirror of public packages — every lookup still applies, keyed by the public name.
- A **scope-mapped registry** hosts packages the npmjs downloads API and maintainer search cannot know — those two are skipped (`status: "skipped"`, shown in the report), while OSV and GitHub still run.
- Every skip is visible in the report, the score, and the JSON — an unchecked package is never presented as externally verified clean.

## `internalScopes` — name privacy

Querying OSV, the downloads API, or the maintainer search **sends the package name to a third party**. For company-internal packages the name itself can be confidential (`@acme/payments-fraud-model`). Declare those scopes in the [team policy](policy-reference.md):

```yaml
# targate.policy.yaml
dependencyPolicy:
  internalScopes: ["@acme"]
```

For matching packages targate:

- never sends the name to OSV, the npm downloads API, the maintainer search, or GitHub — in single-package runs, `--deep` tree walks, `targate diff`, and `targate monitor` alike;
- skips the typosquat similarity check (it compares against popular *public* names — meaningless for an internal package);
- says so, everywhere: the report shows `ℹ internal scope — … lookups skipped`, the score deducts under *Vulnerabilities* ("not externally checked"), `explain` lists it as a residual risk, and the JSON carries `signals.internalScope: true`.

The static analysis (lifecycle scripts, tarball contents, native surface, RN hardening) is unaffected — it runs entirely locally.

> **Trust trade-off, stated plainly:** an internal-scope package is *not* checked against the malicious-package databases. That is the right call for genuinely private code (the databases cannot know it, and the query would leak the name), but it also means a compromised internal package will not be flagged by OSV. The deterministic content analysis and the [trust history](team-workflow.md#trust-history--targate-history) are the compensating controls.

## Dependency confusion

Scope-mapped registries are the standard defense against dependency-confusion attacks (a public package squatting an internal name): with `@acme:registry=` in the committed project `.npmrc`, npm — and targate — will never resolve `@acme/*` from npmjs. targate adds a second layer: an `@acme` package that *doesn't* match an `.npmrc` scope rule resolves from npmjs and gets the **full** public-package analysis, including the typosquat check and reputation signals, so a confusion attempt surfaces as a suspicious young public package rather than sliding through as internal.

## doctor

`targate doctor` shows the resolved registry configuration — the default registry, any global override, each scoped registry, and whether credentials are configured for it (presence only; values are never printed).
