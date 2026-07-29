---
title: Decisions & trust
description: The four decisions, hard vs soft blocks, and how tarball artifact identity is established.
---

## The four decisions

Every package resolves to exactly one decision, ordered by severity:

| Decision | Meaning | Installs? |
|---|---|---|
| <span class="verdict verdict--allow">ALLOW</span> | No high-risk install-time behavior. | Yes |
| <span class="verdict verdict--warn">ALLOW_WITH_WARNINGS</span> | Legitimate but worth noting (native surface, advisories, missing repo). | Yes |
| <span class="verdict verdict--approve">REQUIRE_APPROVAL</span> | A human should vouch first (install-time scripts, suspicious constructs, unknown analysis). | Only with a committed approval |
| <span class="verdict verdict--block">BLOCK</span> | Dangerous or untrustworthy. | No |

The **rules engine** produces this verdict deterministically. An AI reviewer, if configured, may raise the severity but can never lower it — the rules verdict is a floor. See **[AI & privacy](/docs/concepts/ai-and-privacy/)**.

## Hard vs soft blocks

Not all blocks are equal:

- **Hard blocks can never be overridden** — not by an approval, an allow-list, or the AI. They are:
  - a **mutated artifact** (tarball bytes don't match trusted evidence),
  - a **known-malicious** OSV/OpenSSF record,
  - a lifecycle command that **downloads *and* executes** remote code (`curl … | bash`, `node -e` fetching a payload).
- **Soft blocks are heuristic** — a strong signal a human may deliberately clear for a specific version. The classic case is a native-binary installer (esbuild, swc, sharp, playwright) whose install script legitimately reads `process.env` *and* hits the network to fetch its platform binary — indistinguishable from exfiltration by pattern, but routinely legitimate. Soft blocks can be cleared by a committed, version-pinned approval or an allow-list entry.

## Artifact identity & trust levels

Before targate reads a single byte of a tarball, it establishes **who vouches for those exact bytes**. It computes the SHA-512 digest and compares it against every independent source available, then assigns a trust level:

| Trust | How it was established |
|---|---|
| `public-equivalent` | Bytes match an **independent** public-registry checksum. |
| `lockfile-verified` | Bytes match the reviewed lockfile checksum. |
| `history-verified` | Bytes match a previously recorded digest for this version. |
| `registry-consistent` | Bytes match the checksum declared by their own source registry. |
| `private-only` | A private artifact with no comparable public version. |
| `public-unavailable` | The public comparison could not be made. |
| `unverified` | No registry, lockfile, public, or historical checksum was available. |
| `mutated` | Bytes **differ** from trusted evidence → **hard block**. |

Two claims from the *same* registry are never treated as independent evidence. This is what makes a **compromised mirror** detectable: if a mirror rewrites both the tarball and its own metadata to agree, the independent public-registry comparison still disagrees, and the artifact is `mutated`.

### Benign metadata drift

Sometimes a registry packument legitimately disagrees with the authentic tarball — for example [fsevents](https://www.npmjs.com/package/fsevents) keeps an `install` script in its packument that the published tarball dropped. When the **bytes are checksum-verified** and the tarball merely omits a script the metadata declares (the tarball hides nothing extra), that is treated as an **approvable drift**, not tampering. The reverse — a tarball running a script the metadata hides — remains a hard block.

## Analysis that can't complete

Network bodies, tarball size, extracted tree size, per-file size, and scan time all have configurable limits. When a limit is exceeded or a lookup times out, the result is reported as `UNKNOWN` and deterministically **requires approval** — it is never presented as clean. `--fail-on-osv-error` makes an unreachable malicious-package lookup fail closed.
