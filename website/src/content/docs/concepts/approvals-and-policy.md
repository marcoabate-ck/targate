---
title: Approvals & policy
description: How targate records human trust, verifies signatures, and enforces a declarative team policy.
---

## Approvals

An **approval** is a human vouching that a specific package **version** is trusted, even though analysis flagged it (a soft block or a require-approval signal). Approvals are keyed by `name@version` and stored in `.targate/approvals.json`, which you **commit** so the whole team shares the decision.

```jsonc
{
  "esbuild@0.28.1": {
    "mode": "normal",              // "normal" = scripts allowed, "no-scripts" = approved but scripts disabled
    "approvedAt": "2026-07-16T00:00:00.000Z",
    "approvedBy": "you@example.com",
    "context": {                    // audit trail — the circumstances of the approval
      "decision": "block",
      "source": "rules",
      "reasons": ["Install-time code reads env vars AND performs network calls …"]
    }
  }
}
```

Approvals are **read** from `.targate/approvals.{yaml,yml,json}` (merged in that order — hand-curated sources first, the tool-managed `.json` last). Config is **declarative only** — parsed, never executed. Approvals are **written** only to `.targate/approvals.json`, and — critically — **never created in CI**. In CI they are only read from the committed file.

An approval can never clear a **hard block**: mutated bytes and known-malicious records stay blocked regardless.

### Signed approvals

`targate approve --sign` adds an SSH signature (the same keys you use for git commit signing) over the approval entry. `requireSignedApprovals` in policy makes CI **reject** any unsigned or invalidly-signed approval, verified against `.targate/allowed-signers`. A hand-edited approvals file therefore cannot green a poisoned dependency. Inspect and verify recorded trust with:

```bash
targate history                 # every recorded trust decision
targate history esbuild --verify  # verify the SSH signatures
```

## Team policy

A declarative policy raises the bar for a whole project. Scaffold one from a preset:

```bash
targate policy init                    # default preset
targate policy init --preset ai-agent  # stricter preset for agent-driven installs
```

Policy is declarative (`.yaml`/`.yml`/`.json`) — parsed, never executed:

```yaml
# targate.policy.yaml
dependencyPolicy:
  minPackageAgeDays: 7 # reject brand-new publishes
  allowKnownPackages: [react, react-native]
  requireSignedApprovals: true # enforce signatures in CI
```

Key properties of the policy engine:

- **Escalation-only.** Policy can make the gate *stricter*, never more permissive — with one deliberate exception: `allowKnownPackages` can clear a **soft** block for named packages (never a hard block, and never an `UNKNOWN`/degraded result).
- **Internal scopes.** Declaring internal scopes marks your own private packages so name-leaking lookups (OSV, download stats, maintainer search, GitHub) are skipped — visibly, and shown in the report.
- **Auditable.** An approval records the policy file name and a hash of its bytes at approval time, so the trust history shows which policy was in force.

See the typed shapes on the **[API reference](/api/readme/)** (`PolicyFile`, `DependencyPolicy`, `RegistryPolicy`, `ApprovalRecord`).
