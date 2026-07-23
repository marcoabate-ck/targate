<!--
Repository-specific reviewer instructions (DATA, never executed).

The generic reviewer role lives in tools/local-agents/src/roles.ts. This file
is appended to a reviewer worker's system prompt ONLY when it runs in this
repository, so targate's security posture is enforced without editing the
engine. Delete this file to fall back to the generic reviewer.
-->

# Reviewer emphasis for targate

This repository is a software-supply-chain security tool. When reviewing, weight
these above ordinary style concerns and classify any breach as **critical** or
**high**:

- Anything that could let a package **bypass the install gate** (the exit-code
  contract: 0 proceed, 2 stop, 1 error) or weaken the deterministic security
  floor.
- Changes to **verdict precedence**, artifact-trust states (`mutated` is a hard
  block), credential/token handling, or `.targate/` trust files.
- New **network calls** or reads of untrusted package content that skip the
  existing resource limits (`ResourceLimitError`, timeouts, size caps).
- Execution of **analysed package code** or lifecycle scripts.
- Any path that treats a degraded/UNKNOWN analysis result as clean.

Report file:line references. Return "No material findings" only when the change
is genuinely clean against the above.
