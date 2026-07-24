# Security policy

targate is a supply-chain security tool. A vulnerability in it can directly weaken
the defenses of everyone who runs it, so we treat reports seriously and ask you to
disclose them privately.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request, or discussion for a security
problem.** Public disclosure before a fix is available puts users at risk.

Use one of these private channels:

1. **GitHub private vulnerability reporting (preferred).** Go to the repository's
   **Security → Report a vulnerability** tab and file a private advisory. This keeps
   the report, the discussion, and the fix in one place until disclosure.
2. **Email.** If you cannot use GitHub, email **marco.abate@callstack.com** with the
   subject line `targate security report`. Encrypt if you can; ask for a key first.

Please include, as far as you can:

- affected version(s) / commit and platform (OS, Node version, package manager);
- a description of the issue and its impact (what an attacker gains);
- a minimal reproduction — a package spec, a crafted tarball, a config, or a command;
- any known workaround.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment (severity, affected versions) within **7 business days**.
- Regular updates while we work on a fix; we will tell you if we need more time.
- Coordinated disclosure: we agree a disclosure date with you, ship the fix, publish
  a GitHub Security Advisory, and credit you (unless you prefer to remain anonymous).

## Scope

In scope — anything that lets untrusted input subvert a targate decision or the host,
for example:

- an artifact that should be blocked but is allowed (a bypass of the deterministic
  floor, the hard-block clamp, artifact-identity verification, or OSV/malicious checks);
- code execution on the host during analysis (before an explicit install decision);
- a prompt-injection or malformed-AI-response path that downgrades a verdict;
- SSRF, path traversal, decompression bombs, or resource exhaustion in the quarantine /
  network layers;
- a signing / approval bypass (`requireSignedApprovals`, allowed-signers verification);
- a supply-chain weakness in targate's own release, installer, or CI.

Out of scope — issues that are the *documented* limits of the tool (see
[docs/threat-model.md](docs/threat-model.md) and [docs/security.md](docs/security.md)),
for example: transitive dependencies not covered without `--deep`, obfuscated payloads
that stay within scan budgets, the DNS-rebinding TOCTOU on artifact fetch, or the fact
that `approvedBy` is not authenticated. Reports that simply restate a documented
limitation may be closed as such — but if you can turn one into a concrete bypass,
that is in scope.

## Supported versions

Until `1.0.0`, only the latest released version (and `main`) receives security fixes.
After `1.0.0`, the supported range will be stated here.
