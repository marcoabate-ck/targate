# Sandboxed trial install

```bash
targate sandbox suspicious-package
```

Runs `npm install` in a **disposable Docker container** (`node:20-alpine`): no host environment variables, no SSH agent, no npm/GitHub tokens, no host filesystem mounted, all Linux capabilities dropped, no privilege escalation, 1 CPU / 1 GB cap, killed after a timeout. The package spec is passed as a container environment variable, never interpolated into the container's shell script, so a hostile spec string cannot inject commands. Lifecycle scripts run with `--foreground-scripts` so their full output lands in the log, which is then scanned for exfiltration patterns (credential file references, raw network connections, base64 decoding, …); the container also reports filesystem writes outside the project directory. Exit code `2` means the log contains something you should read before installing on your machine.

## Network — read this before relying on the sandbox as a jail

By default the container has **full outbound network access** (docker's bridge network): npm needs it to download the package and its dependencies, and a malicious install script can use that same access to exfiltrate or phone home. The sandbox keeps that activity *off your host and out of your real environment*, and surfaces it in the log — it is an **observation sandbox, not a network jail**. It does not restrict *which* hosts the install can reach, and there is no per-host allowlist. `--network none` runs a fully offline trial (useful to confirm a script does **not** need the network — a phone-home attempt then fails loudly), but a normal cold install cannot fetch its dependencies with the network off.

Only the `sandbox` command needs Docker; every other command runs without it.
