# Sandboxed trial install

```bash
targate sandbox suspicious-package
```

Runs `npm install` in a **disposable Docker container** (`node:20-alpine`): no host environment variables, no SSH agent, no npm/GitHub tokens, no host filesystem mounted, all Linux capabilities dropped, no privilege escalation, and — as of the hardened sandbox — the untrusted install runs as a **non-root user on a read-only root filesystem**, with only two `tmpfs` work directories writable, so a hostile lifecycle script cannot escalate, persist into the image, or write outside them. 1 CPU / 1 GB / 512-PID cap, and the whole container (not just the client) is `docker kill`ed after a timeout. The package spec is passed as a container environment variable, never interpolated into the container's shell script, so a hostile spec string cannot inject commands. Lifecycle scripts run with `--foreground-scripts` so their full output lands in the log, which is then scanned for exfiltration patterns (credential file references, raw network connections, base64 decoding, …); the container also reports filesystem writes outside the project directory. Exit code `2` means the log contains something you should read before installing on your machine.

## Network — read this before relying on the sandbox as a jail

By default the container has **full outbound network access** (docker's bridge network): npm needs it to download the package and its dependencies, and a malicious install script can use that same access to exfiltrate or phone home. The sandbox keeps that activity *off your host and out of your real environment*, and surfaces it in the log — it is an **observation sandbox, not a network jail**. It does not restrict *which* hosts the install can reach, and there is no per-host allowlist. `--network none` runs a fully offline trial (useful to confirm a script does **not** need the network — a phone-home attempt then fails loudly), but a normal cold install cannot fetch its dependencies with the network off.

## Network capture

With capture on (the default when the network is open; disable with `--no-capture`), targate observes the install's network activity from *inside* the container and prints a **Network activity** section: DNS query names, the destination host/port of each connection, and per-direction byte counts (uploads are the exfiltration signal). Destinations that a cold install legitimately needs — the npm registry, GitHub/GitLab/Bitbucket, `nodejs.org` for node-gyp headers — are marked expected; anything else is flagged and escalates the exit code to `2`.

How it works: a tiny dependency-free Node shim runs a DNS forwarder on `127.0.0.1:53` and a logging HTTP CONNECT + plain-HTTP proxy on `127.0.0.1:8888`. Because the container is non-root and read-only it cannot rewrite `/etc/resolv.conf`, so DNS is directed at the shim with docker `--dns 127.0.0.1` (set when the container is created); the npm/proxy environment is pointed at the proxy inside the script. The shim needs no extra Linux capability (`--cap-drop=ALL` stays intact — it binds its low port via a namespaced `--sysctl`) and forwards DNS to a public upstream.

**This is observation, not enforcement, and it has real gaps:**

- Traffic to **hardcoded IP addresses**, or by tools that **ignore the proxy environment**, or over **raw sockets**, bypasses the HTTP proxy and is not logged. (DNS lookups made through the system resolver are still captured, because docker `--dns` points the container's resolver at the shim.)
- A **hostile install script can kill the capture process** — it runs in the same container.
- **Capture failure never blocks the install** and is reported (`network capture failed to start`); the install proceeds uncaptured rather than failing.

Treat the network log as evidence to review, not a guarantee that nothing else happened.

Only the `sandbox` command needs Docker; every other command runs without it. `targate sandbox --json` emits the result (including the structured `network` activity) as one JSON document — see [CLI reference](cli-reference.md#json-output-schema).
