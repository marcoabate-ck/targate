/**
 * `CAPTURE_SCRIPT` is a self-contained, dependency-free Node ESM program that
 * runs INSIDE the sandbox container to *observe* (never block) the network
 * activity of a trial install:
 *
 *   - a DNS forwarder on 127.0.0.1:53 (udp + tcp) that logs every query name
 *     and relays it to the container's original resolver;
 *   - a logging HTTP CONNECT + plain-HTTP proxy on 127.0.0.1:8888 that logs
 *     each destination host/port and counts bytes per direction (uploads are
 *     the exfiltration signal).
 *
 * The container script points resolv.conf and the npm/http proxy env at these
 * listeners. Everything the shim emits is a single line on stdout with the
 * fixed grammar below — `src/sandbox.ts` (extractNetworkActivity) is the only
 * consumer and depends on it exactly:
 *
 *   [targate-net] ready
 *   [targate-net] dns <name> <TYPE>
 *   [targate-net] connect <host> <port>
 *   [targate-net] http <METHOD> <url>
 *   [targate-net] close <host> <port> sent=<n> recv=<n>
 *   [targate-net] error <free text>
 *
 * Observation, not enforcement: traffic to hardcoded IPs, tools that ignore
 * the proxy env, or raw sockets bypass the proxy log; a hostile script can
 * kill this process. Those gaps are documented and surfaced in the report.
 * Every failure here is non-fatal — the install must proceed regardless.
 */
export const CAPTURE_SCRIPT = String.raw`
import dgram from "node:dgram";
import net from "node:net";
import http from "node:http";
import { writeFileSync, readFileSync } from "node:fs";

const P = "[targate-net]";
const log = (s) => { try { process.stdout.write(P + " " + s + "\n"); } catch {} };
const err = (s) => log("error " + s);

// Upstream resolvers from the ORIGINAL resolv.conf (parsed before the shell
// rewrites it to point at us). Used only by the DNS forwarder below; the proxy
// resolves destinations through the container resolver (i.e. via us), which
// keeps resolution working AND logs the name.
let UPSTREAMS = [];
try {
  UPSTREAMS = readFileSync("/etc/resolv.conf", "utf8")
    .split("\n").map((l) => l.trim())
    .filter((l) => l.startsWith("nameserver "))
    .map((l) => l.split(/\s+/)[1])
    .filter((ip) => ip && ip !== "127.0.0.1");
} catch {}
if (UPSTREAMS.length === 0) UPSTREAMS = ["8.8.8.8"];

const QTYPE = { 1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV" };
function parseQuestion(buf) {
  try {
    let off = 12, labels = [];
    while (off < buf.length) {
      const len = buf[off++];
      if (len === 0) break;
      labels.push(buf.toString("utf8", off, off + len));
      off += len;
    }
    const type = buf.readUInt16BE(off);
    return { name: labels.join("."), type: QTYPE[type] || ("TYPE" + type) };
  } catch { return null; }
}

let ready = 0;
const NEEDED = 3; // udp53, tcp53, proxy8888
function markReady() {
  if (++ready === NEEDED) {
    try { writeFileSync("/tmp/targate-capture.ready", ""); } catch {}
    log("ready");
  }
}

// --- DNS over UDP ---
const udp = dgram.createSocket("udp4");
udp.on("error", (e) => err("udp " + e.message));
udp.on("message", (msg, rinfo) => {
  const q = parseQuestion(msg);
  if (q && q.name) log("dns " + q.name + " " + q.type);
  const out = dgram.createSocket("udp4");
  out.on("error", () => { try { out.close(); } catch {} });
  out.send(msg, 53, UPSTREAMS[0], (e) => {
    if (e) { try { out.close(); } catch {} return; }
  });
  out.on("message", (reply) => {
    udp.send(reply, rinfo.port, rinfo.address, () => { try { out.close(); } catch {} });
  });
  setTimeout(() => { try { out.close(); } catch {} }, 5000);
});
udp.bind(53, "127.0.0.1", markReady);

// --- DNS over TCP (byte pipe to upstream) ---
const tcp53 = net.createServer((sock) => {
  sock.on("error", () => sock.destroy());
  const up = net.connect(53, UPSTREAMS[0]);
  up.on("error", () => sock.destroy());
  sock.pipe(up); up.pipe(sock);
});
tcp53.on("error", (e) => err("tcp53 " + e.message));
tcp53.listen(53, "127.0.0.1", markReady);

// --- HTTP(S) logging proxy ---
const proxy = http.createServer((req, res) => {
  let host = "", port = 80;
  try { const u = new URL(req.url); host = u.hostname; port = Number(u.port) || 80; } catch {}
  log("http " + req.method + " " + req.url);
  let sent = 0, recv = 0;
  const up = http.request(
    req.url,
    { method: req.method, headers: req.headers },
    (upRes) => {
      res.writeHead(upRes.statusCode || 502, upRes.headers);
      upRes.on("data", (c) => { recv += c.length; });
      upRes.pipe(res);
      upRes.on("end", () => log("close " + host + " " + port + " sent=" + sent + " recv=" + recv));
    },
  );
  up.on("error", () => { try { res.destroy(); } catch {} });
  req.on("data", (c) => { sent += c.length; });
  req.pipe(up);
});
// Open tunnels get flushed on SIGTERM so keep-alive sockets still report bytes.
const openTunnels = new Set();
proxy.on("connect", (req, clientSock, head) => {
  const [host, portStr] = String(req.url).split(":");
  const port = Number(portStr) || 443;
  log("connect " + host + " " + port);
  let sent = 0, recv = 0, closed = false;
  const flush = () => {
    if (closed) return;
    closed = true;
    openTunnels.delete(flush);
    log("close " + host + " " + port + " sent=" + sent + " recv=" + recv);
  };
  openTunnels.add(flush);
  const up = net.connect({ host, port }, () => {
    clientSock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length) up.write(head);
    clientSock.on("data", (c) => { sent += c.length; up.write(c); });
    up.on("data", (c) => { recv += c.length; clientSock.write(c); });
  });
  const done = () => {
    flush();
    try { clientSock.destroy(); } catch {}
    try { up.destroy(); } catch {}
  };
  up.on("error", done); up.on("close", done);
  clientSock.on("error", done); clientSock.on("close", done);
});
proxy.on("error", (e) => err("proxy " + e.message));
proxy.listen(8888, "127.0.0.1", markReady);

process.on("uncaughtException", (e) => err("uncaught " + e.message));
process.on("SIGTERM", () => {
  for (const flush of [...openTunnels]) flush();
  process.exit(0);
});
`;
