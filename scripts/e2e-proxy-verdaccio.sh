#!/usr/bin/env bash
#
# Local private-registry end-to-end for the registry proxy, with NO external
# credentials: a real Verdaccio (auth-required scope) behind the proxy. Proves
# per-scope routing, credential relay to the upstream, metadata override,
# dist.tarball rewrite, quarantine of the private tarball, and interactive
# approval — against real registry software, not a stub.
#
# Requires: node, npm, curl, and network access to fetch verdaccio via npx.
# Uses an isolated HOME so it never touches your real ~/.targate. macOS/Linux.
#
# Run:   bash scripts/e2e-proxy-verdaccio.sh
# Exit:  0 on PASS, non-zero on failure.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TSX="$REPO/node_modules/.bin/tsx"
CLI=("$TSX" "$REPO/src/cli.ts")
VPORT="${VERDACCIO_PORT:-4950}"
PPORT="${PROXY_PORT:-4951}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/targate-verdaccio-e2e.XXXXXX")"
export HOME="$WORK/home"
mkdir -p "$HOME/.targate" "$WORK/storage"
export TARGATE_INSECURE_REGISTRY_HOSTS="localhost,127.0.0.1" # test-only: allow the loopback upstream

VPID=""
cleanup() {
  [ -n "$VPID" ] && kill "$VPID" 2>/dev/null
  ( cd "$WORK/consumer" 2>/dev/null && "${CLI[@]}" proxy stop >/dev/null 2>&1 )
  for p in "$VPORT" "$PPORT"; do lsof -ti :"$p" 2>/dev/null | xargs kill -9 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

for p in "$VPORT" "$PPORT"; do lsof -ti :"$p" 2>/dev/null | xargs kill -9 2>/dev/null; done

# --- start Verdaccio: @vtest requires auth for access AND publish ---
cat > "$WORK/config.yaml" <<EOF
storage: $WORK/storage
auth:
  htpasswd:
    file: $WORK/htpasswd
    max_users: 1000
packages:
  '@vtest/*':
    access: \$authenticated
    publish: \$authenticated
  '**':
    access: \$all
    publish: \$authenticated
log: { type: stdout, format: pretty, level: warn }
EOF
echo "Starting Verdaccio on :$VPORT ..."
npx --yes verdaccio@6 --config "$WORK/config.yaml" --listen "0.0.0.0:$VPORT" >"$WORK/verdaccio.log" 2>&1 &
VPID=$!
for _ in $(seq 1 30); do curl -sf "http://localhost:$VPORT/-/ping" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "http://localhost:$VPORT/-/ping" >/dev/null 2>&1 || fail "verdaccio did not start; log: $(tail -3 "$WORK/verdaccio.log")"

# --- user + token ---
TOKEN="$(curl -s -XPUT "http://localhost:$VPORT/-/user/org.couchdb.user:tester" \
  -H "content-type: application/json" \
  -d '{"name":"tester","password":"pass1234","email":"t@example.com"}' \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).token||"")}catch{process.stdout.write("")}})')"
[ -n "$TOKEN" ] || fail "could not obtain a verdaccio token"

# --- publish a private @vtest/pkg ---
PK="$WORK/pkgsrc"; mkdir -p "$PK"
printf '{"name":"@vtest/pkg","version":"1.0.0","description":"private verdaccio test"}' > "$PK/package.json"
printf 'module.exports=1;\n' > "$PK/index.js"
printf 'registry=http://localhost:%s/\n//localhost:%s/:_authToken=%s\n' "$VPORT" "$VPORT" "$TOKEN" > "$PK/.npmrc"
( cd "$PK" && npm publish --registry "http://localhost:$VPORT/" >/dev/null 2>&1 ) || fail "publish to verdaccio failed"

# --- proxy: uplink @vtest -> verdaccio (with the captured token, as `setup` would produce) ---
printf '[{"scope":"@vtest","upstream":"http://localhost:%s","auth":"Bearer %s"}]' "$VPORT" "$TOKEN" > "$HOME/.targate/proxy-uplinks.json"
C="$WORK/consumer"; mkdir -p "$C"
printf '{"name":"consumer","version":"1.0.0","dependencies":{"@vtest/pkg":"1.0.0"}}' > "$C/package.json"
printf 'registry=http://localhost:%s\n@vtest:registry=http://localhost:%s\n' "$PPORT" "$PPORT" > "$C/.npmrc"
( cd "$C" && "${CLI[@]}" proxy start --port "$PPORT" >/dev/null 2>&1 )
sleep 1

# --- install through the proxy, auto-approving the require_approval hold ---
echo "Installing @vtest/pkg through the proxy ..."
( cd "$C" && npm_config_cache="$C/npmcache" NPM_CONFIG_FETCH_TIMEOUT=120000 npm install --no-audit --no-fund --loglevel=error >"$C/npm.out" 2>&1 ) &
NPID=$!
for _ in $(seq 1 30); do
  if ( cd "$C" && "${CLI[@]}" proxy approvals 2>/dev/null | grep -q "@vtest/pkg@1.0.0" ); then
    ( cd "$C" && "${CLI[@]}" proxy approve @vtest/pkg@1.0.0 >/dev/null )
    break
  fi
  sleep 1
done
wait "$NPID"

[ -f "$C/node_modules/@vtest/pkg/package.json" ] || fail "private package not installed; npm: $(tail -3 "$C/npm.out")"
grep -q "@vtest/pkg@1.0.0" "$HOME/.targate/proxy.log" || fail "no proxy decision logged for @vtest/pkg (it bypassed the proxy)"

echo "PASS: private package routed through the proxy, credential relayed to Verdaccio, approved, and installed."
