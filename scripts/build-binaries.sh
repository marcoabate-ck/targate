#!/usr/bin/env bash
#
# Build standalone targate executables for every supported platform with
# `bun build --compile`, then emit SHA-256 checksums.
#
# One toolchain, one runner: bun cross-compiles all targets from a single host,
# so this runs identically in CI (ubuntu) and locally. The compile entry is the
# already-built `dist/cli.js`, so the binary is the exact JS that ships to npm.
#
# Prerequisites: `bun` on PATH and `pnpm build` already run (dist/cli.js present).
# The embedded `--version` comes from package.json AT BUILD TIME, so callers that
# cut a release must set the version (npm version <v>) before invoking this.
#
# Usage: scripts/build-binaries.sh [output-dir]   (default: dist-bin)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${ROOT}/dist-bin}"
ENTRY="${ROOT}/dist/cli.js"

# Version embedded into the binary (package.json is not on disk inside a bun
# single-file binary). Prefer an explicit VERSION env (CI sets it from the tag);
# fall back to package.json for local builds.
VERSION="${VERSION:-$(node -p "require('${ROOT}/package.json').version")}"

# target triple : asset-os : asset-arch : extension
TARGETS=(
  "bun-linux-x64:linux:x64:"
  "bun-linux-arm64:linux:arm64:"
  "bun-darwin-x64:darwin:x64:"
  "bun-darwin-arm64:darwin:arm64:"
  "bun-windows-x64:windows:x64:.exe"
)

fail() { echo "error: $*" >&2; exit 1; }

command -v bun >/dev/null 2>&1 || fail "bun is not installed (https://bun.sh)"
[ -f "$ENTRY" ] || fail "missing $ENTRY — run \`pnpm build\` first"

# Portable SHA-256: prefer sha256sum (Linux), fall back to shasum (macOS).
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
  else shasum -a 256 "$1"; fi
}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "Building targate binaries from ${ENTRY#"$ROOT"/}"
for spec in "${TARGETS[@]}"; do
  IFS=":" read -r triple os arch ext <<<"$spec"
  name="targate-${os}-${arch}${ext}"
  out="${OUT_DIR}/${name}"
  echo "  → ${name} (${triple})"
  # --compile: standalone binary. Deterministic flags: no sourcemap, minify off
  # (keep stack traces readable; size is not a release constraint here).
  # --define injects the version so `targate --version` works without a
  # package.json on disk (see src/version.ts).
  bun build "$ENTRY" --compile --target="$triple" \
    --define "process.env.TARGATE_VERSION=\"${VERSION}\"" \
    --outfile "$out" >/dev/null
  [ -f "$out" ] || fail "bun did not produce $out"
done

# Per-file checksums plus one aggregate SHA256SUMS (basenames only, so the file
# is portable and matches what release consumers download).
echo "Writing checksums"
(
  cd "$OUT_DIR"
  : >SHA256SUMS
  for f in targate-*; do
    [ "$f" = "SHA256SUMS" ] && continue
    line="$(sha256 "$f")"
    # Normalise to "<hash>  <basename>" regardless of the tool used.
    hash="${line%% *}"
    printf '%s  %s\n' "$hash" "$f" >>SHA256SUMS
    printf '%s  %s\n' "$hash" "$f" >"${f}.sha256"
  done
)

echo
echo "Artifacts in ${OUT_DIR#"$ROOT"/}:"
ls -1 "$OUT_DIR"
