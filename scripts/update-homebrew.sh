#!/usr/bin/env bash
#
# Render the Homebrew formula from packaging/homebrew/targate.rb.tmpl using the
# release binaries' SHA-256 sums, then push it to the tap repository.
#
# Required env:
#   VERSION   release version, no leading v (e.g. 1.2.3)
#   REPO      main repo, owner/name (e.g. marcoabate-ck/targate) — used in URLs
# Optional env:
#   DIST_DIR         directory holding the binaries + SHA256SUMS (default: dist-bin)
#   TAP_REPO         tap repo owner/name (default: <owner>/homebrew-targate)
#   GH_TOKEN         token with push access to the tap (required unless dry run)
#   HOMEBREW_DRY_RUN 1 → render to stdout and exit, no clone/push

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${DIST_DIR:-${ROOT}/dist-bin}"
SUMS="${DIST}/SHA256SUMS"
TMPL="${ROOT}/packaging/homebrew/targate.rb.tmpl"

fail() { echo "error: $*" >&2; exit 1; }

: "${VERSION:?VERSION is required}"
: "${REPO:?REPO is required (owner/name)}"
[ -f "$SUMS" ] || fail "missing $SUMS"
[ -f "$TMPL" ] || fail "missing $TMPL"

OWNER="${REPO%%/*}"
TAP_REPO="${TAP_REPO:-${OWNER}/homebrew-targate}"

# Look up a checksum by asset basename from SHA256SUMS ("<hash>  <name>").
sha() {
  local h
  h="$(grep " $1\$" "$SUMS" | awk '{print $1}')"
  [ -n "$h" ] || fail "no SHA-256 for $1 in $SUMS"
  printf '%s' "$h"
}

DA="$(sha targate-darwin-arm64)"
DX="$(sha targate-darwin-x64)"
LA="$(sha targate-linux-arm64)"
LX="$(sha targate-linux-x64)"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
sed \
  -e "s|__VERSION__|${VERSION}|g" \
  -e "s|__REPO__|${REPO}|g" \
  -e "s|__SHA_DARWIN_ARM64__|${DA}|g" \
  -e "s|__SHA_DARWIN_X64__|${DX}|g" \
  -e "s|__SHA_LINUX_ARM64__|${LA}|g" \
  -e "s|__SHA_LINUX_X64__|${LX}|g" \
  "$TMPL" >"$rendered"

if [ "${HOMEBREW_DRY_RUN:-}" = "1" ]; then
  cat "$rendered"
  exit 0
fi

: "${GH_TOKEN:?GH_TOKEN is required to push the formula}"

work="$(mktemp -d)"
trap 'rm -f "$rendered"; rm -rf "$work"' EXIT
git clone --depth 1 "https://x-access-token:${GH_TOKEN}@github.com/${TAP_REPO}.git" "${work}/tap" \
  || fail "could not clone tap ${TAP_REPO} (does it exist and does the token have access?)"

mkdir -p "${work}/tap/Formula"
cp "$rendered" "${work}/tap/Formula/targate.rb"

cd "${work}/tap"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add Formula/targate.rb
if git diff --cached --quiet; then
  echo "Formula already up to date for ${VERSION}"
  exit 0
fi
git commit -m "targate ${VERSION}"
git push
echo "Pushed targate ${VERSION} formula to ${TAP_REPO}"
