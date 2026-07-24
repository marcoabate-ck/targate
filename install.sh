#!/bin/sh
#
# targate installer.
#
#   curl -fsSL https://raw.githubusercontent.com/marcoabate-ck/targate/main/install.sh | sh
#
# Detects OS/arch, downloads the matching standalone binary from the GitHub
# Release, verifies its SHA-256 (and the minisign signature when a public key is
# configured), and installs it to a standard location. Fails safely with clear
# messages and never runs anything from the downloaded artifact.
#
# Environment overrides:
#   TARGATE_VERSION       version to install (e.g. 1.2.3); default: latest
#   TARGATE_INSTALL_DIR   install directory; default: /usr/local/bin or ~/.local/bin
#   TARGATE_REPO          owner/repo; default: marcoabate-ck/targate
#   TARGATE_BASE_URL      base URL for assets (advanced: mirrors / local testing)
#   TARGATE_MINISIGN_PUBKEY  minisign public key line to verify against

set -eu

# Minisign public key for release checksums. Fill in after `minisign -G` and
# committing minisign.pub; leave empty to skip signature verification (SHA-256
# is always enforced). Overridable via TARGATE_MINISIGN_PUBKEY.
MINISIGN_PUBKEY_DEFAULT=""

REPO="${TARGATE_REPO:-marcoabate-ck/targate}"
VERSION="${TARGATE_VERSION:-latest}"

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- download helper (curl or wget) ---------------------------------------
if have curl; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif have wget; then
  fetch() { wget -q "$1" -O "$2"; }
else
  err "need curl or wget to download targate"
fi

download() {
  # $1 url, $2 dest — fail with a clear message rather than a raw tool error.
  fetch "$1" "$2" || err "failed to download $1"
}

# ---- detect platform -------------------------------------------------------
os="$(uname -s)"
case "$os" in
  Darwin) os="darwin" ;;
  Linux) os="linux" ;;
  *) err "unsupported operating system: $os (targate ships macOS and Linux binaries)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch="x64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

asset="targate-${os}-${arch}"

# ---- resolve the download base ---------------------------------------------
if [ -n "${TARGATE_BASE_URL:-}" ]; then
  base="$TARGATE_BASE_URL"
elif [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/v${VERSION#v}"
fi

# ---- sha-256 checker (sha256sum or shasum) ---------------------------------
if have sha256sum; then
  checksum() { sha256sum -c "$1" >/dev/null 2>&1; }
elif have shasum; then
  checksum() { shasum -a 256 -c "$1" >/dev/null 2>&1; }
else
  err "need sha256sum or shasum to verify the download"
fi

# ---- work in an isolated temp dir, always cleaned up -----------------------
tmp="$(mktemp -d 2>/dev/null || mktemp -d -t targate)"
[ -d "$tmp" ] || err "could not create a temporary directory"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

info "Installing targate (${VERSION}) for ${os}/${arch}"

download "${base}/${asset}" "${tmp}/${asset}"
download "${base}/SHA256SUMS" "${tmp}/SHA256SUMS"

# ---- verify SHA-256 --------------------------------------------------------
# Reduce SHA256SUMS to just our asset's line, then check it in the temp dir so
# the "<hash>  <basename>" entry matches the downloaded file by name.
if ! grep -E "  ${asset}\$" "${tmp}/SHA256SUMS" > "${tmp}/expected.sums"; then
  err "no checksum entry for ${asset} in SHA256SUMS"
fi
( cd "$tmp" && checksum "expected.sums" ) || err "SHA-256 verification failed for ${asset}"
info "SHA-256 verified"

# ---- optional minisign signature verification ------------------------------
pubkey="${TARGATE_MINISIGN_PUBKEY:-$MINISIGN_PUBKEY_DEFAULT}"
if [ -n "$pubkey" ]; then
  if have minisign; then
    download "${base}/SHA256SUMS.minisig" "${tmp}/SHA256SUMS.minisig"
    printf '%s\n' "$pubkey" > "${tmp}/minisign.pub"
    minisign -Vm "${tmp}/SHA256SUMS" -p "${tmp}/minisign.pub" >/dev/null 2>&1 \
      || err "minisign signature verification failed"
    info "minisign signature verified"
  else
    warn "minisign not installed — skipping signature verification (SHA-256 already verified)"
  fi
fi

# ---- choose an install directory (no surprise sudo) ------------------------
if [ -n "${TARGATE_INSTALL_DIR:-}" ]; then
  dir="$TARGATE_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  dir="/usr/local/bin"
else
  dir="${HOME}/.local/bin"
fi
mkdir -p "$dir" || err "cannot create install directory: $dir"

# ---- install (verify passed, so make executable and move into place) -------
chmod +x "${tmp}/${asset}"
mv -f "${tmp}/${asset}" "${dir}/targate" || err "failed to install into ${dir} (try sudo, or set TARGATE_INSTALL_DIR)"

info "targate installed to ${dir}/targate"

case ":${PATH}:" in
  *":${dir}:"*) ;;
  *) warn "${dir} is not on your PATH — add it, e.g.:  export PATH=\"${dir}:\$PATH\"" ;;
esac

info "Run 'targate --help' to get started."
