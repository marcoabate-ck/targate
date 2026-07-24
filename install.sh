#!/bin/sh
#
# targate installer.
#
#   curl -fsSL https://raw.githubusercontent.com/marcoabate-ck/targate/main/install.sh | sh
#
# Detects OS/arch, downloads the matching standalone binary from the GitHub
# Release, verifies its SHA-256 AND a MANDATORY minisign signature over the
# checksums, then installs it to a standard location. Fails closed: if the
# signature cannot be verified — minisign missing, signature file missing, or a
# bad signature — nothing is installed. Never runs anything from the artifact.
#
# Environment overrides:
#   TARGATE_VERSION          version to install (e.g. 1.2.3); default: latest
#   TARGATE_INSTALL_DIR      install directory; default: /usr/local/bin or ~/.local/bin
#   TARGATE_REPO             owner/repo; default: marcoabate-ck/targate
#   TARGATE_BASE_URL         base URL for assets (advanced: mirrors); must be https://
#   TARGATE_MINISIGN_PUBKEY  minisign public key line ("RW…") to verify against;
#                            overrides the built-in default, same single-line format

set -eu

# Minisign public key: the single "RW…" line from minisign.pub (NOT the
# "untrusted comment:" line). Verification is mandatory, so an empty value makes
# the installer refuse to install — fill this in before cutting a release.
# Overridable at runtime via TARGATE_MINISIGN_PUBKEY (same single-line format).
MINISIGN_PUBKEY_DEFAULT="RWRWhwiii5/4059Qt8rbESflWRnN5hbhVubYJJvGa4tObtrf3kmZHUsX"

REPO="${TARGATE_REPO:-marcoabate-ck/targate}"
VERSION="${TARGATE_VERSION:-latest}"

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# $1 url, $2 dest — returns non-zero on failure so the caller can craft the message.
download() {
  if have curl; then
    curl -fsSL "$1" -o "$2"
  elif have wget; then
    wget -q "$1" -O "$2"
  else
    err "need curl or wget to download targate"
  fi
}

# Verify a "<hash>  <name>" sums file in the current directory.
checksum() {
  if have sha256sum; then
    sha256sum -c "$1" >/dev/null 2>&1
  elif have shasum; then
    shasum -a 256 -c "$1" >/dev/null 2>&1
  else
    err "need sha256sum or shasum to verify the download"
  fi
}

cleanup() { [ -n "${tmp:-}" ] && rm -rf "$tmp"; }

main() {
  # ---- detect platform -----------------------------------------------------
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

  # ---- resolve the download base -------------------------------------------
  if [ -n "${TARGATE_BASE_URL:-}" ]; then
    base="$TARGATE_BASE_URL"
  elif [ "$VERSION" = "latest" ]; then
    base="https://github.com/${REPO}/releases/latest/download"
  else
    base="https://github.com/${REPO}/releases/download/v${VERSION#v}"
  fi

  # The base URL is where BOTH the binary and its checksums/signature come from;
  # a non-TLS base would let a network attacker rewrite all three. Require https.
  case "$base" in
    https://*) ;;
    *) err "refusing to use a non-https base URL: $base" ;;
  esac

  # ---- signature verification is mandatory: resolve the trust anchor first --
  pubkey="${TARGATE_MINISIGN_PUBKEY:-$MINISIGN_PUBKEY_DEFAULT}"
  [ -n "$pubkey" ] || err "no minisign public key is configured (MINISIGN_PUBKEY_DEFAULT / TARGATE_MINISIGN_PUBKEY); cannot verify the release — refusing to install"
  have minisign || err "minisign is required to verify the release signature. Install it (https://jedisct1.github.io/minisign/) and re-run."

  # ---- work in an isolated temp dir, always cleaned up ---------------------
  tmp="$(mktemp -d 2>/dev/null || mktemp -d -t targate)"
  [ -d "$tmp" ] || err "could not create a temporary directory"
  trap cleanup EXIT INT TERM

  info "Installing targate (${VERSION}) for ${os}/${arch}"

  download "${base}/${asset}" "${tmp}/${asset}" || err "failed to download ${base}/${asset}"
  download "${base}/SHA256SUMS" "${tmp}/SHA256SUMS" || err "failed to download ${base}/SHA256SUMS"
  download "${base}/SHA256SUMS.minisig" "${tmp}/SHA256SUMS.minisig" \
    || err "release signature SHA256SUMS.minisig not found at ${base} — refusing to install an unsigned release"

  # ---- verify minisign signature over the checksums (authenticity) ---------
  # -P takes the public key as a single-line string, so no temp key file is
  # written. A bad or absent signature is fatal.
  minisign -Vm "${tmp}/SHA256SUMS" -P "$pubkey" >/dev/null 2>&1 \
    || err "minisign signature verification failed for SHA256SUMS — refusing to install"
  info "minisign signature verified"

  # ---- verify SHA-256 of our asset against the signed checksums (integrity) -
  # Reduce SHA256SUMS to just our asset's line, then check it in the temp dir so
  # the "<hash>  <basename>" entry matches the downloaded file by name.
  if ! grep -E "  ${asset}\$" "${tmp}/SHA256SUMS" > "${tmp}/expected.sums"; then
    err "no checksum entry for ${asset} in SHA256SUMS"
  fi
  ( cd "$tmp" && checksum "expected.sums" ) || err "SHA-256 verification failed for ${asset}"
  info "SHA-256 verified"

  # ---- choose an install directory (no surprise sudo) ----------------------
  if [ -n "${TARGATE_INSTALL_DIR:-}" ]; then
    dir="$TARGATE_INSTALL_DIR"
  elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    dir="/usr/local/bin"
  else
    dir="${HOME}/.local/bin"
  fi
  mkdir -p "$dir" || err "cannot create install directory: $dir"

  # ---- install (both checks passed) ----------------------------------------
  chmod +x "${tmp}/${asset}"
  mv -f "${tmp}/${asset}" "${dir}/targate" || err "failed to install into ${dir} (try sudo, or set TARGATE_INSTALL_DIR)"

  info "targate installed to ${dir}/targate"

  case ":${PATH}:" in
    *":${dir}:"*) ;;
    *) warn "${dir} is not on your PATH — add it, e.g.:  export PATH=\"${dir}:\$PATH\"" ;;
  esac

  info "Run 'targate --help' to get started."
}

main "$@"
