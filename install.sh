#!/bin/sh
# secure-transfer installer
# Usage: curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/secure-transfer/main/install.sh | sh
set -e

REPO="YOUR_USERNAME/secure-transfer"
BINARY="secure-transfer"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { printf "${CYAN}${BOLD}▸${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}${BOLD}✓${NC} %s\n" "$1"; }
err()   { printf "${RED}${BOLD}✗${NC} %s\n" "$1" >&2; exit 1; }

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  OS="unknown-linux-gnu" ;;
        darwin) OS="apple-darwin" ;;
        *)      err "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="x86_64" ;;
        aarch64|arm64)  ARCH="aarch64" ;;
        *)              err "Unsupported architecture: $ARCH" ;;
    esac

    PLATFORM="${ARCH}-${OS}"
}

# Get latest release tag from GitHub
get_latest_version() {
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"//;s/".*//')

    if [ -z "$VERSION" ]; then
        err "Failed to fetch latest version. Check https://github.com/${REPO}/releases"
    fi
}

# Download and install binary
install_binary() {
    TARBALL="${BINARY}-${VERSION}-${PLATFORM}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

    info "Downloading ${BINARY} ${VERSION} for ${PLATFORM}…"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    if ! curl -fsSL "$URL" -o "${TMPDIR}/${TARBALL}"; then
        err "Download failed. Binary may not be available for your platform.
  Try installing from source: cargo install --git https://github.com/${REPO}"
    fi

    tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

    info "Installing to ${INSTALL_DIR}…"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    fi

    chmod +x "${INSTALL_DIR}/${BINARY}"
}

# Main
main() {
    echo ""
    echo "  ${BOLD}🛡️  secure-transfer installer${NC}"
    echo "  ${CYAN}Quantum-safe file transfer over LAN${NC}"
    echo ""

    detect_platform
    info "Detected platform: ${PLATFORM}"

    get_latest_version
    info "Latest version: ${VERSION}"

    install_binary

    echo ""
    ok "Installed ${BINARY} ${VERSION} to ${INSTALL_DIR}/${BINARY}"
    echo ""
    echo "  Get started:"
    echo "    ${BOLD}secure-transfer listen${NC}          # Receiver"
    echo "    ${BOLD}secure-transfer send ./file${NC}     # Sender"
    echo ""
}

main
