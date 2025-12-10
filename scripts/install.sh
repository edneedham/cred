#!/bin/sh
set -e

REPO="edneedham/cred"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Use provided version or fetch latest
if [ -n "$1" ]; then
  VERSION="$1"
else
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi

if [ -z "$VERSION" ]; then
  echo "Error: Could not determine version to install"
  exit 1
fi

echo "Installing cred ${VERSION}..."

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
  linux)  OS_TARGET="unknown-linux-gnu" ;;
  darwin) OS_TARGET="apple-darwin" ;;
  mingw*|msys*|cygwin*) 
    echo "For Windows, download the binary directly from:"
    echo "https://github.com/${REPO}/releases"
    exit 1
    ;;
  *)
    echo "Unsupported OS: ${OS}"
    exit 1
    ;;
esac

case "${ARCH}" in
  x86_64|amd64) ARCH_TARGET="x86_64" ;;
  aarch64|arm64) ARCH_TARGET="aarch64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}"
    exit 1
    ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"
BINARY="cred-${VERSION}-${TARGET}"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${BINARY}..."
if ! curl -fsSL "${URL}" -o "${TMP_DIR}/cred"; then
  echo "Error: Failed to download from ${URL}"
  echo "Check that the version and platform are available at:"
  echo "https://github.com/${REPO}/releases"
  exit 1
fi

chmod +x "${TMP_DIR}/cred"

# Install
echo "Installing to ${INSTALL_DIR}/cred..."
if [ -w "${INSTALL_DIR}" ]; then
  mv "${TMP_DIR}/cred" "${INSTALL_DIR}/cred"
else
  sudo mv "${TMP_DIR}/cred" "${INSTALL_DIR}/cred"
fi

echo ""
echo "✓ Installed cred ${VERSION} to ${INSTALL_DIR}/cred"
echo ""

# Verify
if command -v cred >/dev/null 2>&1; then
  cred --version
else
  echo "Note: ${INSTALL_DIR} may not be in your PATH"
  echo "Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

