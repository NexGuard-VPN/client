#!/bin/bash
set -e

BASE="https://nexguard.sh/download"
INSTALL_DIR="/usr/local/bin"
BIN="nexguard"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64|amd64) URL="$BASE/linux" ;;
      aarch64|arm64) URL="$BASE/linux-arm64" ;;
      *) echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      arm64) URL="$BASE/macos" ;;
      x86_64) URL="$BASE/macos-intel" ;;
      *) echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "Installing to $INSTALL_DIR needs root. Run this script as root."
    exit 1
  fi
  SUDO="sudo"
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "Downloading NexGuard for $OS/$ARCH..."
curl -fsSL -o "$TMP" "$URL"

if [ -n "$SUDO" ]; then
  echo "Installing to $INSTALL_DIR — your password may be asked."
fi
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO install -m 755 "$TMP" "$INSTALL_DIR/$BIN"

REAL_USER=${SUDO_USER:-$(id -un)}
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
  REAL_HOME=$(eval echo "~$REAL_USER")
  if [ -d "$REAL_HOME/.nexguard" ] && [ -n "$(find "$REAL_HOME/.nexguard" ! -user "$REAL_USER" -print -quit 2>/dev/null)" ]; then
    $SUDO chown -R "$REAL_USER" "$REAL_HOME/.nexguard" 2>/dev/null || true
  fi
fi

echo ""
echo "$("$INSTALL_DIR/$BIN" --version 2>&1 | head -1) installed"
echo "Run: sudo nexguard"
