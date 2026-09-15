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

echo "Downloading NexGuard for $OS/$ARCH..."
curl -fsSL -o "$INSTALL_DIR/$BIN" "$URL"
chmod +x "$INSTALL_DIR/$BIN"

# Fix ownership for existing config
REAL_USER=${SUDO_USER:-$USER}
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
  REAL_HOME=$(eval echo ~$REAL_USER)
  if [ -d "$REAL_HOME/.nexguard" ]; then
    chown -R "$REAL_USER" "$REAL_HOME/.nexguard" 2>/dev/null
  fi
fi

echo ""
echo "$("$INSTALL_DIR/$BIN" --version 2>&1 | head -1) installed"
echo "Run: sudo nexguard"
