#!/bin/bash
set -e

BASE="${NEXGUARD_DOWNLOAD_BASE:-https://nexguard.sh/download}"
RUNTIME_LIBRARIES="libxkbcommon-x11.so.0 libEGL.so.1"
INSTALL_DIR="/usr/local/bin"
BIN="nexguard"
UNIT="/etc/systemd/system/nexguard.service"
LAUNCHER="nexguard.desktop"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

FLAVOR="auto"
for arg in "$@"; do
  case "$arg" in
    --gui) FLAVOR="gui" ;;
    --cli) FLAVOR="cli" ;;
    *) echo "Unknown option: $arg (use --gui or --cli)"; exit 1 ;;
  esac
done

graphical_session() {
  [ -n "$WAYLAND_DISPLAY" ] || [ -n "$DISPLAY" ] && return 0
  case "$XDG_SESSION_TYPE" in x11|wayland) return 0 ;; esac
  command -v systemctl >/dev/null 2>&1 && [ "$(systemctl get-default 2>/dev/null)" = "graphical.target" ]
}

missing_libraries() {
  ldd "$1" 2>/dev/null | awk '/not found/ {print $1}'
  for lib in $RUNTIME_LIBRARIES; do
    ldconfig -p 2>/dev/null | grep -q "$lib" || echo "$lib"
  done
}

install_desktop_libraries() {
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq || true
    $SUDO apt-get install -y --no-install-recommends libgtk-3-0 libxdo3 libayatana-appindicator3-1 libxkbcommon-x11-0 libegl1
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y gtk3 libxdo libayatana-appindicator-gtk3 libxkbcommon-x11 mesa-libEGL
  elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -S --needed --noconfirm gtk3 xdotool libayatana-appindicator libxkbcommon-x11 libglvnd
  elif command -v zypper >/dev/null 2>&1; then
    $SUDO zypper --non-interactive install libgtk-3-0 libxdo3 libayatana-appindicator3-1 libxkbcommon-x11-0 libEGL1
  else
    return 1
  fi
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "Installing to $INSTALL_DIR needs root. Run this script as root."
    exit 1
  fi
  SUDO="sudo"
fi

DESKTOP=0
case "$OS" in
  linux)
    case "$ARCH" in
      x86_64|amd64) URL="$BASE/linux" ;;
      aarch64|arm64) URL="$BASE/linux-arm64" ;;
      *) echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    if [ "$FLAVOR" = "gui" ] || { [ "$FLAVOR" = "auto" ] && graphical_session; }; then
      case "$ARCH" in
        x86_64|amd64) URL="$BASE/linux-desktop"; DESKTOP=1 ;;
        *) echo "The desktop app is not built for $ARCH yet; installing the command-line version." ;;
      esac
    fi
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

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if [ "$DESKTOP" = 1 ]; then
  echo "Downloading the NexGuard desktop app for $OS/$ARCH..."
else
  echo "Downloading NexGuard (command line) for $OS/$ARCH..."
fi
curl -fsSL -o "$TMP" "$URL"
chmod +x "$TMP"

if [ "$DESKTOP" = 1 ] && [ -n "$(missing_libraries "$TMP")" ]; then
  echo "Installing the libraries the app window needs — your password may be asked."
  install_desktop_libraries || true
  if [ -n "$(missing_libraries "$TMP")" ]; then
    echo "Still missing: $(missing_libraries "$TMP" | tr '\n' ' ')"
    echo "Installing the command-line version instead."
    DESKTOP=0
    curl -fsSL -o "$TMP" "$BASE/linux"
  fi
fi

if [ -n "$SUDO" ]; then
  echo "Installing to $INSTALL_DIR — your password may be asked."
fi
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO install -m 755 "$TMP" "$INSTALL_DIR/$BIN"

REAL_USER=${SUDO_USER:-$(id -un)}
REAL_HOME=""
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
  REAL_HOME=$(eval echo "~$REAL_USER")
  if [ -d "$REAL_HOME/.nexguard" ] && [ -n "$(find "$REAL_HOME/.nexguard" ! -user "$REAL_USER" -print -quit 2>/dev/null)" ]; then
    $SUDO chown -R "$REAL_USER" "$REAL_HOME/.nexguard" 2>/dev/null || true
  fi
fi

echo ""
echo "$("$INSTALL_DIR/$BIN" --version 2>&1 | head -1) installed"

if [ "$DESKTOP" = 1 ]; then
  if [ ! -f "$UNIT" ]; then
    echo "Starting the background service the app connects through..."
    $SUDO "$INSTALL_DIR/$BIN" --install-service >/dev/null
  fi
  if [ -n "$REAL_HOME" ]; then
    APPS="$REAL_HOME/.local/share/applications"
    mkdir -p "$APPS"
    cat > "$APPS/$LAUNCHER" <<EOF
[Desktop Entry]
Type=Application
Name=NexGuard
Comment=NexGuard VPN
Exec=$INSTALL_DIR/$BIN
Icon=network-vpn
Terminal=false
Categories=Network;
EOF
    [ "$(id -u)" -eq 0 ] && chown -R "$REAL_USER" "$REAL_HOME/.local/share/applications" 2>/dev/null || true
  fi
  echo "Open NexGuard from your applications menu, or run: nexguard"
else
  echo "Join your network:  sudo nexguard join TOKEN --install-service"
  echo "Help:               nexguard --help"
fi
