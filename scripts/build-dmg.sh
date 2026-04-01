#!/bin/bash
set -e

VERSION="${1:-0.3.0}"
APP_NAME="NexGuard"
BUNDLE="${APP_NAME}.app"
DMG_NAME="NexGuard-${VERSION}-macOS.dmg"
BUILD_DIR="build/dmg"
BINARY="target/release/nexguard"

if [ ! -f "$BINARY" ]; then
    echo "Building release binary..."
    cargo build --release
fi

echo "Creating app bundle..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/${BUNDLE}/Contents/MacOS"
mkdir -p "$BUILD_DIR/${BUNDLE}/Contents/Resources"

cp "$BINARY" "$BUILD_DIR/${BUNDLE}/Contents/MacOS/nexguard-bin"
chmod +x "$BUILD_DIR/${BUNDLE}/Contents/MacOS/nexguard-bin"

cat > "$BUILD_DIR/${BUNDLE}/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>NexGuard</string>
    <key>CFBundleDisplayName</key>
    <string>NexGuard VPN</string>
    <key>CFBundleIdentifier</key>
    <string>com.nexguard.vpn</string>
    <key>CFBundleVersion</key>
PLIST
echo "    <string>${VERSION}</string>" >> "$BUILD_DIR/${BUNDLE}/Contents/Info.plist"
cat >> "$BUILD_DIR/${BUNDLE}/Contents/Info.plist" << 'PLIST'
    <key>CFBundleShortVersionString</key>
PLIST
echo "    <string>${VERSION}</string>" >> "$BUILD_DIR/${BUNDLE}/Contents/Info.plist"
cat >> "$BUILD_DIR/${BUNDLE}/Contents/Info.plist" << 'PLIST'
    <key>CFBundleExecutable</key>
    <string>nexguard</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSUIElement</key>
    <false/>
    <key>NSNetworkVolumes</key>
    <true/>
    <key>NSSystemAdministrationUsageDescription</key>
    <string>NexGuard VPN needs administrator privileges to create network tunnels and modify routing tables.</string>
</dict>
</plist>
PLIST

# Generate icon
if command -v python3 &>/dev/null; then
    echo "Generating icons..."
    ICON_DIR=$(mktemp -d)
    python3 scripts/gen-icon.py "$ICON_DIR"

    ICONSET="$ICON_DIR/AppIcon.iconset"
    mkdir -p "$ICONSET"
    cp "$ICON_DIR/icon_16x16.png" "$ICONSET/icon_16x16.png"
    cp "$ICON_DIR/icon_32x32.png" "$ICONSET/icon_16x16@2x.png"
    cp "$ICON_DIR/icon_32x32.png" "$ICONSET/icon_32x32.png"
    cp "$ICON_DIR/icon_64x64.png" "$ICONSET/icon_32x32@2x.png"
    cp "$ICON_DIR/icon_128x128.png" "$ICONSET/icon_128x128.png"
    cp "$ICON_DIR/icon_256x256.png" "$ICONSET/icon_128x128@2x.png"
    cp "$ICON_DIR/icon_256x256.png" "$ICONSET/icon_256x256.png"
    cp "$ICON_DIR/icon_512x512.png" "$ICONSET/icon_256x256@2x.png"
    cp "$ICON_DIR/icon_512x512.png" "$ICONSET/icon_512x512.png"
    cp "$ICON_DIR/icon_1024x1024.png" "$ICONSET/icon_512x512@2x.png"

    iconutil -c icns "$ICONSET" -o "$BUILD_DIR/${BUNDLE}/Contents/Resources/AppIcon.icns"
    rm -rf "$ICON_DIR"
fi

# Create helper that elevates to root
cat > "$BUILD_DIR/${BUNDLE}/Contents/MacOS/NexGuard" << 'LAUNCHER'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" -ne 0 ]; then
    osascript -e "do shell script \"'$0'\" with administrator privileges"
    exit 0
fi
exec "${DIR}/nexguard-bin"
LAUNCHER
chmod +x "$BUILD_DIR/${BUNDLE}/Contents/MacOS/NexGuard"

sed -i '' 's|<string>nexguard</string>|<string>NexGuard</string>|' "$BUILD_DIR/${BUNDLE}/Contents/Info.plist"

echo "Creating DMG..."
mkdir -p "$BUILD_DIR/dmg-content"
cp -r "$BUILD_DIR/${BUNDLE}" "$BUILD_DIR/dmg-content/"
ln -s /Applications "$BUILD_DIR/dmg-content/Applications"

hdiutil create -volname "NexGuard VPN" \
    -srcfolder "$BUILD_DIR/dmg-content" \
    -ov -format UDZO \
    "$DMG_NAME"

rm -rf "$BUILD_DIR"
echo ""
echo "DMG created: $DMG_NAME"
echo "Size: $(du -h "$DMG_NAME" | cut -f1)"
