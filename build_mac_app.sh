#!/bin/bash
# Builds dist/URL Checker.app -- a real Mac app with its own Dock icon and
# window (no Terminal, no browser chrome) wrapping this same project.
#
# Not a standalone/relocatable bundle: it launches this checkout's own
# .venv + desktop_app.py, so it shares the same history.db/.env as
# start.py/python app.py. If you move this project folder afterward,
# re-run this script.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
APP="dist/URL Checker.app"

echo "Setting up .venv + dependencies ..."
python3 start.py --setup-only

echo "Building app icon ..."
ICONSET="static/icons/AppIcon.iconset"
rm -rf "$ICONSET" static/icons/app.icns
mkdir -p "$ICONSET"
SRC="static/icons/icon-512.png"
sips -z 16 16     "$SRC" --out "$ICONSET/icon_16x16.png" >/dev/null
sips -z 32 32     "$SRC" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
sips -z 32 32     "$SRC" --out "$ICONSET/icon_32x32.png" >/dev/null
sips -z 64 64     "$SRC" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
sips -z 128 128   "$SRC" --out "$ICONSET/icon_128x128.png" >/dev/null
sips -z 256 256   "$SRC" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256   "$SRC" --out "$ICONSET/icon_256x256.png" >/dev/null
sips -z 512 512   "$SRC" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
cp "$SRC"         "$ICONSET/icon_512x512.png"
cp "$SRC"         "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o static/icons/app.icns

echo "Assembling $APP ..."
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp static/icons/app.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>URL Checker</string>
  <key>CFBundleDisplayName</key><string>URL Checker</string>
  <key>CFBundleIdentifier</key><string>com.urlchecker.desktop</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>launcher</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

cat > "$APP/Contents/MacOS/launcher" <<LAUNCHER
#!/bin/bash
exec "$ROOT/.venv/bin/python" "$ROOT/desktop_app.py" >> "\$HOME/Library/Logs/URL Checker.log" 2>&1
LAUNCHER
chmod +x "$APP/Contents/MacOS/launcher"

echo
echo "Built: $APP"
echo "Double-click it from Finder, or drag it to /Applications."
echo "(Logs, if anything goes wrong: ~/Library/Logs/URL Checker.log)"
