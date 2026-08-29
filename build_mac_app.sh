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
installer/macos/make_icns.sh

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
