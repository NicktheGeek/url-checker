#!/bin/bash
# Builds static/icons/app.icns from static/icons/icon-512.png using only
# tools already on every Mac (sips, iconutil) -- no extra dependency.
#
# Shared by build_mac_app.sh (local dev wrapper) and the GitHub Actions
# release workflow (fully frozen PyInstaller build) -- app.icns is
# gitignored (a regenerable build artifact), so a fresh checkout needs this
# run before either build can use it as an --icon.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

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

echo "Built static/icons/app.icns"
