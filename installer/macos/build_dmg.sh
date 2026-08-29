#!/bin/bash
# Packages a built "URL Checker.app" into a distributable .dmg -- the .app
# plus an Applications symlink alongside it, the standard "drag to
# Applications" layout.
#
# Usage: build_dmg.sh <path-to-URL-Checker.app> <output.dmg>
set -euo pipefail

APP_PATH="$1"
OUT_DMG="$2"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cp -R "$APP_PATH" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$OUT_DMG"

if command -v create-dmg >/dev/null 2>&1; then
  echo "Building $OUT_DMG with create-dmg ..."
  create-dmg \
    --volname "URL Checker" \
    --window-size 660 400 \
    --icon-size 128 \
    --icon "URL Checker.app" 160 185 \
    --app-drop-link 500 185 \
    --hide-extension "URL Checker.app" \
    "$OUT_DMG" \
    "$STAGE" \
    || {
      echo "create-dmg failed, falling back to plain hdiutil ..."
      hdiutil create -volname "URL Checker" -srcfolder "$STAGE" -ov -format UDZO "$OUT_DMG"
    }
else
  echo "create-dmg not found, building $OUT_DMG with plain hdiutil ..."
  hdiutil create -volname "URL Checker" -srcfolder "$STAGE" -ov -format UDZO "$OUT_DMG"
fi

echo "Built $OUT_DMG"
