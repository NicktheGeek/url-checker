#!/usr/bin/env python3
"""Builds static/icons/app.ico from static/icons/icon-512.png via Pillow.

Shared by build_windows_app.bat (local dev wrapper) and the GitHub Actions
release workflow (Inno Setup installer icon / .exe icon) -- app.ico is
gitignored (a regenerable build artifact), so a fresh checkout needs this
run before either build can use it. Requires Pillow (`pip install pillow`)
-- a build-time-only tool, not a runtime dependency of the app itself.
"""
import os

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "static", "icons", "icon-512.png")
OUT = os.path.join(ROOT, "static", "icons", "app.ico")


def main():
    img = Image.open(SRC)
    img.save(OUT, sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
    print(f"Built {OUT}")


if __name__ == "__main__":
    main()
