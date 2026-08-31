"""Filesystem locations that resolve identically to today for every existing
launch path (python app.py, start.py, cli.py, unfrozen desktop_app.py) and
only diverge when running inside a PyInstaller-frozen bundle. `sys.frozen`
is a bootloader-only attribute PyInstaller's runtime stub sets -- it is
never present in a normal `python` invocation, so every existing flow is
unaffected by construction, not by any check in this file.
"""
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")

# Bundled, read-only resources (templates/, static/, sample.env). Frozen:
# PyInstaller's extraction/install root. Unfrozen: identical to today's
# `Path(__file__).parent`.
BASE_DIR = Path(sys._MEIPASS) if FROZEN else Path(__file__).parent


def _user_data_dir(app_name: str) -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / app_name
    if sys.platform == "win32":
        import os

        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / app_name
    return Path.home() / f".{app_name.lower().replace(' ', '-')}"


# Persistent, writable, per-user location for history.db/.env -- frozen
# only. PyInstaller's own docs advise never writing into the install/
# extraction directory (breaks the codesign seal on macOS; Program Files
# isn't writable at runtime on Windows), so this is a real requirement, not
# just tidiness. Unfrozen: identical to today's `Path(__file__).parent`.
DATA_DIR = _user_data_dir("URL Checker") if FROZEN else Path(__file__).parent
DATA_DIR.mkdir(parents=True, exist_ok=True)
