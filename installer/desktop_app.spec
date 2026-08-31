# PyInstaller spec for the fully self-contained desktop build used by the
# GitHub Actions release pipeline (.github/workflows/release-installers.yml).
#
# This is NOT the same thing as build_mac_app.sh/build_windows_app.bat --
# those wrap this checkout's own .venv for local dev convenience. This spec
# freezes a truly standalone build (Python + all deps + templates/static
# bundled in) for people who download an installer with no repo, no
# Python, nothing pre-existing.
#
# Build with (from anywhere -- paths are anchored to this spec file's own
# location via SPECPATH, not the invocation directory):
#   pyinstaller installer/desktop_app.spec
import os
import sys

# SPECPATH is injected into this file's namespace by PyInstaller itself
# (the directory containing this .spec file) -- NOT the same as the
# invocation cwd, which is why paths below go through it rather than a
# bare "../".
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

# Set by the release workflow to the tag with its leading "v" stripped
# (e.g. "3.0.3"); left at "0.0.0" for a local `pyinstaller` run so nothing
# breaks outside CI. Feeds macOS's CFBundleShortVersionString/CFBundleVersion
# and the Windows .exe's own FileVersion/ProductVersion resource below --
# separately, the Windows *installer* gets this same value via Inno Setup's
# /DMyAppVersion, which doesn't go through this spec at all.
VERSION = os.environ.get("VERSION", "0.0.0")


def _version_tuple(version_string):
    """"3.0.3" -> (3, 0, 3, 0); anything that doesn't parse as plain dotted
    integers (the "dev-<run_number>" fallback tag, "0.0.0" itself) -> all
    zeros, since a Windows version resource requires 4 actual integers, not
    an arbitrary string like CFBundleShortVersionString accepts."""
    parts = [int(p) for p in version_string.split(".") if p.isdigit()]
    parts = (parts + [0, 0, 0, 0])[:4]
    return tuple(parts)


# Windows only: an embedded version resource (Explorer's Properties >
# Details tab) -- built inline rather than as a separate version-file
# because the values need to come from VERSION above, computed at build
# time. PyInstaller.utils.win32.versioninfo imports `pefile`, which is only
# installed on Windows (PyInstaller's own platform-conditional dependency),
# so this whole block must stay inside the win32 check -- importing it
# unconditionally breaks the macOS build.
win_version_info = None
if sys.platform == "win32":
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    _vt = _version_tuple(VERSION)
    win_version_info = VSVersionInfo(
        ffi=FixedFileInfo(filevers=_vt, prodvers=_vt),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", "Nick Croft"),
                            StringStruct("FileDescription", "URL Checker"),
                            StringStruct("FileVersion", VERSION),
                            StringStruct("InternalName", "URL Checker"),
                            StringStruct("OriginalFilename", "URL Checker.exe"),
                            StringStruct("ProductName", "URL Checker"),
                            StringStruct("ProductVersion", VERSION),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )

a = Analysis(
    [os.path.join(ROOT, "desktop_app.py")],
    pathex=[ROOT],
    datas=[
        (os.path.join(ROOT, "templates"), "templates"),
        (os.path.join(ROOT, "static"), "static"),
        (os.path.join(ROOT, "sample.env"), "."),
    ],
    hiddenimports=(
        ["webview.platforms.cocoa"]
        if sys.platform == "darwin"
        # pywebview's Windows backend loads the .NET runtime via
        # pythonnet/clr_loader, which has a long-documented, still-open
        # PyInstaller freezing failure mode ("Failed to resolve
        # Python.Runtime.Loader.Initialize" / clr_loader DLL not found --
        # see r0x0r/pywebview#1215). pyinstaller-hooks-contrib's clr_loader
        # hook (merged 2022, present in the version installer/requirements-
        # build.txt pulls in) collects the required DLLs as data files,
        # which covers the reported cases -- these two extra hiddenimports
        # are the other half of the workaround users have reported needing.
        # This is NOT guaranteed to fully resolve it -- test the Windows
        # build specifically for a "clr"/"Python.Runtime" error at
        # webview.start() (not just at process launch) before trusting it.
        else ["webview.platforms.edgechromium", "clr_loader", "clr"]
        if sys.platform == "win32"
        else []
    ),
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="URL Checker",
    console=False,
    version=win_version_info,
)
coll = COLLECT(exe, a.binaries, a.datas, name="URL Checker")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="URL Checker.app",
        icon=os.path.join(ROOT, "static", "icons", "app.icns"),
        bundle_identifier="com.urlchecker.desktop",
        version=VERSION,
        info_plist={"NSHighResolutionCapable": True, "CFBundleVersion": VERSION},
    )
