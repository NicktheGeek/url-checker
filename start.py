#!/usr/bin/env python3
"""One-click setup + launch for URL Checker.

Double-click start.command (Mac) or start.bat (Windows) -- or just run:
    python3 start.py

First run creates a private .venv and installs dependencies into it
automatically; every run after that just starts the server. No manual
pip/venv commands needed.
"""
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import venv
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(ROOT, ".venv")
IS_WINDOWS = platform.system() == "Windows"
VENV_PY = os.path.join(VENV_DIR, "Scripts" if IS_WINDOWS else "bin", "python.exe" if IS_WINDOWS else "python")
PORT = 5050


def ensure_venv():
    if os.path.exists(VENV_PY):
        return
    print("First run: creating a private Python environment in .venv ...")
    venv.EnvBuilder(with_pip=True).create(VENV_DIR)


def ensure_deps():
    req_path = os.path.join(ROOT, "requirements.txt")
    marker = os.path.join(VENV_DIR, ".deps-installed")
    if os.path.exists(marker) and os.path.getmtime(marker) >= os.path.getmtime(req_path):
        return
    print("Installing dependencies ...")
    subprocess.run([VENV_PY, "-m", "pip", "install", "-q", "-r", req_path], check=True)
    with open(marker, "w") as f:
        f.write("ok")


def ensure_env_file():
    env_path = os.path.join(ROOT, ".env")
    sample_path = os.path.join(ROOT, "sample.env")
    if not os.path.exists(env_path) and os.path.exists(sample_path):
        shutil.copyfile(sample_path, env_path)
        print("Created .env from sample.env -- add API keys later from the Settings tab in the app.")


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def setup():
    """venv + dependencies + .env, no server. Shared with build_mac_app.sh /
    build_windows_app.bat via `python start.py --setup-only` so the desktop
    app build doesn't duplicate this bootstrap logic."""
    ensure_venv()
    ensure_deps()
    ensure_env_file()


def main():
    if "--setup-only" in sys.argv:
        setup()
        return

    setup()

    ip = lan_ip()
    print()
    print(f"  On this computer:      http://127.0.0.1:{PORT}")
    if ip:
        print(f"  On your phone/tablet:  http://{ip}:{PORT}   (same WiFi network)")
        print("  Open that address on a phone/tablet, then use the browser's")
        print("  \"Add to Home Screen\" / \"Install app\" option for an app icon.")
    print()
    print("Press Ctrl+C here to stop the server.")
    print()

    proc = subprocess.Popen([VENV_PY, os.path.join(ROOT, "app.py")])
    time.sleep(1.2)
    try:
        webbrowser.open(f"http://127.0.0.1:{PORT}")
    except Exception:
        pass

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()


if __name__ == "__main__":
    sys.exit(main())
