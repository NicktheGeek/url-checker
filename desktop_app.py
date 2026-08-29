#!/usr/bin/env python3
"""Native desktop window for URL Checker (built into an app by
build_mac_app.sh / build_windows_app.bat -- not meant to be run directly
from a terminal, though `.venv/bin/python desktop_app.py` works fine too).

Runs the exact same Flask app as `python app.py`/start.py -- same
history.db, same .env, same LAN binding for phone/tablet access -- just
opened in its own native window instead of a browser tab. Don't run this
at the same time as start.py/app.py; both bind port 5050.
"""
import logging
import os
import socket
import sys
import threading
import time

import webview

from app import app

PORT = 5050


def _redirect_stdio_to_log():
    """A window launched from Finder/the Start Menu has no attached
    console -- an unhandled write to a broken stdout/stderr (a stray
    print(), Werkzeug's own startup banner) can otherwise kill the process
    with no way to see why."""
    if os.name == "posix" and sys.platform == "darwin":
        log_dir = os.path.expanduser("~/Library/Logs")
    elif os.name == "nt":
        log_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "URL Checker")
    else:
        log_dir = os.path.expanduser("~/.url-checker")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "URL Checker.log" if sys.platform == "darwin" else "log.txt")
    log_file = open(log_path, "a", buffering=1)
    sys.stdout = log_file
    sys.stderr = log_file


def _run_flask():
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=PORT, threaded=True, use_reloader=False)


def _wait_until_ready(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    _redirect_stdio_to_log()
    threading.Thread(target=_run_flask, daemon=True).start()
    _wait_until_ready()
    webview.create_window(
        "URL Checker",
        f"http://127.0.0.1:{PORT}",
        width=1100,
        height=800,
        min_size=(480, 600),
    )
    webview.start()


if __name__ == "__main__":
    main()
