"""
Build script for WebGeeks SystemShield v1.3.2.

This script builds the portable PyInstaller executable while keeping the
package small and avoiding overly aggressive exclusions that can break
PyInstaller hooks.

It also embeds Windows EXE Details metadata from file_version_info.txt.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

APP_NAME = "WebGeeks-SystemShield"
ENTRY = "System_Scanner.py"
VERSION_FILE = "file_version_info.txt"
ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
ICON_CANDIDATES = [
    ROOT / "web" / "data" / "icon.ico",
    ROOT / "data" / "icon.ico",
    ROOT / "logo.ico",
]

HIDDEN_IMPORTS = [
    "eel", "bottle", "bottle_websocket", "gevent", "gevent.pywsgi",
    "geventwebsocket", "geventwebsocket.handler", "greenlet", "psutil",
    "wmi", "win32api", "win32com", "win32com.client", "pythoncom",
]

EXCLUDED_MODULES = [
    "matplotlib", "numpy", "pandas", "scipy", "PIL", "IPython",
    "jupyter", "notebook", "pytest", "email.tests", "test", "tests",
    "unittest.tests",
]


def add_data_arg(source: Path, dest: str) -> str:
    sep = ";" if os.name == "nt" else ":"
    return f"{source}{sep}{dest}"


def find_icon() -> Path | None:
    for icon in ICON_CANDIDATES:
        if icon.exists():
            return icon
    return None


def verify_tkinter() -> None:
    try:
        import tkinter  # noqa: F401
    except Exception:
        print("WARNING: tkinter could not be imported from this Python install.")
        print("VirusTotal Browse & Scan uses tkinter for the native file picker.")
        print("Install/repair Python with Tcl/Tk support if you want Browse & Scan in the packaged app.")


def build() -> int:
    if not (ROOT / ENTRY).exists():
        print(f"ERROR: {ENTRY} was not found in {ROOT}")
        return 1
    if not WEB_DIR.exists():
        print(f"ERROR: web folder was not found in {ROOT}")
        return 1
    if not (ROOT / VERSION_FILE).exists():
        print(f"ERROR: {VERSION_FILE} was not found in {ROOT}")
        print("This file is required so the compiled EXE has Windows Details metadata.")
        return 1

    verify_tkinter()
    icon = find_icon()

    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--windowed", "--onefile", "--name", APP_NAME,
        "--add-data", add_data_arg(WEB_DIR, "web"),
        "--version-file", str(ROOT / VERSION_FILE),
        "--collect-submodules", "eel",
    ]

    if icon:
        cmd.extend(["--icon", str(icon)])
    else:
        print("WARNING: icon.ico was not found. Build will use the default EXE icon.")

    for item in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", item])
    for item in EXCLUDED_MODULES:
        cmd.extend(["--exclude-module", item])

    cmd.append(ENTRY)
    print("Running PyInstaller:\n" + " ".join(f'\"{x}\"' if " " in x else x for x in cmd))
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(build())
