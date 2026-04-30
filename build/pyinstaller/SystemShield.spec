# -*- mode: python ; coding: utf-8 -*-
# WebGeeks SystemShield v1.3.2 PyInstaller spec
# icon.ico should live at web/data/icon.ico.
# file_version_info.txt embeds Windows EXE Details metadata.

from pathlib import Path

ROOT = Path.cwd()
ICON_PATHS = [ROOT / "web" / "data" / "icon.ico", ROOT / "data" / "icon.ico", ROOT / "logo.ico"]
ICON = next((str(p) for p in ICON_PATHS if p.exists()), None)
VERSION_FILE = str(ROOT / "file_version_info.txt")

hiddenimports = [
    "eel", "bottle", "bottle_websocket", "gevent", "gevent.pywsgi",
    "geventwebsocket", "geventwebsocket.handler", "greenlet", "psutil",
    "wmi", "win32api", "win32com", "win32com.client", "pythoncom",
]

excludes = [
    "matplotlib", "numpy", "pandas", "scipy", "PIL", "IPython",
    "jupyter", "notebook", "pytest", "email.tests", "test", "tests",
    "unittest.tests",
]

a = Analysis(
    ["System_Scanner.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "web"), "web")],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WebGeeks-SystemShield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
    version=VERSION_FILE,
)
