# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


docs_root = Path(SPECPATH)
project_root = docs_root.parent
ui_root = project_root / "ui"
version_file = docs_root / "systemshield-version-info.txt"

if not version_file.exists():
    raise SystemExit("Missing docs/systemshield-version-info.txt. Run scripts/write_build_metadata.py first.")

ui_datas = []
for path in ui_root.rglob("*"):
    if path.is_file():
        ui_datas.append((str(path), str(path.relative_to(project_root).parent)))

hiddenimports = sorted(
    set(
        collect_submodules("webview")
        + collect_submodules("proxy_tools")
        + [
            "bottle",
            "pythonnet",
            "clr",
        ]
    )
)

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=ui_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "qtpy",
        "gi",
        "cefpython3",
        "jnius",
        "android",
        "objc",
        "AppKit",
        "Foundation",
        "WebKit",
        "PyObjCTools",
        "Xlib",
    ],
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SystemShield",
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
    icon=[str(ui_root / "data" / "icon.ico")],
    version=str(version_file),
)
