# -*- mode: python ; coding: utf-8 -*-
"""Build the Windows folder package, using OS ICU when Qt requires its ABI."""

from pathlib import Path
import sys

import pefile
from PyInstaller.utils.hooks import copy_metadata


project = Path(SPECPATH)
notices = []
for package in ("PySide6-Essentials", "shiboken6", "PyInstaller"):
    notices.extend(copy_metadata(package))
for filename in ("LICENSE.txt", "LICENSE"):
    python_license = Path(sys.base_prefix) / filename
    if python_license.is_file():
        notices.append((str(python_license), "third-party-licenses/Python"))
        break
a = Analysis(
    [str(project / "app.py")],
    pathex=[str(project)],
    binaries=[],
    datas=notices,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick"],
    noarchive=False,
    optimize=0,
)

# Some Python distributions ship an unrelated ICU DLL. Qt's Windows ICU calls
# require unversioned exports, whereas that DLL exports e.g. ucnv_open_78. A
# frozen app would load the incompatible bundled DLL before the Windows DLL.
# Inspect the actual ABI; keep a compatible private ICU if one is ever bundled.
incompatible_icu = False
for destination, source, kind in a.binaries:
    if Path(destination).name.lower() != "icuuc.dll":
        continue
    library = pefile.PE(source, fast_load=True)
    try:
        library.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        symbols = getattr(library, "DIRECTORY_ENTRY_EXPORT", None)
        compatible = symbols is not None and any(symbol.name == b"ucnv_open" for symbol in symbols.symbols)
        incompatible_icu = not compatible
    finally:
        library.close()

if incompatible_icu:
    a.binaries = [
        entry for entry in a.binaries
        if Path(entry[0]).name.lower() != "icuuc.dll"
        and not (Path(entry[0]).name.lower().startswith("icudt") and Path(entry[0]).suffix.lower() == ".dll")
    ]

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CipherDesk",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="CipherDesk")
