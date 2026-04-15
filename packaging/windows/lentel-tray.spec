# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for Lentel.exe — coordinator-free edition.
#
# Produces a single windowless .exe for the Windows system tray.
# No server of any kind is required.
#
# Usage:
#   cd packaging\windows
#   .\build.ps1    (or build.bat)
#
# Output: dist\Lentel.exe
from __future__ import annotations

import os

_HERE = os.path.abspath(os.path.dirname(SPEC))  # type: ignore[name-defined]
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))
_ENTRY = os.path.join(_REPO, "lentel", "app", "__main__.py")

block_cipher = None

a = Analysis(
    [_ENTRY],
    pathex=[_REPO],
    binaries=[],
    datas=[],
    hiddenimports=[
        "pystray._win32",
        "PIL._tkinter_finder",
        "tkinter",
        "tkinter.filedialog",
        "tkinter.simpledialog",
        "tkinter.messagebox",
        "lentel",
        "lentel.app.tray",
        "lentel.app.state",
        "lentel.app.runner",
        "lentel.app.icon",
        "lentel.app.dialogs",
        "lentel.wire",
        "lentel.crypto",
        "lentel.chunker",
        "lentel.congestion",
        "lentel.transport",
        "lentel.nat",
        "lentel.session",
        "lentel.rendezvous",
        "lentel.wordlist",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "numpy", "pandas", "matplotlib", "scipy",
        "IPython", "jupyter", "sphinx", "black", "docutils", "pytest",
        "lentel.server",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

_ICON = os.path.join(_REPO, "packaging", "common", "Lentel.ico")
_icon_arg = _ICON if os.path.exists(_ICON) else None

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Lentel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,             # no console window — tray only
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_icon_arg,
)
