"""
Lentel menu-bar / system-tray application.

This subpackage wraps the core `lentel` protocol in a GUI that lives in the
macOS menu bar (`NSStatusItem`) or the Windows system tray (`NOTIFYICONDATA`).
The same Python code runs on both platforms via `pystray`; only the bundler
used to produce an installable app differs (see `packaging/`).

Entry point:    python -m lentel.app
Packaged:       Lentel.app / Lentel.exe
"""
