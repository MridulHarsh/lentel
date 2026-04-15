"""
Legacy py2app config — kept for reference only.

py2app's modulegraph hits a RecursionError when your Python environment
has a large dependency tree (common with Anaconda). Use the PyInstaller-
based build.sh instead:

    cd packaging/macos
    ./build.sh
"""
raise SystemExit(
    "py2app is not recommended. Run ./build.sh instead (uses PyInstaller)."
)
