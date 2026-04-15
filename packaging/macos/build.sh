#!/usr/bin/env bash
# Build Lentel.app for macOS — coordinator-free edition.
#
# Produces a .app bundle in ./dist/ with LSUIElement=True (menu-bar only,
# no dock icon). No server of any kind is required to use the app.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

cd "$REPO"

echo "==> Installing dependencies..."
python3 -m pip install -e ".[tray]" --quiet
python3 -m pip install pyinstaller --quiet

echo "==> Cleaning old build..."
rm -rf "$HERE/build" "$HERE/dist" "$HERE/Lentel.spec"

echo "==> Building Lentel.app..."
python3 -m PyInstaller \
    --name Lentel \
    --windowed \
    --noconfirm \
    --clean \
    --distpath "$HERE/dist" \
    --workpath "$HERE/build" \
    --specpath "$HERE" \
    --hidden-import lentel \
    --hidden-import lentel.app.tray \
    --hidden-import lentel.app.state \
    --hidden-import lentel.app.runner \
    --hidden-import lentel.app.icon \
    --hidden-import lentel.app.dialogs \
    --hidden-import lentel.wire \
    --hidden-import lentel.crypto \
    --hidden-import lentel.chunker \
    --hidden-import lentel.congestion \
    --hidden-import lentel.transport \
    --hidden-import lentel.nat \
    --hidden-import lentel.session \
    --hidden-import lentel.rendezvous \
    --hidden-import lentel.wordlist \
    --hidden-import pystray._darwin \
    --hidden-import PIL._tkinter_finder \
    --collect-submodules lentel \
    --collect-submodules pystray \
    --exclude-module numpy \
    --exclude-module pandas \
    --exclude-module matplotlib \
    --exclude-module scipy \
    --exclude-module IPython \
    --exclude-module jupyter \
    --exclude-module sphinx \
    --exclude-module black \
    --exclude-module docutils \
    --exclude-module pytest \
    --exclude-module lentel.server \
    --osx-bundle-identifier com.lentel.app \
    "$REPO/lentel/app/__main__.py"

# Patch Info.plist: menu-bar only (no dock icon).
PLIST="$HERE/dist/Lentel.app/Contents/Info.plist"
if [ -f "$PLIST" ]; then
    /usr/libexec/PlistBuddy -c "Add :LSUIElement bool true"  "$PLIST" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Set :LSUIElement true"       "$PLIST"
    /usr/libexec/PlistBuddy -c "Add :NSHighResolutionCapable bool true" "$PLIST" 2>/dev/null || true
    echo "==> Patched Info.plist (LSUIElement=true)"
fi

SIZE=$(du -sh "$HERE/dist/Lentel.app" | cut -f1)
echo
echo "========================================"
echo "  Built: $HERE/dist/Lentel.app ($SIZE)"
echo "========================================"
echo
echo "  Run:     open '$HERE/dist/Lentel.app'"
echo "  Install: cp -R '$HERE/dist/Lentel.app' /Applications/"
echo
echo "  No server needed — the sender's address is"
echo "  embedded in the ticket automatically via STUN/UPnP."
