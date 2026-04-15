# Packaging Lentel as a desktop app

Lentel is fully peer-to-peer — **no server of any kind is needed**.
The sender's public address is discovered automatically via STUN/UPnP
and embedded in the ticket. The receiver connects directly.

The same Python source (`lentel/app/`) runs on both macOS and Windows;
only the bundler differs.

```
packaging/
├── macos/
│   └── build.sh          # PyInstaller → Lentel.app (menu-bar only)
├── windows/
│   ├── lentel-tray.spec  # PyInstaller spec (system tray, no console)
│   ├── build.ps1         # PowerShell build script
│   └── build.bat         # cmd.exe build script
└── common/
    └── (drop Lentel.icns / Lentel.ico here for custom icons)
```

## macOS → `Lentel.app`

```bash
cd packaging/macos
./build.sh
open dist/Lentel.app
```

Uses **PyInstaller** with `--windowed` to produce a `.app` bundle.
The build script patches `Info.plist` with `LSUIElement=true` so the
app lives purely in the menu bar — no dock icon, no Cmd-Tab entry.

Install:
```bash
cp -R packaging/macos/dist/Lentel.app /Applications/
```

Auto-start: **System Settings → General → Login Items** → add Lentel.

## Windows → `Lentel.exe`

From PowerShell:
```powershell
cd packaging\windows
.\build.ps1
.\dist\Lentel.exe
```

Or from cmd.exe:
```
cd packaging\windows
build.bat
dist\Lentel.exe
```

Single-file `--onefile --noconsole` executable. Docks into the system
tray with no terminal window.

Auto-start: **Win+R → `shell:startup`** → copy `Lentel.exe` there.

## Running without bundling

```bash
pip install 'lentel[tray]'
python -m lentel.app
```

Same functionality, no build step needed.
