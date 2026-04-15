@echo off
REM Build Lentel.exe for Windows — coordinator-free edition.
REM No server of any kind is required.

setlocal
pushd "%~dp0"
cd ..\..

echo ==> Installing dependencies...
python -m pip install --upgrade pip --quiet || goto :err
python -m pip install -e ".[tray]" --quiet || goto :err
python -m pip install pyinstaller --quiet || goto :err

cd packaging\windows

echo ==> Cleaning old build...
if exist build  rmdir /S /Q build
if exist dist   rmdir /S /Q dist

echo ==> Building Lentel.exe...
pyinstaller --clean --noconfirm lentel-tray.spec || goto :err

echo.
echo ========================================
echo   Built: %CD%\dist\Lentel.exe
echo ========================================
echo.
echo   Run: .\dist\Lentel.exe
echo   Auto-start: Win+R -^> shell:startup, copy Lentel.exe there
echo.
echo   No server needed.
popd
endlocal
exit /b 0

:err
echo.
echo build failed
popd
endlocal
exit /b 1
