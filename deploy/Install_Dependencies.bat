@echo off
title FU PERSON - Install Dependencies
color 0B
mode con: cols=80 lines=35
cd /d "%~dp0.."

:: Kali-style small banner
echo.
echo     ___ ___     ___  ___  ___  ___
echo    ] - ] - [   ] __ ] __]  _ ] __
echo    ]_  _____]  ]  _ ] _] ___ ] _
echo      ]_[     ]  [___][___][___][___]
echo.
echo    ╔══════════════════════════════════════════════════════════╗
echo    ║  FU PERSON - First Time Setup / Install Dependencies    ║
echo    ╚══════════════════════════════════════════════════════════╝
echo.
echo    [*] Checking Python installation...

python --version 2>nul
if errorlevel 1 (
    echo    [!] ERROR: Python is not installed or not in PATH!
    echo    [!] Download Python from: https://www.python.org/downloads/
    echo    [!] Make sure to check "Add Python to PATH" during install!
    echo.
    pause
    exit /b 1
)
echo    [+] Python found
echo.
echo    [*] Installing required packages from requirements.txt...
echo    ────────────────────────────────────────────────────────────
echo.

pip install -r "%~dp0..\requirements.txt"

echo.
echo    ────────────────────────────────────────────────────────────
echo    [+] Setup complete!
echo.
echo    ╔══════════════════════════════════════════════════════════╗
echo    ║  You can now run:                                        ║
echo    ║    - deploy\LAUNCH.bat         (Main menu)               ║
echo    ║    - deploy\Run_Galaxy_Recon.bat                         ║
echo    ║    - deploy\Run_Pentest_Suite.bat                        ║
echo    ║    - deploy\Run_OSINT_Recon.bat                         ║
echo    ╚══════════════════════════════════════════════════════════╝
echo.
pause
