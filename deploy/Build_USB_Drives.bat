@echo off
title FU PERSON - Build USB Drives
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
echo    ║  FU PERSON - Build USB Drives (Tri-Drive Deployment)   ║
echo    ╚══════════════════════════════════════════════════════════╝
echo.
echo    [*] Checking virtual environment...

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo    [+] Virtual environment activated
) else (
    echo    [!] No .venv found - using system Python
)
echo.
echo    [*] Launching build_usb.py...
echo    ────────────────────────────────────────────────────────────
echo.

python deploy\build_usb.py %*

echo.
echo    ────────────────────────────────────────────────────────────
echo    [+] Build USB Drives finished
echo.
pause
