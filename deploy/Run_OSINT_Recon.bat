@echo off
title FU PERSON - OSINT Recon Suite
color 0E
mode con: cols=80 lines=45
cd /d "%~dp0.."

:: Kali-style small banner
echo.
echo     ___ ___     ___  ___  ___  ___
echo    ] - ] - [   ] __ ] __]  _ ] __
echo    ]_  _____]  ]  _ ] _] ___ ] _
echo      ]_[     ]  [___][___][___][___]
echo.
echo    ╔══════════════════════════════════════════════════════════╗
echo    ║  FU PERSON - OSINT Recon Suite                           ║
echo    ║  Open Source Intelligence Gathering                      ║
echo    ╚══════════════════════════════════════════════════════════╝
echo.
echo    [*] Capabilities: DNS Records, Subdomains, WHOIS,
echo        Technology Detection, Social Media, Breach Checks
echo.
echo    ────────────────────────────────────────────────────────────

set /p target="    root@fuperson:~# target: "
if "%target%"=="" (
    echo.
    echo    [!] ERROR: You must enter a target website!
    echo.
    pause
    exit /b 1
)
echo.
echo    [*] Launching OSINT Recon on %target%...
echo    ────────────────────────────────────────────────────────────
echo.

python "core\osint_recon_suite.py" --target %target% --authorized

echo.
echo    ────────────────────────────────────────────────────────────
echo    [+] Recon complete - Check JSON report in deploy folder
echo.
dir /b osint_report_*.json 2>nul
echo.
pause
