@echo off
title FU PERSON - Galaxy Recon Suite
color 0D
mode con: cols=80 lines=50
cd /d "%~dp0.."

:: Kali-style small banner
echo.
echo     ___ ___     ___  ___  ___  ___
echo    ] - ] - [   ] __ ] __]  _ ] __
echo    ]_  _____]  ]  _ ] _] ___ ] _
echo      ]_[     ]  [___][___][___][___]
echo.
echo    ╔══════════════════════════════════════════════════════════╗
echo    ║  FU PERSON - Galaxy People Finder v4.0                   ║
echo    ║  25 Questions + 30 Data Sources + Breach Check            ║
echo    ╚══════════════════════════════════════════════════════════╝
echo.
echo    [*] Answer what you know, press ENTER to skip
echo.
echo    ────────────────────────────────────────────────────────────
echo.

python "core\galaxy_recon_suite.py" --interactive

echo.
echo    ────────────────────────────────────────────────────────────
echo    [+] Mission complete - Check JSON report in deploy folder
echo.
dir /b galaxy_report_*.json 2>nul
echo.
pause
