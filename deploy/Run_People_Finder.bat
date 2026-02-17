@echo off
title FU PERSON - People Finder (OSINT)
color 0B
mode con: cols=80 lines=40
cd /d "%~dp0.."

:: Kali-style small banner
echo.
echo     ___ ___     ___  ___  ___  ___
echo    ] - ] - [   ] __ ] __]  _ ] __
echo    ]_  _____]  ]  _ ] _] ___ ] _
echo      ]_[     ]  [___][___][___][___]
echo.
echo    ╔══════════════════════════════════════════════════════════╗
echo    ║  FU PERSON - People Finder (OSINT)                      ║
echo    ║  Comprehensive Intelligence Aggregator                 ║
echo    ╚══════════════════════════════════════════════════════════╝
echo.
echo    [*] Checking virtual environment...

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo    [+] Virtual environment activated
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
    echo    [+] Virtual environment activated
)
echo.
if "%~1"=="" (
    echo    [*] Launching interactive mode...
    echo    ────────────────────────────────────────────────────────────
    echo.
    python "core\people_finder.py" --interactive
) else (
    echo     [*] Launching with arguments...
    echo     [36m────────────────────────────────────────────────────────────[0m
    echo.
    python "core\people_finder.py" %*
)
echo.
echo    [+] Search complete
echo.
pause
