@echo off
title FLLC OSINT People Finder
color 0F

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║  FLLC OSINT PEOPLE FINDER                            ║
echo  ║  Comprehensive Intelligence Aggregator                  ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

REM Check for virtual environment
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Check if running with arguments or interactive
if "%~1"=="" (
    echo  Launching interactive mode...
    echo.
    python "%~dp0people_finder.py" --interactive
) else (
    python "%~dp0people_finder.py" %*
)

echo.
echo  Press any key to exit...
pause >nul
