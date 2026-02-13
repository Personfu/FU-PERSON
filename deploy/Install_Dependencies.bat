@echo off
color 0B
title FLLC - First Time Setup
mode con: cols=80 lines=30

cls
echo.
echo  ============================================================
echo  =                                                          =
echo  =     FLLC - FIRST TIME SETUP                       =
echo  =     Installing Python Dependencies                       =
echo  =                                                          =
echo  ============================================================
echo.
echo  Checking Python installation...
echo.
python --version
if errorlevel 1 (
    echo.
    echo  ERROR: Python is not installed or not in PATH!
    echo  Download Python from: https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during install!
    echo.
    pause
    exit
)
echo.
echo  Python found! Installing required packages...
echo.
pip install -r "%~dp0requirements.txt"
echo.
echo  ============================================================
echo  =     SETUP COMPLETE!                                      =
echo  =                                                          =
echo  =     You can now double-click any of these to start:      =
echo  =       - LAUNCH.bat        (Main menu)                    =
echo  =       - Run_Galaxy_Recon.bat                              =
echo  =       - Run_Pentest_Suite.bat                             =
echo  =       - Run_OSINT_Recon.bat                               =
echo  =                                                          =
echo  ============================================================
echo.
pause
