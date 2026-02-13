@echo off
color 0E
title FLLC - OSINT Recon Suite
mode con: cols=90 lines=45

cls
echo.
echo  ================================================================
echo  =                                                              =
echo  =     FLLC - OSINT RECON SUITE                          =
echo  =     Open Source Intelligence Gathering                       =
echo  =                                                              =
echo  ================================================================
echo.
echo  This tool performs OSINT reconnaissance including:
echo    - DNS Records and Subdomains
echo    - WHOIS Information
echo    - Technology Detection
echo    - Social Media Discovery
echo    - Data Breach Checks
echo.
echo  ================================================================
echo.
set /p target="  Enter target website (e.g. example.com): "
if "%target%"=="" (
    echo.
    echo  ERROR: You must enter a target website!
    echo.
    pause
    exit
)
echo.
echo  ================================================================
echo  =     LAUNCHING OSINT RECON...                                 =
echo  ================================================================
echo.

python "%~dp0osint_recon_suite.py" --target %target% --authorized

echo.
echo  ================================================================
echo  =     RECON COMPLETE                                           =
echo  =     Check the JSON report file in this folder                =
echo  ================================================================
echo.
echo  Your report files:
dir /b "%~dp0osint_report_*.json" 2>nul
echo.
pause
