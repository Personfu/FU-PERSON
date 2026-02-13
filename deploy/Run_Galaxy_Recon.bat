@echo off
color 0D
title FLLC - Galaxy People Finder
mode con: cols=90 lines=50

cls
echo.
echo  ================================================================
echo  =                                                              =
echo  =     FLLC - GALAXY PEOPLE FINDER v4.0                 =
echo  =     25 Questions + 30 Data Sources + Breach Check            =
echo  =                                                              =
echo  ================================================================
echo.
echo  This tool will ask you questions about who you're looking for.
echo  Answer what you know, press ENTER to skip what you don't.
echo.
echo  ================================================================
echo.

python "%~dp0galaxy_recon_suite.py" --interactive

echo.
echo  ================================================================
echo  =     MISSION COMPLETE                                         =
echo  =     Check the JSON report file in this folder                =
echo  ================================================================
echo.
echo  Your report files:
dir /b "%~dp0galaxy_report_*.json" 2>nul
echo.
pause
