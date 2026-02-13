@echo off
setlocal enabledelayedexpansion
color 0B
title FLLC - Security Testing Launcher
mode con: cols=90 lines=50

:MENU
cls
echo.
echo  ====================================================================
echo  =                                                                  =
echo  =     FLLC - SECURITY TESTING LAUNCHER                      =
echo  =     Double-Click Friendly Edition                                =
echo  =                                                                  =
echo  ====================================================================
echo.
echo    Choose a tool to run:
echo.
echo    [1]  People Finder         (Interactive 25-Q Deep OSINT v4)
echo    [2]  Domain Recon          (Deep website reconnaissance)
echo    [3]  Pentest Suite         (Full penetration testing)
echo    [4]  OSINT Recon Suite     (Open Source Intelligence)
echo    [5]  Run ALL Tools         (Everything on one target)
echo    [6]  View Past Reports     (Open saved JSON reports)
echo    [7]  Install Dependencies  (First time setup)
echo    [8]  Exit
echo.
echo  ====================================================================
echo.
set /p choice="  Enter your choice (1-8): "

if "%choice%"=="1" goto PEOPLEFINDER
if "%choice%"=="2" goto DOMAINRECON
if "%choice%"=="3" goto PENTEST
if "%choice%"=="4" goto OSINT
if "%choice%"=="5" goto RUNALL
if "%choice%"=="6" goto REPORTS
if "%choice%"=="7" goto INSTALL
if "%choice%"=="8" exit
echo.
echo  Invalid choice. Please try again.
timeout /t 2 >nul
goto MENU

:PEOPLEFINDER
cls
echo.
echo  ====================================================================
echo  =     GALAXY PEOPLE FINDER v4.0 - Deep OSINT                       =
echo  =     25 Questions + 30 Data Sources + Breach Check               =
echo  ====================================================================
echo.
echo  The tool will ask you a series of questions about the person.
echo  Answer what you know, press ENTER to skip what you don't.
echo.
echo  Launching...
echo.
python "%~dp0galaxy_recon_suite.py" --interactive
echo.
echo  ====================================================================
echo  =     SEARCH COMPLETE - Results saved to JSON report               =
echo  ====================================================================
echo.
set /p again="  Press ENTER to return to menu or type EXIT to quit: "
if /i "%again%"=="exit" exit
goto MENU

:DOMAINRECON
cls
echo.
echo  ====================================================================
echo  =     DOMAIN RECONNAISSANCE                                       =
echo  ====================================================================
echo.
set /p target="  Enter target website (e.g. example.com): "
if "%target%"=="" (
    echo  No target entered. Going back...
    timeout /t 2 >nul
    goto MENU
)
echo.
echo  Starting Domain Recon on %target%...
echo  ====================================================================
echo.
python "%~dp0galaxy_recon_suite.py" --domain %target%
echo.
echo  ====================================================================
echo  =     SCAN COMPLETE - Results saved to JSON report                 =
echo  ====================================================================
echo.
set /p again="  Press ENTER to return to menu or type EXIT to quit: "
if /i "%again%"=="exit" exit
goto MENU

:PENTEST
cls
echo.
echo  ====================================================================
echo  =     PENETRATION TESTING SUITE                                    =
echo  ====================================================================
echo.
set /p target="  Enter target website (e.g. example.com): "
if "%target%"=="" (
    echo  No target entered. Going back...
    timeout /t 2 >nul
    goto MENU
)
echo.
echo  Starting Pentest Suite on %target%...
echo  ====================================================================
echo.
python "%~dp0pentest_suite.py" %target% --authorized
echo.
echo  ====================================================================
echo  =     SCAN COMPLETE - Results saved to JSON report                 =
echo  ====================================================================
echo.
set /p again="  Press ENTER to return to menu or type EXIT to quit: "
if /i "%again%"=="exit" exit
goto MENU

:OSINT
cls
echo.
echo  ====================================================================
echo  =     OSINT RECON SUITE                                           =
echo  ====================================================================
echo.
set /p target="  Enter target website (e.g. example.com): "
if "%target%"=="" (
    echo  No target entered. Going back...
    timeout /t 2 >nul
    goto MENU
)
echo.
echo  Starting OSINT Recon on %target%...
echo  ====================================================================
echo.
python "%~dp0osint_recon_suite.py" --target %target% --authorized
echo.
echo  ====================================================================
echo  =     SCAN COMPLETE - Results saved to JSON report                 =
echo  ====================================================================
echo.
set /p again="  Press ENTER to return to menu or type EXIT to quit: "
if /i "%again%"=="exit" exit
goto MENU

:RUNALL
cls
echo.
echo  ====================================================================
echo  =     RUN ALL TOOLS                                               =
echo  ====================================================================
echo.
echo  This will run:
echo    Phase 1: People Finder (Interactive)
echo    Phase 2: Domain Recon
echo    Phase 3: Full Pentest
echo.
echo  ====================================================================
echo.
echo  PHASE 1: People Finder
echo  -----------------------
python "%~dp0galaxy_recon_suite.py" --interactive
echo.
set /p target="  Enter a DOMAIN to scan (or press ENTER to skip): "
if "%target%"=="" goto RUNALL_DONE
echo.
echo  PHASE 2: Domain Recon on %target%
echo  ----------------------------------
python "%~dp0galaxy_recon_suite.py" --domain %target%
echo.
echo  PHASE 3: Pentest Suite on %target%
echo  -----------------------------------
python "%~dp0pentest_suite.py" %target% --authorized
:RUNALL_DONE
echo.
echo  ====================================================================
echo  =     ALL SCANS COMPLETE - Check your reports!                     =
echo  ====================================================================
echo.
set /p again="  Press ENTER to return to menu or type EXIT to quit: "
if /i "%again%"=="exit" exit
goto MENU

:REPORTS
cls
echo.
echo  ====================================================================
echo  =     SAVED REPORTS                                                =
echo  ====================================================================
echo.
echo  JSON reports found:
echo  -------------------
dir /b "%~dp0*report*.json" 2>nul
if errorlevel 1 (
    echo  No reports found yet. Run a scan first!
) else (
    echo.
    echo  -------------------
    echo.
    set /p openfile="  Type a filename to open it (or ENTER to go back): "
    if not "!openfile!"=="" (
        notepad "%~dp0!openfile!"
    )
)
echo.
set /p again="  Press ENTER to return to menu: "
goto MENU

:INSTALL
cls
echo.
echo  ====================================================================
echo  =     INSTALLING DEPENDENCIES                                      =
echo  ====================================================================
echo.
echo  Installing Python packages...
echo.
pip install -r "%~dp0requirements.txt"
echo.
echo  ====================================================================
echo  =     INSTALLATION COMPLETE                                        =
echo  ====================================================================
echo.
set /p again="  Press ENTER to return to menu: "
goto MENU
