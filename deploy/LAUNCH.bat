@echo off
title FU PERSON - FLLC Operations Platform v2.0
mode con: cols=80 lines=40
cd /d "%~dp0"
cls
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$e=[char]27; $c=$e+'[36m'; $r=$e+'[0m'; $y=$e+'[33m'; Write-Host ('    '+$c+' ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗'+$r); Write-Host ('    '+$c+' ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║'+$r); Write-Host ('    '+$c+' █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║'+$r); Write-Host ('    '+$c+' ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║'+$r); Write-Host ('    '+$c+' ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║'+$r); Write-Host ('    '+$c+' ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝'+$r)"
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$e=[char]27; $c=$e+'[36m'; $r=$e+'[0m'; Write-Host ('    '+$c+'╔══════════════════════════════════════════════════════════╗'+$r); Write-Host ('    '+$c+'║  FLLC Operations Platform v2.0                          ║'+$r); Write-Host ('    '+$c+'║  Property of FLLC - Authorized Use Only                 ║'+$r); Write-Host ('    '+$c+'╚══════════════════════════════════════════════════════════╝'+$r)"
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$e=[char]27; $y=$e+'[33m'; $r=$e+'[0m'; Write-Host ('    '+$y+'╔══════════════════════════════════════════════════════════╗'+$r); Write-Host ('    '+$y+'║  [1] People Finder (OSINT)                              ║'+$r); Write-Host ('    '+$y+'║  [2] Pentest Suite                                      ║'+$r); Write-Host ('    '+$y+'║  [3] OSINT Recon Suite                                  ║'+$r); Write-Host ('    '+$y+'║  [4] Galaxy Recon Suite                                 ║'+$r); Write-Host ('    '+$y+'║  [5] Build USB Drives                                   ║'+$r); Write-Host ('    '+$y+'║  [6] Install Dependencies                               ║'+$r); Write-Host ('    '+$y+'║  [0] Exit                                               ║'+$r); Write-Host ('    '+$y+'╚══════════════════════════════════════════════════════════╝'+$r)"
echo.

set /p choice="    root@fuperson:~# select: "

if "%choice%"=="1" call "%~dp0Run_People_Finder.bat"
if "%choice%"=="2" call "%~dp0Run_Pentest_Suite.bat"
if "%choice%"=="3" call "%~dp0Run_OSINT_Recon.bat"
if "%choice%"=="4" call "%~dp0Run_Galaxy_Recon.bat"
if "%choice%"=="5" call "%~dp0Build_USB_Drives.bat"
if "%choice%"=="6" call "%~dp0Install_Dependencies.bat"
if "%choice%"=="0" exit /b 0

echo.
pause
