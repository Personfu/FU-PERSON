@echo off
REM ============================================================================
REM  FLLC - Silent Listener Launcher
REM  Starts the voice-activated recorder with no visible window
REM ============================================================================

REM Try pythonw first (no console window), fall back to python
where pythonw >nul 2>nul
if %errorlevel% equ 0 (
    start "" /b pythonw "%~dp0listener.py" --output "%~d0" --threshold 50 --format mp3 --bitrate 32k --max-storage 180
) else (
    start "" /min python "%~dp0listener.py" --output "%~d0" --threshold 50 --format mp3 --bitrate 32k --max-storage 180
)

exit
