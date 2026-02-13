@echo off
REM ============================================================================
REM  FLLC - scrcpy Setup for Headless S20+
REM  Screen Mirror / Remote Control (even with broken screen!)
REM ============================================================================
REM
REM  scrcpy lets you see and control the S20+ from your PC even though
REM  the screen is broken. It mirrors the display over USB/WiFi.
REM
REM  Prerequisites:
REM    - scrcpy installed (winget install Genymobile.scrcpy)
REM    - ADB installed
REM    - USB debugging enabled on phone
REM    - Phone connected via USB
REM ============================================================================

title FLLC - S20+ Screen Mirror

echo.
echo  ============================================
echo   FLLC - S20+ Screen Mirror (scrcpy)
echo  ============================================
echo.

REM Check if scrcpy is installed
where scrcpy >nul 2>nul
if %errorlevel% neq 0 (
    echo  [!] scrcpy not found. Installing...
    winget install Genymobile.scrcpy --accept-source-agreements --accept-package-agreements 2>nul
    if %errorlevel% neq 0 (
        echo  [!] Auto-install failed. Download from:
        echo      https://github.com/Genymobile/scrcpy/releases
        echo.
        pause
        exit /b 1
    )
)

REM Check for connected device
adb devices | findstr /C:"device" >nul 2>nul
if %errorlevel% neq 0 (
    echo  [!] No device detected. Connect the S20+ via USB.
    echo      Make sure USB debugging is enabled.
    pause
    exit /b 1
)

echo  [+] Device detected!
echo.
echo  Select mode:
echo    1. Full mirror (see + control phone screen)
echo    2. Control only (no video, lower bandwidth)
echo    3. Record screen to file
echo    4. WiFi mode (disconnect USB after setup)
echo    5. Turn off phone screen (save battery, still control via PC)
echo.
set /p MODE="  Choice: "

if "%MODE%"=="1" (
    echo  [*] Starting full mirror...
    scrcpy --stay-awake --turn-screen-off --power-off-on-close
) else if "%MODE%"=="2" (
    echo  [*] Starting control-only mode...
    scrcpy --no-video --stay-awake
) else if "%MODE%"=="3" (
    echo  [*] Recording to screen_capture.mp4...
    scrcpy --record screen_capture.mp4 --stay-awake
) else if "%MODE%"=="4" (
    echo  [*] Enabling WiFi ADB...
    adb tcpip 5555
    timeout /t 3 /nobreak >nul
    for /f "tokens=2 delims=:" %%a in ('adb shell ip addr show wlan0 ^| findstr "inet "') do (
        for /f "tokens=1 delims=/" %%b in ("%%a") do set PHONE_IP=%%b
    )
    set PHONE_IP=%PHONE_IP: =%
    echo  [+] Disconnect USB cable now.
    echo  [+] Then run: adb connect %PHONE_IP%:5555
    echo  [+] Then run: scrcpy --stay-awake
    pause
) else if "%MODE%"=="5" (
    echo  [*] Screen off mode (control via PC only)...
    scrcpy --turn-screen-off --stay-awake --power-off-on-close
) else (
    echo  [!] Invalid choice
)

pause
