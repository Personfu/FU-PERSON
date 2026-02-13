@echo off
title FLLC Tri-Drive Deployment
color 0F

echo.
echo  ================================================================
echo   FLLC - TRI-DRIVE DEPLOYMENT
echo  ================================================================
echo.

cd /d "%~dp0.."

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

python deploy\build_usb.py %*

echo.
pause
