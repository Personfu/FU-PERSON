<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | DEVICE SYNC v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Auto-detect and sync loot from all connected devices           ║
   ║  Flipper Zero | ESP32 | Galaxy S20+ | Nintendo DSi | USB        ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Find-LootDrive {
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
    foreach ($drive in $drives) {
        $marker = Join-Path $drive.DeviceID ".loot_target"
        if (Test-Path $marker) {
            return $drive.DeviceID
        }
    }
    $fallback = Join-Path $scriptDir "..\..\loot"
    if (-not (Test-Path $fallback)) { New-Item -ItemType Directory -Path $fallback -Force | Out-Null }
    return $fallback
}

function Sync-FlipperZero {
    param([string]$LootDir)

    Write-Host "`n    [*] Scanning for Flipper Zero..." -ForegroundColor Cyan
    $flipperDrive = $null
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
    foreach ($drive in $drives) {
        $flipperMarker = Join-Path $drive.DeviceID "flipper"
        $flipperMarker2 = Join-Path $drive.DeviceID ".metadata"
        if ((Test-Path $flipperMarker) -or (Test-Path $flipperMarker2)) {
            $flipperDrive = $drive.DeviceID
            break
        }
    }

    if (-not $flipperDrive) {
        $comPorts = Get-WmiObject Win32_SerialPort 2>$null
        foreach ($port in $comPorts) {
            if ($port.Description -match 'flipper') {
                Write-Host "    [+] Flipper Zero detected on $($port.DeviceID) (serial)" -ForegroundColor Green
                Write-Host "    [!] Serial mode - mount SD card for file sync" -ForegroundColor Yellow
                return
            }
        }
        Write-Host "    [-] Flipper Zero not detected" -ForegroundColor DarkGray
        return
    }

    Write-Host "    [+] Flipper Zero SD mounted at $flipperDrive" -ForegroundColor Green

    $flipperLoot = Join-Path $LootDir "flipper_sync_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $flipperLoot -Force | Out-Null

    $syncDirs = @(
        @{ Source = "badusb"; Desc = "BadUSB logs" },
        @{ Source = "subghz"; Desc = "Sub-GHz captures" },
        @{ Source = "nfc"; Desc = "NFC card data" },
        @{ Source = "infrared"; Desc = "IR captures" },
        @{ Source = "rfid"; Desc = "RFID data" },
        @{ Source = "ibutton"; Desc = "iButton data" },
        @{ Source = "loot"; Desc = "Flipper loot" }
    )

    foreach ($dir in $syncDirs) {
        $srcPath = Join-Path $flipperDrive $dir.Source
        if (Test-Path $srcPath) {
            $destPath = Join-Path $flipperLoot $dir.Source
            Copy-Item -Path $srcPath -Destination $destPath -Recurse -Force
            $fileCount = (Get-ChildItem -Path $srcPath -Recurse -File).Count
            Write-Host "    [+] Synced $($dir.Desc): $fileCount files" -ForegroundColor Green
        }
    }
}

function Sync-ESP32 {
    param([string]$LootDir)

    Write-Host "`n    [*] Scanning for ESP32 data..." -ForegroundColor Cyan

    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
    $esp32Found = $false

    foreach ($drive in $drives) {
        $scanLogs = @("wifi_scan.csv", "ble_scan.csv", "pcap", "scan_data", "wardriver")
        foreach ($logFile in $scanLogs) {
            $logPath = Join-Path $drive.DeviceID $logFile
            if (Test-Path $logPath) {
                $esp32Loot = Join-Path $LootDir "esp32_sync_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                New-Item -ItemType Directory -Path $esp32Loot -Force | Out-Null
                Copy-Item -Path $logPath -Destination $esp32Loot -Recurse -Force
                Write-Host "    [+] ESP32 data synced from $($drive.DeviceID)\$logFile" -ForegroundColor Green
                $esp32Found = $true
            }
        }
    }

    if (-not $esp32Found) {
        $comPorts = Get-WmiObject Win32_SerialPort 2>$null
        foreach ($port in $comPorts) {
            if ($port.Description -match 'cp210|ch340|esp32|silicon labs') {
                Write-Host "    [+] ESP32 detected on $($port.DeviceID) (serial)" -ForegroundColor Green
                Write-Host "    [*] Reading serial output for 10 seconds..." -ForegroundColor DarkGray

                try {
                    $serialPort = New-Object System.IO.Ports.SerialPort($port.DeviceID, 115200)
                    $serialPort.ReadTimeout = 10000
                    $serialPort.Open()
                    $serialData = @()
                    $endTime = (Get-Date).AddSeconds(10)

                    while ((Get-Date) -lt $endTime) {
                        try {
                            $line = $serialPort.ReadLine()
                            $serialData += $line
                        } catch { }
                    }

                    $serialPort.Close()

                    if ($serialData.Count -gt 0) {
                        $esp32Loot = Join-Path $LootDir "esp32_serial_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                        New-Item -ItemType Directory -Path $esp32Loot -Force | Out-Null
                        $serialData | Out-File (Join-Path $esp32Loot "serial_capture.txt")
                        Write-Host "    [+] Captured $($serialData.Count) lines of ESP32 serial data" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "    [!] Could not read ESP32 serial: $($_.Exception.Message)" -ForegroundColor Yellow
                }
                return
            }
        }
        Write-Host "    [-] ESP32 not detected" -ForegroundColor DarkGray
    }
}

function Sync-AndroidDevice {
    param([string]$LootDir)

    Write-Host "`n    [*] Scanning for Android device (ADB)..." -ForegroundColor Cyan

    try {
        $adbDevices = & adb devices 2>$null
        $connected = $adbDevices | Select-String "device$"

        if (-not $connected) {
            Write-Host "    [-] No Android device connected via ADB" -ForegroundColor DarkGray
            return
        }

        Write-Host "    [+] Android device connected via ADB" -ForegroundColor Green

        $androidLoot = Join-Path $LootDir "android_sync_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $androidLoot -Force | Out-Null

        $pullDirs = @(
            @{ Remote = "/sdcard/loot/"; Desc = "Loot directory" },
            @{ Remote = "/sdcard/scan_results/"; Desc = "Scan results" },
            @{ Remote = "/sdcard/wifi_data/"; Desc = "WiFi data" },
            @{ Remote = "/sdcard/recon/"; Desc = "Recon data" }
        )

        foreach ($dir in $pullDirs) {
            $destDir = Join-Path $androidLoot ($dir.Remote -replace '/sdcard/','')
            & adb pull $dir.Remote $destDir 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [+] Pulled $($dir.Desc)" -ForegroundColor Green
            }
        }

        $deviceInfo = & adb shell getprop ro.product.model 2>$null
        $deviceInfo | Out-File (Join-Path $androidLoot "device_info.txt")
        Write-Host "    [+] Device info captured: $deviceInfo" -ForegroundColor Green

    } catch {
        Write-Host "    [!] ADB not found or not in PATH" -ForegroundColor Yellow
    }
}

function Sync-DSiData {
    param([string]$LootDir)

    Write-Host "`n    [*] Scanning for DSi SD card data..." -ForegroundColor Cyan

    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
    $dsiFound = $false

    foreach ($drive in $drives) {
        $cyberWorldDir = Join-Path $drive.DeviceID ".cyberworld"
        $scanData = Join-Path $cyberWorldDir ".scan_data"
        $ndsDir = Join-Path $drive.DeviceID "_nds"

        if ((Test-Path $scanData) -or (Test-Path $ndsDir)) {
            $dsiLoot = Join-Path $LootDir "dsi_sync_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            New-Item -ItemType Directory -Path $dsiLoot -Force | Out-Null

            if (Test-Path $scanData) {
                Copy-Item -Path $scanData -Destination (Join-Path $dsiLoot "scan_data") -Recurse -Force
                $scanFiles = (Get-ChildItem -Path $scanData -Recurse -File).Count
                Write-Host "    [+] DSi CyberWorld scan data: $scanFiles files synced" -ForegroundColor Green
                $dsiFound = $true
            }

            $dsiLogs = Join-Path $drive.DeviceID ".cyberworld\logs"
            if (Test-Path $dsiLogs) {
                Copy-Item -Path $dsiLogs -Destination (Join-Path $dsiLoot "logs") -Recurse -Force
                Write-Host "    [+] DSi operation logs synced" -ForegroundColor Green
            }
        }
    }

    if (-not $dsiFound) {
        Write-Host "    [-] No DSi SD card with CyberWorld data detected" -ForegroundColor DarkGray
    }
}

function Start-DeviceSync {
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "    ║  DEVICE SYNC - Multi-Device Loot Aggregation             ║" -ForegroundColor Cyan
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    $lootDrive = Find-LootDrive
    $syncDir = Join-Path $lootDrive "loot\device_sync_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $syncDir -Force | Out-Null

    Write-Host "    [*] Loot destination: $syncDir" -ForegroundColor DarkGray

    Sync-FlipperZero -LootDir $syncDir
    Sync-ESP32 -LootDir $syncDir
    Sync-AndroidDevice -LootDir $syncDir
    Sync-DSiData -LootDir $syncDir

    $totalFiles = (Get-ChildItem -Path $syncDir -Recurse -File).Count
    $totalSize = [math]::Round(((Get-ChildItem -Path $syncDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 2)

    Write-Host ""
    Write-Host "    ┌─── Sync Summary ─────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "    │  Total files synced: $totalFiles" -ForegroundColor Green
    Write-Host "    │  Total size: ${totalSize} MB" -ForegroundColor Green
    Write-Host "    │  Location: $syncDir" -ForegroundColor Green
    Write-Host "    └──────────────────────────────────────────────────────┘" -ForegroundColor Green
}
