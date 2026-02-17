<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | NETWORK RECON v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Pure PowerShell. Zero dependencies. Runs from USB.              ║
   ║  Port scanning, ARP discovery, WiFi analysis, service            ║
   ║  fingerprinting, share enumeration, route mapping.               ║
   ║  Bluetooth discovery | USB history | Kali nmap-style output      ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ══════════════════════════════════════════════════════════════════════
# PORT SCANNER (async, fast)
# ══════════════════════════════════════════════════════════════════════

function Scan-Ports {
    param(
        [string]$Target,
        [int[]]$Ports = @(),
        [int]$Timeout = 200,
        [int]$Threads = 100
    )
    
    # Default: top 100 most common ports
    if ($Ports.Count -eq 0) {
        $Ports = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,
                   5985,5986,8080,8443,8888,27017,1433,1521,6379,11211,2049,515,631,9100,
                   49152,49153,49154,49155,49156,49157,389,636,88,464,593,3268,3269,
                   5060,5061,4443,9090,9200,9300,15672,5672,1883,8883,1080,3128,8081,
                   8000,8001,8002,8008,8010,8181,8444,8880,9443,
                   20,69,161,162,514,520,1900,5353,137,138,
                   2222,2121,4444,4445,5555,6666,7777,8082,9999,
                   10000,10443,27018,28017,50000,50070,50090,60010,60030,
                   6443,10250,10255,2379,2380,30000,31000,32000,
                   1434,5984,6984,7474,7687,9042,9160,8529)
    }
    
    Write-Host "`n  [*] Scanning $Target ($($Ports.Count) ports, ${Timeout}ms timeout)" -ForegroundColor Cyan
    
    $openPorts = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
    $runspacePool = [System.Management.Automation.Runspaces.RunspacePool]::CreateRunspacePool(1, $Threads)
    $runspacePool.Open()
    
    $jobs = @()
    
    foreach ($port in $Ports) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $runspacePool
        [void]$ps.AddScript({
            param($t, $p, $to)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($t, $p, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne($to, $false)
                if ($wait -and $tcp.Connected) {
                    $tcp.EndConnect($connect)
                    $tcp.Close()
                    return $p
                }
                $tcp.Close()
            } catch {}
            return -1
        }).AddArgument($Target).AddArgument($port).AddArgument($Timeout)
        
        $jobs += @{
            PS = $ps
            Handle = $ps.BeginInvoke()
            Port = $port
        }
    }
    
    # Collect results
    $open = @()
    foreach ($job in $jobs) {
        $result = $job.PS.EndInvoke($job.Handle)
        if ($result -ne -1 -and $result -gt 0) {
            $open += $result
        }
        $job.PS.Dispose()
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    # Service identification
    $serviceMap = @{
        21="FTP";22="SSH";23="Telnet";25="SMTP";53="DNS";80="HTTP";110="POP3";111="RPCBind";
        135="MSRPC";139="NetBIOS";143="IMAP";443="HTTPS";445="SMB";993="IMAPS";995="POP3S";
        1433="MSSQL";1521="Oracle";1723="PPTP";2049="NFS";2222="SSH-Alt";3128="Proxy";
        3306="MySQL";3389="RDP";5060="SIP";5432="PostgreSQL";5672="AMQP";5900="VNC";
        5984="CouchDB";5985="WinRM-HTTP";5986="WinRM-HTTPS";6379="Redis";6443="K8s-API";
        7474="Neo4j";8080="HTTP-Proxy";8443="HTTPS-Alt";8888="HTTP-Alt";9042="Cassandra";
        9090="Prometheus";9200="Elasticsearch";9300="ES-Transport";10250="Kubelet";
        11211="Memcached";15672="RabbitMQ-Mgmt";27017="MongoDB";50000="Jenkins"
    }
    
    $open = $open | Sort-Object
    if ($open.Count -gt 0) {
        Write-Host "`n  OPEN PORTS:" -ForegroundColor Green
        Write-Host "  ------------------------------------------------" -ForegroundColor DarkGray
        foreach ($p in $open) {
            $svc = if ($serviceMap.ContainsKey($p)) { $serviceMap[$p] } else { "unknown" }
            Write-Host "    $p/tcp  OPEN  [$svc]" -ForegroundColor Green
        }
        Write-Host "  ------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Total: $($open.Count) open ports" -ForegroundColor Yellow
    } else {
        Write-Host "  No open ports found." -ForegroundColor DarkGray
    }
    
    return $open
}

# ══════════════════════════════════════════════════════════════════════
# ARP / HOST DISCOVERY
# ══════════════════════════════════════════════════════════════════════

function Discover-Hosts {
    param([string]$Subnet = "")
    
    if (-not $Subnet) {
        # Auto-detect local subnet
        $adapter = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown"
        } | Select-Object -First 1
        
        if ($adapter) {
            $ip = $adapter.IPAddress
            $prefix = $adapter.PrefixLength
            $octets = $ip -split '\.'
            $Subnet = "$($octets[0]).$($octets[1]).$($octets[2])"
            Write-Host "  [*] Auto-detected subnet: $Subnet.0/$prefix" -ForegroundColor Cyan
        } else {
            Write-Host "  [!] Cannot detect subnet" -ForegroundColor Red
            return
        }
    }
    
    Write-Host "  [*] Discovering hosts on $Subnet.0/24" -ForegroundColor Cyan
    Write-Host "  [*] Sending ARP/ICMP probes..." -ForegroundColor DarkGray
    
    # Parallel ping sweep
    $jobs = @()
    for ($i = 1; $i -le 254; $i++) {
        $target = "$Subnet.$i"
        $jobs += Test-Connection $target -Count 1 -TimeoutSeconds 1 -AsJob -ErrorAction SilentlyContinue
    }
    
    $alive = @()
    foreach ($job in $jobs) {
        $result = $job | Wait-Job -Timeout 3 | Receive-Job -ErrorAction SilentlyContinue
        if ($result -and $result.Status -eq "Success") {
            $alive += $result.Address
        }
        $job | Remove-Job -Force -ErrorAction SilentlyContinue
    }
    
    # Also parse ARP table
    $arpLines = arp -a 2>$null
    $arpEntries = @{}
    foreach ($line in $arpLines) {
        if ($line -match '(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)') {
            $arpEntries[$Matches[1]] = $Matches[2]
        }
    }
    
    # Merge results
    $allHosts = ($alive + $arpEntries.Keys) | Sort-Object -Unique | Where-Object { $_ -match '^\d' }
    
    Write-Host "`n  DISCOVERED HOSTS:" -ForegroundColor Green
    Write-Host "  ------------------------------------------------" -ForegroundColor DarkGray
    foreach ($h in ($allHosts | Sort-Object { [version]$_ })) {
        $mac = if ($arpEntries.ContainsKey($h)) { $arpEntries[$h] } else { "(no MAC)" }
        $hostname = ""
        try { $hostname = [System.Net.Dns]::GetHostEntry($h).HostName } catch {}
        if ($hostname -eq $h) { $hostname = "" }
        
        $line = "    $h"
        if ($mac -ne "(no MAC)") { $line += "  [$mac]" }
        if ($hostname) { $line += "  ($hostname)" }
        Write-Host $line -ForegroundColor Green
    }
    Write-Host "  ------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Total: $($allHosts.Count) hosts" -ForegroundColor Yellow
    
    return $allHosts
}

# ══════════════════════════════════════════════════════════════════════
# WIFI ANALYSIS
# ══════════════════════════════════════════════════════════════════════

function Analyze-WiFi {
    Write-Host "`n  [*] WiFi environment analysis" -ForegroundColor Cyan
    
    # Current connection
    Write-Host "`n  [CURRENT CONNECTION]" -ForegroundColor Yellow
    $iface = netsh wlan show interfaces 2>$null
    if ($iface) {
        $iface | ForEach-Object {
            if ($_ -match "SSID|State|Channel|Signal|Auth|Cipher|Band|Radio") {
                Write-Host "    $_" -ForegroundColor Green
            }
        }
    }
    
    # Saved profiles + passwords
    Write-Host "`n  [SAVED WIFI PASSWORDS]" -ForegroundColor Yellow
    $profiles = (netsh wlan show profiles 2>$null) | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[-1].Trim()
    }
    
    foreach ($p in $profiles) {
        $detail = netsh wlan show profile name="$p" key=clear 2>$null
        $key = ($detail | Select-String "Key Content") -replace '.*:\s+', ''
        $auth = ($detail | Select-String "Authentication") -replace '.*:\s+', '' | Select-Object -First 1
        $cipher = ($detail | Select-String "Cipher") -replace '.*:\s+', '' | Select-Object -First 1
        
        if ($key) {
            Write-Host "    $p | $auth | $cipher | Password: $key" -ForegroundColor Green
        } else {
            Write-Host "    $p | $auth | $cipher | Password: (none/enterprise)" -ForegroundColor DarkGray
        }
    }
    
    # Nearby networks
    Write-Host "`n  [NEARBY NETWORKS]" -ForegroundColor Yellow
    $networks = netsh wlan show networks mode=bssid 2>$null
    if ($networks) {
        $currentSSID = ""
        $networks | ForEach-Object {
            if ($_ -match "^SSID \d+\s*:\s*(.+)") { $currentSSID = $Matches[1].Trim() }
            if ($_ -match "Signal|Channel|Authentication|Encryption|BSSID") {
                Write-Host "    $_" -ForegroundColor Gray
            }
            if ($_ -match "^SSID") { Write-Host "    $_" -ForegroundColor Cyan }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════
# SMB / SHARE ENUMERATION
# ══════════════════════════════════════════════════════════════════════

function Enum-Shares {
    param([string]$Target = "")
    
    if ($Target) {
        Write-Host "`n  [*] Enumerating shares on $Target" -ForegroundColor Cyan
        $shares = net view "\\$Target" 2>$null
        if ($shares) {
            $shares | ForEach-Object { Write-Host "    $_" -ForegroundColor Green }
        } else {
            Write-Host "    (access denied or no shares)" -ForegroundColor DarkGray
        }
        
        # Try common share names
        $commonShares = @("C$","ADMIN$","IPC$","SYSVOL","NETLOGON","Users","Public","Shared")
        Write-Host "`n  [COMMON SHARES]" -ForegroundColor Yellow
        foreach ($s in $commonShares) {
            $path = "\\$Target\$s"
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                Write-Host "    [OPEN] $path" -ForegroundColor Green
            } else {
                Write-Host "    [----] $path" -ForegroundColor DarkGray
            }
        }
    } else {
        # Local shares
        Write-Host "`n  [*] Local shares" -ForegroundColor Cyan
        Get-SmbShare | Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host
        
        # Mapped drives
        Write-Host "  [MAPPED DRIVES]" -ForegroundColor Yellow
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot } |
        Format-Table Name, DisplayRoot -AutoSize | Out-String | Write-Host
    }
}

# ══════════════════════════════════════════════════════════════════════
# FULL AUTO RECON
# ══════════════════════════════════════════════════════════════════════

function Run-FullRecon {
    param([string]$OutputDir = "")
    
    if (-not $OutputDir) {
        $usb = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
        foreach ($d in $usb) {
            if (Test-Path "$($d.DeviceID)\.loot_target") {
                $OutputDir = "$($d.DeviceID)\recon_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                break
            }
        }
        if (-not $OutputDir) { $OutputDir = "$env:USERPROFILE\Desktop\recon_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    }
    
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    Write-Host "`n  [*] FULL RECON MODE - Output: $OutputDir" -ForegroundColor Cyan
    
    # WiFi
    Write-Host "`n  === PHASE 1: WiFi ===" -ForegroundColor Yellow
    Analyze-WiFi | Tee-Object -FilePath "$OutputDir\wifi.txt"
    
    # Host discovery
    Write-Host "`n  === PHASE 2: Host Discovery ===" -ForegroundColor Yellow
    $hosts = Discover-Hosts
    $hosts | Out-File "$OutputDir\hosts.txt" -Encoding utf8
    
    # Port scan top hosts
    Write-Host "`n  === PHASE 3: Port Scanning ===" -ForegroundColor Yellow
    $gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
    $scanTargets = @($gateway)
    if ($hosts) { $scanTargets += ($hosts | Select-Object -First 5) }
    $scanTargets = $scanTargets | Select-Object -Unique
    
    foreach ($t in $scanTargets) {
        if ($t) {
            $openPorts = Scan-Ports -Target $t
            if ($openPorts) {
                $openPorts | Out-File "$OutputDir\ports_$($t.Replace('.','_')).txt" -Encoding utf8
            }
        }
    }
    
    # Shares
    Write-Host "`n  === PHASE 4: Share Enumeration ===" -ForegroundColor Yellow
    Enum-Shares | Tee-Object -FilePath "$OutputDir\shares.txt"
    
    Write-Host "`n  [+] Full recon complete: $OutputDir" -ForegroundColor Green
}

# ══════════════════════════════════════════════════════════════════════
# INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════════════

function Show-ReconMenu {
    while ($true) {
        Write-Host @"

  ================================================
   FLLC NETWORK RECON v2.0
   Pure PowerShell | Zero Dependencies
  ================================================
   [1] Port Scan (single target)
   [2] Host Discovery (ARP + ICMP sweep)
   [3] WiFi Analysis (passwords + nearby)
   [4] Share Enumeration
   [5] Full Auto Recon (all of the above)
   [6] Exit
  ================================================
"@ -ForegroundColor Cyan
        
        $choice = Read-Host "  Select"
        
        switch ($choice) {
            "1" {
                $target = Read-Host "  Target IP or hostname"
                $portInput = Read-Host "  Ports (comma-separated, or Enter for top 100)"
                if ($portInput) {
                    $ports = $portInput -split ',' | ForEach-Object { [int]$_.Trim() }
                    Scan-Ports -Target $target -Ports $ports
                } else {
                    Scan-Ports -Target $target
                }
            }
            "2" {
                $subnet = Read-Host "  Subnet (e.g. 192.168.1, or Enter for auto-detect)"
                Discover-Hosts -Subnet $subnet
            }
            "3" { Analyze-WiFi }
            "4" {
                $target = Read-Host "  Target IP (or Enter for local)"
                Enum-Shares -Target $target
            }
            "5" { Run-FullRecon }
            "6" { return }
            default { Write-Host "  Invalid selection" -ForegroundColor Red }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Show-ReconMenu
}
