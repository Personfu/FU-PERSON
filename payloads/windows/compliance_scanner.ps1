<# ============================================================================
    FLLC | FU PERSON | COMPLIANCE SCANNER v1.777
    Automated NIST 800-53 / CIS v8 / PCI-DSS 4.0 / SOC 2 Audit Engine
    
    Scans target system and maps findings to compliance control IDs.
    Generates audit-ready reports with pass/fail/partial scoring.
    
    Phases:
      1 — Access Control (AC)
      2 — Audit & Accountability (AU)
      3 — Identification & Authentication (IA)
      4 — System & Communications Protection (SC)
      5 — System & Information Integrity (SI)
      6 — Configuration Management (CM)
      7 — Risk Assessment (RA)
      8 — Report Generation
============================================================================ #>

$ErrorActionPreference = 'SilentlyContinue'
$SCAN_VERSION = "1.777"

# ── Output Setup ──
$Global:COMP_FINDINGS = @()
$Global:COMP_LOG = "$env:TEMP\compliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Add-Finding {
    param(
        [string]$Control,      # e.g. "NIST AC-2"
        [string]$Title,
        [string]$Status,       # PASS, FAIL, PARTIAL
        [string]$Details,
        [string]$CIS = "",
        [string]$PCI = "",
        [string]$SOC2 = ""
    )
    $Global:COMP_FINDINGS += [PSCustomObject]@{
        Control  = $Control
        CIS      = $CIS
        PCI      = $PCI
        SOC2     = $SOC2
        Title    = $Title
        Status   = $Status
        Details  = $Details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    $icon = switch ($Status) { "PASS" {"[+]"} "FAIL" {"[-]"} "PARTIAL" {"[~]"} default {"[?]"} }
    $line = "$icon $Control | $Title | $Status"
    $line | Out-File -FilePath $Global:COMP_LOG -Append -Encoding utf8
}

# ============================================================================
# PHASE 1: ACCESS CONTROL
# ============================================================================
function Test-AccessControls {
    Write-Host "`n=== PHASE 1: ACCESS CONTROL ===" -ForegroundColor Cyan
    
    # AC-2: Account Management — check for stale/disabled/guest accounts
    $staleThreshold = (Get-Date).AddDays(-90)
    $localUsers = Get-LocalUser 2>$null
    $staleAccounts = $localUsers | Where-Object {
        $_.LastLogon -and $_.LastLogon -lt $staleThreshold -and $_.Enabled
    }
    if ($staleAccounts.Count -eq 0) {
        Add-Finding "NIST AC-2" "No stale accounts (>90 days)" "PASS" "All active accounts logged in within 90 days" "5.1" "8.1" "CC6.1"
    } else {
        Add-Finding "NIST AC-2" "Stale accounts detected" "FAIL" "$($staleAccounts.Count) accounts inactive >90 days: $($staleAccounts.Name -join ', ')" "5.1" "8.1" "CC6.1"
    }
    
    # AC-2: Guest account
    $guest = $localUsers | Where-Object { $_.Name -eq "Guest" }
    if ($guest -and -not $guest.Enabled) {
        Add-Finding "NIST AC-2" "Guest account disabled" "PASS" "Guest account is disabled" "5.1" "8.1" "CC6.1"
    } elseif ($guest -and $guest.Enabled) {
        Add-Finding "NIST AC-2" "Guest account ENABLED" "FAIL" "Guest account should be disabled" "5.1" "2.1" "CC6.1"
    }
    
    # AC-6: Least Privilege — check admin group membership
    $admins = net localgroup Administrators 2>$null
    $adminCount = ($admins | Where-Object { $_ -match "^\w" -and $_ -notmatch "^(The command|Members|---)" }).Count
    if ($adminCount -le 2) {
        Add-Finding "NIST AC-6" "Admin group membership minimal" "PASS" "$adminCount admin accounts" "5.4" "7.1" "CC6.3"
    } else {
        Add-Finding "NIST AC-6" "Excessive admin accounts" "FAIL" "$adminCount accounts in Administrators group" "5.4" "7.1" "CC6.3"
    }
    
    # AC-7: Unsuccessful Logon Attempts — check lockout policy
    $lockoutInfo = net accounts 2>$null
    $lockoutThreshold = ($lockoutInfo | Select-String "Lockout threshold") -replace '.*:\s+', ''
    if ($lockoutThreshold -match "^\d+$" -and [int]$lockoutThreshold -le 5 -and [int]$lockoutThreshold -gt 0) {
        Add-Finding "NIST AC-7" "Account lockout configured" "PASS" "Lockout after $lockoutThreshold attempts" "5.2" "8.3" "CC6.1"
    } else {
        Add-Finding "NIST AC-7" "Account lockout NOT configured" "FAIL" "Threshold: $lockoutThreshold (should be 3-5)" "5.2" "8.3" "CC6.1"
    }
}

# ============================================================================
# PHASE 2: AUDIT & ACCOUNTABILITY
# ============================================================================
function Test-AuditControls {
    Write-Host "`n=== PHASE 2: AUDIT & ACCOUNTABILITY ===" -ForegroundColor Cyan
    
    # AU-2: Audit Events — check if audit policy is enabled
    $auditPolicy = auditpol /get /category:* 2>$null
    $successAudits = ($auditPolicy | Select-String "Success").Count
    $failureAudits = ($auditPolicy | Select-String "Failure").Count
    
    if ($successAudits -gt 5 -and $failureAudits -gt 5) {
        Add-Finding "NIST AU-2" "Audit policies configured" "PASS" "Success: $successAudits, Failure: $failureAudits categories" "8.2" "10.2" "CC7.2"
    } elseif ($successAudits -gt 0 -or $failureAudits -gt 0) {
        Add-Finding "NIST AU-2" "Audit policies partial" "PARTIAL" "Some categories not audited" "8.2" "10.2" "CC7.2"
    } else {
        Add-Finding "NIST AU-2" "No audit policies" "FAIL" "Auditing not configured" "8.2" "10.2" "CC7.2"
    }
    
    # AU-8: Time Stamps — check NTP configuration
    $w32tmStatus = w32tm /query /status 2>$null
    if ($w32tmStatus -match "Leap Indicator") {
        Add-Finding "NIST AU-8" "Time synchronization active" "PASS" "W32Time service operational" "8.4" "10.4" "CC7.2"
    } else {
        Add-Finding "NIST AU-8" "Time sync not verified" "PARTIAL" "W32Time service status unclear" "8.4" "10.4" "CC7.2"
    }
    
    # AU-12: Audit Generation — check Windows Event Log sizes
    $secLog = Get-WinEvent -ListLog Security 2>$null
    if ($secLog) {
        $sizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 1)
        if ($sizeMB -ge 256) {
            Add-Finding "NIST AU-12" "Security log size adequate" "PASS" "Max size: ${sizeMB}MB" "8.3" "10.7" "CC7.2"
        } else {
            Add-Finding "NIST AU-12" "Security log size small" "PARTIAL" "Max size: ${sizeMB}MB (recommend 256MB+)" "8.3" "10.7" "CC7.2"
        }
    }
}

# ============================================================================
# PHASE 3: IDENTIFICATION & AUTHENTICATION
# ============================================================================
function Test-AuthControls {
    Write-Host "`n=== PHASE 3: IDENTIFICATION & AUTHENTICATION ===" -ForegroundColor Cyan
    
    # IA-5: Password Policy
    $passInfo = net accounts 2>$null
    $minLength = ($passInfo | Select-String "Minimum password length") -replace '.*:\s+', ''
    $maxAge = ($passInfo | Select-String "Maximum password age") -replace '.*:\s+', ''
    $complexity = ($passInfo | Select-String "complexity") -replace '.*:\s+', ''
    
    if ($minLength -match "^\d+$" -and [int]$minLength -ge 12) {
        Add-Finding "NIST IA-5" "Password length adequate" "PASS" "Minimum length: $minLength" "5.2" "8.3" "CC6.1"
    } elseif ($minLength -match "^\d+$" -and [int]$minLength -ge 8) {
        Add-Finding "NIST IA-5" "Password length acceptable" "PARTIAL" "Minimum length: $minLength (recommend 12+)" "5.2" "8.3" "CC6.1"
    } else {
        Add-Finding "NIST IA-5" "Weak password length" "FAIL" "Minimum length: $minLength (must be 8+, recommend 12+)" "5.2" "8.3" "CC6.1"
    }
    
    # IA-2(1): MFA check
    $credGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard 2>$null
    if ($credGuard.SecurityServicesRunning -contains 1) {
        Add-Finding "NIST IA-2(1)" "Credential Guard active" "PASS" "Hardware-backed credential protection" "6.3" "8.4" "CC6.1"
    } else {
        Add-Finding "NIST IA-2(1)" "Credential Guard not active" "PARTIAL" "No hardware credential protection detected" "6.3" "8.4" "CC6.1"
    }
    
    # IA-5(1): Check for stored plaintext credentials
    $credFiles = @()
    $searchPaths = @("$env:USERPROFILE", "$env:ProgramData", "C:\inetpub")
    foreach ($sp in $searchPaths) {
        if (Test-Path $sp) {
            $credFiles += Get-ChildItem -Path $sp -Recurse -Include "*.config","*.ini","*.xml" -ErrorAction SilentlyContinue |
                Select-String -Pattern "password\s*=|pwd\s*=|connectionstring.*password" -List |
                Select-Object -ExpandProperty Path
        }
    }
    if ($credFiles.Count -eq 0) {
        Add-Finding "NIST IA-5(1)" "No plaintext credentials found" "PASS" "Searched config/ini/xml files" "" "8.3" "CC6.1"
    } else {
        Add-Finding "NIST IA-5(1)" "Plaintext credentials detected" "FAIL" "$($credFiles.Count) files with potential credentials" "" "8.3" "CC6.1"
    }
}

# ============================================================================
# PHASE 4: SYSTEM & COMMUNICATIONS PROTECTION
# ============================================================================
function Test-SystemProtection {
    Write-Host "`n=== PHASE 4: SYSTEM & COMMS PROTECTION ===" -ForegroundColor Cyan
    
    # SC-7: Boundary Protection — Windows Firewall
    $fwProfiles = Get-NetFirewallProfile 2>$null
    $enabledProfiles = $fwProfiles | Where-Object { $_.Enabled -eq $true }
    if ($enabledProfiles.Count -eq 3) {
        Add-Finding "NIST SC-7" "All firewall profiles enabled" "PASS" "Domain, Private, Public all active" "4.1" "1.3" "CC6.6"
    } elseif ($enabledProfiles.Count -gt 0) {
        Add-Finding "NIST SC-7" "Partial firewall coverage" "PARTIAL" "$($enabledProfiles.Count)/3 profiles enabled" "4.1" "1.3" "CC6.6"
    } else {
        Add-Finding "NIST SC-7" "Firewall DISABLED" "FAIL" "No firewall profiles enabled" "4.1" "1.3" "CC6.6"
    }
    
    # SC-8: Transmission Confidentiality — TLS configuration
    $tls12 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" 2>$null
    $tls13 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" 2>$null
    
    if ($tls12.Enabled -ne 0 -or $tls13) {
        Add-Finding "NIST SC-8" "TLS 1.2+ available" "PASS" "Modern TLS protocols enabled" "3.10" "4.2" "CC6.6"
    } else {
        Add-Finding "NIST SC-8" "TLS configuration unclear" "PARTIAL" "Verify TLS 1.2+ is enforced" "3.10" "4.2" "CC6.6"
    }
    
    # SC-13: Cryptographic Protection — BitLocker
    $bitlocker = Get-BitLockerVolume -MountPoint "C:" 2>$null
    if ($bitlocker.ProtectionStatus -eq "On") {
        Add-Finding "NIST SC-13" "BitLocker encryption active" "PASS" "C: drive encrypted with $($bitlocker.EncryptionMethod)" "" "3.4" "CC6.6"
    } else {
        Add-Finding "NIST SC-13" "Disk encryption not active" "FAIL" "BitLocker not enabled on C:" "" "3.4" "CC6.6"
    }
    
    # SC-28: Protection of Information at Rest
    $openShares = net share 2>$null | Where-Object { $_ -match "^\w.*\s+\w:\\" }
    if ($openShares.Count -le 2) {
        Add-Finding "NIST SC-28" "Minimal network shares" "PASS" "$($openShares.Count) shares detected" "" "" "CC6.6"
    } else {
        Add-Finding "NIST SC-28" "Multiple network shares" "PARTIAL" "$($openShares.Count) shares - review access controls" "" "" "CC6.6"
    }
}

# ============================================================================
# PHASE 5: SYSTEM & INFORMATION INTEGRITY
# ============================================================================
function Test-SystemIntegrity {
    Write-Host "`n=== PHASE 5: SYSTEM & INFO INTEGRITY ===" -ForegroundColor Cyan
    
    # SI-2: Flaw Remediation — check for pending updates
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $searcher = $updateSession.CreateUpdateSearcher()
        $pending = $searcher.Search("IsInstalled=0").Updates.Count
        if ($pending -eq 0) {
            Add-Finding "NIST SI-2" "System fully patched" "PASS" "No pending updates" "7.1" "6.3" "CC7.1"
        } elseif ($pending -le 5) {
            Add-Finding "NIST SI-2" "Minor updates pending" "PARTIAL" "$pending updates available" "7.1" "6.3" "CC7.1"
        } else {
            Add-Finding "NIST SI-2" "Significant updates pending" "FAIL" "$pending updates not installed" "7.1" "6.3" "CC7.1"
        }
    } catch {
        Add-Finding "NIST SI-2" "Update status unknown" "PARTIAL" "Could not query Windows Update" "7.1" "6.3" "CC7.1"
    }
    
    # SI-3: Malicious Code Protection — Antivirus status
    $avStatus = Get-MpComputerStatus 2>$null
    if ($avStatus) {
        if ($avStatus.RealTimeProtectionEnabled) {
            Add-Finding "NIST SI-3" "Real-time AV protection active" "PASS" "Defender RTP enabled, sigs: $($avStatus.AntivirusSignatureVersion)" "10.1" "5.1" "CC7.1"
        } else {
            Add-Finding "NIST SI-3" "Real-time AV DISABLED" "FAIL" "Windows Defender RTP is off" "10.1" "5.1" "CC7.1"
        }
        
        # Signature freshness
        $sigAge = (Get-Date) - $avStatus.AntivirusSignatureLastUpdated
        if ($sigAge.TotalDays -le 1) {
            Add-Finding "NIST SI-3" "AV signatures current" "PASS" "Updated $([int]$sigAge.TotalHours) hours ago" "" "5.1" ""
        } elseif ($sigAge.TotalDays -le 7) {
            Add-Finding "NIST SI-3" "AV signatures aging" "PARTIAL" "Updated $([int]$sigAge.TotalDays) days ago" "" "5.1" ""
        } else {
            Add-Finding "NIST SI-3" "AV signatures STALE" "FAIL" "Updated $([int]$sigAge.TotalDays) days ago" "" "5.1" ""
        }
    }
    
    # SI-4: System Monitoring — Sysmon presence
    $sysmon = Get-Service Sysmon* 2>$null
    if ($sysmon -and $sysmon.Status -eq "Running") {
        Add-Finding "NIST SI-4" "Sysmon monitoring active" "PASS" "Enhanced system monitoring in place" "8.5" "10.6" "CC7.2"
    } else {
        Add-Finding "NIST SI-4" "No enhanced monitoring" "PARTIAL" "Sysmon not detected - recommend deployment" "8.5" "10.6" "CC7.2"
    }
}

# ============================================================================
# PHASE 6: CONFIGURATION MANAGEMENT
# ============================================================================
function Test-ConfigManagement {
    Write-Host "`n=== PHASE 6: CONFIGURATION MANAGEMENT ===" -ForegroundColor Cyan
    
    # CM-6: Configuration Settings — PowerShell execution policy
    $execPolicy = Get-ExecutionPolicy
    if ($execPolicy -eq "Restricted" -or $execPolicy -eq "AllSigned") {
        Add-Finding "NIST CM-6" "PowerShell execution restricted" "PASS" "Policy: $execPolicy" "4.2" "2.2" "CC6.1"
    } elseif ($execPolicy -eq "RemoteSigned") {
        Add-Finding "NIST CM-6" "PowerShell partially restricted" "PARTIAL" "Policy: $execPolicy" "4.2" "2.2" "CC6.1"
    } else {
        Add-Finding "NIST CM-6" "PowerShell execution UNRESTRICTED" "FAIL" "Policy: $execPolicy" "4.2" "2.2" "CC6.1"
    }
    
    # CM-7: Least Functionality — unnecessary services
    $riskyServices = @("SNMP", "Telnet", "RemoteRegistry", "SSDPSRV", "upnphost")
    $runningRisky = @()
    foreach ($svc in $riskyServices) {
        $s = Get-Service $svc 2>$null
        if ($s -and $s.Status -eq "Running") {
            $runningRisky += $svc
        }
    }
    if ($runningRisky.Count -eq 0) {
        Add-Finding "NIST CM-7" "No unnecessary services running" "PASS" "Checked: $($riskyServices -join ', ')" "4.1" "2.2" "CC6.6"
    } else {
        Add-Finding "NIST CM-7" "Unnecessary services detected" "FAIL" "Running: $($runningRisky -join ', ')" "4.1" "2.2" "CC6.6"
    }
    
    # CM-11: User-Installed Software — check for unauthorized software
    $installedApps = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>$null |
        Where-Object { $_.DisplayName } | Select-Object DisplayName
    Add-Finding "NIST CM-11" "Software inventory collected" "PASS" "$($installedApps.Count) applications installed" "2.1" "2.4" "CC6.8"
}

# ============================================================================
# PHASE 7: RISK ASSESSMENT
# ============================================================================
function Test-RiskAssessment {
    Write-Host "`n=== PHASE 7: RISK ASSESSMENT ===" -ForegroundColor Cyan
    
    # RA-5: Vulnerability Scanning — check for common misconfigs
    
    # SMBv1 check
    $smbv1 = Get-SmbServerConfiguration 2>$null | Select-Object EnableSMB1Protocol
    if ($smbv1.EnableSMB1Protocol -eq $false) {
        Add-Finding "NIST RA-5" "SMBv1 disabled" "PASS" "Legacy SMB protocol disabled" "4.1" "2.2" "CC7.1"
    } else {
        Add-Finding "NIST RA-5" "SMBv1 ENABLED" "FAIL" "EternalBlue-class vulnerability present" "4.1" "2.2" "CC7.1"
    }
    
    # RDP check
    $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections 2>$null
    if ($rdp.fDenyTSConnections -eq 1) {
        Add-Finding "NIST RA-5" "RDP disabled" "PASS" "Remote Desktop is disabled" "" "2.2" ""
    } else {
        # Check NLA
        $nla = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication 2>$null
        if ($nla.UserAuthentication -eq 1) {
            Add-Finding "NIST RA-5" "RDP with NLA" "PARTIAL" "RDP enabled but NLA required" "" "2.2" ""
        } else {
            Add-Finding "NIST RA-5" "RDP without NLA" "FAIL" "RDP enabled without Network Level Authentication" "" "2.2" ""
        }
    }
    
    # AutoRun check
    $autorun = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun 2>$null
    if ($autorun.NoDriveTypeAutoRun -eq 255) {
        Add-Finding "NIST RA-5" "AutoRun disabled" "PASS" "AutoRun disabled for all drives" "" "" ""
    } else {
        Add-Finding "NIST RA-5" "AutoRun may be enabled" "PARTIAL" "Review AutoRun policy" "" "" ""
    }
}

# ============================================================================
# PHASE 8: REPORT GENERATION
# ============================================================================
function Write-ComplianceReport {
    param([string]$OutputDir = "$env:TEMP\compliance_report")
    
    Write-Host "`n=== PHASE 8: REPORT GENERATION ===" -ForegroundColor Cyan
    
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    $total = $Global:COMP_FINDINGS.Count
    $pass = ($Global:COMP_FINDINGS | Where-Object { $_.Status -eq "PASS" }).Count
    $fail = ($Global:COMP_FINDINGS | Where-Object { $_.Status -eq "FAIL" }).Count
    $partial = ($Global:COMP_FINDINGS | Where-Object { $_.Status -eq "PARTIAL" }).Count
    $score = if ($total -gt 0) { [math]::Round(($pass / $total) * 100, 1) } else { 0 }
    
    # ── Text Report ──
    $report = @"
================================================================================
 FLLC COMPLIANCE SCAN REPORT v$SCAN_VERSION
 Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
 Host: $env:COMPUTERNAME
 User: $env:USERNAME
================================================================================

 SCORE: $score% ($pass PASS / $fail FAIL / $partial PARTIAL / $total TOTAL)

================================================================================
 FINDINGS DETAIL
================================================================================

"@
    
    foreach ($f in $Global:COMP_FINDINGS) {
        $icon = switch ($f.Status) { "PASS" {"[PASS]"} "FAIL" {"[FAIL]"} "PARTIAL" {"[WARN]"} }
        $controls = @($f.Control)
        if ($f.CIS) { $controls += "CIS $($f.CIS)" }
        if ($f.PCI) { $controls += "PCI $($f.PCI)" }
        if ($f.SOC2) { $controls += "SOC2 $($f.SOC2)" }
        
        $report += @"
$icon $($f.Title)
  Controls: $($controls -join " | ")
  Details:  $($f.Details)
  Time:     $($f.Timestamp)

"@
    }
    
    $report += @"
================================================================================
 REMEDIATION PRIORITY
================================================================================

"@
    $failFindings = $Global:COMP_FINDINGS | Where-Object { $_.Status -eq "FAIL" }
    $idx = 1
    foreach ($f in $failFindings) {
        $report += "  $idx. $($f.Title) [$($f.Control)]`n"
        $idx++
    }
    
    $report += "`n================================================================================`n FLLC 2026 - FU PERSON by PERSON FU`n================================================================================"
    
    $reportPath = Join-Path $OutputDir "compliance_report.txt"
    $report | Out-File -FilePath $reportPath -Encoding utf8
    
    # ── JSON Report ──
    $jsonReport = @{
        version    = $SCAN_VERSION
        generated  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        host       = $env:COMPUTERNAME
        score      = $score
        summary    = @{ pass = $pass; fail = $fail; partial = $partial; total = $total }
        findings   = $Global:COMP_FINDINGS
    } | ConvertTo-Json -Depth 5
    
    $jsonPath = Join-Path $OutputDir "compliance_report.json"
    $jsonReport | Out-File -FilePath $jsonPath -Encoding utf8
    
    # ── CSV Report ──
    $csvPath = Join-Path $OutputDir "compliance_findings.csv"
    $Global:COMP_FINDINGS | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    
    Write-Host "`nCompliance Score: $score%" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
    Write-Host "Reports saved to: $OutputDir" -ForegroundColor Gray
    Write-Host "  - compliance_report.txt"
    Write-Host "  - compliance_report.json"
    Write-Host "  - compliance_findings.csv"
    
    return @{
        Score     = $score
        Pass      = $pass
        Fail      = $fail
        Partial   = $partial
        Total     = $total
        OutputDir = $OutputDir
    }
}

# ============================================================================
# MASTER ENTRY POINT
# ============================================================================
function Start-ComplianceScan {
    param(
        [string]$OutputDir = "$env:TEMP\compliance_report"
    )
    
    Write-Host @"

 ====================================================
  FLLC COMPLIANCE SCANNER v$SCAN_VERSION
  NIST 800-53 | CIS v8 | PCI-DSS 4.0 | SOC 2
 ====================================================
  Host: $env:COMPUTERNAME
  Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
 ====================================================

"@ -ForegroundColor Cyan
    
    $Global:COMP_FINDINGS = @()
    
    Test-AccessControls
    Test-AuditControls
    Test-AuthControls
    Test-SystemProtection
    Test-SystemIntegrity
    Test-ConfigManagement
    Test-RiskAssessment
    
    $result = Write-ComplianceReport -OutputDir $OutputDir
    return $result
}

# Auto-run if executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Start-ComplianceScan
}
