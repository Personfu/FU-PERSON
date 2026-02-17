<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | OSINT LOOKUP v2.0
   ╔══════════════════════════════════════════════════════════════════╗
   ║  Pure PowerShell. Zero dependencies. Runs from USB.              ║
   ║  People search, reverse phone/email, public records, social      ║
   ║  media enumeration — all using native Windows HTTP and DNS.      ║
   ║  88+ platform coverage | Breach DB links | Social media sweep    ║
   ╚══════════════════════════════════════════════════════════════════╝
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ── HTTP helper (no dependencies) ──
function Web-Request {
    param([string]$Url, [hashtable]$Headers = @{})
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Timeout = 10000
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        foreach ($h in $Headers.GetEnumerator()) { $req.Headers.Add($h.Key, $h.Value) }
        $resp = $req.GetResponse()
        $stream = $resp.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $body = $reader.ReadToEnd()
        $reader.Close(); $stream.Close(); $resp.Close()
        return $body
    } catch {
        return $null
    }
}

# ── DNS lookup helper ──
function Resolve-Host {
    param([string]$Name)
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Name)
        return ($addrs | ForEach-Object { $_.IPAddressToString })
    } catch { return @() }
}

function Resolve-Reverse {
    param([string]$IP)
    try {
        $entry = [System.Net.Dns]::GetHostEntry($IP)
        return $entry.HostName
    } catch { return "(no reverse DNS)" }
}

# ══════════════════════════════════════════════════════════════════════
# PERSON LOOKUP
# ══════════════════════════════════════════════════════════════════════

function Search-Person {
    param(
        [string]$FirstName,
        [string]$LastName,
        [string]$City = "",
        [string]$State = ""
    )
    
    $results = @()
    $query = "$FirstName $LastName"
    if ($City) { $query += " $City" }
    if ($State) { $query += " $State" }
    $encoded = [System.Uri]::EscapeDataString($query)
    
    Write-Host "`n  [*] Searching for: $query" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor DarkGray
    
    # ── People search engines ──
    $peopleSearchSites = @(
        @{ Name = "WhitePages"; Url = "https://www.whitepages.com/name/$FirstName-$LastName$(if($City){"/$City"})$(if($State){"/$State"})" },
        @{ Name = "TruePeopleSearch"; Url = "https://www.truepeoplesearch.com/results?name=$encoded" },
        @{ Name = "FastPeopleSearch"; Url = "https://www.fastpeoplesearch.com/name/$($FirstName.ToLower())-$($LastName.ToLower())$(if($City){"_$($City.ToLower().Replace(' ','-'))"})" },
        @{ Name = "ThatsThem"; Url = "https://thatsthem.com/name/$FirstName-$LastName$(if($City){"/$City"})$(if($State){"/$State"})" },
        @{ Name = "Spokeo"; Url = "https://www.spokeo.com/$FirstName-$LastName$(if($State){"?l=$State"})" },
        @{ Name = "BeenVerified"; Url = "https://www.beenverified.com/people/$FirstName-$LastName/" },
        @{ Name = "Intelius"; Url = "https://www.intelius.com/people-search/$FirstName-$LastName/" },
        @{ Name = "USSearch"; Url = "https://www.ussearch.com/search/results?fn=$FirstName&ln=$LastName" },
        @{ Name = "PeopleFinder"; Url = "https://www.peoplefinder.com/people/$FirstName-$LastName/" },
        @{ Name = "ZabaSearch"; Url = "https://www.zabasearch.com/people/$FirstName+$LastName/" },
        @{ Name = "Radaris"; Url = "https://radaris.com/p/$FirstName/$LastName/" },
        @{ Name = "CyberBackgroundChecks"; Url = "https://www.cyberbackgroundchecks.com/people/$FirstName-$LastName" }
    )
    
    Write-Host "`n  [PEOPLE SEARCH ENGINES]" -ForegroundColor Yellow
    foreach ($site in $peopleSearchSites) {
        $body = Web-Request -Url $site.Url
        $found = $false
        if ($body) {
            # Check if the page has actual person results vs "no results"
            if ($body -match $LastName -and $body -notmatch "no results|not found|0 results|no records") {
                $found = $true
            }
        }
        $status = if ($found) { "[HIT]" } else { "[---]" }
        $color = if ($found) { "Green" } else { "DarkGray" }
        Write-Host "    $status $($site.Name): $($site.Url)" -ForegroundColor $color
        $results += [PSCustomObject]@{
            Category = "People Search"
            Source   = $site.Name
            URL      = $site.Url
            Hit      = $found
        }
        Start-Sleep -Milliseconds (Get-Random -Min 300 -Max 800)
    }
    
    # ── Social media username guesses ──
    $usernames = @(
        "$FirstName$LastName",
        "$($FirstName.ToLower())$($LastName.ToLower())",
        "$($FirstName[0])$LastName",
        "$($FirstName.ToLower()).$($LastName.ToLower())",
        "$($FirstName.ToLower())_$($LastName.ToLower())",
        "$($LastName.ToLower())$($FirstName[0].ToString().ToLower())",
        "$($FirstName.ToLower())$($LastName.ToLower())1"
    )
    
    $socialPlatforms = @(
        @{ Name = "Twitter/X"; Pattern = "https://x.com/{0}" },
        @{ Name = "Instagram"; Pattern = "https://www.instagram.com/{0}/" },
        @{ Name = "Facebook"; Pattern = "https://www.facebook.com/{0}" },
        @{ Name = "LinkedIn"; Pattern = "https://www.linkedin.com/in/{0}" },
        @{ Name = "GitHub"; Pattern = "https://github.com/{0}" },
        @{ Name = "Reddit"; Pattern = "https://www.reddit.com/user/{0}" },
        @{ Name = "TikTok"; Pattern = "https://www.tiktok.com/@{0}" },
        @{ Name = "Pinterest"; Pattern = "https://www.pinterest.com/{0}/" },
        @{ Name = "YouTube"; Pattern = "https://www.youtube.com/@{0}" },
        @{ Name = "Twitch"; Pattern = "https://www.twitch.tv/{0}" },
        @{ Name = "Medium"; Pattern = "https://medium.com/@{0}" },
        @{ Name = "Tumblr"; Pattern = "https://{0}.tumblr.com" },
        @{ Name = "Steam"; Pattern = "https://steamcommunity.com/id/{0}" },
        @{ Name = "Keybase"; Pattern = "https://keybase.io/{0}" }
    )
    
    Write-Host "`n  [SOCIAL MEDIA ENUMERATION]" -ForegroundColor Yellow
    foreach ($platform in $socialPlatforms) {
        foreach ($uname in ($usernames | Select-Object -First 3)) {
            $url = $platform.Pattern -f $uname
            $body = Web-Request -Url $url
            $exists = $false
            if ($body -and $body.Length -gt 1000) {
                if ($body -notmatch "Page Not Found|404|not exist|User not found|Sorry|doesn.t exist") {
                    $exists = $true
                }
            }
            if ($exists) {
                Write-Host "    [HIT] $($platform.Name): $url" -ForegroundColor Green
                $results += [PSCustomObject]@{
                    Category = "Social Media"
                    Source   = $platform.Name
                    URL      = $url
                    Hit      = $true
                }
            }
            Start-Sleep -Milliseconds (Get-Random -Min 200 -Max 600)
        }
    }
    
    # ── Public records / court records ──
    $publicRecords = @(
        @{ Name = "PACER (Federal Courts)"; Url = "https://www.pacer.gov/" },
        @{ Name = "CourtListener"; Url = "https://www.courtlistener.com/?q=%22$encoded%22&type=r" },
        @{ Name = "SEC EDGAR"; Url = "https://efts.sec.gov/LATEST/search-index?q=%22$encoded%22&dateRange=custom&startdt=2000-01-01&enddt=2026-12-31" },
        @{ Name = "FEC Donations"; Url = "https://www.fec.gov/data/receipts/individual-contributions/?contributor_name=$encoded" },
        @{ Name = "USPTO Patents"; Url = "https://patft.uspto.gov/netacgi/nph-Parser?Sect1=PTO2&Sect2=HITOFF&u=%2Fnetahtml%2FPTO%2Fsearch-adv.htm&r=0&p=1&f=S&l=50&Query=IN%2F%22$LastName%3B+$FirstName%22&d=PTXT" },
        @{ Name = "Open Corporates"; Url = "https://opencorporates.com/officers?q=$encoded&utf8=1" }
    )
    
    Write-Host "`n  [PUBLIC RECORDS]" -ForegroundColor Yellow
    foreach ($rec in $publicRecords) {
        Write-Host "    [URL] $($rec.Name): $($rec.Url)" -ForegroundColor Cyan
        $results += [PSCustomObject]@{
            Category = "Public Records"
            Source   = $rec.Name
            URL      = $rec.Url
            Hit      = $true
        }
    }
    
    # ── News / media ──
    Write-Host "`n  [NEWS & MEDIA SEARCH]" -ForegroundColor Yellow
    $newsUrls = @(
        @{ Name = "Google News"; Url = "https://news.google.com/search?q=%22$encoded%22" },
        @{ Name = "Bing News"; Url = "https://www.bing.com/news/search?q=%22$encoded%22" },
        @{ Name = "Archive.org"; Url = "https://web.archive.org/web/*/%22$encoded%22" }
    )
    foreach ($news in $newsUrls) {
        Write-Host "    [URL] $($news.Name): $($news.Url)" -ForegroundColor Cyan
        $results += [PSCustomObject]@{
            Category = "News/Media"
            Source   = $news.Name
            URL      = $news.Url
            Hit      = $true
        }
    }
    
    # ── Breach / exposure check ──
    Write-Host "`n  [BREACH DATA]" -ForegroundColor Yellow
    $breachUrls = @(
        @{ Name = "HaveIBeenPwned"; Url = "https://haveibeenpwned.com/" },
        @{ Name = "DeHashed"; Url = "https://dehashed.com/search?query=%22$encoded%22" },
        @{ Name = "IntelX"; Url = "https://intelx.io/?s=%22$encoded%22" },
        @{ Name = "LeakCheck"; Url = "https://leakcheck.io/" }
    )
    foreach ($b in $breachUrls) {
        Write-Host "    [URL] $($b.Name): $($b.Url)" -ForegroundColor Cyan
        $results += [PSCustomObject]@{
            Category = "Breach Data"
            Source   = $b.Name
            URL      = $b.Url
            Hit      = $true
        }
    }
    
    return $results
}

# ══════════════════════════════════════════════════════════════════════
# REVERSE PHONE LOOKUP
# ══════════════════════════════════════════════════════════════════════

function Search-Phone {
    param([string]$Phone)
    
    $clean = $Phone -replace '[^\d]', ''
    Write-Host "`n  [*] Reverse phone lookup: $Phone" -ForegroundColor Cyan
    
    $sites = @(
        @{ Name = "WhitePages"; Url = "https://www.whitepages.com/phone/$clean" },
        @{ Name = "TrueCaller"; Url = "https://www.truecaller.com/search/us/$clean" },
        @{ Name = "NumLookup"; Url = "https://www.numlookup.com/phone/$clean" },
        @{ Name = "SpyDialer"; Url = "https://www.spydialer.com/default.aspx" },
        @{ Name = "ThatsThem"; Url = "https://thatsthem.com/phone/$clean" },
        @{ Name = "Spokeo"; Url = "https://www.spokeo.com/phone-lookup/$clean" },
        @{ Name = "USPhoneBook"; Url = "https://www.usphonebook.com/$clean" },
        @{ Name = "CallerID"; Url = "https://www.calleridtest.com/look-up-phone-number/$clean" },
        @{ Name = "FastPeople"; Url = "https://www.fastpeoplesearch.com/$clean" }
    )
    
    foreach ($site in $sites) {
        $body = Web-Request -Url $site.Url
        $hit = $false
        if ($body -and $body -notmatch "no results|not found|0 results") { $hit = $true }
        $color = if ($hit) { "Green" } else { "DarkGray" }
        $tag = if ($hit) { "[HIT]" } else { "[---]" }
        Write-Host "    $tag $($site.Name): $($site.Url)" -ForegroundColor $color
        Start-Sleep -Milliseconds (Get-Random -Min 300 -Max 700)
    }
}

# ══════════════════════════════════════════════════════════════════════
# REVERSE EMAIL LOOKUP
# ══════════════════════════════════════════════════════════════════════

function Search-Email {
    param([string]$Email)
    
    Write-Host "`n  [*] Reverse email lookup: $Email" -ForegroundColor Cyan
    $encoded = [System.Uri]::EscapeDataString($Email)
    
    $sites = @(
        @{ Name = "Hunter.io"; Url = "https://hunter.io/email-verifier/$Email" },
        @{ Name = "EmailRep"; Url = "https://emailrep.io/$Email" },
        @{ Name = "ThatsThem"; Url = "https://thatsthem.com/email/$Email" },
        @{ Name = "Spokeo"; Url = "https://www.spokeo.com/email-search/$Email" },
        @{ Name = "Pipl"; Url = "https://pipl.com/search/?q=$encoded" },
        @{ Name = "Epieos"; Url = "https://epieos.com/?q=$Email" },
        @{ Name = "HaveIBeenPwned"; Url = "https://haveibeenpwned.com/account/$Email" },
        @{ Name = "Gravatar"; Url = "https://en.gravatar.com/site/check/$Email" }
    )
    
    foreach ($site in $sites) {
        $body = Web-Request -Url $site.Url
        $hit = $false
        if ($body -and $body.Length -gt 500 -and $body -notmatch "not found|no results") { $hit = $true }
        $color = if ($hit) { "Green" } else { "DarkGray" }
        $tag = if ($hit) { "[HIT]" } else { "[---]" }
        Write-Host "    $tag $($site.Name): $($site.Url)" -ForegroundColor $color
        Start-Sleep -Milliseconds (Get-Random -Min 300 -Max 700)
    }
    
    # Check MX record for email domain
    $domain = $Email.Split("@")[1]
    if ($domain) {
        Write-Host "`n    [DNS] MX records for $domain:" -ForegroundColor Yellow
        try {
            $mx = Resolve-DnsName $domain -Type MX -ErrorAction Stop
            $mx | ForEach-Object { Write-Host "      $($_.NameExchange) (Priority: $($_.Preference))" -ForegroundColor Gray }
        } catch {
            Write-Host "      (MX lookup failed)" -ForegroundColor DarkGray
        }
    }
}

# ══════════════════════════════════════════════════════════════════════
# DOMAIN RECON
# ══════════════════════════════════════════════════════════════════════

function Search-Domain {
    param([string]$Domain)
    
    Write-Host "`n  [*] Domain reconnaissance: $Domain" -ForegroundColor Cyan
    
    # DNS records
    Write-Host "`n  [DNS RECORDS]" -ForegroundColor Yellow
    foreach ($type in @("A","AAAA","MX","NS","TXT","CNAME","SOA")) {
        try {
            $records = Resolve-DnsName $Domain -Type $type -ErrorAction Stop
            foreach ($r in $records) {
                switch ($type) {
                    "A"     { Write-Host "    A:     $($r.IPAddress)" -ForegroundColor Green }
                    "AAAA"  { Write-Host "    AAAA:  $($r.IPAddress)" -ForegroundColor Green }
                    "MX"    { Write-Host "    MX:    $($r.NameExchange) (Pri: $($r.Preference))" -ForegroundColor Green }
                    "NS"    { Write-Host "    NS:    $($r.NameHost)" -ForegroundColor Green }
                    "TXT"   { Write-Host "    TXT:   $($r.Strings -join '')" -ForegroundColor Green }
                    "CNAME" { Write-Host "    CNAME: $($r.NameHost)" -ForegroundColor Green }
                    "SOA"   { Write-Host "    SOA:   $($r.PrimaryServer) | Admin: $($r.NameAdministrator)" -ForegroundColor Green }
                }
            }
        } catch {}
    }
    
    # Subdomains via common names
    Write-Host "`n  [SUBDOMAIN ENUMERATION]" -ForegroundColor Yellow
    $subdomains = @("www","mail","ftp","smtp","pop","imap","webmail","vpn","remote","portal",
                    "api","dev","staging","test","admin","login","sso","cdn","static","assets",
                    "app","dashboard","panel","m","mobile","ns1","ns2","dns","mx","blog",
                    "shop","store","pay","secure","auth","id","accounts","cloud","git","ci",
                    "jenkins","jira","confluence","wiki","docs","support","help","status")
    
    foreach ($sub in $subdomains) {
        $fqdn = "$sub.$Domain"
        $ips = Resolve-Host -Name $fqdn
        if ($ips) {
            Write-Host "    [FOUND] $fqdn -> $($ips -join ', ')" -ForegroundColor Green
        }
    }
    
    # OSINT URLs
    Write-Host "`n  [OSINT RESOURCES]" -ForegroundColor Yellow
    $osintUrls = @(
        "https://crt.sh/?q=%25.$Domain",
        "https://www.shodan.io/search?query=hostname%3A$Domain",
        "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=$Domain",
        "https://securitytrails.com/domain/$Domain",
        "https://dnsdumpster.com/",
        "https://www.virustotal.com/gui/domain/$Domain",
        "https://urlscan.io/search/#domain:$Domain",
        "https://web.archive.org/web/*/$Domain"
    )
    foreach ($u in $osintUrls) {
        Write-Host "    [URL] $u" -ForegroundColor Cyan
    }
}

# ══════════════════════════════════════════════════════════════════════
# IP LOOKUP
# ══════════════════════════════════════════════════════════════════════

function Search-IP {
    param([string]$IP)
    
    Write-Host "`n  [*] IP lookup: $IP" -ForegroundColor Cyan
    
    # Reverse DNS
    $hostname = Resolve-Reverse -IP $IP
    Write-Host "    Reverse DNS: $hostname" -ForegroundColor Green
    
    # GeoIP via free APIs
    $geo = Web-Request -Url "http://ip-api.com/json/$IP"
    if ($geo) {
        try {
            Add-Type -AssemblyName System.Web.Extensions 2>$null
            $json = (New-Object System.Web.Script.Serialization.JavaScriptSerializer).DeserializeObject($geo)
            Write-Host "    Country:  $($json.country)" -ForegroundColor Green
            Write-Host "    Region:   $($json.regionName)" -ForegroundColor Green
            Write-Host "    City:     $($json.city)" -ForegroundColor Green
            Write-Host "    ISP:      $($json.isp)" -ForegroundColor Green
            Write-Host "    Org:      $($json.org)" -ForegroundColor Green
            Write-Host "    AS:       $($json.as)" -ForegroundColor Green
            Write-Host "    Lat/Lon:  $($json.lat), $($json.lon)" -ForegroundColor Green
        } catch {
            Write-Host "    (raw) $geo" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n  [OSINT RESOURCES]" -ForegroundColor Yellow
    $ipUrls = @(
        "https://www.shodan.io/host/$IP",
        "https://search.censys.io/hosts/$IP",
        "https://www.abuseipdb.com/check/$IP",
        "https://www.virustotal.com/gui/ip-address/$IP",
        "https://ipinfo.io/$IP",
        "https://bgp.he.net/ip/$IP"
    )
    foreach ($u in $ipUrls) {
        Write-Host "    [URL] $u" -ForegroundColor Cyan
    }
}

# ══════════════════════════════════════════════════════════════════════
# SAVE REPORT
# ══════════════════════════════════════════════════════════════════════

function Save-Report {
    param([string]$Query, [array]$Results, [string]$OutputDir)
    
    if (-not $OutputDir) {
        # Try to save to MicroSD loot, fallback to Desktop
        $usb = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
        foreach ($d in $usb) {
            if (Test-Path "$($d.DeviceID)\.loot_target") {
                $OutputDir = "$($d.DeviceID)\osint_reports"
                break
            }
        }
        if (-not $OutputDir) { $OutputDir = "$env:USERPROFILE\Desktop\osint_reports" }
    }
    
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeName = ($Query -replace '[^\w]', '_').Substring(0, [Math]::Min(30, $Query.Length))
    $file = "$OutputDir\${safeName}_${ts}.txt"
    
    $report = "FLLC OSINT REPORT`n"
    $report += "Query: $Query`n"
    $report += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
    $report += "================================================`n`n"
    
    if ($Results) {
        $grouped = $Results | Group-Object Category
        foreach ($g in $grouped) {
            $report += "--- $($g.Name) ---`n"
            foreach ($r in $g.Group) {
                $tag = if ($r.Hit) { "[HIT]" } else { "[---]" }
                $report += "  $tag $($r.Source): $($r.URL)`n"
            }
            $report += "`n"
        }
    }
    
    $report | Out-File -FilePath $file -Encoding utf8
    Write-Host "`n  [+] Report saved: $file" -ForegroundColor Green
}

# ══════════════════════════════════════════════════════════════════════
# INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════════════

function Show-OsintMenu {
    while ($true) {
        Write-Host @"

  ================================================
   FLLC OSINT TOOLKIT v2.0
   Pure PowerShell | Zero Dependencies
  ================================================
   [1] Person Lookup (name + location)
   [2] Reverse Phone Lookup
   [3] Reverse Email Lookup
   [4] Domain Recon
   [5] IP Lookup
   [6] Exit
  ================================================
"@ -ForegroundColor Cyan
        
        $choice = Read-Host "  Select"
        
        switch ($choice) {
            "1" {
                $fn = Read-Host "  First name"
                $ln = Read-Host "  Last name"
                $city = Read-Host "  City (or Enter to skip)"
                $state = Read-Host "  State (or Enter to skip)"
                $results = Search-Person -FirstName $fn -LastName $ln -City $city -State $state
                Save-Report -Query "$fn $ln $city $state" -Results $results
            }
            "2" {
                $phone = Read-Host "  Phone number"
                Search-Phone -Phone $phone
            }
            "3" {
                $email = Read-Host "  Email address"
                Search-Email -Email $email
            }
            "4" {
                $domain = Read-Host "  Domain (e.g. example.com)"
                Search-Domain -Domain $domain
            }
            "5" {
                $ip = Read-Host "  IP address"
                Search-IP -IP $ip
            }
            "6" { return }
            default { Write-Host "  Invalid selection" -ForegroundColor Red }
        }
    }
}

# Auto-launch menu if run directly
if ($MyInvocation.InvocationName -ne '.') {
    Show-OsintMenu
}
