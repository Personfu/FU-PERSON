#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: OSINT RECON SUITE v2.0
  Domain / IP / Network Reconnaissance
  DNS | Subdomains | WHOIS | GeoIP | Port Scan | Threat Intel Links
===============================================================================
"""

import os
import sys
import json
import time
import re
import socket
import struct
import argparse
import textwrap
import asyncio
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import warnings

warnings.filterwarnings("ignore")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=False)
except ImportError:
    pass


# =============================================================================
#  ANSI COLORS & DISPLAY
# =============================================================================

class C:
    R   = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    UND = "\033[4m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"

    @staticmethod
    def p(text: str):
        try:
            print(text)
        except UnicodeEncodeError:
            print(re.sub(r"\033\[[0-9;]*m", "", str(text)))

    @staticmethod
    def section(title: str):
        w = 70
        C.p(f"\n  {C.CYN}{C.BLD}{'=' * w}")
        C.p(f"  {'':>2}{title}")
        C.p(f"  {'=' * w}{C.R}")

    @staticmethod
    def ok(msg: str):
        C.p(f"  {C.GRN}[+]{C.R} {msg}")

    @staticmethod
    def info(msg: str):
        C.p(f"  {C.CYN}[*]{C.R} {msg}")

    @staticmethod
    def warn(msg: str):
        C.p(f"  {C.YLW}[!]{C.R} {msg}")

    @staticmethod
    def fail(msg: str):
        C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def progress(current: int, total: int, label: str = ""):
        pct = current / max(total, 1)
        filled = int(30 * pct)
        bar = f"{C.GRN}{'█' * filled}{C.DIM}{'░' * (30 - filled)}{C.R}"
        sys.stdout.write(f"\r  {bar} {C.CYN}{current}/{total}{C.R} {label}  ")
        sys.stdout.flush()
        if current >= total:
            print()


BANNER = rf"""
{C.CYN}{C.BLD}
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.R}{C.GRN}    ──────────────── OSINT RECON SUITE v2.0 ────────────────────────────{C.R}
{C.DIM}    FLLC  |  Legal OSINT Only  |  Network Reconnaissance{C.R}
"""

DISCLAIMER = f"""{C.YLW}{C.BLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│  LEGAL DISCLAIMER                                                            │
│  This tool performs passive reconnaissance using ONLY public data sources.    │
│  DNS lookups, WHOIS queries, and port scans to YOUR OWN infrastructure or    │
│  with EXPLICIT AUTHORIZATION only. Users must comply with all applicable      │
│  laws. The developers assume NO liability for misuse.                        │
└──────────────────────────────────────────────────────────────────────────────┘{C.R}
"""


# =============================================================================
#  TOP 100 PORTS
# =============================================================================

TOP_100_PORTS = [
    21, 22, 23, 25, 26, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139,
    143, 161, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4443, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 5901, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
    8443, 8888, 9090, 9100, 9200, 9999, 10000, 11211, 27017, 27018,
    32768, 49152, 49153, 49154,
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "Submission", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
    3000: "Dev/Grafana", 3306: "MySQL", 3389: "RDP",
    4443: "HTTPS-Alt", 5000: "UPnP/Dev", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "WebConsole",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "test", "dev", "staging", "prod",
    "api", "api2", "api3", "v1", "v2", "portal", "vpn", "remote",
    "cloud", "app", "mobile", "m", "secure", "ssl", "webmail", "email",
    "smtp", "pop", "imap", "ns1", "ns2", "dns", "cdn", "static",
    "assets", "media", "images", "img", "blog", "news", "forum", "shop",
    "store", "cart", "checkout", "payment", "account", "login", "auth",
    "dashboard", "panel", "sysadmin", "db", "database", "mysql",
    "postgres", "mongo", "redis", "backup", "archive", "old", "legacy",
    "internal", "intranet", "private", "monitor", "status", "health",
    "metrics", "git", "svn", "jenkins", "ci", "build", "deploy",
    "grafana", "kibana", "elastic", "prometheus", "docker", "k8s",
    "registry", "jira", "confluence", "gitlab", "vault", "config",
    "sso", "oauth", "ldap", "exchange", "owa", "autodiscover",
    "sharepoint", "sandbox", "demo", "beta", "web", "www2", "mx",
    "sftp", "ssh", "rdp", "telnet", "ntp", "snmp", "syslog",
    "waf", "firewall", "dmz", "mgmt", "management", "pki", "cert",
    "data", "analytics", "ml", "ai", "billing", "invoice",
    "crm", "erp", "hr", "marketing", "sales", "docs", "wiki",
    "help", "support", "ticket", "jira", "slack", "teams",
    "proxy", "gateway", "lb", "edge", "node", "worker",
    "staging2", "uat", "preprod", "qa", "release", "canary",
]


# =============================================================================
#  DNS ENUMERATOR
# =============================================================================

class DNSEnumerator:
    """Enumerate DNS records for a domain."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]

    def __init__(self, domain: str, nameserver: str = None):
        self.domain = domain
        self.resolver = dns.resolver.Resolver() if HAS_DNS else None
        if self.resolver and nameserver:
            self.resolver.nameservers = [nameserver]
        if self.resolver:
            self.resolver.timeout = 5
            self.resolver.lifetime = 10

    def enumerate_all(self) -> Dict[str, list]:
        """Query all DNS record types for the domain."""
        if not self.resolver:
            C.warn("dnspython not installed. pip install dnspython")
            return {}

        results = {}
        C.section("DNS ENUMERATION")
        C.info(f"Target domain: {C.BLD}{self.domain}{C.R}")
        C.p("")

        for rtype in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                records = []
                for rdata in answers:
                    record_str = str(rdata)
                    records.append(record_str)
                results[rtype] = records
                for rec in records:
                    C.ok(f"{C.GRN}{rtype:>6}{C.R}  {rec}")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                C.fail(f"Domain {self.domain} does not exist (NXDOMAIN)")
                break
            except dns.resolver.NoNameservers:
                C.warn(f"No nameservers for {rtype}")
            except Exception:
                pass

        if not results:
            C.warn("No DNS records found")
        else:
            C.p(f"\n  {C.GRN}[+] Found {sum(len(v) for v in results.values())} records across {len(results)} types{C.R}")

        return results

    def resolve_ip(self) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            if self.resolver:
                answers = self.resolver.resolve(self.domain, "A")
                return str(answers[0])
            else:
                return socket.gethostbyname(self.domain)
        except Exception:
            return None

    def reverse_dns(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            if HAS_DNS:
                rev = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev, "PTR")
                return str(answers[0])
            else:
                return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None


# =============================================================================
#  SUBDOMAIN BRUTE-FORCER
# =============================================================================

class SubdomainBruteForcer:
    """Brute-force subdomains using a wordlist."""

    def __init__(self, domain: str, wordlist: List[str] = None, max_workers: int = 20):
        self.domain = domain
        self.wordlist = wordlist or SUBDOMAIN_WORDLIST
        self.max_workers = max_workers
        self.found: List[Tuple[str, str]] = []

    def check_subdomain(self, sub: str) -> Optional[Tuple[str, str]]:
        fqdn = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except (socket.gaierror, socket.herror):
            return None
        except Exception:
            return None

    def run(self) -> List[Tuple[str, str]]:
        C.section("SUBDOMAIN ENUMERATION")
        C.info(f"Brute-forcing {len(self.wordlist)} subdomains for {C.BLD}{self.domain}{C.R}")
        C.p("")

        self.found = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.check_subdomain, sub): sub for sub in self.wordlist}
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result:
                    self.found.append(result)
                    C.ok(f"{C.GRN}{result[0]:<45}{C.R} -> {C.CYN}{result[1]}{C.R}")
                C.progress(i + 1, len(self.wordlist), "subdomains")

        C.p(f"\n  {C.GRN}[+] Found {C.BLD}{len(self.found)}{C.R}{C.GRN} live subdomains{C.R}")
        return self.found


# =============================================================================
#  WHOIS LOOKUP (socket-based, no external lib needed)
# =============================================================================

class WHOISLookup:
    """WHOIS lookup using raw socket connections to whois servers."""

    WHOIS_SERVERS = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "us": "whois.nic.us",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "default": "whois.iana.org",
    }

    def query(self, domain: str) -> Dict[str, str]:
        C.section("WHOIS LOOKUP")
        C.info(f"Querying WHOIS for: {C.BLD}{domain}{C.R}")
        C.p("")

        tld = domain.rsplit(".", 1)[-1].lower()
        server = self.WHOIS_SERVERS.get(tld, self.WHOIS_SERVERS["default"])

        raw = self._raw_query(domain, server)
        if not raw:
            C.fail("WHOIS query returned no data")
            return {}

        parsed = self._parse(raw)

        for key, val in parsed.items():
            C.ok(f"{C.WHT}{key:<25}{C.R} {val}")

        return parsed

    def _raw_query(self, domain: str, server: str, port: int = 43) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))
            sock.sendall((domain + "\r\n").encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            return response.decode("utf-8", errors="replace")
        except Exception as e:
            C.fail(f"WHOIS connection error: {e}")
            return ""

    def _parse(self, raw: str) -> Dict[str, str]:
        parsed = {"_raw": raw}
        patterns = {
            "Registrar": r"Registrar:\s*(.+)",
            "Creation Date": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
            "Expiration Date": r"Expir(?:ation|y)\s*Date:\s*(.+)",
            "Updated Date": r"Updated?\s*Date:\s*(.+)",
            "Name Servers": r"Name\s*Server:\s*(.+)",
            "Status": r"Status:\s*(.+)",
            "Registrant Org": r"Registrant\s*Organi[sz]ation:\s*(.+)",
            "Registrant Country": r"Registrant\s*Country:\s*(.+)",
            "DNSSEC": r"DNSSEC:\s*(.+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if matches:
                if key == "Name Servers":
                    parsed[key] = ", ".join(m.strip().lower() for m in matches[:4])
                elif key == "Status":
                    parsed[key] = ", ".join(m.strip().split()[0] for m in matches[:3])
                else:
                    parsed[key] = matches[0].strip()
        return parsed


# =============================================================================
#  GEOIP LOOKUP (uses free ip-api.com)
# =============================================================================

class GeoIPLookup:
    """GeoIP lookup using free public APIs."""

    API_URL = "http://ip-api.com/json/{ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"

    def lookup(self, ip: str) -> Dict:
        C.section("GEOIP LOOKUP")
        C.info(f"Looking up: {C.BLD}{ip}{C.R}")
        C.p("")

        if not HAS_REQUESTS:
            C.warn("requests library required for GeoIP. pip install requests")
            return {}

        try:
            resp = requests.get(self.API_URL.format(ip=ip), timeout=10)
            data = resp.json()
            if data.get("status") == "success":
                display_fields = [
                    ("IP", "query"), ("Country", "country"), ("Region", "regionName"),
                    ("City", "city"), ("ZIP", "zip"), ("Latitude", "lat"),
                    ("Longitude", "lon"), ("Timezone", "timezone"), ("ISP", "isp"),
                    ("Organization", "org"), ("AS Number", "as"), ("AS Name", "asname"),
                    ("Reverse DNS", "reverse"), ("Continent", "continent"),
                ]
                for label, key in display_fields:
                    val = data.get(key, "N/A")
                    if val:
                        C.ok(f"{C.WHT}{label:<18}{C.R} {val}")
                return data
            else:
                C.fail(f"GeoIP lookup failed: {data.get('message', 'unknown')}")
                return {}
        except Exception as e:
            C.fail(f"GeoIP error: {e}")
            return {}


# =============================================================================
#  ASYNC PORT SCANNER
# =============================================================================

class PortScanner:
    """Async TCP port scanner for top 100 ports."""

    def __init__(self, target: str, ports: List[int] = None, timeout: float = 1.5, max_concurrent: int = 50):
        self.target = target
        self.ports = ports or TOP_100_PORTS
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.open_ports: List[Dict] = []

    async def _scan_port(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                service = PORT_SERVICES.get(port, "unknown")
                return {"port": port, "state": "open", "service": service}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def _scan_all(self, ip: str) -> List[Dict]:
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._scan_port(ip, port, semaphore) for port in self.ports]
        results = []
        total = len(tasks)
        completed = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            if completed % 10 == 0 or completed == total:
                C.progress(completed, total, "ports scanned")
            if result:
                results.append(result)
        return sorted(results, key=lambda x: x["port"])

    def scan(self) -> List[Dict]:
        C.section("PORT SCAN (Top 100)")
        C.info(f"Scanning: {C.BLD}{self.target}{C.R} ({len(self.ports)} ports)")
        C.p("")

        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            C.fail(f"Cannot resolve {self.target}")
            return []

        if ip != self.target:
            C.info(f"Resolved to: {ip}")

        start = time.time()

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.open_ports = loop.run_until_complete(self._scan_all(ip))
            loop.close()
        except Exception as e:
            C.fail(f"Port scan error: {e}")
            return []

        elapsed = time.time() - start

        C.p("")
        if self.open_ports:
            C.p(f"  {C.GRN}{'PORT':<10} {'STATE':<10} {'SERVICE':<20}{C.R}")
            C.p(f"  {C.DIM}{'─' * 40}{C.R}")
            for p in self.open_ports:
                C.p(f"  {C.GRN}{p['port']:<10}{C.R} {C.CYN}{p['state']:<10}{C.R} {p['service']}")
        else:
            C.warn("No open ports found")

        C.p(f"\n  {C.GRN}[+] Scan complete: {len(self.open_ports)} open ports found in {elapsed:.1f}s{C.R}")
        return self.open_ports


# =============================================================================
#  THREAT INTEL LINK GENERATOR
# =============================================================================

class ThreatIntelLinks:
    """Generate links to Shodan, Censys, AbuseIPDB, etc."""

    @staticmethod
    def generate(target: str, ip: str = None) -> Dict[str, str]:
        C.section("THREAT INTELLIGENCE LINKS")
        C.info(f"Generating third-party recon links for: {C.BLD}{target}{C.R}")
        C.p("")

        links = {}

        if ip:
            links["Shodan IP"] = f"https://www.shodan.io/host/{ip}"
            links["Censys IP"] = f"https://search.censys.io/hosts/{ip}"
            links["AbuseIPDB"] = f"https://www.abuseipdb.com/check/{ip}"
            links["VirusTotal IP"] = f"https://www.virustotal.com/gui/ip-address/{ip}"
            links["GreyNoise"] = f"https://viz.greynoise.io/ip/{ip}"
            links["IPInfo"] = f"https://ipinfo.io/{ip}"
            links["IP2Location"] = f"https://www.ip2location.com/demo/{ip}"

        encoded = urllib.parse.quote(target)
        links["Shodan Search"] = f"https://www.shodan.io/search?query={encoded}"
        links["Censys Search"] = f"https://search.censys.io/search?resource=hosts&q={encoded}"
        links["crt.sh (SSL Certs)"] = f"https://crt.sh/?q=%.{target}"
        links["SecurityTrails"] = f"https://securitytrails.com/domain/{target}/dns"
        links["DNSDumpster"] = f"https://dnsdumpster.com/"
        links["VirusTotal Domain"] = f"https://www.virustotal.com/gui/domain/{target}"
        links["URLScan.io"] = f"https://urlscan.io/search/#{target}"
        links["Wayback Machine"] = f"https://web.archive.org/web/*/{target}"
        links["BuiltWith"] = f"https://builtwith.com/{target}"
        links["Netcraft"] = f"https://sitereport.netcraft.com/?url={target}"
        links["ViewDNS.info"] = f"https://viewdns.info/whois/?domain={target}"
        links["MXToolbox"] = f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{target}&run=toolpage"
        links["SpiderFoot HX"] = f"https://hx.spiderfoot.net/search?q={encoded}"

        for name, url in links.items():
            C.ok(f"{C.WHT}{name:<25}{C.R} {C.DIM}{url}{C.R}")

        return links


# =============================================================================
#  OSINT RECON ENGINE (ORCHESTRATOR)
# =============================================================================

class OSINTReconEngine:
    """Main orchestrator that runs all recon modules."""

    def __init__(self, target: str, output_dir: str = "fu_recon_output"):
        self.target = target
        self.output_dir = output_dir
        self.ip = None
        self.results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tool": "FU PERSON :: OSINT Recon Suite v2.0",
            "dns": {},
            "subdomains": [],
            "whois": {},
            "geoip": {},
            "ports": [],
            "threat_intel_links": {},
            "reverse_dns": None,
        }

    def run_all(self, skip_ports: bool = False, skip_subdomains: bool = False,
                wordlist_file: str = None, nameserver: str = None):
        """Execute the full recon pipeline."""

        dns_enum = DNSEnumerator(self.target, nameserver=nameserver)

        self.ip = dns_enum.resolve_ip()
        if self.ip:
            C.info(f"Resolved {self.target} -> {C.BLD}{self.ip}{C.R}")
            self.results["ip"] = self.ip

            rev = dns_enum.reverse_dns(self.ip)
            if rev:
                C.ok(f"Reverse DNS: {rev}")
                self.results["reverse_dns"] = rev
        else:
            C.warn(f"Could not resolve {self.target} - may be an IP address")
            self.ip = self.target
            self.results["ip"] = self.ip

        self.results["dns"] = dns_enum.enumerate_all()

        if not skip_subdomains:
            wordlist = SUBDOMAIN_WORDLIST
            if wordlist_file and os.path.isfile(wordlist_file):
                C.info(f"Loading custom wordlist: {wordlist_file}")
                with open(wordlist_file, "r", encoding="utf-8", errors="replace") as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                C.ok(f"Loaded {len(wordlist)} entries from wordlist")

            brute = SubdomainBruteForcer(self.target, wordlist=wordlist)
            subs = brute.run()
            self.results["subdomains"] = [{"subdomain": s[0], "ip": s[1]} for s in subs]

        whois = WHOISLookup()
        self.results["whois"] = whois.query(self.target)

        if self.ip:
            geo = GeoIPLookup()
            self.results["geoip"] = geo.lookup(self.ip)

        if not skip_ports and self.ip:
            scanner = PortScanner(self.target)
            self.results["ports"] = scanner.scan()

        self.results["threat_intel_links"] = ThreatIntelLinks.generate(self.target, self.ip)

        self._export()

    def _export(self):
        """Export results to JSON."""
        os.makedirs(self.output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.target)
        filepath = os.path.join(self.output_dir, f"recon_{target_safe}_{ts}.json")

        export_data = {}
        for k, v in self.results.items():
            if k == "whois" and isinstance(v, dict):
                export_data[k] = {key: val for key, val in v.items() if key != "_raw"}
            else:
                export_data[k] = v

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

        C.section("EXPORT")
        C.ok(f"JSON report saved: {C.BLD}{filepath}{C.R}")

        summary = []
        summary.append(f"DNS Records:  {sum(len(v) for v in self.results['dns'].values()) if self.results['dns'] else 0}")
        summary.append(f"Subdomains:   {len(self.results['subdomains'])}")
        summary.append(f"Open Ports:   {len(self.results['ports'])}")
        summary.append(f"Intel Links:  {len(self.results['threat_intel_links'])}")

        C.p("")
        for s in summary:
            C.ok(s)

        C.p(f"\n  {C.GRN}{C.BLD}[*] Reconnaissance complete for {self.target}{C.R}")
        C.p(f"  {C.DIM}    Timestamp: {datetime.utcnow().isoformat()}Z{C.R}\n")


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def main():
    C.p(BANNER)
    C.p(DISCLAIMER)

    parser = argparse.ArgumentParser(
        prog="osint_recon_suite",
        description=f"{C.CYN}FU PERSON :: OSINT Recon Suite v2.0 -- Network Reconnaissance{C.R}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        {C.CYN}Examples:{C.R}
          python osint_recon_suite.py -t example.com
          python osint_recon_suite.py -t 93.184.216.34 --skip-subdomains
          python osint_recon_suite.py -t example.com -w subdomains.txt --ns 8.8.8.8
          python osint_recon_suite.py -t example.com --skip-ports -o ./reports
        """),
    )

    parser.add_argument("-t", "--target", required=True, help="Target domain or IP address")
    parser.add_argument("-o", "--output", default="fu_recon_output", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Custom subdomain wordlist file")
    parser.add_argument("--ns", "--nameserver", dest="nameserver", help="Custom DNS nameserver (e.g. 8.8.8.8)")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain brute-force")

    args = parser.parse_args()

    if not HAS_DNS:
        C.warn("dnspython not installed - DNS features limited. pip install dnspython")

    engine = OSINTReconEngine(target=args.target, output_dir=args.output)
    engine.run_all(
        skip_ports=args.skip_ports,
        skip_subdomains=args.skip_subdomains,
        wordlist_file=args.wordlist,
        nameserver=args.nameserver,
    )


if __name__ == "__main__":
    main()
