# OSINT & Reconnaissance Suite - Quick Start Guide

```
╔══════════════════════════════════════════════════════════════╗
║  FLLC — OSINT QUICK START                                    ║
║  Open Source Intelligence in 60 seconds                     ║
╚══════════════════════════════════════════════════════════════╝
```

## `[root@fuperson]─[~/what-it-does]`

### What This Tool Does

A comprehensive OSINT (Open Source Intelligence) and reconnaissance suite that gathers publicly available information about targets and people. Includes stress testing capabilities for authorized targets.

## `[root@fuperson]─[~/quick-commands]`

### Quick Commands

**Domain Reconnaissance**

```bash
# [+] Basic domain scan
root@fuperson:~# python osint_recon_suite.py --target fllc.net

# [+] Full scan with authorization
root@fuperson:~# python osint_recon_suite.py --target example.com --authorized
```

**People Search**

```bash
# [*] Search for a person
root@fuperson:~# python osint_recon_suite.py --person "John Doe"

# [*] Search person with company domain
root@fuperson:~# python osint_recon_suite.py --person "John Doe" --target company.com
```

**Stress Testing (AUTHORIZED ONLY)**

```bash
# [!] Stress test a target (REQUIRES WRITTEN AUTHORIZATION)
root@fuperson:~# python osint_recon_suite.py --stress https://target.com --authorized
```

## `[root@fuperson]─[~/what-it-finds]`

### What It Finds

**Domain Information**
- [+] DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV)
- [+] Subdomains (100+ common patterns)
- [+] Technology stack (WordPress, Laravel, React, etc.)
- [+] Certificate transparency data
- [+] Historical snapshots (Wayback Machine)
- [+] IP geolocation and ISP information
- [+] Open ports and services

**People Information**
- [+] Email addresses (pattern-based)
- [+] Social media profiles (LinkedIn, Twitter, Facebook, Instagram, GitHub)
- [+] Username enumeration
- [+] Data breach information (Have I Been Pwned)
- [+] Phone numbers (requires API keys)

**Stress Testing**
- [+] Network stress testing
- [+] Request rate statistics
- [+] Success/failure metrics
- [+] Real-time monitoring

## `[root@fuperson]─[~/output]`

### Output

Reports are saved as JSON files:
- `osint_report_<target>_<timestamp>.json`

Contains:
- [+] All discovered information
- [+] Email addresses
- [+] Phone numbers
- [+] Social media profiles
- [+] Subdomains and domains
- [+] IP addresses
- [+] Technologies detected
- [+] Data breach information
- [+] Stress test statistics

## `[root@fuperson]─[~/legal-warnings]`

### [!] Legal Warnings

1. **[+] OSINT Gathering**: Legal when using public sources
2. **[!] Stress Testing**: **REQUIRES EXPLICIT WRITTEN AUTHORIZATION**
3. **[*] Rate Limiting**: Respect target systems
4. **[*] Terms of Service**: Follow all platform ToS
5. **[*] Privacy**: Handle discovered data responsibly

## `[root@fuperson]─[~/advanced]`

### Advanced Usage

**Combine Target and Person Search**

```bash
root@fuperson:~# python osint_recon_suite.py --person "FLLC" --target fllc.net
```

**Stress Test Configuration**
The stress test runs for 60 seconds with 10 threads by default. Modify in code:
- `duration=60` - Test duration in seconds
- `threads=10` - Number of concurrent threads

## `[root@fuperson]─[~/example-output]`

### Example Output

```
═══ DOMAIN RECONNAISSANCE ═══

[*] Enumerating DNS records...
[INFO] DNS: A record: 104.26.15.126
[INFO] DNS: MX record: mail.example.com

[*] Enumerating subdomains...
[MEDIUM] SUBDOMAIN: Found: www.fllc.net
[MEDIUM] SUBDOMAIN: Found: api.fllc.net

[*] Detecting technologies...
[INFO] TECH: Server: cloudflare
[MEDIUM] TECH: Framework: Angular

[*] Gathering IP information...
[INFO] IP: IP Information
  -> {'ip': '104.26.15.126', 'country': 'United States', ...}
```

## `[root@fuperson]─[~/features]`

### Features

- **[+] Automated**: Runs all checks automatically
- **[+] Comprehensive**: Multiple data sources
- **[+] Fast**: Parallel processing
- **[+] Professional**: Clean output and reports
- **[+] Safe**: Authorization checks built-in

## `[root@fuperson]─[~/getting-started]`

### Getting Started

```bash
# [*] Step 1: Install dependencies
root@fuperson:~# pip install -r requirements.txt

# [+] Step 2: Run your first scan
root@fuperson:~# python osint_recon_suite.py --target fllc.net

# [*] Step 3: Review the generated report
root@fuperson:~# cat osint_report_fllc_net_*.json
```

## `[root@fuperson]─[~/tips]`

### Tips

- [+] Use `--authorized` flag only when you have written authorization
- [+] Review reports carefully for sensitive information
- [+] Respect rate limits on APIs
- [+] Handle discovered PII responsibly
- [!] Only stress test authorized targets

## `[root@fuperson]─[~/support]`

### Support

For questions or issues:
- [*] Review legal requirements
- [*] Check API rate limits
- [*] Verify target authorization
- [*] Review error messages

---

**FLLC | OSINT Quick Start | 2026**

*Use responsibly and legally. Unauthorized access is illegal.*
