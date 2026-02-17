# OSINT & Reconnaissance Suite

```
╔══════════════════════════════════════════════════════════════╗
║  FLLC — OSINT & RECONNAISSANCE SUITE                         ║
║  Open Source Intelligence & People Search                   ║
╚══════════════════════════════════════════════════════════════╝
```

## `[root@fuperson]─[~/legal]`

### [!] LEGAL WARNING

```
╔══════════════════════════════════════════════════════════════╗
║  UNAUTHORIZED USE MAY BE ILLEGAL                             ║
║                                                              ║
║  [+] OSINT gathering from public sources is generally legal  ║
║  [!] Stress testing/DDoS requires EXPLICIT WRITTEN AUTH       ║
║  [-] Only use against authorized targets or own infrastructure║
╚══════════════════════════════════════════════════════════════╝
```

## `[root@fuperson]─[~/features]`

### Features

**[+] Domain Reconnaissance**
- DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV)
- Comprehensive subdomain discovery (100+ common subdomains)
- Technology stack detection
- Certificate transparency log checking
- Historical data from Wayback Machine
- IP geolocation and ISP information

**[+] People Search**
- Email address discovery
- Social media profile search (LinkedIn, Twitter, Facebook, Instagram, GitHub)
- Username enumeration across platforms
- Data breach database checking (Have I Been Pwned)
- Phone number search (requires API keys)

**[!] Stress Testing (Authorized Only)**
- Network stress testing capabilities
- Configurable duration and thread count
- Real-time statistics
- **REQUIRES EXPLICIT AUTHORIZATION**

## `[root@fuperson]─[~/installation]`

### Installation

```bash
root@fuperson:~# pip install -r requirements.txt
[+] Dependencies installed
```

## `[root@fuperson]─[~/usage]`

### Usage

**Domain Reconnaissance**

```bash
# [+] Basic domain reconnaissance
root@fuperson:~# python osint_recon_suite.py --target fllc.net

# [+] With authorization for stress testing
root@fuperson:~# python osint_recon_suite.py --target example.com --authorized
```

**People Search**

```bash
# [*] Search for person
root@fuperson:~# python osint_recon_suite.py --person "John Doe"

# [*] Search person with company domain
root@fuperson:~# python osint_recon_suite.py --person "John Doe" --target company.com
```

**Stress Testing (Authorized Only)**

```bash
# [!] Stress test a target (REQUIRES AUTHORIZATION)
root@fuperson:~# python osint_recon_suite.py --stress https://example.com --authorized
```

## `[root@fuperson]─[~/output]`

### Output

The suite generates comprehensive JSON reports including:
- [+] All discovered information
- [+] Email addresses
- [+] Phone numbers
- [+] Social media profiles
- [+] Subdomains and domains
- [+] IP addresses
- [+] Technologies detected
- [+] Data breach information
- [+] Stress test statistics

## `[root@fuperson]─[~/legal-considerations]`

### Legal Considerations

1. **[+] OSINT Gathering**: Legal when using public sources
2. **[!] Stress Testing**: Requires written authorization
3. **[*] Rate Limiting**: Respect target systems
4. **[*] Terms of Service**: Follow all platform ToS
5. **[*] Privacy**: Handle discovered data responsibly

## `[root@fuperson]─[~/api-keys]`

### API Keys (Optional)

For enhanced functionality, you can add API keys:
- **Hunter.io**: Email search
- **Have I Been Pwned**: Breach checking (v3 API)
- **Shodan**: Infrastructure search
- **TrueCaller**: Phone number lookup

## `[root@fuperson]─[~/examples]`

### Examples

**Example 1: Domain Reconnaissance**

```bash
root@fuperson:~# python osint_recon_suite.py --target fllc.net
```

Output:
- [+] DNS records
- [+] Subdomains discovered
- [+] Technologies used
- [+] IP information
- [+] Certificate transparency data

**Example 2: People Search**

```bash
root@fuperson:~# python osint_recon_suite.py --person "FLLC" --target fllc.net
```

Output:
- [+] Possible email addresses
- [+] Social media profiles
- [+] Username patterns
- [+] Data breach information

**Example 3: Stress Testing**

```bash
root@fuperson:~# python osint_recon_suite.py --stress https://test.example.com --authorized
```

**[!] WARNING**: Only use on authorized targets!

## `[root@fuperson]─[~/report-format]`

### Report Format

Reports are saved as JSON with the following structure:

```json
{
  "target": "example.com",
  "timestamp": "2026-02-09T22:00:00",
  "findings": [...],
  "emails": [...],
  "subdomains": [...],
  "ip_addresses": [...],
  "technologies": [...],
  "social_media": {...},
  "breaches": [...],
  "summary": {...}
}
```

## `[root@fuperson]─[~/ethical-use]`

### Ethical Use

- [+] Only gather publicly available information
- [+] Respect rate limits
- [-] Don't abuse APIs
- [+] Handle PII responsibly
- [+] Obtain authorization for stress testing
- [+] Follow all applicable laws

## `[root@fuperson]─[~/support]`

### Support

For questions or issues:
- [*] Review legal requirements
- [*] Check API rate limits
- [*] Verify target authorization
- [*] Review error messages

---

**FLLC | OSINT Operations | 2026**

*Use responsibly and legally. Unauthorized access is illegal.*
