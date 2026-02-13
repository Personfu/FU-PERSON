# OSINT & Reconnaissance Suite

## ⚠️ LEGAL WARNING

**UNAUTHORIZED USE MAY BE ILLEGAL**

- OSINT gathering from public sources is generally legal
- **Stress testing/DDoS requires EXPLICIT WRITTEN AUTHORIZATION**
- Only use against authorized targets or your own infrastructure

## Features

### Domain Reconnaissance
- DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV)
- Comprehensive subdomain discovery (100+ common subdomains)
- Technology stack detection
- Certificate transparency log checking
- Historical data from Wayback Machine
- IP geolocation and ISP information

### People Search
- Email address discovery
- Social media profile search (LinkedIn, Twitter, Facebook, Instagram, GitHub)
- Username enumeration across platforms
- Data breach database checking (Have I Been Pwned)
- Phone number search (requires API keys)

### Stress Testing (Authorized Only)
- Network stress testing capabilities
- Configurable duration and thread count
- Real-time statistics
- **REQUIRES EXPLICIT AUTHORIZATION**

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Domain Reconnaissance

```bash
# Basic domain reconnaissance
python osint_recon_suite.py --target fllc.net

# With authorization for stress testing
python osint_recon_suite.py --target example.com --authorized
```

### People Search

```bash
# Search for person
python osint_recon_suite.py --person "John Doe"

# Search person with company domain
python osint_recon_suite.py --person "John Doe" --target company.com
```

### Stress Testing (Authorized Only)

```bash
# Stress test a target (REQUIRES AUTHORIZATION)
python osint_recon_suite.py --stress https://example.com --authorized
```

## Output

The suite generates comprehensive JSON reports including:
- All discovered information
- Email addresses
- Phone numbers
- Social media profiles
- Subdomains and domains
- IP addresses
- Technologies detected
- Data breach information
- Stress test statistics

## Legal Considerations

1. **OSINT Gathering**: Legal when using public sources
2. **Stress Testing**: Requires written authorization
3. **Rate Limiting**: Respect target systems
4. **Terms of Service**: Follow all platform ToS
5. **Privacy**: Handle discovered data responsibly

## API Keys (Optional)

For enhanced functionality, you can add API keys:
- **Hunter.io**: Email search
- **Have I Been Pwned**: Breach checking (v3 API)
- **Shodan**: Infrastructure search
- **TrueCaller**: Phone number lookup

## Examples

### Example 1: Domain Reconnaissance
```bash
python osint_recon_suite.py --target fllc.net
```

Output:
- DNS records
- Subdomains discovered
- Technologies used
- IP information
- Certificate transparency data

### Example 2: People Search
```bash
python osint_recon_suite.py --person "FLLC" --target fllc.net
```

Output:
- Possible email addresses
- Social media profiles
- Username patterns
- Data breach information

### Example 3: Stress Testing
```bash
python osint_recon_suite.py --stress https://test.example.com --authorized
```

**WARNING**: Only use on authorized targets!

## Report Format

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

## Ethical Use

- Only gather publicly available information
- Respect rate limits
- Don't abuse APIs
- Handle PII responsibly
- Obtain authorization for stress testing
- Follow all applicable laws

## Support

For questions or issues:
- Review legal requirements
- Check API rate limits
- Verify target authorization
- Review error messages

---

**Remember**: Use responsibly and legally. Unauthorized access is illegal.
