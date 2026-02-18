# Security Policy

**FLLC Security Advisory — Classification: RESTRICTED**

## `[root@fuperson]─[~/supported-versions]`

| Version | Status | Notes |
|---------|--------|-------|
| v3.x | **Supported** | Active development, full security patches |
| v2.x | Limited support | Critical fixes only |
| v1.x | Unsupported | No patches — upgrade immediately |

## `[root@fuperson]─[~/ownership]`

This software is the sole property of **FLLC**. All intellectual property rights are reserved.

## `[root@fuperson]─[~/authorized-use]`

All use of this software must comply with applicable law. See `LICENSE` for full terms.

This software is designed for **authorized security research and penetration testing only**. Unauthorized access to systems, networks, or data you do not own or have written permission to test is a criminal offense under federal and state law.

```
[!] WARNING: Unauthorized use of this software constitutes a federal crime
[!] 18 U.S.C. 1030 — Computer Fraud and Abuse Act applies
[!] All activity is logged and attributable
```

## `[root@fuperson]─[~/scope-of-authorized-use]`

### Permitted Uses

- Penetration testing on systems you **own** or have **written authorization** to test
- Security research in isolated lab environments
- Educational use in controlled classroom or training settings
- Authorized red-team engagements with signed rules of engagement (ROE)
- Integration into FLLC-approved security workflows

### Prohibited Uses

- Unauthorized access to any system, network, or data
- Deployment against production systems without explicit written consent
- Distribution of payloads to unauthorized third parties
- Use in any manner that violates local, state, federal, or international law
- Modification of this software to remove attribution, licensing, or safety controls

## `[root@fuperson]─[~/scope]`

This policy covers all code, firmware, payloads, and configurations in this repository.

```
[*] Scope includes:
    - PowerShell scripts (.ps1)
    - Python tools (.py)
    - Shell scripts (.sh)
    - Batch files (.bat)
    - ESP32 firmware (.ino, .h)
    - Flipper Zero payloads (.txt, .ir)
    - Web frontend (HTML/CSS/JS)
    - All documentation (.md)
```

## `[root@fuperson]─[~/vuln-disclosure]`

If you discover a security vulnerability in this software:

```
root@fuperson:~# cat /proc/disclosure_protocol
[1] DO NOT open a public issue
[2] DO NOT disclose the vulnerability publicly
[3] Email preston@fllc.net with:
    - Description of the vulnerability
    - Steps to reproduce
    - Potential impact assessment
[4] Follow coordinated disclosure timeline
```

### PGP Key

PGP key available upon request to **preston@fllc.net**.
Include "PGP KEY REQUEST" in the subject line.

## `[root@fuperson]─[~/incident-response]`

FLLC commits to the following response timelines for reported vulnerabilities:

| Severity | Acknowledgment | Initial Assessment | Fix Target |
|----------|---------------|--------------------|------------|
| Critical (CVSS 9.0+) | Within 24 hours | Within 72 hours | 7 days |
| High (CVSS 7.0–8.9) | Within 24 hours | Within 72 hours | 14 days |
| Medium (CVSS 4.0–6.9) | Within 24 hours | Within 72 hours | 30 days |
| Low (CVSS < 4.0) | Within 24 hours | Within 72 hours | Next release |

- **Acknowledgment**: Confirmation that your report was received.
- **Initial Assessment**: Preliminary severity classification and scope determination.
- **Fix Target**: Estimated timeline for patch release, subject to complexity.

Reporters will be kept informed at each stage and credited (if desired) in the advisory.

## `[root@fuperson]─[~/legal]`

Unauthorized testing against this software's infrastructure, any systems owned by FLLC, or any systems using this software without authorization may violate the Computer Fraud and Abuse Act (18 U.S.C. 1030) and will be prosecuted to the fullest extent of the law.

## `[root@fuperson]─[~/contact]`

| Purpose | Channel |
|---------|---------|
| Security disclosures | `preston@fllc.net` |
| General inquiries | `preston@fllc.net` |
| Emergency (active clients) | Contact via website |

---

```
FLLC | 2026 | All Rights Reserved
```
