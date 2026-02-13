# Compliance Framework Reference

> FLLC — FU PERSON v1.777
> Quick reference for compliance-to-pentest mapping.

---

## Supported Frameworks

| Framework | Version | Coverage |
|-----------|---------|----------|
| NIST 800-53 | Rev 5 | 28 controls actively tested |
| CIS Controls | v8 | 18 controls mapped |
| PCI-DSS | 4.0 | 12 requirements covered |
| SOC 2 Type II | 2024 | CC criteria mapped |
| ISO 27001 | 2022 | Annex A cross-referenced |
| HIPAA | Security Rule | PHI-relevant controls noted |
| FedRAMP | Moderate | NIST-derived controls |

---

## How compliance_scanner.ps1 Works

```
Phase 1 — Access Control (NIST AC family)
  - Account staleness, guest accounts, admin group, lockout policy

Phase 2 — Audit & Accountability (NIST AU family)
  - Audit policies, time sync, event log sizing

Phase 3 — Identification & Authentication (NIST IA family)
  - Password policy, Credential Guard, plaintext credential search

Phase 4 — System & Communications Protection (NIST SC family)
  - Firewall profiles, TLS config, BitLocker, network shares

Phase 5 — System & Information Integrity (NIST SI family)
  - Patch status, AV status/signatures, Sysmon monitoring

Phase 6 — Configuration Management (NIST CM family)
  - PowerShell execution policy, unnecessary services, software inventory

Phase 7 — Risk Assessment (NIST RA family)
  - SMBv1, RDP/NLA, AutoRun policy

Phase 8 — Report Generation
  - TXT, JSON, CSV output with compliance score
```

---

## Report Output

| File | Format | Use |
|------|--------|-----|
| `compliance_report.txt` | Human-readable text | Executive briefings |
| `compliance_report.json` | Structured JSON | SIEM ingestion, API integration |
| `compliance_findings.csv` | CSV | Spreadsheet analysis, GRC tools |

### Scoring
- **80-100%** — Strong posture (green)
- **60-79%** — Acceptable with remediation needed (yellow)
- **Below 60%** — Critical gaps requiring immediate action (red)

---

## Pentest Finding to Control Mapping

| Finding | NIST | CIS | PCI | Remediation Priority |
|---------|------|-----|-----|---------------------|
| Weak passwords | IA-5 | 5.2 | 8.3 | Critical — 72h |
| Missing patches | SI-2 | 7.1 | 6.3 | High — 30d |
| No MFA | IA-2(1) | 6.3 | 8.4 | Critical — 72h |
| Firewall disabled | SC-7 | 4.1 | 1.3 | Critical — 24h |
| No encryption | SC-13 | 3.10 | 4.2 | High — 30d |
| Excessive admins | AC-6 | 5.4 | 7.1 | High — 30d |
| No audit logging | AU-2 | 8.2 | 10.2 | Critical — 72h |
| RDP exposed | RA-5 | 4.1 | 2.2 | Critical — 24h |
| SMBv1 enabled | RA-5 | 4.1 | 2.2 | Critical — 24h |

---

**FLLC 2026** — FU PERSON by PERSON FU
