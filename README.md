<div align="center">

# FU PERSON v4.0

### **F**ind yo**U** **PERSON**

```
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Full-Spectrum Security Operations & OSINT Platform**

[![Version](https://img.shields.io/badge/Version-4.0-00FFFF?style=for-the-badge)]()
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)]()
[![FLLC](https://img.shields.io/badge/FLLC-2026-7B2FBE?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-Source--Available-FF6600?style=for-the-badge)]()
[![Stars](https://img.shields.io/github/stars/Personfu/FU-PERSON?style=for-the-badge&color=FFD700)]()

</div>

---

> Five devices. 19 core modules. Full Kali-category coverage. Quantum-ready cryptography. Live CVE intelligence. One objective.

```
Property of FLLC  |  Source-Available  |  Authorized Use Only
OSINT Finder: https://fllc.net/osint  |  Contact: preston@fllc.net
```

---

## `[root@fuperson]─[~/overview]`

FU PERSON is a self-contained security operations platform covering every major Kali Linux tool category with custom Python and PowerShell implementations. No Kali install required. No VMs. No cloud dependencies. Runs from a USB stick, a phone, or a laptop.

**What changed in v4.0:**
- 12 new Python modules covering all remaining Kali categories
- Live CVE intelligence engine with NVD/CISA/EPSS feeds and SQLite cache
- CVE monitoring daemon with desktop alerts and digest reports
- Post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA) with hybrid encryption
- Cryptographic vulnerability auditor with quantum threat assessment
- Pre-commit secret scanning and file integrity verification
- Cleaned up repo structure -- removed redundant docs, professional layout

---

## `[root@fuperson]─[~/arsenal]`

| Device | Role | Automation | Status |
|--------|------|------------|--------|
| **USB Drive** | Data extraction + OSINT + network recon | Fully automated -- insert and walk away | `[ACTIVE]` |
| **Flipper Zero** | RF/NFC/IR/BadUSB field operations | Manual -- you operate it | `[ACTIVE]` |
| **ESP32** | WiFi pineapple + wardriving + BLE | Standalone firmware | `[ACTIVE]` |
| **Android (S20+)** | Headless pentest platform via ADB | ADB controlled, no screen needed | `[ACTIVE]` |
| **Nintendo DSi** | WiFi recon under CyberWorld game cover | Background scanning while "playing Pokemon" | `[ACTIVE]` |

---

## `[root@fuperson]─[~/kali-coverage]`

### Tool Categories -- All 14 Kali Categories Covered

| # | Category | Module(s) | Key Capabilities |
|---|----------|-----------|-----------------|
| 1 | **Information Gathering** | `osint_recon_suite`, `people_finder`, `galaxy_recon_suite`, `network_sniffer` | DNS/WHOIS/GeoIP, 88+ platform people search, packet capture, passive OS fingerprinting |
| 2 | **Vulnerability Analysis** | `pentest_suite`, `cve_engine`, `crypto_audit` | Web app testing, live NVD/CISA/EPSS CVE feeds, TLS/crypto weakness scanning |
| 3 | **Web Application Analysis** | `cms_scanner`, `pentest_suite` | WordPress/Joomla/Drupal scanning, 20+ tech fingerprints, web shell detection |
| 4 | **Database Assessment** | `pentest_suite`, `sqli_scanner.ps1` | SQL injection automation, multi-DBMS support |
| 5 | **Password Attacks** | `harvest.ps1`, `cloud_harvester.ps1`, `crypto_hunter.ps1` | Browser creds, cloud tokens, crypto wallets, credential manager dumps |
| 6 | **Wireless Attacks** | ESP32 firmware, `wifi_attacks.sh`, `network_sniffer` | Evil twin, PMKID capture, deauth detection, BLE scanning, wardriving |
| 7 | **Reverse Engineering** | `reverse_engineer` | PE/ELF parsing, string extraction, entropy analysis, capstone disassembly, YARA rules |
| 8 | **Exploitation** | `exploit_dev`, `auto_pwn.ps1`, `privesc.ps1` | Shellcode gen, cyclic patterns, ROP gadgets, 20+ privesc vectors, 12 persistence methods |
| 9 | **Sniffing & Spoofing** | `network_sniffer` | Raw packet capture, ARP spoofing detection, DNS interception, PCAP output |
| 10 | **Post-Exploitation** | `persistence_engine.ps1`, `stealth_mode.ps1`, `tunnel_proxy` | 12 persistence methods, 15-phase anti-forensics, SOCKS5/SSH/encrypted tunnels, pivot chains |
| 11 | **Forensics** | `harvest.ps1`, `linux_collector.sh`, `linux_exploit.py` | 13-phase Windows extraction, Linux privesc audit, container escape detection |
| 12 | **Reporting** | `report_generator.ps1`, `cve_engine`, `compliance_scanner.ps1` | AES-256 encrypted reports, CVE intelligence reports, NIST/CIS/PCI/SOC2 gap analysis |
| 13 | **Social Engineering** | Flipper BadUSB (35+ payloads), `setup.bat` | Zero-click USB deployment, social engineering triggers |
| 14 | **Stress Testing** | `stress_tester` | HTTP flood, Slowloris, TCP/UDP flood -- all with mandatory authorization controls |

### Beyond Kali

| Module | Category | What It Adds |
|--------|----------|-------------|
| `voip_scanner` | VoIP Security | SIP discovery, user enumeration, RTP analysis, protocol fuzzing |
| `ids_evasion` | IDS/WAF Evasion | 20+ WAF fingerprints, payload mutation engine, IP fragmentation, session splicing |
| `cve_engine` | Threat Intelligence | NVD API v2, CISA KEV, EPSS scoring, Exploit-DB cross-reference, SQLite cache |
| `cve_monitor` | Live Monitoring | Background CVE daemon, watchlists, desktop alerts, daily/weekly digests |
| `quantum_crypto` | Post-Quantum Crypto | Kyber/Dilithium/SPHINCS+, hybrid X25519+Kyber, AES-256-GCM, SHA-3 |
| `crypto_audit` | Crypto Auditing | TLS scanner, 29 weak-crypto regex patterns, quantum vulnerability assessment, migration planner |
| `tunnel_proxy` | Tunneling & Pivoting | SOCKS5 proxy, SSH tunnels, AES-256 encrypted tunnels, multi-hop pivot chains |
| `linux_exploit.py` | Linux Privesc | 52 kernel CVEs, 85+ GTFOBins, cron abuse, capability checker, container escape |

---

## `[root@fuperson]─[~/cve-intelligence]`

Real-time vulnerability intelligence -- not a static list, a live feed.

```bash
# Search for a specific CVE
root@fuperson:~# python core/cve_engine.py lookup --cve CVE-2024-1086

# Search by product
root@fuperson:~# python core/cve_engine.py search --keyword "Apache" --severity CRITICAL

# Check if a CVE is actively exploited
root@fuperson:~# python core/cve_engine.py kev --cve CVE-2024-1086

# Get EPSS exploit probability
root@fuperson:~# python core/cve_engine.py epss --cve CVE-2024-1086

# Enrich with all sources (NVD + CISA + EPSS + Exploit-DB)
root@fuperson:~# python core/cve_engine.py enrich --cve CVE-2024-1086

# Start the monitoring daemon
root@fuperson:~# python core/cve_monitor.py watch add --product "Microsoft Windows"
root@fuperson:~# python core/cve_monitor.py watch add --product "OpenSSL"
root@fuperson:~# python core/cve_monitor.py start
[*] CVE Monitor started. Polling every 6 hours.
[*] Watching: Microsoft Windows, OpenSSL
[*] Alert threshold: CVSS >= 7.0
```

---

## `[root@fuperson]─[~/quantum-readiness]`

Quantum computers will break RSA and ECDSA. We're ready now.

```bash
# Generate post-quantum keypair
root@fuperson:~# python core/quantum_crypto.py keygen --algorithm kyber768

# Hybrid encrypt (classical X25519 + quantum Kyber)
root@fuperson:~# python core/quantum_crypto.py encrypt --input secret.txt --key pub.pqkey --hybrid

# Audit codebase for quantum-vulnerable crypto
root@fuperson:~# python core/crypto_audit.py quantum --directory ./
[!] CRITICAL: RSA-2048 found in 3 files (Shor's algorithm -- broken by quantum)
[!] HIGH: AES-128 found in 2 files (Grover's algorithm -- reduced to 64-bit)
[+] SAFE: AES-256-GCM found in 5 files (128-bit post-quantum security)
```

| Algorithm | Type | NIST Standard | Status |
|-----------|------|---------------|--------|
| ML-KEM (Kyber) 512/768/1024 | Key Encapsulation | FIPS 203 | Implemented |
| ML-DSA (Dilithium) 2/3/5 | Digital Signature | FIPS 204 | Implemented |
| SLH-DSA (SPHINCS+) | Hash-Based Signature | FIPS 205 | Implemented |
| AES-256-GCM | Symmetric Encryption | -- | Implemented |
| SHA-3 (SHA3-256/512, SHAKE) | Hashing | FIPS 202 | Implemented |

Full guide: `docs/QUANTUM_READINESS.md`

---

## `[root@fuperson]─[~/usb-weapon]`

Insert. Walk away. Retrieve. 60 seconds, zero dependencies, zero traces.

```
root@fuperson:~# ./harvest.ps1 --silent --auto
[Phase 01/13] System info, users, processes, services, AV, USB history
[Phase 02/13] IP config, ARP, connections, routes, DNS cache, shares
[Phase 03/13] Every saved WiFi password (SSID + plaintext key)
[Phase 04/13] Browser data -- 7 browsers (logins, cookies, history, DPAPI)
[Phase 05/13] Credential Manager, RDP, PuTTY, SSH keys, cloud creds
[Phase 06/13] Discord, Telegram, Slack, Teams, Signal, VPN configs
[Phase 07/13] Password grep, .env files, KeePass DBs, certificates
[Phase 08/13] 11 crypto wallets + seed phrase search
[Phase 09/13] Privesc recon (unquoted paths, writable dirs, DLL hijack)
[Phase 10/13] Screenshot + clipboard capture
[Phase 11/13] Browser session tokens (Chrome, Edge, Firefox)
[Phase 12/13] Clipboard history + PowerShell transcript logs
[Phase 13/13] Trace cleanup (PS history, Run dialog, prefetch, logs)
[+] COMPLETE -- 13/13 phases -- loot on MicroSD
```

---

## `[root@fuperson]─[~/repo-structure]`

```
FU-PERSON/
├── core/                           19 Python modules
│   ├── pentest_suite.py            Web application penetration testing
│   ├── osint_recon_suite.py        Domain/IP/network reconnaissance
│   ├── galaxy_recon_suite.py       Deep intelligence aggregator
│   ├── people_finder.py            88+ platform people search
│   ├── repo_collector.py           GitHub scanner + secret detector
│   ├── list_consolidator.py        Wordlist engine
│   ├── consolidated_lists.py       Pre-built wordlists
│   ├── network_sniffer.py          Packet capture + ARP + DNS + OS fingerprint
│   ├── tunnel_proxy.py             SOCKS5 / SSH / encrypted tunnels
│   ├── reverse_engineer.py         PE/ELF analysis + YARA + disassembly
│   ├── exploit_dev.py              Shellcode + patterns + ROP + encoders
│   ├── cms_scanner.py              CMS fingerprint + web shell detection
│   ├── voip_scanner.py             SIP/RTP/VoIP analysis
│   ├── stress_tester.py            Authorized stress testing
│   ├── ids_evasion.py              WAF detect + IDS evasion + mutation
│   ├── cve_engine.py               NVD/CISA/EPSS CVE intelligence
│   ├── cve_monitor.py              Live CVE monitoring daemon
│   ├── quantum_crypto.py           Post-quantum cryptography
│   ├── crypto_audit.py             TLS/crypto vulnerability auditor
│   └── data/                       Master wordlists
│
├── payloads/
│   ├── windows/                    15 PowerShell attack modules
│   └── linux/
│       ├── linux_collector.sh      12-phase Linux data collection
│       └── linux_exploit.py        Kernel CVE mapper + privesc auditor
│
├── usb_payload/                    Ready-to-deploy USB files
│   ├── sd_card/.p/                 Hidden PowerShell payloads
│   ├── microsd/                    Loot collection point
│   └── flipper_badusb/             Zero-click USB harvest
│
├── flipper/                        Flipper Zero arsenal
│   ├── badusb/                     35+ BadUSB payloads
│   ├── subghz/                     Sub-GHz frequency database
│   ├── nfc/                        150+ MIFARE keys + attack playbook
│   ├── infrared/                   290+ IR signals
│   ├── rfid/                       19 protocol formats
│   ├── ibutton/                    25+ model types
│   └── gpio/                       ESP32 integration
│
├── firmware/esp32/                 ESP32 wardriver + pineapple firmware
├── mobile/
│   ├── s20_headless/               Galaxy S20+ headless pentest
│   └── dsi/                        Nintendo DSi + CyberWorld
│
├── web/                            FLLC.net OSINT Finder frontend
├── scripts/
│   └── verify_integrity.py         SHA-256 file integrity checker
├── docs/                           Technical documentation
│   ├── QUANTUM_READINESS.md        PQC migration guide
│   ├── AI_THREAT_LANDSCAPE_2026.md AI security landscape
│   ├── COMPLIANCE_FRAMEWORK.md     NIST/CIS/PCI/SOC2 reference
│   ├── TOOL_INSTALLATION.md        Setup instructions
│   ├── PENTEST_DOCUMENTATION.md    Methodology reference
│   └── DRIVE_LAYOUT.md             Tri-drive architecture
│
├── .pre-commit-config.yaml         Secret scanning + syntax hooks
├── .env.example                    Environment variable template
├── requirements.txt                Python dependencies
├── LICENSE                         Source-Available License v1.0
├── SECURITY.md                     Vulnerability disclosure + PGP
└── CONTRIBUTING.md                 Contribution policy
```

---

## `[root@fuperson]─[~/quick-start]`

```bash
# Install Python dependencies
root@fuperson:~# pip install -r requirements.txt

# Run an OSINT search
root@fuperson:~# python core/people_finder.py --target "John Doe"

# Scan a domain
root@fuperson:~# python core/osint_recon_suite.py --target example.com

# Check a CVE
root@fuperson:~# python core/cve_engine.py lookup --cve CVE-2024-1086

# Deploy USB payloads
root@fuperson:~# usb_payload/DEPLOY.bat

# Verify file integrity
root@fuperson:~# python scripts/verify_integrity.py verify
```

---

## `[root@fuperson]─[~/source-integrity]`

Every module has SHA-256 checksums tracked via `scripts/verify_integrity.py`. Run `verify` after cloning to confirm no files have been tampered with. Pre-commit hooks via `detect-secrets` prevent accidental credential leaks.

```bash
# Generate checksums (maintainer)
root@fuperson:~# python scripts/verify_integrity.py generate

# Verify checksums (anyone)
root@fuperson:~# python scripts/verify_integrity.py verify
[+] 47 files verified: 47 passed, 0 failed, 0 missing

# Install pre-commit hooks
root@fuperson:~# pre-commit install
```

---

## `[root@fuperson]─[~/legal]`

```
FU PERSON (Find You Person) Source-Available License v1.0
Copyright 2025-2026 FLLC. All rights reserved.

Authorized security testing only. Unauthorized computer access is a
federal crime (18 U.S.C. 1030). You are solely responsible for legal
compliance. Do not use against any system without explicit written
authorization.

Contact: preston@fllc.net
```

---

<div align="center">

**FLLC | 2026 | Find You Person. Always.**

</div>
