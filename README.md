# FU PERSON

**Integrated Security Operations Toolkit**

Offensive security, reconnaissance, intelligence gathering, and field-deployable exploitation — consolidated into a single portable platform built around the tri-drive USB form factor.

```
Property of FLLC (FLLC LLC)
Source-Available | All Rights Reserved | Authorized Use Only
```

---

## Legal Notice

**READ BEFORE PROCEEDING**

This software is the intellectual property of **FLLC (FLLC LLC)**. It is provided in source-visible form under the **FU PERSON Source-Available License v1.0** (see `LICENSE`). This is **not** open-source software. Redistribution, sublicensing, and unauthorized commercial use are prohibited.

All tools in this repository are intended for **authorized security testing and research only**. Unauthorized access to computer systems is a federal crime under 18 U.S.C. 1030 (Computer Fraud and Abuse Act). Users are solely responsible for ensuring their use complies with all applicable law.

**Do not use this software against any system without explicit written authorization from the system owner.**

---

## Architecture

FU PERSON is built around a USB device with three storage interfaces:

| Interface | Drive | Role | Description |
|-----------|-------|------|-------------|
| SD Card | H: | **Offense** | Tool suites, firmware, Flipper payloads, mobile platform scripts |
| Micro SD | I: | **Collection** | Exploitation payloads, loot directories, exfiltrated data |
| ESP32 | USB | **Wireless** | Packet capture, deauthentication, rogue AP, BLE recon |

The design principle is separation of concerns: the SD card carries the tools, the Micro SD receives the output, and the ESP32 operates independently on the wireless layer. All three components deploy from a single command.

---

## Repository Structure

```
FU-PERSON/
|
|-- core/                              Primary tool suites
|   |-- pentest_suite.py               Automated penetration testing framework
|   |-- osint_recon_suite.py           Open-source intelligence and target recon
|   |-- galaxy_recon_suite.py          Full-auto deep intelligence platform
|   |-- people_finder.py              People search across 88+ platforms
|   |-- repo_collector.py             GitHub repository aggregation engine
|   |-- list_consolidator.py          Wordlist and endpoint consolidation
|   |-- consolidated_lists.py         Merged master lists (Python importable)
|   +-- data/                          Consolidated wordlists
|       |-- master_domains.txt         Aggregated domain list
|       |-- master_subdomains.txt      Subdomain enumeration seeds
|       |-- master_api_endpoints.txt   API endpoint paths
|       |-- master_directories.txt     Directory brute-force paths
|       +-- master_services.txt        Service fingerprint data
|
|-- payloads/
|   |-- windows/                       Windows target payloads
|   |   |-- auto_pwn.ps1              Master attack chain orchestrator
|   |   |-- windows_collector.ps1     System, browser, credential harvesting
|   |   |-- privesc.ps1               Privilege escalation scanner + exploit
|   |   |-- sqli_scanner.ps1          Local service SQL injection automation
|   |   |-- npp_exploit.ps1           Application-level DLL hijack + exfil
|   |   |-- input_monitor.py          Keystroke, mouse, clipboard capture
|   |   |-- start_monitor.bat         Silent monitor launcher
|   |   |-- run_me.bat                Social engineering wrapper
|   |   +-- windows_collector.bat     CMD fallback for restricted systems
|   +-- linux/
|       +-- linux_collector.sh         Linux system and credential harvesting
|
|-- firmware/
|   +-- esp32/
|       |-- FLLC_wardriver/
|       |   |-- FLLC_wardriver.ino  Dual-core 11-mode wardriver firmware
|       |   |-- config.h               Hardware pinout + attack parameters
|       |   +-- oui.h                  MAC vendor fingerprint database (3,000+)
|       |-- platformio.ini             Build configuration (DevKit V1.1)
|       +-- flash_esp32.py             Automated firmware flash utility
|
|-- flipper/                           Flipper Zero payload library
|   |-- badusb/                        12 DuckyScript keystroke injection payloads
|   |   |-- auto_pwn_deploy.txt       Deploy full attack chain
|   |   |-- stealth_deploy.txt        Base64-encoded stealth deployment
|   |   |-- deploy_toolkit.txt        Copy toolkit to target
|   |   |-- wifi_passwords.txt        Extract saved Wi-Fi credentials
|   |   |-- full_exfil.txt            Complete data exfiltration
|   |   |-- disable_defender.txt      Neutralize Windows Defender
|   |   |-- reverse_shell.txt         PowerShell reverse shell
|   |   |-- net_diag.txt              Encoded reverse shell (AV bypass)
|   |   |-- empire_stager.txt         Empire post-exploitation stager
|   |   |-- obfuscated_loader.txt     Multi-stage obfuscated loader
|   |   |-- recon_launch.txt          Automated recon kickoff
|   |   +-- linux_reverse_shell.txt   Linux target reverse shell
|   |-- gpio/                          ESP32 bridge commands
|   |   |-- marauder_commands.txt     Marauder firmware command set
|   |   +-- auto_recon.txt            Automated wireless reconnaissance
|   |-- subghz/
|   |   +-- frequencies.txt           Sub-GHz frequency database
|   |-- nfc/
|   |   +-- attack_playbook.txt       NFC/RFID attack methodology
|   +-- infrared/
|       +-- tv_off_universal.ir       Universal IR power-off codes
|
|-- mobile/
|   |-- s20_headless/                  Samsung S20+ as headless attack platform
|   |   |-- setup_termux.sh           Termux + Kali NetHunter bootstrap
|   |   |-- headless_recon.sh         Automated WiFi/BLE/GPS/network recon
|   |   |-- wifi_attacks.sh           Wireless attack automation
|   |   |-- adb_control.py            PC-to-device ADB command interface
|   |   +-- scrcpy_setup.bat          Screen mirroring configuration
|   +-- dsi/
|       +-- dsi_toolkit.py            Nintendo DSi homebrew WiFi scanner
|
|-- recorder/                          Voice-activated audio capture
|   |-- listener.py                    50dB threshold recording engine
|   |-- build_exe.py                   PyInstaller compilation to standalone .exe
|   |-- start_listener.bat            Silent background launcher
|   +-- requirements.txt              Audio dependencies (pyaudio, numpy)
|
|-- deploy/                            Deployment automation
|   |-- build_usb.py                   Tri-drive deployment orchestrator
|   |-- Build_USB_Drives.bat          One-click deployment wrapper
|   |-- Install_Dependencies.bat      Python dependency installer
|   |-- LAUNCH.bat                     Unified tool launcher
|   |-- Run_Pentest_Suite.bat         Pentest suite launcher
|   |-- Run_OSINT_Recon.bat           OSINT suite launcher
|   |-- Run_Galaxy_Recon.bat          Galaxy recon launcher
|   +-- Run_People_Finder.bat         People finder launcher
|
|-- docs/                              Documentation
|   |-- DRIVE_LAYOUT.md               Tri-drive mapping reference
|   |-- PENTEST_DOCUMENTATION.md      Pentest suite technical reference
|   |-- OSINT_QUICK_START.md          OSINT quick-start guide
|   |-- OSINT_README.md               OSINT suite overview
|   |-- TOOL_INSTALLATION.md          Dependency installation guide
|   +-- QUICK_REFERENCE.txt           Command cheat sheet
|
|-- LICENSE                            FU PERSON Source-Available License v1.0
|-- SECURITY.md                        Vulnerability disclosure policy
|-- CONTRIBUTING.md                    Contribution policy
+-- requirements.txt                   Python dependencies
```

**74 files. Zero bloat.**

---

## Core Capabilities

### Pentest Suite

`core/pentest_suite.py`

Automated 8-phase penetration testing framework. Detects and integrates with 200+ security tools installed on the host system.

| Phase | Coverage |
|-------|----------|
| DNS Enumeration | Subdomain discovery, zone transfers, DNS record analysis |
| Network Scanning | Port scanning, service detection, OS fingerprinting |
| OSINT Gathering | Public data collection, email harvesting, metadata extraction |
| SSL/TLS Analysis | Certificate chain validation, cipher suite assessment, HSTS |
| Web Application | Directory enumeration, CMS detection, header analysis |
| Vulnerability Scanning | CVE matching, known exploit detection, misconfig checks |
| Exploitation | SQL injection, command injection, XSS, file inclusion |
| Post-Exploitation | Data extraction, lateral movement prep, persistence |

**Tool Integrations**: Nmap, Masscan, RustScan, Nikto, SQLMap, Gobuster, DIRB, FFuF, WPScan, WhatWeb, WAFW00F, TheHarvester, Amass, Sublist3r, DNSRecon, SSLScan, testssl.sh, Hydra, Hashcat, and 180+ more.

### OSINT Reconnaissance

`core/osint_recon_suite.py`

Target infrastructure mapping from public sources. Subdomain discovery, technology fingerprinting, WHOIS data, DNS records, certificate transparency logs, and organizational intelligence.

### Galaxy Recon

`core/galaxy_recon_suite.py`

Provide a name. Every category searches automatically.

| Category | Sources |
|----------|---------|
| Identity | Name variations, aliases, DOB, SSN-adjacent |
| Vehicles | VIN lookups, registration, title history |
| Property | County assessor, deed records, mortgage filings |
| Employment | LinkedIn, company registries, SEC filings |
| Education | Alumni directories, yearbook archives, degree verification |
| Family | Relatives, associates, household composition |
| Court Records | Federal PACER, state courts, criminal, civil, bankruptcy |
| Voter Registration | State voter files, party affiliation, history |
| Social Media | 88+ platforms, username enumeration, content scraping |
| Breach Data | Credential databases, paste sites, dark web references |
| News & Media | Archive.org TV News, newspaper archives, press releases |

### People Finder

`core/people_finder.py`

88+ platform search across social media, people search engines, public records, and news archives. Generates confidence-scored reports in TXT, JSON, and CSV.

**Search Sources**: Google, Bing, DuckDuckGo, TruePeopleSearch, FastPeopleSearch, PeekYou, WhitePages, Spokeo, BeenVerified, CourtListener, SEC EDGAR, FEC, OpenCorporates, Archive.org Wayback Machine, Archive.org TV News Archive, LinkedIn, Facebook, Instagram, Twitter/X, Reddit, GitHub, and 60+ additional platforms.

**Coverage**: USA, Canada, UK, EU, Australia, New Zealand, and expanding.

### Payload Chain

`payloads/windows/auto_pwn.ps1`

Unattended execution pipeline:

```
auto_pwn.ps1
  |-- windows_collector.ps1    System data, browser artifacts, Wi-Fi creds
  |-- input_monitor.py         Keystroke logging, clipboard capture
  |-- privesc.ps1              Privilege escalation (unquoted paths, weak perms,
  |                            AlwaysInstallElevated, vulnerable tasks)
  |-- sqli_scanner.ps1         Local web service discovery + SQLi automation
  +-- npp_exploit.ps1          DLL hijack, config injection, session exfil
```

Drop `run_me.bat` on a target. Walk away. Data lands in `I:\loot\`.

### ESP32 Wardriver

`firmware/esp32/FLLC_wardriver/`

Production-grade dual-core firmware for the **DIYMalls ESP32 DevKit V1.1**. 11 operational modes:

| Mode | Function |
|------|----------|
| WiFi Scan | Channel-hopping AP and client enumeration |
| BLE Scan | Bluetooth Low Energy device discovery |
| Deauth | Targeted 802.11 deauthentication |
| Probe Sniff | Probe request capture (device tracking) |
| Evil Twin | Rogue AP with captive portal |
| Beacon Spam | SSID flooding (up to 50 networks) |
| Handshake | WPA PMKID and EAPOL 4-way capture |
| Karma | Auto-respond to probe requests |
| DNS Spoof | DNS hijacking on rogue AP |
| PCAP Log | Full packet capture to SD card |
| Recon | Combined scan + log mode |

**Output**: hashcat-ready PMKID hashes, PCAP files, JSON scan logs, OUI-fingerprinted device inventory. All logged to Micro SD.

**Control**: Serial interface or Flipper Zero GPIO bridge.

### Flipper Zero Integration

12 BadUSB payloads, ESP32 GPIO command set, Sub-GHz frequency database, NFC/RFID attack playbook, and universal IR codes. Highlights:

- `auto_pwn_deploy.txt` — Deploy the full attack chain via keystroke injection
- `stealth_deploy.txt` — Base64-encoded variant for endpoint detection bypass
- `net_diag.txt` — Encoded reverse shell disguised as network diagnostics
- `disable_defender.txt` — Windows Defender neutralization
- `full_exfil.txt` — Complete system data exfiltration

### Mobile Attack Platform

**S20+ Headless** (`mobile/s20_headless/`): Rooted Samsung Galaxy S20+ running Termux with Kali NetHunter. Automated WiFi/BLE/GPS reconnaissance, wireless attacks, and ADB-based remote control from PC.

**DSi** (`mobile/dsi/`): Nintendo DSi homebrew for covert WiFi scanning and presence.

---

## Quick Start

### Requirements

- Python 3.10+
- Windows 10/11 (primary host)
- USB tri-drive device (SD + Micro SD + ESP32)
- Optional: Flipper Zero, rooted Android, Arduino IDE / PlatformIO

### Install Dependencies

```
pip install -r requirements.txt
```

Or run `deploy/Install_Dependencies.bat`.

### Deploy to Drives

```
python deploy/build_usb.py
```

Or double-click `deploy/Build_USB_Drives.bat`. The deployer reads from the organized repository structure and writes to H: (SD), I: (Micro SD), and J: (Aux) in one pass.

### Run Individual Tools

```
python core/pentest_suite.py <target>
python core/osint_recon_suite.py <target>
python core/galaxy_recon_suite.py
python core/people_finder.py -n "John Doe" -c "New York" -s "NY"
```

### Flash ESP32

```
cd firmware/esp32
python flash_esp32.py --monitor
```

Or open `firmware/esp32/FLLC_wardriver/` in Arduino IDE / PlatformIO and flash to DevKit V1.1 via USB.

---

## Data Sources

Wordlists and reference data aggregated from 13 public repositories:

| Repository | Data |
|-----------|------|
| Ringmast4r/website-lists | Domain and subdomain lists |
| colonelpanichacks/flock-you | Wireless attack payloads |
| xnl-h4ck3r/waymore | Wayback Machine URL harvesting |
| public-apis/public-apis | API endpoint database |
| nmap/nmap | NSE scripts, service fingerprints |
| wireshark/wireshark | Protocol dissectors, OUI database |
| hydralauncher/hydra | Authentication testing |
| diegocr/netcat | Network utility |
| mhx/dwarfs | Compressed filesystem tools |
| erigontech/erigon | Blockchain node data |
| Ringmast4r/Tower-Hunter | Cell tower logging |
| Ringmast4r/GNSS | GPS satellite tracking |
| KeygraphHQ/shannon | Autonomous web exploit discovery |

Consolidation handled by `core/repo_collector.py` and `core/list_consolidator.py`.

---

## Deployment Layout

See `docs/DRIVE_LAYOUT.md` for complete mapping.

```
H: (SD)        pt_suite/ | esp32/ | flipper/ | mobile/ | lists/ | tools/
I: (Micro SD)  payloads/ | loot/ | tools/
J: (Aux)       recorder/ | recordings/
```

---

## License

**FU PERSON Source-Available License v1.0**

Copyright (c) 2025-2026 FLLC. All rights reserved.

This is **not** open-source software. The source code is visible for transparency and authorized internal use. Redistribution, sublicensing, and unauthorized commercial use are prohibited. See `LICENSE` for full terms.

---

## Contact

| | |
|---|---|
| **Legal** | preston@fllc.net |
| **Licensing** | preston@fllc.net |
| **Security** | preston@fllc.net |
| **General** | preston@fllc.net |

---

**FLLC** | 2026

*Built for operators. Authorized use only.*
