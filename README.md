<div align="center">

# FU PERSON — v1.777

```
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Integrated Security Operations Toolkit**

[![Version](https://img.shields.io/badge/Version-1.777-00FFFF?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-Source--Available-FF00FF?style=for-the-badge)]()
[![FLLC](https://img.shields.io/badge/FLLC-2026-7B2FBE?style=for-the-badge)]()

</div>

---

> Offensive security, reconnaissance, intelligence gathering, and field-deployable exploitation — consolidated into a single portable platform built around the tri-drive USB form factor.

```
Property of FLLC
Source-Available | All Rights Reserved | Authorized Use Only
```

### Theme: Midnight Neon Blacklight Galaxy

```
Background:  #0D0D1A (Midnight)      Text:      #E0E0FF (Ghost White)
Primary:     #00FFFF (Neon Cyan)      Muted:     #8888AA (Lavender)
Secondary:   #FF00FF (Fuchsia)        Success:   #00FF88 (Neon Green)
Accent:      #7B2FBE (Ultraviolet)    Border:    #2A2A4A (Dim)
```

---

## Legal Notice

**READ BEFORE PROCEEDING**

This software is the intellectual property of **FLLC (FLLC LLC)**. It is provided in source-visible form under the **FU PERSON Source-Available License v1.0** (see `LICENSE`). This is **not** open-source software. Redistribution, sublicensing, and unauthorized commercial use are prohibited.

All tools in this repository are intended for **authorized security testing and research only**. Unauthorized access to computer systems is a federal crime under 18 U.S.C. 1030 (Computer Fraud and Abuse Act). Users are solely responsible for ensuring their use complies with all applicable law.

**Do not use this software against any system without explicit written authorization from the system owner.**

---

## Architecture

FU PERSON is built around a multi-device attack platform:

| Device | Role | Description |
|--------|------|-------------|
| **USB Tri-Drive** | Core Platform | SD (H:) + Micro SD (I:) + ESP32/Recorder (J:) |
| **Flipper Zero** | Field Tool | 35+ BadUSB payloads, 290+ IR codes, 150+ NFC keys, Sub-GHz, RFID, iButton, GPIO |
| **ESP32 DevKit V1.1** | Wireless | 11-mode wardriver: WiFi/BLE scan, deauth, evil twin, PMKID |
| **Android (S20+)** | Mobile Platform | Magisk root, Termux, Kali NetHunter, headless recon |
| **Nintendo DSi** | Covert Recon | Jailbroken, 200+ games, homebrew WiFi scanner |

### USB Tri-Drive Layout

| Interface | Drive | Role |
|-----------|-------|------|
| SD Card | H: | **Offense** — Tool suites, firmware, Flipper payloads, mobile scripts |
| Micro SD | I: | **Collection** — Payloads, loot directories, exfiltrated data |
| Aux/ESP32 | J: | **Wireless** — Voice recorder or ESP32 data backup |

---

## Complete Setup Guide

### Step 1: Clone the Repository

```
git clone https://github.com/Personfu/FU-PERSON.git
cd FU-PERSON
```

### Step 2: Install Python Dependencies

```
pip install -r requirements.txt
```

Or double-click `deploy/Install_Dependencies.bat`.

### Step 3: Deploy to USB Tri-Drive

Insert the USB tri-drive. Drives should map to H: (SD), I: (Micro SD), J: (Aux).

```
python deploy/build_usb.py
```

Or double-click `deploy/Build_USB_Drives.bat`.

This deploys:
- **H: (SD)** — Full tool suites, ESP32 firmware, Flipper payloads, mobile scripts
- **I: (Micro SD)** — Attack payloads, autorun triggers, loot directories
- **J: (Aux)** — Voice recorder or ESP32 backup

### Step 4: Flash the ESP32

Connect the DIYMalls ESP32 DevKit V1.1 via USB.

```
cd firmware/esp32
python flash_esp32.py --monitor
```

Or open `firmware/esp32/FLLC_wardriver/` in Arduino IDE and flash manually.

The ESP32 runs an 11-mode wardriver:
- WiFi scanning (channel-hopping)
- BLE device discovery
- Deauthentication attacks
- Probe request sniffing
- Evil Twin + captive portal
- Beacon spam (50 SSIDs)
- WPA PMKID + handshake capture
- Karma AP
- DNS spoofing
- Full PCAP logging
- Combined recon mode

All output logs to the Micro SD card in PCAP, JSON, and hashcat-ready formats.

### Step 5: Load the Flipper Zero

Copy the entire `flipper/` directory to your Flipper Zero SD card (via qFlipper or USB):

```
flipper/badusb/          → SD Card/badusb/       (35+ payloads)
flipper/infrared/        → SD Card/infrared/      (7 databases, 290+ signals)
flipper/subghz/          → SD Card/subghz/        (7 reference files)
flipper/nfc/             → SD Card/nfc/            (5 tools, 150+ keys)
flipper/rfid/            → SD Card/rfid/           (19 protocols)
flipper/ibutton/         → SD Card/ibutton/        (25+ types)
flipper/gpio/            → SD Card/gpio/           (4 ESP32 references)
```

**MEGA Arsenal v2.0 — 35+ BadUSB payloads:**

| Category | Payloads |
|----------|----------|
| Auto-Deploy | `phantom_usb`, `auto_pwn_deploy`, `stealth_deploy` |
| Exfiltration (12) | `rapid_exfil`, `full_exfil`, `credential_dump`, `sam_dump`, `browser_harvest`, `email_harvest`, `token_theft`, `crypto_wallet`, `cloud_creds`, `vpn_creds`, `powershell_history`, `env_dump` |
| Recon (7) | `network_recon`, `wifi_passwords`, `recon_launch`, `ad_enum`, `wmic_recon`, `scheduled_task_enum`, `wifi_evil_twin` |
| Exploitation (11) | `persistence_install`, `keylogger_deploy`, `disable_defender`, `firewall_disable`, `shadow_admin`, `ssh_backdoor`, `rdp_enable`, `uac_bypass`, `dns_poison`, `lsass_dump`, `deploy_toolkit` |
| Shells & C2 (7) | `net_diag`, `reverse_shell`, `linux_reverse_shell`, `mac_reverse_shell`, `linux_cred_dump`, `empire_stager`, `obfuscated_loader` |

**Plus:** 7 IR databases (TVs, ACs, projectors, soundbars, fans, set-top boxes, LEDs), comprehensive Sub-GHz protocol + frequency references, MIFARE key dictionary (150+ keys), NFC attack playbook, RFID cloning guide, iButton database, and full ESP32 GPIO command reference.

See `flipper/FLIPPER_PLAYBOOK.md` for the complete reference with 8 pre-built attack sequences.

Recommended firmware: **Momentum** or **Unleashed** for full Sub-GHz TX unlock.

### Step 6: Set Up Android (Magisk Root)

For the Samsung Galaxy S20+ (or any Android):

1. **Unlock bootloader** — Enable OEM Unlocking in Developer Options
2. **Install Magisk** — Patch boot.img, flash via Odin/Heimdall
3. **Install Termux** — From F-Droid (not Play Store)
4. **Run setup script**:

```bash
# From PC via ADB:
adb push mobile/s20_headless/magisk_setup.sh /sdcard/
adb shell "termux-open /sdcard/magisk_setup.sh"

# Or in Termux directly:
bash magisk_setup.sh
```

This installs:
- 50+ security packages (nmap, aircrack-ng, sqlmap, hydra, hashcat...)
- Python pentest tools (impacket, scapy, mitmproxy, bloodhound...)
- Attack repositories (Empire, Shannon, PathFinder, Tower-Hunter...)
- SSH server (headless remote access)
- Boot services (auto WiFi scan, GPS tracking, cell tower logging)
- Termux Widget shortcuts

Control from PC:
```
python mobile/s20_headless/adb_control.py          # Interactive menu
python mobile/s20_headless/adb_control.py recon     # Run full recon
python mobile/s20_headless/adb_control.py wifi-scan # Quick WiFi scan
python mobile/s20_headless/adb_control.py exfil     # Pull all collected data
```

### Step 7: Set Up Nintendo DSi

Full guide: `mobile/dsi/DSI_FULL_SETUP.md`

1. **Jailbreak** — Memory Pit exploit → Unlaunch → TWiLight Menu++
2. **Load games** — 200+ classics including 35+ Pokemon titles
3. **Install homebrew** — DSLinux, WiFi scanner, DSFTP
4. **Deploy** — `python mobile/dsi/dsi_toolkit.py --sd <path>`

The DSi serves as covert WiFi recon. Nobody suspects a gaming console.

### Step 8: Configure Voice Recorder (Optional)

If using J: drive as an MP3 voice recorder instead of ESP32:

```
python recorder/listener.py --threshold 50 --format mp3
```

Records only when ambient volume exceeds 50dB. Saves compressed audio clips to J:\recordings\.

Build standalone executable:
```
python recorder/build_exe.py
```

---

## How the Autorun Works

When the USB tri-drive is inserted into a target Windows system:

```
USB Insert
    │
    ├── Flipper Zero BadUSB runs phantom_usb.txt (3 seconds)
    │   └── Finds USB drive → launches autorun_service.ps1 silently
    │
    ├── OR: Target clicks run_me.bat (social engineering)
    │   └── Fake "USB Driver Update" progress bar
    │       └── Launches auto_pwn.ps1 + input_monitor.py in background
    │
    ├── OR: Target clicks phantom.bat / setup.bat / install.bat
    │   └── Self-hides immediately → launches full chain
    │
    └── autorun_service.ps1 v2 (Phantom Engine)
        ├── Evasion framework loaded (AMSI/ETW/Defender bypass)
        ├── Sandbox/VM detection with abort logic
        ├── Auto-detects USB drive letters
        ├── Creates loot directory structure on Micro SD
        ├── Launches auto_pwn.ps1 v3 (15-phase attack chain)
        │   ├── Phase 0:   Evasion init + environment fingerprint
        │   ├── Phase 1:   System reconnaissance
        │   ├── Phase 2:   Network lateral movement + AD recon
        │   ├── Phase 3:   Credential harvest (6 browsers + WiFi + cloud)
        │   ├── Phase 4:   DPAPI credential decryption (AES-256-GCM)
        │   ├── Phase 5:   Cloud & SaaS harvesting (M365/Azure/AWS/GCP)
        │   ├── Phase 6:   Communications data (Teams/Slack/Discord/Signal)
        │   ├── Phase 7:   Cryptocurrency wallet hunting (40+ wallets)
        │   ├── Phase 8:   Privilege escalation (17 vectors + UAC bypass)
        │   ├── Phase 9:   SQL injection scan (40+ payloads)
        │   ├── Phase 10:  Application exploitation (Notepad++ DLL hijack)
        │   ├── Phase 11:  Input monitor v2 (keys/mouse/screenshots/network)
        │   ├── Phase 12:  Persistence installation (12 methods)
        │   ├── Phase 13:  Data packaging + network exfiltration
        │   └── Phase 14:  Anti-forensics + cleanup
        ├── Runs inline quick-collect as failsafe
        ├── Timing jitter between phases
        └── Cleans execution traces
```

**Result**: All loot lands in `I:\loot\`. No popups. No alerts. No traces.

---

## Core Tool Suites

### Pentest Suite

`core/pentest_suite.py` — Automated 8-phase penetration testing framework integrating 200+ security tools.

```
python core/pentest_suite.py <target>
```

### OSINT Reconnaissance

`core/osint_recon_suite.py` — Target infrastructure mapping from public sources.

```
python core/osint_recon_suite.py <target>
```

### Galaxy Recon

`core/galaxy_recon_suite.py` — Provide a name. Searches 11 categories automatically (identity, vehicles, property, court records, social media, breach data, etc.).

```
python core/galaxy_recon_suite.py --interactive
```

### People Finder

`core/people_finder.py` — 88+ platform search across social media, people search engines, public records, and news archives.

```
python core/people_finder.py -n "John Doe" -c "New York" -s "NY"
```

---

## Repository Structure

```
FU-PERSON/
│
├── core/                              Primary tool suites
│   ├── pentest_suite.py               Automated penetration testing
│   ├── osint_recon_suite.py           Open-source intelligence
│   ├── galaxy_recon_suite.py          Deep intelligence platform
│   ├── people_finder.py              88+ platform people search
│   ├── repo_collector.py             GitHub repository aggregation
│   ├── list_consolidator.py          Wordlist consolidation
│   ├── consolidated_lists.py         Merged master lists
│   └── data/                          Consolidated wordlists
│
├── payloads/
│   ├── windows/                       Windows target payloads
│   │   ├── auto_pwn.ps1              15-phase attack chain orchestrator (v3)
│   │   ├── autorun_service.ps1       Phantom zero-touch autorun engine (v2)
│   │   ├── evasion.ps1               Universal Defender/EDR bypass framework
│   │   ├── cloud_harvester.ps1       M365/Azure/AWS/GCP token harvester
│   │   ├── comms_harvester.ps1       Teams/Slack/Discord/Signal extractor
│   │   ├── crypto_hunter.ps1         40+ wallet/seed/exchange credential hunter
│   │   ├── persistence_engine.ps1    12-method persistence installer
│   │   ├── ai_evasion.ps1           7-phase AI/ML detection evasion engine
│   │   ├── compliance_scanner.ps1   NIST/CIS/PCI/SOC2 compliance audit engine
│   │   ├── phantom.bat               Silent USB autorun trigger
│   │   ├── windows_collector.ps1     System + browser + credential harvest
│   │   ├── privesc.ps1               Privilege escalation (17 vectors)
│   │   ├── sqli_scanner.ps1          SQL injection automation
│   │   ├── npp_exploit.ps1           DLL hijack + config injection
│   │   ├── input_monitor.py          Input monitor v2 (8-thread capture)
│   │   ├── start_monitor.bat         Silent monitor launcher
│   │   ├── run_me.bat                Social engineering wrapper
│   │   └── windows_collector.bat     CMD fallback collector
│   └── linux/
│       └── linux_collector.sh         Linux collector v2 (12-phase harvest)
│
├── firmware/
│   └── esp32/
│       ├── FLLC_wardriver/
│       │   ├── FLLC_wardriver.ino    11-mode dual-core wardriver
│       │   ├── config.h               Hardware pinout (DevKit V1.1)
│       │   └── oui.h                  3,000+ MAC vendor fingerprints
│       ├── platformio.ini             Build configuration
│       └── flash_esp32.py             Automated flash utility
│
├── flipper/                           Flipper Zero MEGA Arsenal v2.0
│   ├── FLIPPER_PLAYBOOK.md           Complete reference (35+ payloads, 8 attack sequences)
│   ├── badusb/ (35+ payloads)
│   │   ├── phantom_usb.txt           Zero-touch auto-deploy
│   │   ├── auto_pwn_deploy.txt       10-phase attack chain
│   │   ├── stealth_deploy.txt        Base64 EDR bypass
│   │   ├── rapid_exfil.txt           15-second system grab
│   │   ├── full_exfil.txt            Complete data exfil
│   │   ├── credential_dump.txt       All credential types
│   │   ├── sam_dump.txt              Registry hive export
│   │   ├── browser_harvest.txt       Chrome/Edge/Brave/Firefox
│   │   ├── email_harvest.txt         Outlook/Thunderbird/Mail
│   │   ├── token_theft.txt           Discord/Slack/Teams/Telegram
│   │   ├── crypto_wallet.txt         12+ wallet types
│   │   ├── cloud_creds.txt           AWS/Azure/GCP/Docker/K8s
│   │   ├── vpn_creds.txt             VPN configs & creds
│   │   ├── powershell_history.txt    PS history secrets
│   │   ├── env_dump.txt              Environment variables
│   │   ├── ad_enum.txt               Active Directory mapping
│   │   ├── wmic_recon.txt            WMI deep inventory
│   │   ├── scheduled_task_enum.txt   Hijackable task finder
│   │   ├── wifi_evil_twin.txt        Evil twin preparation
│   │   ├── shadow_admin.txt          Hidden admin creation
│   │   ├── ssh_backdoor.txt          SSH persistent access
│   │   ├── rdp_enable.txt            RDP backdoor
│   │   ├── uac_bypass.txt            3-method UAC bypass
│   │   ├── dns_poison.txt            DNS redirect
│   │   ├── lsass_dump.txt            LSASS memory dump
│   │   ├── firewall_disable.txt      Security neutralization
│   │   ├── mac_reverse_shell.txt     macOS reverse shell
│   │   ├── linux_cred_dump.txt       Linux credential dump
│   │   └── ... (+ 8 more)
│   ├── infrared/ (7 databases, 290+ signals)
│   │   ├── tv_off_universal.ir       40+ TV brands
│   │   ├── ac_universal.ir           60+ AC brands
│   │   ├── projector_universal.ir    25+ projector brands
│   │   ├── soundbar_universal.ir     30+ soundbar brands
│   │   ├── fan_universal.ir          20+ fan brands
│   │   ├── settopbox_universal.ir    Cable/streaming devices
│   │   └── led_universal.ir          LED strip controllers
│   ├── subghz/ (7 references)
│   │   ├── frequencies.txt           Master frequency database
│   │   ├── protocols_reference.txt   30+ protocol encyclopedia
│   │   ├── garage_door_codes.txt     8+ garage systems
│   │   ├── vehicle_keyfobs.txt       Manufacturer CVEs + TPMS
│   │   ├── security_systems.txt      Alarm exploitation
│   │   ├── iot_devices.txt           Smart home devices
│   │   └── regional_regulations.txt  Legal frequency bands
│   ├── nfc/ (5 tools, 150+ keys)
│   │   ├── mifare_keys.txt           150+ MIFARE Classic keys
│   │   ├── card_formats.txt          Card format encyclopedia
│   │   ├── emv_reference.txt         EMV contactless reference
│   │   ├── ndef_payloads.txt         Evil NFC tag templates
│   │   └── attack_playbook.txt       NFC attack methodology
│   ├── rfid/
│   │   └── format_database.txt       19 protocols + attacks
│   ├── ibutton/
│   │   └── types_database.txt        25+ types + cloning guide
│   └── gpio/ (4 references)
│       ├── marauder_commands.txt      Marauder command set
│       ├── esp32_advanced.txt         Full ESP32 reference
│       ├── ble_attacks.txt            BLE attack techniques
│       └── auto_recon.txt             Automated recon
│
├── mobile/
│   ├── s20_headless/                  Android attack platform
│   │   ├── magisk_setup.sh           Full Magisk + Termux + tools setup
│   │   ├── setup_termux.sh           Termux package installation
│   │   ├── headless_recon.sh         Automated WiFi/BLE/GPS/network recon
│   │   ├── wifi_attacks.sh           Wireless attack automation
│   │   ├── adb_control.py            PC remote control interface
│   │   └── scrcpy_setup.bat          Screen mirroring configuration
│   └── dsi/
│       ├── DSI_FULL_SETUP.md         Complete jailbreak + game library guide
│       └── dsi_toolkit.py            SD card builder (ROMs, homebrew, tools)
│
├── recorder/                          Voice-activated audio capture
│   ├── listener.py                    50dB threshold recording engine
│   ├── build_exe.py                   PyInstaller standalone build
│   ├── start_listener.bat            Silent background launcher
│   └── requirements.txt              Audio dependencies
│
├── deploy/                            Deployment automation
│   ├── build_usb.py                   Tri-drive deployment orchestrator
│   ├── Build_USB_Drives.bat          One-click deployment
│   ├── Install_Dependencies.bat      Python dependency installer
│   ├── LAUNCH.bat                     Unified tool launcher
│   └── Run_*.bat                      Individual tool launchers
│
├── docs/                              Documentation
│   ├── DRIVE_LAYOUT.md               Tri-drive mapping reference
│   ├── PENTEST_DOCUMENTATION.md      Pentest suite technical reference
│   ├── OSINT_QUICK_START.md          OSINT quick-start guide
│   ├── OSINT_README.md               OSINT suite overview
│   ├── TOOL_INSTALLATION.md          Dependency installation guide
│   ├── QUICK_REFERENCE.txt           Command cheat sheet
│   ├── AI_THREAT_LANDSCAPE_2026.md   AI defense/offense threat mapping
│   ├── COMPLIANCE_FRAMEWORK.md       Compliance-to-pentest control mapping
│   └── SATELLITE_LINKS.md            All FLLC satellite repository links
│
├── LICENSE                            FU PERSON Source-Available License v1.0
├── SECURITY.md                        Vulnerability disclosure policy
├── CONTRIBUTING.md                    Contribution policy
└── requirements.txt                   Python dependencies
```

---

## Data Sources

Wordlists and reference data aggregated from 13+ public repositories:

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
