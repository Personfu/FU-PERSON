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

FU PERSON is built around a multi-device attack platform:

| Device | Role | Description |
|--------|------|-------------|
| **USB Tri-Drive** | Core Platform | SD (H:) + Micro SD (I:) + ESP32/Recorder (J:) |
| **Flipper Zero** | Field Tool | 18 BadUSB payloads, GPIO ESP32 bridge, Sub-GHz, NFC, IR |
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

Copy payloads to your Flipper Zero (via qFlipper or USB):

```
flipper/badusb/*.txt    → SD Card/badusb/
flipper/gpio/*.txt      → SD Card/gpio/
flipper/subghz/*.txt    → SD Card/subghz/
flipper/nfc/*.txt       → SD Card/nfc/
flipper/infrared/*.ir   → SD Card/infrared/
```

**18 BadUSB payloads** ready to deploy:

| Category | Payloads |
|----------|----------|
| Auto-Deploy | `phantom_usb.txt`, `auto_pwn_deploy.txt`, `stealth_deploy.txt` |
| Exfiltration | `rapid_exfil.txt`, `full_exfil.txt`, `credential_dump.txt`, `sam_dump.txt` |
| Recon | `network_recon.txt`, `wifi_passwords.txt`, `recon_launch.txt` |
| Persistence | `persistence_install.txt`, `keylogger_deploy.txt`, `disable_defender.txt` |
| Reverse Shells | `net_diag.txt`, `reverse_shell.txt`, `linux_reverse_shell.txt` |
| Post-Exploit | `empire_stager.txt`, `obfuscated_loader.txt` |

See `flipper/FLIPPER_PLAYBOOK.md` for full attack sequences and timing.

Recommended firmware: **Momentum** or **Unleashed** for maximum capability.

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
    └── autorun_service.ps1 (Phantom Engine)
        ├── Auto-detects USB drive letters
        ├── Sets stealth mode (AMSI bypass, ETW patch, low priority)
        ├── Creates loot directory structure on Micro SD
        ├── Launches auto_pwn.ps1 (10-phase attack chain)
        │   ├── Phase 0:   Environment fingerprint + defense enum
        │   ├── Phase 1:   System reconnaissance
        │   ├── Phase 1.5: Lateral movement + AD recon
        │   ├── Phase 2:   Credential harvest (6 browsers + WiFi + cloud)
        │   ├── Phase 2.5: DPAPI credential decryption
        │   ├── Phase 3:   Privilege escalation (17 vectors + UAC bypass)
        │   ├── Phase 4:   SQL injection scan
        │   ├── Phase 5:   Application exploitation (Notepad++ DLL hijack)
        │   ├── Phase 6:   Input monitor (keystrokes, screenshots)
        │   ├── Phase 7:   Data aggregation
        │   └── Phase 7.5: Network exfiltration (DNS/HTTP)
        ├── Runs inline quick-collect as failsafe
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
│   │   ├── auto_pwn.ps1              10-phase attack chain orchestrator
│   │   ├── autorun_service.ps1       Phantom zero-touch autorun engine
│   │   ├── phantom.bat               Silent USB autorun trigger
│   │   ├── windows_collector.ps1     System + browser + credential harvest
│   │   ├── privesc.ps1               Privilege escalation (17 vectors)
│   │   ├── sqli_scanner.ps1          SQL injection automation
│   │   ├── npp_exploit.ps1           DLL hijack + config injection
│   │   ├── input_monitor.py          Keystrokes, mouse, clipboard, screenshots
│   │   ├── start_monitor.bat         Silent monitor launcher
│   │   ├── run_me.bat                Social engineering wrapper
│   │   └── windows_collector.bat     CMD fallback collector
│   └── linux/
│       └── linux_collector.sh         Linux + cloud + K8s + Docker harvest
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
├── flipper/                           Flipper Zero — 18 payloads
│   ├── FLIPPER_PLAYBOOK.md           Complete attack playbook
│   ├── badusb/                        18 DuckyScript payloads
│   │   ├── phantom_usb.txt           Zero-touch auto-deploy
│   │   ├── auto_pwn_deploy.txt       Full attack chain deploy
│   │   ├── stealth_deploy.txt        Base64 EDR bypass variant
│   │   ├── rapid_exfil.txt           15-second full system grab
│   │   ├── full_exfil.txt            Complete data exfiltration
│   │   ├── credential_dump.txt       Browser + cloud + token dump
│   │   ├── sam_dump.txt              Windows password hash export
│   │   ├── network_recon.txt         Full network map in 30 seconds
│   │   ├── wifi_passwords.txt        Saved WiFi credential extraction
│   │   ├── recon_launch.txt          Automated recon kickoff
│   │   ├── persistence_install.txt   Scheduled task + registry persistence
│   │   ├── keylogger_deploy.txt      Silent input monitor deployment
│   │   ├── disable_defender.txt      Windows Defender neutralization
│   │   ├── deploy_toolkit.txt        Copy toolkit to target
│   │   ├── net_diag.txt              Encoded reverse shell (AV bypass)
│   │   ├── reverse_shell.txt         PowerShell reverse shell
│   │   ├── linux_reverse_shell.txt   Linux target reverse shell
│   │   ├── empire_stager.txt         PowerShell Empire stager
│   │   └── obfuscated_loader.txt     Multi-stage obfuscated loader
│   ├── gpio/                          ESP32 bridge commands
│   ├── subghz/                        Sub-GHz frequency database
│   ├── nfc/                           NFC/RFID attack playbook
│   └── infrared/                      Universal IR codes
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
│   └── QUICK_REFERENCE.txt           Command cheat sheet
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
