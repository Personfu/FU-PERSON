<div align="center">

# FU PERSON — v2.0

```
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**USB Tri-Drive Automated Extraction Platform**

[![Version](https://img.shields.io/badge/Version-2.0-00FFFF?style=for-the-badge)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-Native-FF00FF?style=for-the-badge)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-ZERO-00FF88?style=for-the-badge)]()

</div>

---

## What This Does

You plug the USB tri-drive into a target PC. **One PowerShell script** silently extracts everything and dumps it to your MicroSD. No Java. No Python. No installs. Zero dependencies. Pure native Windows.

```
Property of FLLC | Source-Available | Authorized Use Only
```

---

## How It Works

```
USB Tri-Drive
├── SD Card (H:)    ← Contains the attack payload
└── MicroSD (I:)    ← Receives all stolen data

Trigger Options:
├── Option A: Flipper Zero BadUSB types the command automatically (zero-click)
└── Option B: Target clicks "setup.bat" (social engineering — "install USB drivers")

Either way → harvest.ps1 runs hidden → dumps everything to MicroSD → cleans traces
```

---

## What Gets Extracted (11 Phases, ~60 seconds)

| Phase | What | Details |
|-------|------|---------|
| **1** | System Recon | Hostname, users, admins, processes, services, installed software, scheduled tasks, AV status, USB history, PowerShell history |
| **2** | Network Intel | IP config, ARP table, active connections, routes, DNS cache, shares, firewall rules, WiFi interfaces, domain info |
| **3** | WiFi Passwords | **Every saved WiFi network** — SSID + plaintext password |
| **4** | Browser Data | Login databases, cookies, history, bookmarks from **Chrome, Edge, Brave, Opera, OperaGX, Vivaldi, Firefox** + DPAPI master keys |
| **5** | Windows Creds | Credential Manager, saved RDP connections, PuTTY sessions, SSH keys, AWS/Azure/GCP tokens, Docker/K8s configs, Git credentials |
| **6** | App Data | Discord tokens, Telegram data, Slack storage, Teams cookies, Signal DB + key, VPN configs, Thunderbird passwords, FileZilla/WinSCP sessions |
| **7** | File Hunting | Password grep across all configs, `.env` files, recent docs, desktop/downloads listing, KeePass databases, certificates, SQL backups, sticky notes |
| **8** | Crypto Wallets | Exodus, Electrum, Atomic, Coinomi, Guarda, Wasabi, Bitcoin Core, Ethereum keystore, MetaMask (Chrome+Edge), Phantom + seed phrase search |
| **9** | Priv Esc Recon | Unquoted service paths, writable PATH dirs, AlwaysInstallElevated, autologon creds, token privileges, DLL hijack opportunities |
| **10** | Screenshot | Full-screen capture + clipboard text |
| **11** | Cleanup | Clear PS history, Run dialog MRU, prefetch traces |

**All loot lands in:** `MicroSD:\loot\HOSTNAME_TIMESTAMP\` with a `MANIFEST.txt` summary.

---

## Setup (5 minutes, one time)

### Step 1: Deploy to drives

```
Double-click: usb_payload\DEPLOY.bat
```

This copies:
- **SD Card (H:)** — `setup.bat` (trigger), `.p\harvest.ps1` (hidden payload), `README.txt` (bait)
- **MicroSD (I:)** — `.loot_target` (hidden marker), `loot\` directory

### Step 2: Flipper Zero (optional, for auto-trigger)

Copy `usb_payload\flipper_badusb\usb_harvest.txt` to your Flipper Zero SD card under `badusb/`.

When plugged into a target PC, Flipper types the launch command in under 2 seconds.

### Step 3: Insert and walk away

**With Flipper Zero:** Plug in USB + run BadUSB payload → fully automated, zero-click.

**Without Flipper:** Target sees `setup.bat` labeled as "USB Driver Setup" → clicks it → payload runs silently in background while a fake progress bar shows.

Retrieve MicroSD later. All data is in `loot\`.

---

## Drive Detection

The payload automatically finds your drives:

1. Looks for `.loot_target` marker → that's the MicroSD
2. Looks for `.p\harvest.ps1` → that's the SD card
3. Fallback: smallest removable drive = MicroSD, largest = SD
4. Last resort: tries I:, H:, G:, F:, E:, D: in order

**You don't need to hardcode drive letters.** It just works.

---

## Why PowerShell (Not Java/Python/SQL)

| Language | Problem | Reality |
|----------|---------|---------|
| **Java** | Needs JRE installed | 90% of PCs don't have it → dead on arrival |
| **Python** | Needs Python installed | Same problem → useless for USB drops |
| **SQL Injection** | Attacks web apps, not the PC itself | Irrelevant for a USB payload |
| **PowerShell** | **Native on every Windows PC since 2009** | Zero installs. Zero dependencies. Instant execution. |

PowerShell can do everything: registry access, file system, WMI, networking, cryptography, COM objects, .NET reflection, Win32 API calls. It's the only correct choice for a USB drop tool.

---

## Repository Structure

```
FU-PERSON/
│
├── usb_payload/                    ← READY-TO-DEPLOY USB FILES
│   ├── DEPLOY.bat                  One-click deployment to SD + MicroSD
│   ├── sd_card/                    Goes on SD Card (H:)
│   │   ├── setup.bat              Social engineering trigger
│   │   ├── README.txt             Bait file
│   │   └── .p/                    Hidden payload folder
│   │       └── harvest.ps1        THE WEAPON — one file, zero deps
│   ├── microsd/                   Goes on MicroSD (I:)
│   │   └── .loot_target           Drive identification marker
│   └── flipper_badusb/            Goes on Flipper Zero
│       └── usb_harvest.txt        Zero-click auto-launch BadUSB
│
├── core/                          Python OSINT + pentest tools (laptop use)
│   ├── pentest_suite.py           Automated penetration testing
│   ├── osint_recon_suite.py       Open-source intelligence
│   ├── galaxy_recon_suite.py      Deep intelligence platform
│   ├── people_finder.py           88+ platform people search
│   ├── repo_collector.py          GitHub repository aggregation
│   ├── list_consolidator.py       Wordlist consolidation
│   └── data/                      Consolidated wordlists
│
├── payloads/                      Extended payload modules
│   ├── windows/                   Advanced Windows attack scripts
│   │   ├── auto_pwn.ps1          15-phase attack orchestrator
│   │   ├── evasion.ps1           AMSI/ETW/Defender bypass
│   │   ├── ai_evasion.ps1        7-phase AI/ML EDR evasion
│   │   ├── compliance_scanner.ps1 NIST/CIS/PCI/SOC2 audit
│   │   ├── cloud_harvester.ps1   Cloud token harvesting
│   │   ├── comms_harvester.ps1   Comms app data extraction
│   │   ├── crypto_hunter.ps1     Wallet + seed hunting
│   │   ├── persistence_engine.ps1 12-method persistence
│   │   ├── privesc.ps1           Privilege escalation
│   │   ├── sqli_scanner.ps1      SQL injection automation
│   │   ├── npp_exploit.ps1       App exploitation
│   │   └── input_monitor.py      Keystroke + screenshot logger
│   └── linux/
│       └── linux_collector.sh    Linux data collection
│
├── firmware/esp32/                ESP32 wardriver firmware
├── flipper/                       Flipper Zero MEGA arsenal (35+ payloads)
├── mobile/                        Android S20+ / DSi setup
├── recorder/                      Voice-activated recorder
├── deploy/                        Legacy deployment scripts
├── docs/                          Documentation
│
├── LICENSE                        Source-Available License
├── SECURITY.md                    Vulnerability disclosure
└── requirements.txt               Python deps (for laptop tools only)
```

---

## The Kill Chain

```
┌─────────────────────────────────────────────────────────────────┐
│  INSERT USB                                                      │
│  ↓                                                               │
│  TRIGGER (Flipper BadUSB or setup.bat click)                     │
│  ↓                                                               │
│  harvest.ps1 launches hidden — no window, no popup, no trace     │
│  ↓                                                               │
│  AMSI bypass → ETW blind → script log disable                    │
│  ↓                                                               │
│  Auto-detect SD card (payload) and MicroSD (loot target)         │
│  ↓                                                               │
│  11-phase extraction: system → network → wifi → browsers →       │
│  credentials → apps → files → crypto → privesc → screenshot      │
│  ↓                                                               │
│  All data dumped to MicroSD:\loot\HOSTNAME_TIMESTAMP\            │
│  ↓                                                               │
│  MANIFEST.txt generated with summary                             │
│  ↓                                                               │
│  Cleanup: history cleared, traces removed                        │
│  ↓                                                               │
│  DONE — ~60 seconds — retrieve MicroSD later                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Legal

**FU PERSON Source-Available License v1.0** — Copyright (c) 2025-2026 FLLC.

This software is for **authorized security testing only**. Unauthorized access to computer systems is a federal crime under 18 U.S.C. 1030. You are solely responsible for ensuring your use complies with applicable law. Do not use against any system without explicit written authorization.

**Contact:** preston@fllc.net

---

**FLLC** | 2026

*Insert. Extract. Retrieve.*
