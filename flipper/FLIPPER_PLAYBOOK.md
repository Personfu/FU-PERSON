# Flipper Zero — FU PERSON MEGA Arsenal v2.0

**FLLC | 35 BadUSB Payloads | 7 IR Databases | 8 Sub-GHz References | 5 NFC Tools | RFID + iButton + GPIO**

> *"Every frequency. Every protocol. Every attack vector. One device."*
> — PERSON FU

---

## Table of Contents

1. [BadUSB Payloads (35 Total)](#badusb-payloads-35-total)
2. [Infrared Arsenal (7 Databases)](#infrared-arsenal-7-databases)
3. [Sub-GHz Module (8 References)](#sub-ghz-module-8-references)
4. [NFC / 13.56MHz (5 Tools)](#nfc--1356mhz-5-tools)
5. [125kHz RFID](#125khz-rfid)
6. [iButton (1-Wire)](#ibutton-1-wire)
7. [GPIO — ESP32 Bridge (4 References)](#gpio--esp32-bridge-4-references)
8. [Attack Sequences](#attack-sequences)
9. [Setup Guide](#setup-guide)

---

## BadUSB Payloads (35 Total)

### Automated Attack Chain (Zero-Touch)
| # | Payload | File | Time | Description |
|---|---------|------|------|-------------|
| 1 | **Phantom USB** | `phantom_usb.txt` | 3s | Auto-deploy. Finds USB, launches 10-phase chain silently. |
| 2 | **Auto-Pwn Deploy** | `auto_pwn_deploy.txt` | 5s | Deploy `auto_pwn.ps1` with anti-detection. |
| 3 | **Stealth Deploy** | `stealth_deploy.txt` | 5s | Base64-encoded variant for EDR/AMSI bypass. |

### Data Exfiltration
| # | Payload | File | Time | Description |
|---|---------|------|------|-------------|
| 4 | **Rapid Exfil** | `rapid_exfil.txt` | 15s | WiFi passwords, system info, recent files. Fastest grab. |
| 5 | **Full Exfil** | `full_exfil.txt` | 30s | Complete system dump — browser, creds, network. |
| 6 | **Credential Dump** | `credential_dump.txt` | 20s | Browser DBs, SSH keys, cloud creds, tokens, vault. |
| 7 | **SAM Dump** | `sam_dump.txt` | 10s | Registry hive export (SAM/SYSTEM/SECURITY). Admin req. |
| 8 | **Browser Harvest** | `browser_harvest.txt` | 15s | Chrome/Edge/Brave/Firefox history, cookies, bookmarks, logins. |
| 9 | **Email Harvest** | `email_harvest.txt` | 15s | Outlook PST/OST, Thunderbird profiles, Windows Mail. |
| 10 | **Token Theft** | `token_theft.txt` | 12s | Discord, Slack, Teams, Telegram, browser session tokens. |
| 11 | **Crypto Wallet** | `crypto_wallet.txt` | 15s | Bitcoin, Electrum, Exodus, MetaMask, Phantom, 12+ wallets. |
| 12 | **Cloud Creds** | `cloud_creds.txt` | 15s | AWS/Azure/GCP/Docker/K8s/SSH/NPM/Git credentials. |
| 13 | **VPN Creds** | `vpn_creds.txt` | 10s | OpenVPN, WireGuard, Cisco, FortiClient, NordVPN configs. |
| 14 | **PowerShell History** | `powershell_history.txt` | 8s | PS history, secrets in commands, recent scripts. |
| 15 | **Env Dump** | `env_dump.txt` | 5s | All env vars, PATH, registry secrets, API keys. |

### Reconnaissance
| # | Payload | File | Time | Description |
|---|---------|------|------|-------------|
| 16 | **Network Recon** | `network_recon.txt` | 30s | Full network map — hosts, ports, shares, domain, firewall. |
| 17 | **WiFi Passwords** | `wifi_passwords.txt` | 10s | All saved WiFi credentials in plaintext. |
| 18 | **Recon Launch** | `recon_launch.txt` | 5s | Start automated recon from USB toolkit. |
| 19 | **AD Enumeration** | `ad_enum.txt` | 20s | Domain controllers, users, groups, GPOs, trusts, policies. |
| 20 | **WMI Deep Recon** | `wmic_recon.txt` | 15s | Full WMI inventory — software, services, hardware, shares. |
| 21 | **Sched Task Enum** | `scheduled_task_enum.txt` | 10s | All tasks + identifies writable/hijackable binaries. |
| 22 | **WiFi Evil Twin** | `wifi_evil_twin.txt` | 12s | Prep for evil twin — clone strongest nearby SSID. |

### Persistence & Exploitation
| # | Payload | File | Time | Description |
|---|---------|------|------|-------------|
| 23 | **Persistence Install** | `persistence_install.txt` | 5s | Scheduled task + registry run key. Survives reboots. |
| 24 | **Keylogger Deploy** | `keylogger_deploy.txt` | 5s | Silent input monitor (keys, mouse, clipboard, screenshots). |
| 25 | **Disable Defender** | `disable_defender.txt` | 5s | Neutralize Windows Defender via encoded commands. |
| 26 | **Firewall Disable** | `firewall_disable.txt` | 10s | Kill firewall, open ports, stop AV services. Admin req. |
| 27 | **Deploy Toolkit** | `deploy_toolkit.txt` | 10s | Copy entire FU PERSON toolkit from USB to target. |
| 28 | **Shadow Admin** | `shadow_admin.txt` | 8s | Hidden admin account (svc_update), invisible on login screen. |
| 29 | **SSH Backdoor** | `ssh_backdoor.txt` | 10s | Enable OpenSSH, open port 22, set auto-start. |
| 30 | **RDP Enable** | `rdp_enable.txt` | 10s | Enable RDP, disable NLA, open firewall. |
| 31 | **UAC Bypass** | `uac_bypass.txt` | 8s | 3-method UAC bypass chain (fodhelper/ComputerDefaults/sluihostex). |
| 32 | **DNS Poison** | `dns_poison.txt` | 10s | Hosts file + DNS redirect to attacker server. |
| 33 | **LSASS Dump** | `lsass_dump.txt` | 10s | Dump LSASS memory for offline hash extraction. Admin req. |

### Reverse Shells & C2
| # | Payload | File | Time | Description |
|---|---------|------|------|-------------|
| 34 | **Net Diag** | `net_diag.txt` | 3s | Encoded PS reverse shell (AV bypass). |
| 35 | **Reverse Shell** | `reverse_shell.txt` | 3s | Standard PowerShell reverse shell. |
| 36 | **Linux Rev Shell** | `linux_reverse_shell.txt` | 3s | Bash reverse shell for Linux. |
| 37 | **Mac Rev Shell** | `mac_reverse_shell.txt` | 5s | Python reverse shell for macOS. |
| 38 | **Linux Cred Dump** | `linux_cred_dump.txt` | 10s | Linux: SSH keys, shadow, history, SUID, crons. |
| 39 | **Empire Stager** | `empire_stager.txt` | 5s | PowerShell Empire C2 stager. |
| 40 | **Obfuscated Loader** | `obfuscated_loader.txt` | 5s | Multi-stage obfuscated payload loader. |

---

## Infrared Arsenal (7 Databases)

| File | Signals | Coverage |
|------|---------|----------|
| `infrared/tv_off_universal.ir` | 40+ | Samsung, LG, Sony, Vizio, TCL, Hisense, Panasonic, Sharp, Toshiba, Philips, Sanyo, Magnavox, JVC, Hitachi, Haier, RCA, Funai, Pioneer, and more |
| `infrared/ac_universal.ir` | 30+ | Samsung, LG, Daikin, Mitsubishi, Fujitsu, Carrier, Toshiba, Hitachi, Midea, Gree, Haier, Whirlpool, York, Panasonic, Sharp, Electrolux, Hisense, Chigo, TCL |
| `infrared/projector_universal.ir` | 40+ | Epson, BenQ, Optoma, ViewSonic, Acer, InFocus, NEC, Sony, Panasonic, Hitachi, Casio, LG, Vivitek, XGIMI, Dell, Canon, JVC |
| `infrared/soundbar_universal.ir` | 55+ | Samsung, LG, Sony, Vizio, Bose, JBL, Yamaha, Sonos, Denon, Polk, Harman Kardon, TCL, Hisense |
| `infrared/fan_universal.ir` | 35+ | Dyson, Honeywell, Lasko, Hunter, Hampton Bay, Vornado, Rowenta, Dreo |
| `infrared/settopbox_universal.ir` | 50+ | Xfinity, DirecTV, Dish, Roku (full remote), Fire TV (full), Apple TV, Nvidia Shield, Spectrum, AT&T |
| `infrared/led_universal.ir` | 40+ | 24-key LED controller, 44-key LED controller (all colors, modes, speeds) |

**Total IR Signals: 290+**

**Usage:** Flipper -> Infrared -> Saved -> Select file -> Send All (or individual)

---

## Sub-GHz Module (8 References)

| File | Content |
|------|---------|
| `subghz/frequencies.txt` | Master frequency database — garage, car, IoT, pager, ham |
| `subghz/protocols_reference.txt` | Protocol encyclopedia — 30+ protocols, modulation types, Flipper presets |
| `subghz/garage_door_codes.txt` | Garage system attack guide — Chamberlain, Genie, Linear, Nice, CAME, Hormann, FAAC, BFT, Marantec |
| `subghz/vehicle_keyfobs.txt` | Vehicle RKE reference — manufacturer protocols, known CVEs, TPMS tracking |
| `subghz/security_systems.txt` | Alarm system exploitation — Honeywell, ADT, SimpliSafe, Ring, DSC, Interlogix |
| `subghz/iot_devices.txt` | IoT device database — smart outlets, weather stations, doorbells, meters |
| `subghz/regional_regulations.txt` | Legal frequency bands — US, EU, UK, Japan, Australia, China |

### Key Sub-GHz Capabilities
- **Fixed Code Replay** — Capture once, replay forever (Princeton, Nice FLO, CAME, Linear)
- **Rolling Code Analysis** — Rolljam attack flow for KeeLoq, Security+, FloR-S
- **Signal Jamming** — Suppress security sensor communications
- **TPMS Tracking** — Read tire sensors for vehicle identification
- **Frequency Analyzer** — Find what's transmitting in the area
- **RAW Capture** — Record any Sub-GHz signal for offline analysis

---

## NFC / 13.56MHz (5 Tools)

| File | Content |
|------|---------|
| `nfc/attack_playbook.txt` | Complete NFC attack methodology — 5 attack types with step-by-step |
| `nfc/mifare_keys.txt` | 150+ MIFARE Classic keys — factory, transit, hotel, parking, elevator |
| `nfc/card_formats.txt` | Card format encyclopedia — 125kHz & 13.56MHz types, Wiegand layouts |
| `nfc/ndef_payloads.txt` | Evil NFC tag templates — WiFi harvest, phishing, SMS, BT pair, vCard |
| `nfc/emv_reference.txt` | EMV contactless card reference — AIDs, data fields, BIN ranges |

### NFC Attack Types
1. **Badge Cloning** — Read 125kHz badge -> write to T5577 blank
2. **MIFARE Classic Cracking** — Dictionary + nested attack with 150+ keys
3. **EMV Card Reading** — Capture cardholder name, PAN, expiry from wallets
4. **NTAG Manipulation** — Write evil URLs, WiFi configs, vCards to tags
5. **Detect Reader** — Capture authentication keys from card readers

---

## 125kHz RFID

| File | Content |
|------|---------|
| `rfid/format_database.txt` | Full RFID attack playbook — 19 protocols, cloning, brute force, social engineering |

### Supported Protocols
EM4100, HID ProxCard (26/34/37-bit), Indala, AWID, Viking, Pyramid, Keri, FDX-A/B, PAC/Stanley, Nexwatch, Securakey, GProx II, Noralsy, IoProx, Jablotron, Paradox

### Key RFID Attacks
- **Read & Clone** — Badge to T5577 in under 3 seconds
- **Emulation** — Flipper becomes the badge
- **Brute Force** — Increment card numbers against reader
- **Downgrade** — Hit 125kHz side of dual-frequency systems

---

## iButton (1-Wire)

| File | Content |
|------|---------|
| `ibutton/types_database.txt` | Complete iButton type reference — 25+ models, attack scenarios |

### Key iButton Attacks
- **DS1990A Cloning** — Zero-security access keys, instant clone
- **RW1990 Writing** — Clone to blank iButton ($1 each)
- **Emulation** — Flipper becomes the iButton
- **Apartment/Building Access** — Intercoms, elevators, parking gates

---

## GPIO — ESP32 Bridge (4 References)

| File | Content |
|------|---------|
| `gpio/marauder_commands.txt` | Full Marauder command reference for ESP32 |
| `gpio/auto_recon.txt` | Automated wireless recon sequences |
| `gpio/esp32_advanced.txt` | Advanced ESP32 commands, PCAP, attack chains, DIYMalls pinout |
| `gpio/ble_attacks.txt` | BLE attack techniques — spam, tracking, device ID, correlation |

### ESP32 via Flipper GPIO
```
scanap          — WiFi AP scan
scansta         — Client scan
sniff pmkid     — PMKID hash capture (no client needed!)
attack -t deauth— Deauth all clients
attack -t rogue — Evil Twin with captive portal
attack -t karma — Respond to all probe requests
scan ble        — BLE device enumeration
pcap start      — Wireshark-compatible capture to SD
```

### Wiring (Flipper -> ESP32 DevKit V1.1)
```
Flipper TX  (pin 13) -> ESP32 RX (GPIO 3)
Flipper RX  (pin 14) -> ESP32 TX (GPIO 1)
Flipper GND (pin 18) -> ESP32 GND
Flipper 5V  (pin 1)  -> ESP32 VIN
```

---

## Attack Sequences

### Sequence 1: "Walk-By" — 30 seconds, zero touch
1. Plug Flipper as BadUSB
2. Run `phantom_usb.txt` (3s) — auto-deploys everything
3. Unplug and walk away
4. Full 10-phase attack chain runs silently in background
5. Collect USB later for loot

### Sequence 2: "Smash & Grab" — 20 seconds
1. `rapid_exfil.txt` — WiFi creds, system info, files
2. `browser_harvest.txt` — All browser data
3. `token_theft.txt` — Discord/Slack/Teams tokens
4. Unplug. All data on USB.

### Sequence 3: "Persistent Ghost" — 15 seconds
1. `phantom_usb.txt` (3s)
2. `persistence_install.txt` (5s) — survives reboot
3. `keylogger_deploy.txt` (5s) — continuous capture
4. Unplug. Target silently compromised. Survives reboot.

### Sequence 4: "Full Scorched Earth" — 90 seconds
1. `disable_defender.txt` (5s)
2. `uac_bypass.txt` (8s)
3. `auto_pwn_deploy.txt` (5s) — 10-phase attack
4. `shadow_admin.txt` (8s) — hidden admin account
5. `ssh_backdoor.txt` (10s) — SSH access
6. `rdp_enable.txt` (10s) — RDP access
7. `persistence_install.txt` (5s)
8. Wait 30s for initial data collection
9. Unplug. You now have: all creds, hidden admin, SSH, RDP, persistent keylogger.

### Sequence 5: "Domain Takeover"
1. `disable_defender.txt` (5s)
2. `sam_dump.txt` (10s) — registry hives
3. `lsass_dump.txt` (10s) — LSASS memory
4. `ad_enum.txt` (20s) — full AD map
5. `credential_dump.txt` (20s) — all creds
6. `network_recon.txt` (30s) — network map
7. Offline: crack hashes, escalate, pivot

### Sequence 6: "Cloud Heist" — 45 seconds
1. `cloud_creds.txt` (15s) — AWS/Azure/GCP
2. `env_dump.txt` (5s) — API keys in env vars
3. `vpn_creds.txt` (10s) — VPN configs
4. `powershell_history.txt` (8s) — secrets in history
5. Unplug. You now have cloud access keys.

### Sequence 7: "Crypto Raid" — 30 seconds
1. `crypto_wallet.txt` (15s) — all wallet files
2. `browser_harvest.txt` (15s) — extension data
3. Unplug. Wallet files ready for extraction.

### Sequence 8: "RF Chaos" — Physical proximity
1. Sub-GHz: Frequency Analyzer to find active signals
2. Sub-GHz: Capture garage/gate remote
3. IR: Kill every TV/projector in the room
4. NFC: Read badges from people nearby
5. BLE: Spam Apple/Android notification floods
6. iButton: Clone building access keys

---

## Setup Guide

### Step 1: Install Custom Firmware
**Momentum** (recommended) or **Unleashed** required for full Sub-GHz TX.

- Momentum: https://github.com/Next-Flip/Momentum-Firmware
- Unleashed: https://github.com/DarkFlippers/unleashed-firmware

Install via qFlipper or web updater at lab.flipper.net

### Step 2: Deploy FU PERSON Arsenal
```
# Connect Flipper to PC via USB, open SD card
# Copy entire flipper/ directory structure:

flipper/
  badusb/          -> SD Card/badusb/
  infrared/        -> SD Card/infrared/
  subghz/          -> SD Card/subghz/
  nfc/             -> SD Card/nfc/
  rfid/            -> SD Card/rfid/
  ibutton/         -> SD Card/ibutton/
  gpio/            -> SD Card/gpio/
```

### Step 3: Wire ESP32 (Optional)
Connect ESP32 DevKit V1.1 via GPIO for WiFi/BLE attacks.
See `gpio/esp32_advanced.txt` for full pinout.

### Step 4: Acquire Blank Cards
- **T5577** (125kHz RFID cloning) — $1 each
- **MIFARE Classic 1K UID-changeable (Gen2/CUID)** — $2-3 each
- **NTAG215** (NFC tag attacks) — $0.25-0.50 each
- **RW1990** (iButton cloning) — $1 each

### Step 5: Load MIFARE Keys
Copy `nfc/mifare_keys.txt` to `SD Card/nfc/assets/` for automatic key recovery during MIFARE Classic reads.

---

## File Tree

```
flipper/
+-- FLIPPER_PLAYBOOK.md          <-- You are here
+-- badusb/
|   +-- ad_enum.txt              Active Directory enumeration
|   +-- auto_pwn_deploy.txt      10-phase auto-attack deploy
|   +-- browser_harvest.txt      Browser data steal
|   +-- cloud_creds.txt          Cloud credential extraction
|   +-- credential_dump.txt      Full credential dump
|   +-- crypto_wallet.txt        Crypto wallet finder
|   +-- deploy_toolkit.txt       Deploy full toolkit
|   +-- disable_defender.txt     Kill Windows Defender
|   +-- dns_poison.txt           DNS/hosts poisoning
|   +-- email_harvest.txt        Email client data
|   +-- empire_stager.txt        Empire C2 stager
|   +-- env_dump.txt             Environment variables
|   +-- firewall_disable.txt     Firewall neutralization
|   +-- full_exfil.txt           Full system exfil
|   +-- keylogger_deploy.txt     Input monitor deploy
|   +-- linux_cred_dump.txt      Linux credential dump
|   +-- linux_reverse_shell.txt  Linux bash reverse shell
|   +-- lsass_dump.txt           LSASS memory dump
|   +-- mac_reverse_shell.txt    macOS Python reverse shell
|   +-- net_diag.txt             Encoded reverse shell
|   +-- network_recon.txt        Network mapping
|   +-- obfuscated_loader.txt    Multi-stage loader
|   +-- persistence_install.txt  Reboot persistence
|   +-- phantom_usb.txt          Zero-touch auto-deploy
|   +-- powershell_history.txt   PS history & secrets
|   +-- rapid_exfil.txt          Fast data grab
|   +-- rdp_enable.txt           Enable RDP backdoor
|   +-- recon_launch.txt         Launch recon suite
|   +-- reverse_shell.txt        Standard reverse shell
|   +-- sam_dump.txt             SAM/SYSTEM/SECURITY dump
|   +-- scheduled_task_enum.txt  Task enumeration + hijack
|   +-- shadow_admin.txt         Hidden admin creation
|   +-- ssh_backdoor.txt         SSH backdoor install
|   +-- stealth_deploy.txt       Base64 stealth deploy
|   +-- token_theft.txt          Session token theft
|   +-- uac_bypass.txt           3-method UAC bypass
|   +-- vpn_creds.txt            VPN credential theft
|   +-- wifi_evil_twin.txt       Evil twin preparation
|   +-- wifi_passwords.txt       WiFi password dump
|   +-- wmic_recon.txt           WMI deep reconnaissance
+-- infrared/
|   +-- ac_universal.ir          60+ AC brands
|   +-- fan_universal.ir         20+ fan brands
|   +-- led_universal.ir         LED strip controllers
|   +-- projector_universal.ir   25+ projector brands
|   +-- settopbox_universal.ir   Cable/streaming boxes
|   +-- soundbar_universal.ir    30+ soundbar brands
|   +-- tv_off_universal.ir      40+ TV brands
+-- subghz/
|   +-- frequencies.txt          Master frequency database
|   +-- garage_door_codes.txt    Garage system attack guide
|   +-- iot_devices.txt          IoT device database
|   +-- protocols_reference.txt  Protocol encyclopedia
|   +-- regional_regulations.txt Regional legal frequencies
|   +-- security_systems.txt     Alarm system exploitation
|   +-- vehicle_keyfobs.txt      Vehicle RKE + TPMS
+-- nfc/
|   +-- attack_playbook.txt      NFC attack methodology
|   +-- card_formats.txt         Card format encyclopedia
|   +-- emv_reference.txt        EMV/contactless reference
|   +-- mifare_keys.txt          150+ MIFARE keys
|   +-- ndef_payloads.txt        Evil NFC tag templates
+-- rfid/
|   +-- format_database.txt      RFID protocol database + attacks
+-- ibutton/
|   +-- types_database.txt       iButton types + cloning guide
+-- gpio/
    +-- auto_recon.txt           Automated wireless recon
    +-- ble_attacks.txt          BLE attack techniques
    +-- esp32_advanced.txt       Full ESP32 Marauder reference
    +-- marauder_commands.txt    Basic Marauder commands
```

---

## Stats

| Category | Count |
|----------|-------|
| BadUSB Payloads | 35+ |
| IR Signal Databases | 7 (290+ signals) |
| Sub-GHz References | 7 |
| NFC Tools | 5 (150+ keys) |
| RFID Protocols | 19 |
| iButton Types | 25+ |
| GPIO Commands | 50+ |
| **Total Attack Vectors** | **100+** |

---

**FLLC — FU PERSON — by PERSON FU**

*35+ payloads. 290+ IR codes. 150+ crypto keys. Every frequency. Every protocol. Authorized testing only.*
