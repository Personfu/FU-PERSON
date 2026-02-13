# Flipper Zero — FU PERSON MEGA Playbook

**FLLC | 18 BadUSB Payloads + GPIO + SubGHz + NFC + IR**

---

## BadUSB Payloads (18 Total)

### Automated Attack Chain
| Payload | File | Time | Description |
|---------|------|------|-------------|
| **Phantom USB** | `phantom_usb.txt` | 3s | Zero-touch auto-deploy. Finds USB, launches full chain silently. |
| **Auto-Pwn Deploy** | `auto_pwn_deploy.txt` | 5s | Deploy `auto_pwn.ps1` 10-phase attack chain. Anti-detect. |
| **Stealth Deploy** | `stealth_deploy.txt` | 5s | Base64-encoded variant for EDR bypass. |

### Data Exfiltration
| Payload | File | Time | Description |
|---------|------|------|-------------|
| **Rapid Exfil** | `rapid_exfil.txt` | 15s | WiFi passwords, system info, recent files. Fastest grab. |
| **Full Exfil** | `full_exfil.txt` | 30s | Complete system dump. Browser, credentials, network. |
| **Credential Dump** | `credential_dump.txt` | 20s | Browser DBs, SSH keys, cloud creds, tokens, vault. |
| **SAM Dump** | `sam_dump.txt` | 10s | Registry hive export (SAM/SYSTEM/SECURITY). Requires admin. |

### Reconnaissance
| Payload | File | Time | Description |
|---------|------|------|-------------|
| **Network Recon** | `network_recon.txt` | 30s | Full network map: hosts, ports, shares, domain, firewall. |
| **WiFi Passwords** | `wifi_passwords.txt` | 10s | Extract all saved WiFi credentials. |
| **Recon Launch** | `recon_launch.txt` | 5s | Start automated reconnaissance on target. |

### Persistence & Exploitation
| Payload | File | Time | Description |
|---------|------|------|-------------|
| **Persistence Install** | `persistence_install.txt` | 5s | Scheduled task + registry run key. Survives reboot. |
| **Keylogger Deploy** | `keylogger_deploy.txt` | 5s | Deploy silent input monitor (keys, mouse, clipboard, screenshots). |
| **Disable Defender** | `disable_defender.txt` | 5s | Neutralize Windows Defender via encoded commands. |
| **Deploy Toolkit** | `deploy_toolkit.txt` | 10s | Copy entire toolkit to target from USB. |

### Reverse Shells
| Payload | File | Time | Description |
|---------|------|------|-------------|
| **Net Diag** | `net_diag.txt` | 3s | Encoded reverse shell (AV bypass). Disguised as network diagnostics. |
| **Reverse Shell** | `reverse_shell.txt` | 3s | Standard PowerShell reverse shell. |
| **Linux Reverse Shell** | `linux_reverse_shell.txt` | 3s | Bash reverse shell for Linux targets. |

### Post-Exploitation
| Payload | File | Time | Description |
|---------|------|------|-------------|
| **Empire Stager** | `empire_stager.txt` | 5s | PowerShell Empire C2 stager deployment. |
| **Obfuscated Loader** | `obfuscated_loader.txt` | 5s | Multi-stage obfuscated payload loader. |

---

## Attack Sequences

### Sequence 1: "Walk-By" (30 seconds total)
1. Plug in Flipper Zero as BadUSB
2. Run `phantom_usb.txt` (3s)
3. Unplug
4. Full attack chain runs silently in background
5. Collect USB drive later for loot

### Sequence 2: "Smash and Grab" (20 seconds total)
1. Plug in Flipper
2. Run `rapid_exfil.txt` (15s)
3. Run `wifi_passwords.txt` (10s — runs parallel)
4. Unplug. Data is on USB.

### Sequence 3: "Persistent Access" (15 seconds total)
1. Run `phantom_usb.txt` (3s)
2. Run `persistence_install.txt` (5s)
3. Run `keylogger_deploy.txt` (5s)
4. Unplug. Target is compromised. Re-runs on reboot.

### Sequence 4: "Full Compromise" (60 seconds total)
1. Run `disable_defender.txt` (5s)
2. Run `auto_pwn_deploy.txt` (5s)
3. Run `persistence_install.txt` (5s)
4. Run `keylogger_deploy.txt` (5s)
5. Wait 30s for initial collection
6. Unplug

### Sequence 5: "Domain Takeover" (requires admin on DC)
1. Run `disable_defender.txt` (5s)
2. Run `sam_dump.txt` (10s)
3. Run `credential_dump.txt` (20s)
4. Run `network_recon.txt` (30s)
5. Collect hashes for offline cracking

---

## GPIO — ESP32 Bridge

| File | Description |
|------|-------------|
| `gpio/marauder_commands.txt` | Full Marauder command reference for ESP32 |
| `gpio/auto_recon.txt` | Automated wireless recon via GPIO serial |

### ESP32 Commands via Flipper GPIO
```
scanap           — Scan for access points
scansta          — Scan for client stations  
stopscan         — Stop current scan
attack -t deauth — Deauthentication attack
attack -t beacon — Beacon spam
sniffpmkid       — Capture PMKID hashes
sniffpwnagotchi  — Detect Pwnagotchi devices
list ap          — List discovered APs
list sta         — List discovered stations
save pcap        — Save packet capture to SD
```

---

## Sub-GHz

| File | Description |
|------|-------------|
| `subghz/frequencies.txt` | Frequency database for common devices |

### Common Frequencies
```
300.000 MHz  — Garage doors (US)
315.000 MHz  — Car key fobs (US)
390.000 MHz  — Garage doors (US)
433.920 MHz  — Universal (EU remote controls, sensors)
868.350 MHz  — EU smart home devices
915.000 MHz  — US ISM band (LoRa, sensors)
```

---

## NFC/RFID

| File | Description |
|------|-------------|
| `nfc/attack_playbook.txt` | NFC attack methodology and card types |

### Supported Card Types
- **MIFARE Classic** — Read, write, clone, brute-force keys
- **MIFARE Ultralight** — Read, write
- **NTAG** — Read, write, emulate
- **EM4100** — Read, clone (125kHz RFID)
- **HID Prox** — Read, emulate (access cards)

---

## Infrared

| File | Description |
|------|-------------|
| `infrared/tv_off_universal.ir` | Universal IR power-off codes for TVs |

Covers: Samsung, LG, Sony, Vizio, TCL, Hisense, Panasonic, Sharp, Toshiba, Philips, and more.

---

## Setup Guide

### Firmware
Use **Momentum Firmware** for maximum capability:
- https://github.com/Next-Flip/Momentum-Firmware
- Or **Unleashed**: https://github.com/DarkFlippers/unleashed-firmware

### Install Payloads
1. Connect Flipper to PC via USB
2. Open qFlipper or Flipper Lab
3. Copy `flipper/badusb/*.txt` to Flipper's `SD Card/badusb/`
4. Copy `flipper/gpio/*.txt` to `SD Card/gpio/`
5. Copy `flipper/subghz/*.txt` to `SD Card/subghz/`
6. Copy `flipper/nfc/*.txt` to `SD Card/nfc/`
7. Copy `flipper/infrared/*.ir` to `SD Card/infrared/`

### Usage
1. On Flipper: Navigate to **Bad USB**
2. Select a payload `.txt` file
3. Plug Flipper into target's USB port
4. Press **Run** (center button)
5. Payload executes automatically

---

**FLLC** | 18 payloads. Every attack vector covered. Authorized use only.
