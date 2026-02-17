# Tri-Drive Layout Reference

```
╔══════════════════════════════════════════════════════════════╗
║  FLLC TRI-DRIVE ARCHITECTURE                                 ║
║  Three drives. Three roles. Zero overlap.                    ║
╚══════════════════════════════════════════════════════════════╝
```

## `[root@fuperson]─[~/drive-map]`

```
root@fuperson:~# lsblk --fu-person
╔═══════╦═══════════╦══════════════════════════════════╦══════════╗
║ Drive ║ Media     ║ Role                             ║ Size     ║
╠═══════╬═══════════╬══════════════════════════════════╬══════════╣
║ H:    ║ SD Card   ║ OFFENSE (tools, firmware, payloads) ║ 32-128GB ║
║ I:    ║ Micro SD  ║ COLLECTION (loot, exfil, logs)   ║ 32-128GB ║
║ J:    ║ Aux/ESP32 ║ RECORDER or ESP32 data backup    ║ Varies   ║
╚═══════╩═══════════╩══════════════════════════════════╩══════════╝
```

## `[root@fuperson]─[~/H-drive]` — Attack Surface

```
root@fuperson:~# tree H:\ --attack
H:\
├── .p/                    [HIDDEN] Payload folder
│   ├── harvest.ps1        Silent 13-phase data extraction
│   ├── osint.ps1          People/phone/email/domain/IP lookup
│   ├── recon.ps1          Port scan, host discovery, WiFi, shares
│   ├── launcher.ps1       Master menu for all tools
│   ├── device_sync.ps1    Multi-device loot synchronization
│   ├── stealth_mode.ps1   Ultra-quiet trace elimination
│   └── report_generator.ps1  Encrypted loot report builder
├── setup.bat              Social engineering trigger ("USB 3.0 Driver Setup")
├── README.txt             Bait file
├── pt_suite/              Core Python tool suites + launchers
├── esp32/                 ESP32 wardriver firmware + flash utility
├── flipper/               Flipper Zero payloads (BadUSB, GPIO, SubGHz, NFC, IR)
├── mobile/                S20+ headless scripts, DSi toolkit + CyberWorld
└── lists/                 Consolidated wordlists (domains, APIs, directories)
```

## `[root@fuperson]─[~/I-drive]` — Collection Point

```
root@fuperson:~# tree I:\ --loot
I:\
├── .loot_target           Drive identification marker
├── run_me.bat             Social engineering entry point
├── payloads/              All collection + exploitation scripts
├── tools/                 People Finder (portable)
└── loot/                  [*] DATA LANDS HERE AT RUNTIME
    ├── input_logs/        Keystroke and activity captures
    ├── privesc/           Privilege escalation results
    ├── sqli/              SQL injection findings
    ├── npp/               Application exploit output
    ├── system_info/       OS, hardware, network data
    ├── browser_data/      Browser history, cookies, passwords
    ├── wifi_profiles/     Saved Wi-Fi credentials
    ├── session_tokens/    Browser session tokens
    ├── clipboard/         Clipboard history dumps
    └── recordings/        Audio captures
```

## `[root@fuperson]─[~/J-drive]` — Auxiliary

```
root@fuperson:~# tree J:\ --aux
J:\
├── listener.py            Voice-activated recording engine
├── start_listener.bat     Silent launcher
├── build_exe.py           PyInstaller build script
└── recordings/            Audio clips (50dB threshold)
```

## `[root@fuperson]─[~/deployment]`

```bash
# Deploy all drives in one command
root@fuperson:~# python deploy/build_usb.py --deploy-only
[+] H: drive (SD Card) ......... payloads deployed
[+] I: drive (MicroSD) ......... loot structure created
[+] J: drive (Aux) ............. recorder deployed
[*] Tri-drive ready for field deployment.

# Or use the batch launcher
root@fuperson:~# deploy/Build_USB_Drives.bat
```

---

```
FLLC | Tri-Drive Architecture | 2026
```
---
