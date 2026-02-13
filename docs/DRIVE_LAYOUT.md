# Tri-Drive Layout Reference

## Overview

The toolkit deploys across a USB device containing three storage interfaces:

| Drive | Media | Role | Size |
|-------|-------|------|------|
| H: | SD Card | Offense (tools, firmware, payloads) | 32-128 GB |
| I: | Micro SD | Collection (loot, exfil, logs) | 32-128 GB |
| J: | Aux/ESP32 | Recorder or ESP32 data backup | Varies |

## H: Drive (SD Card) - Attack

```
H:\
|-- pt_suite/              Core Python tool suites + launchers
|-- esp32/                 ESP32 wardriver firmware + flash utility
|-- flipper/               Flipper Zero payloads (BadUSB, GPIO, SubGHz, NFC, IR)
|-- mobile/                S20+ headless scripts, DSi toolkit
|-- lists/                 Consolidated wordlists (domains, APIs, directories)
+-- tools/                 Extracted repository data (nmap, wireshark, etc.)
```

## I: Drive (Micro SD) - Collection

```
I:\
|-- run_me.bat             Social engineering entry point
|-- payloads/              All collection + exploitation scripts
|-- tools/                 People Finder (portable)
+-- loot/                  Data lands here at runtime
    |-- input_logs/        Keystroke and activity captures
    |-- privesc/           Privilege escalation results
    |-- sqli/              SQL injection findings
    |-- npp/               Application exploit output
    |-- system_info/       OS, hardware, network data
    |-- browser_data/      Browser history, cookies, passwords
    |-- wifi_profiles/     Saved Wi-Fi credentials
    +-- recordings/        Audio captures
```

## J: Drive (Aux) - Optional

```
J:\
|-- listener.py            Voice-activated recording engine
|-- start_listener.bat     Silent launcher
|-- build_exe.py           PyInstaller build script
+-- recordings/            Audio clips (50dB threshold)
```

## Deployment

Run from project root:

```
python deploy/build_usb.py --deploy-only
```

Or double-click `deploy/Build_USB_Drives.bat`.
