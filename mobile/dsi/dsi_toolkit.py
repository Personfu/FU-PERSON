#!/usr/bin/env python3
"""
FLLC - Nintendo DSi Hacking Toolkit
=============================================
Concepts, tools, and utilities for leveraging a jailbroken Nintendo DSi
as a covert penetration testing device.

WHY THE DSi?
  - Nobody suspects a kids' gaming console
  - Has built-in WiFi (802.11b/g, WEP/WPA support)
  - Has a camera (0.3MP but functional)
  - Has a microphone
  - Has SD card slot (for data storage)
  - Can run homebrew via Unlaunch/TWiLight Menu++/HiyaCFW
  - ARM9 + ARM7 processors
  - Can run DSLinux (full Linux on DS!)

LIMITATIONS:
  - WiFi is 802.11b/g only (2.4GHz)
  - WPA2-Enterprise not supported natively
  - Limited RAM (16MB)
  - No Bluetooth
  - No USB host mode

HOMEBREW TOOLS FOR DSi:
  1. DSLinux      - Full Linux distro for NDS/DSi
  2. DSOrganize   - File manager with WiFi capabilities
  3. DSFTP        - FTP client/server
  4. NDS-Wireshark - Basic packet viewer (concept)
  5. WiFi Scanner - Scan and display nearby networks

This script helps prepare SD card contents for DSi homebrew tools
and generates NDS-compatible scanning applications.

FLLC
"""

import os
import sys
import json
import struct
import shutil
from pathlib import Path
from datetime import datetime


# ============================================================================
#  DSi SD CARD STRUCTURE BUILDER
# ============================================================================

def build_dsi_sd(sd_path):
    """
    Set up SD card structure for a jailbroken DSi with offensive tools.

    Expected existing setup:
      - Unlaunch installed (NAND exploit)
      - TWiLight Menu++ (homebrew launcher)
      - HiyaCFW (optional, NAND redirect)

    We add:
      - WiFi scanning homebrew
      - File transfer tools
      - Data collection scripts
      - Wordlists for offline reference
    """
    print("=" * 50)
    print("  FLLC - DSi SD Card Builder")
    print("=" * 50)

    # Create directory structure — full game library layout
    dirs = [
        '_nds',              # TWiLight Menu++ config
        '_nds/TWiLightMenu', # TW Menu++ assets
        '_nds/TWiLightMenu/boxart',
        'roms/nds',          # Nintendo DS ROMs
        'roms/gba',          # Game Boy Advance ROMs
        'roms/gb',           # Game Boy / Color ROMs
        'roms/nes',          # NES ROMs
        'roms/snes',         # SNES ROMs
        'roms/sega',         # Sega Genesis / MD ROMs
        'roms/homebrew',     # Homebrew .nds apps
        'saves',             # Save files (auto-created by emulators)
        'tools',             # FLLC custom tools
        'tools/wordlists',   # Offline wordlists
        'tools/data',        # Collected data output
        'tools/data/wifi_scans',
        'tools/data/recon',
        'tools/scripts',     # Source code / Makefiles
        'cheats',            # Cheat databases
    ]

    for d in dirs:
        full = os.path.join(sd_path, d)
        os.makedirs(full, exist_ok=True)
        print(f"  [+] Created {d}/")

    # ====================================================================
    # WiFi Scanner Configuration
    # ====================================================================
    wifi_scanner_config = {
        "app_name": "FLLC WiFi Scanner",
        "version": "1.0",
        "description": "Scan and log WiFi networks using DSi hardware",
        "features": [
            "Scan all 2.4GHz channels",
            "Display SSID, BSSID, RSSI, encryption",
            "Log results to SD card",
            "Continuous scanning mode",
            "Hidden network detection",
            "Client probe sniffing (limited)"
        ],
        "controls": {
            "A": "Start/Stop scan",
            "B": "Save results",
            "X": "Toggle continuous mode",
            "Y": "Switch display mode",
            "L/R": "Change channel",
            "START": "Menu",
            "SELECT": "Exit"
        },
        "output_path": "/tools/data/wifi_scans/"
    }

    config_path = os.path.join(sd_path, 'tools', 'wifi_scanner_config.json')
    with open(config_path, 'w') as f:
        json.dump(wifi_scanner_config, f, indent=2)
    print(f"  [+] WiFi scanner config written")

    # ====================================================================
    # DSi WiFi Scanner Source (ARM9 C concept)
    # ====================================================================
    # This is a conceptual source file. To compile, you need:
    # - devkitPro (devkitARM)
    # - libnds
    # - dswifi library
    # Compile with: make (using the provided Makefile)

    scanner_source = r"""/*
 * FLLC - DSi WiFi Scanner
 * ================================
 * Homebrew WiFi scanner for Nintendo DSi
 *
 * BUILD REQUIREMENTS:
 *   - devkitPro / devkitARM
 *   - libnds
 *   - dswifi
 *
 * COMPILE:
 *   Install devkitPro: https://devkitpro.org/wiki/Getting_Started
 *   export DEVKITARM=/opt/devkitpro/devkitARM
 *   make
 *
 * The DSi's WiFi hardware (Mitsumi MM3218) supports:
 *   - 802.11b/g scanning
 *   - WEP/WPA/WPA2 (connect only, not crack)
 *   - Passive beacon sniffing
 *   - Signal strength measurement
 */

#include <nds.h>
#include <fat.h>
#include <dswifi9.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NETWORKS 64
#define SCAN_INTERVAL 3000  // ms between scans
#define LOG_FILE "/tools/data/wifi_scans/scan_log.csv"

typedef struct {
    char ssid[33];
    unsigned char bssid[6];
    int rssi;
    int channel;
    int encryption;  // 0=open, 1=WEP, 2=WPA, 3=WPA2
    int hidden;
    unsigned int seen_count;
    unsigned int first_seen;
    unsigned int last_seen;
} WifiNetwork;

WifiNetwork networks[MAX_NETWORKS];
int networkCount = 0;
int scanCount = 0;
int continuousMode = 0;

// Convert BSSID to string
void bssidToString(unsigned char *bssid, char *out) {
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            bssid[0], bssid[1], bssid[2],
            bssid[3], bssid[4], bssid[5]);
}

// Find network by BSSID
int findNetwork(unsigned char *bssid) {
    for (int i = 0; i < networkCount; i++) {
        if (memcmp(networks[i].bssid, bssid, 6) == 0)
            return i;
    }
    return -1;
}

// Scan callback
void scanCallback(void) {
    // This is called by dswifi when scan results are available
    Wifi_ScanMode();
}

// Perform WiFi scan
void doScan(void) {
    iprintf("\x1b[2J");  // Clear screen
    iprintf("=== FLLC WiFi Scanner ===\n");
    iprintf("Scan #%d | Networks: %d\n", ++scanCount, networkCount);
    iprintf("----------------------------\n");

    // Get scan results from dswifi
    Wifi_ScanMode();

    int count = Wifi_GetNumAP();
    for (int i = 0; i < count && i < MAX_NETWORKS; i++) {
        Wifi_AccessPoint ap;
        if (Wifi_GetAPData(i, &ap) != WIFI_RETURN_OK) continue;

        // Check if we already know this network
        int idx = findNetwork(ap.bssid);
        if (idx < 0) {
            if (networkCount >= MAX_NETWORKS) continue;
            idx = networkCount++;
            memcpy(networks[idx].bssid, ap.bssid, 6);
            networks[idx].first_seen = scanCount;
            networks[idx].seen_count = 0;
        }

        strncpy(networks[idx].ssid, (char*)ap.ssid, 32);
        networks[idx].ssid[32] = '\0';
        networks[idx].rssi = ap.rssi;
        networks[idx].channel = ap.channel;
        networks[idx].last_seen = scanCount;
        networks[idx].seen_count++;

        // Determine encryption
        if (ap.flags & WFLAG_APDATA_WPA) {
            networks[idx].encryption = 3;  // WPA2
        } else if (ap.flags & WFLAG_APDATA_WEP) {
            networks[idx].encryption = 1;  // WEP
        } else {
            networks[idx].encryption = 0;  // Open
        }

        networks[idx].hidden = (strlen(networks[idx].ssid) == 0);
    }

    // Display on bottom screen
    consoleDemoInit();  // Use bottom screen

    const char *encNames[] = {"OPEN", "WEP", "WPA", "WPA2"};

    for (int i = 0; i < networkCount && i < 20; i++) {
        char bssidStr[18];
        bssidToString(networks[i].bssid, bssidStr);

        int enc = networks[i].encryption;
        if (enc > 3) enc = 0;

        iprintf("%2d %-16s %4ddBm CH%2d %s\n",
                i,
                networks[i].hidden ? "<hidden>" : networks[i].ssid,
                networks[i].rssi,
                networks[i].channel,
                encNames[enc]);
    }

    iprintf("\n[A]Scan [B]Save [X]Cont [Y]Detail\n");
}

// Save results to SD card
void saveResults(void) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) {
        iprintf("ERROR: Cannot open log file\n");
        return;
    }

    // Write header if file is empty
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) {
        fprintf(f, "Scan#,SSID,BSSID,RSSI,Channel,Encryption,Hidden,SeenCount\n");
    }

    for (int i = 0; i < networkCount; i++) {
        char bssidStr[18];
        bssidToString(networks[i].bssid, bssidStr);

        const char *encNames[] = {"OPEN", "WEP", "WPA", "WPA2"};
        int enc = networks[i].encryption;
        if (enc > 3) enc = 0;

        fprintf(f, "%d,%s,%s,%d,%d,%s,%d,%d\n",
                scanCount,
                networks[i].ssid,
                bssidStr,
                networks[i].rssi,
                networks[i].channel,
                encNames[enc],
                networks[i].hidden,
                networks[i].seen_count);
    }

    fclose(f);
    iprintf("Saved %d networks to SD\n", networkCount);
}

// Main entry point
int main(void) {
    // Initialize displays
    videoSetMode(MODE_0_2D);
    videoSetModeSub(MODE_0_2D);

    consoleDemoInit();  // Console on bottom screen

    iprintf("=== FLLC WiFi Scanner ===\n\n");
    iprintf("Initializing...\n");

    // Initialize FAT (SD card access)
    if (!fatInitDefault()) {
        iprintf("ERROR: SD card init failed!\n");
        iprintf("Make sure SD card is inserted.\n");
        while (1) swiWaitForVBlank();
    }
    iprintf("[+] SD card ready\n");

    // Create output directories
    mkdir("/tools/data/wifi_scans", 0777);

    // Initialize WiFi
    iprintf("[+] Starting WiFi...\n");
    Wifi_InitDefault(INIT_ONLY);
    Wifi_EnableWifi();
    iprintf("[+] WiFi enabled\n\n");
    iprintf("Press A to scan!\n");

    // Main loop
    while (1) {
        swiWaitForVBlank();
        scanKeys();
        int keys = keysDown();

        if (keys & KEY_A) {
            doScan();
        }
        if (keys & KEY_B) {
            saveResults();
        }
        if (keys & KEY_X) {
            continuousMode = !continuousMode;
            iprintf("Continuous: %s\n", continuousMode ? "ON" : "OFF");
        }
        if (keys & KEY_SELECT) {
            break;
        }

        // Continuous scanning
        if (continuousMode) {
            static unsigned int lastScan = 0;
            unsigned int now = (unsigned int)(time(NULL));
            if (now - lastScan >= 3) {
                doScan();
                lastScan = now;
            }
        }
    }

    Wifi_DisableWifi();
    return 0;
}
"""

    scanner_path = os.path.join(sd_path, 'tools', 'scripts', 'wifi_scanner.c')
    with open(scanner_path, 'w') as f:
        f.write(scanner_source)
    print(f"  [+] WiFi scanner source written (needs devkitPro to compile)")

    # ====================================================================
    # Makefile for DSi homebrew
    # ====================================================================
    makefile = """# FLLC - DSi WiFi Scanner Makefile
# Requires devkitPro with devkitARM
#
# Install devkitPro:
#   Windows: https://github.com/devkitPro/installer/releases
#   Linux:   sudo dkp-pacman -S nds-dev
#
# Build:
#   export DEVKITARM=/opt/devkitpro/devkitARM
#   make

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment")
endif

include $(DEVKITARM)/ds_rules

TARGET   := wifi_scanner
SOURCES  := .
INCLUDES := $(LIBNDS)/include
LIBS     := -lfat -ldswifi9 -lnds9

CFLAGS   := -Wall -O2 $(INCLUDE)
LDFLAGS  := -specs=ds_arm9.specs

%.nds: %.elf
\t$(DEVKITARM)/bin/ndstool -c $@ -9 $<

$(TARGET).elf: wifi_scanner.o
\t$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

wifi_scanner.o: wifi_scanner.c
\t$(CC) $(CFLAGS) -c -o $@ $<

clean:
\trm -f *.o *.elf *.nds

.PHONY: clean
"""

    makefile_path = os.path.join(sd_path, 'tools', 'scripts', 'Makefile')
    with open(makefile_path, 'w') as f:
        f.write(makefile)
    print(f"  [+] Makefile written")

    # ====================================================================
    # DSi Tool Descriptions (what to install from homebrew scene)
    # ====================================================================
    tools_guide = """# ============================================================================
#  FLLC - DSi Homebrew Tool Guide
# ============================================================================
#  Your jailbroken DSi with TWiLight Menu++ can run these tools.
#  Place .nds files in /roms/nds/ on the SD card.
#
#  ESSENTIAL HOMEBREW:
# ============================================================================

# 1. DSLinux
#    Full Linux on your DSi! Includes networking, shell, basic tools.
#    Download: https://www.dslinux.org/
#    What it does: Gives you a full Linux terminal on the DSi
#    Pentest use: Run basic network tools (ping, nslookup, netcat)

# 2. DSOrganize
#    File manager with built-in web browser and WiFi
#    Download: https://www.gamebrew.org/wiki/DSOrganize
#    What it does: Browse files, basic web browsing, IRC chat
#    Pentest use: File transfers, web reconnaissance

# 3. DSFTP
#    FTP client for DSi
#    Download: https://www.gamebrew.org/wiki/DSFTP
#    What it does: FTP file transfers over WiFi
#    Pentest use: Exfiltrate data to/from DSi over network

# 4. WiFi Scanner (our custom build - see wifi_scanner.c)
#    Custom-built WiFi scanner
#    What it does: Scans and logs all nearby WiFi networks
#    Pentest use: Covert WiFi reconnaissance

# 5. DSWiFi Example Apps
#    Various WiFi test applications
#    Download: devkitPro examples
#    What it does: Network testing and exploration

# 6. Colors!
#    Drawing application
#    What it does: Paint on the touchscreen
#    Pentest use: Cover story - "just playing with my DS"

# 7. StellaDS / NesDS / GameYob
#    Emulators (NES, SNES, Game Boy)
#    What it does: Play retro games
#    Pentest use: Cover story + entertainment while waiting

# ============================================================================
#  OPERATIONAL USE
# ============================================================================
#  The DSi's greatest strength is that it's INVISIBLE as a hacking tool.
#
#  Scenario 1: WiFi Recon
#    - Walk through target location with DSi "playing games"
#    - WiFi scanner runs in background logging all networks
#    - Save to SD card for later analysis
#
#  Scenario 2: Data Transfer
#    - Connect DSi to target WiFi network
#    - Use DSFTP to transfer files
#    - Nobody questions a kid/person with a gaming device
#
#  Scenario 3: Distraction
#    - Leave DSi playing music/sounds as a distraction
#    - Use built-in camera for visual recon
#    - Microphone for audio capture
#
#  Scenario 4: DSLinux Terminal
#    - Boot into DSLinux for a full terminal
#    - Run ping sweeps, DNS lookups, basic network mapping
#    - Netcat for connections
# ============================================================================
"""

    guide_path = os.path.join(sd_path, 'tools', 'DSI_TOOL_GUIDE.txt')
    with open(guide_path, 'w') as f:
        f.write(tools_guide)
    print(f"  [+] DSi tool guide written")

    # ====================================================================
    # ROM Library Manifest (what to download)
    # ====================================================================
    rom_manifest = {
        "pokemon": {
            "gb": [
                "Pokemon_Red.gb", "Pokemon_Blue.gb", "Pokemon_Yellow.gb",
                "Pokemon_Gold.gbc", "Pokemon_Silver.gbc", "Pokemon_Crystal.gbc",
                "Pokemon_Pinball.gbc", "Pokemon_TCG.gbc", "Pokemon_Puzzle.gbc"
            ],
            "gba": [
                "Pokemon_Ruby.gba", "Pokemon_Sapphire.gba", "Pokemon_Emerald.gba",
                "Pokemon_FireRed.gba", "Pokemon_LeafGreen.gba",
                "Pokemon_MD_Red.gba", "Pokemon_Pinball_RS.gba"
            ],
            "nds": [
                "Pokemon_Diamond.nds", "Pokemon_Pearl.nds", "Pokemon_Platinum.nds",
                "Pokemon_HeartGold.nds", "Pokemon_SoulSilver.nds",
                "Pokemon_Black.nds", "Pokemon_White.nds",
                "Pokemon_Black2.nds", "Pokemon_White2.nds",
                "Pokemon_Conquest.nds", "Pokemon_Ranger.nds",
                "Pokemon_Ranger_SoA.nds", "Pokemon_Ranger_GS.nds",
                "Pokemon_MD_Blue.nds", "Pokemon_MD_Time.nds",
                "Pokemon_MD_Darkness.nds", "Pokemon_MD_Sky.nds",
                "Pokemon_Dash.nds", "Pokemon_Trozei.nds", "Pokemon_Typing.nds"
            ]
        },
        "classics_nds": [
            "Mario_Kart_DS.nds", "New_Super_Mario_Bros.nds",
            "Super_Mario_64_DS.nds", "Zelda_Phantom_Hourglass.nds",
            "Zelda_Spirit_Tracks.nds", "Animal_Crossing_Wild_World.nds",
            "Kirby_Super_Star_Ultra.nds", "Castlevania_Dawn_of_Sorrow.nds",
            "Metroid_Prime_Hunters.nds", "Advance_Wars_Dual_Strike.nds",
            "Fire_Emblem_Shadow_Dragon.nds", "Chrono_Trigger.nds",
            "Dragon_Quest_IX.nds", "The_World_Ends_With_You.nds",
            "Phoenix_Wright_Ace_Attorney.nds", "999.nds",
            "Ghost_Trick.nds", "Elite_Beat_Agents.nds",
            "Tetris_DS.nds", "Scribblenauts.nds"
        ],
        "classics_gba": [
            "Zelda_Minish_Cap.gba", "Metroid_Fusion.gba",
            "Metroid_Zero_Mission.gba", "Super_Mario_Advance_4.gba",
            "Golden_Sun.gba", "Golden_Sun_Lost_Age.gba",
            "Fire_Emblem.gba", "Fire_Emblem_Sacred_Stones.gba",
            "Advance_Wars.gba", "FF_Tactics_Advance.gba",
            "Castlevania_Aria_of_Sorrow.gba", "Mega_Man_Zero.gba",
            "Wario_Land_4.gba", "Mother_3.gba", "Kingdom_Hearts_CoM.gba"
        ],
        "classics_gb": [
            "Zelda_Links_Awakening_DX.gbc", "Zelda_Oracle_Seasons.gbc",
            "Zelda_Oracle_Ages.gbc", "Super_Mario_Land.gb",
            "Super_Mario_Land_2.gb", "Wario_Land.gb",
            "Kirbys_Dream_Land.gb", "Metroid_II.gb",
            "Donkey_Kong_94.gb", "Tetris.gb", "Shantae.gbc",
            "Metal_Gear_Solid.gbc", "Dragon_Warrior_III.gbc"
        ]
    }

    manifest_path = os.path.join(sd_path, 'roms', 'ROM_MANIFEST.json')
    with open(manifest_path, 'w') as f:
        json.dump(rom_manifest, f, indent=2)

    # Count total games
    total_roms = 0
    for cat, data in rom_manifest.items():
        if isinstance(data, dict):
            for sys_roms in data.values():
                total_roms += len(sys_roms)
        elif isinstance(data, list):
            total_roms += len(data)

    print(f"  [+] ROM manifest written ({total_roms} games cataloged)")
    print(f"      Pokemon: {sum(len(v) for v in rom_manifest['pokemon'].values())} titles")
    print(f"      Download ROMs and place in matching roms/<system>/ folders")

    # ====================================================================
    # Compact wordlists for SD card
    # ====================================================================
    # DSi SD cards are small, so we provide compact lists
    common_wifi_passwords = [
        "password", "12345678", "qwerty123", "admin123", "letmein1",
        "welcome1", "monkey12", "dragon12", "master12", "abc12345",
        "password1", "iloveyou", "trustno1", "sunshine", "princess",
        "football", "charlie1", "shadow12", "michael1", "qwerty12",
        "123456789", "1234567890", "password123", "admin1234", "welcome123",
        "homewifi", "wifihome", "internet", "wireless", "netgear",
        "linksys1", "default1", "changeme", "guest123", "router12",
    ]

    wifi_pw_path = os.path.join(sd_path, 'tools', 'wordlists', 'common_wifi_passwords.txt')
    with open(wifi_pw_path, 'w') as f:
        for pw in common_wifi_passwords:
            f.write(pw + '\n')
    print(f"  [+] WiFi password wordlist ({len(common_wifi_passwords)} entries)")

    print(f"\n{'=' * 50}")
    print(f"  DSi SD card prepared at: {sd_path}")
    print(f"{'=' * 50}")
    print(f"\n  Next steps:")
    print(f"  1. Install devkitPro to compile wifi_scanner.c")
    print(f"  2. Copy compiled .nds to {sd_path}/roms/nds/")
    print(f"  3. Download DSLinux from dslinux.org")
    print(f"  4. Insert SD into DSi, boot TWiLight Menu++")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='FLLC - DSi Toolkit Builder')
    parser.add_argument('--sd', default=None, help='Path to DSi SD card')
    args = parser.parse_args()

    sd = args.sd
    if not sd:
        # Auto-detect or use local directory
        sd = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dsi_sd_contents')

    build_dsi_sd(sd)
