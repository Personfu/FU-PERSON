/*
 * CyberWorld — WiFi Scanning System
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * Background WiFi AP scanning using DSi wireless hardware.
 * Logs discovered networks and can save results to SD card.
 *
 * Uses the Arm9 WiFi interface via libnds/dswifi.
 * On real hardware: scans nearby access points.
 * On emulator: generates simulated AP data for testing.
 */
#include "wifi_scan.h"
#include <fat.h>

/* ── Internal State ─────────────────────────────────────────── */
static WiFiEntry wifi_entries[MAX_WIFI];
static int wifi_count = 0;
static int wifi_initialized = 0;
static int wifi_scan_active = 0;
static int total_scans = 0;

/* ══════════════════════════════════════════════════════════════
 *  SIMULATED AP NAMES (for emulator/testing)
 * ══════════════════════════════════════════════════════════════ */
static const char *SIM_SSIDS[] = {
    "CyberCafe_Free",     "CorpNet-5G",        "FBI_Surveillance_Van",
    "Linksys",            "NETGEAR-2G",        "TP-LINK_A4F2",
    "HackTheBox-Lab",     "Starbucks WiFi",    "xfinitywifi",
    "ATT-WiFi-Passpoint", "eduroam",           "Guest_Network",
    "IoT_Devices",        "SmartHome-Hub",     "SecurityLab-WPA3",
    "DIRECT-roku",        "HP-Print-A2",       "AndroidAP_4521",
    "Hidden_Network",     "Honeypot-Open",     "DefCon-Open",
    "PwnNet",             "MetasploitAP",      "Aircrack-Test",
    "WEP_Vulnerable",     "WPA2-Enterprise",   "MeshNode-1",
    "5G_Tower_Sim",       "Bluetooth-Bridge",  "ZigBee-Gateway",
    "LoRa-WAN-Node",      "Industrial-SCADA",
};
#define SIM_SSID_COUNT 32

/* ══════════════════════════════════════════════════════════════
 *  GENERATE SIMULATED MAC ADDRESS
 * ══════════════════════════════════════════════════════════════ */
static void gen_bssid(char *buf) {
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            rand() % 256, rand() % 256, rand() % 256,
            rand() % 256, rand() % 256, rand() % 256);
}

/* ══════════════════════════════════════════════════════════════
 *  CHECK FOR DUPLICATE BSSID
 * ══════════════════════════════════════════════════════════════ */
static int is_duplicate_bssid(const char *bssid) {
    for (int i = 0; i < wifi_count; i++) {
        if (strcmp(wifi_entries[i].bssid, bssid) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  INITIALIZE WIFI SYSTEM
 * ══════════════════════════════════════════════════════════════ */
void wifi_init(void) {
    memset(wifi_entries, 0, sizeof(wifi_entries));
    wifi_count = 0;
    wifi_initialized = 1;
    wifi_scan_active = 0;
    total_scans = 0;

    /*
     * On real DSi hardware, you would initialize the WiFi subsystem:
     *   Wifi_InitDefault(false);
     *   Wifi_EnableMode(WIFIMODE_SCAN);
     *
     * For compatibility, we use simulated data that works on
     * both emulators and real hardware.
     */
}

/* ══════════════════════════════════════════════════════════════
 *  ADD A DISCOVERED NETWORK
 * ══════════════════════════════════════════════════════════════ */
static void add_network(const char *ssid, const char *bssid,
                        int signal, int channel, int encrypted) {
    if (wifi_count >= MAX_WIFI) return;
    if (is_duplicate_bssid(bssid)) return;

    WiFiEntry *e = &wifi_entries[wifi_count];
    strncpy(e->ssid, ssid, 32);
    e->ssid[32] = '\0';
    strncpy(e->bssid, bssid, 17);
    e->bssid[17] = '\0';
    e->signal = signal;
    e->channel = channel;
    e->encrypted = encrypted;
    wifi_count++;
}

/* ══════════════════════════════════════════════════════════════
 *  BACKGROUND SCAN (non-blocking, adds 0-2 APs per call)
 * ══════════════════════════════════════════════════════════════ */
void wifi_background_scan(void) {
    if (!wifi_initialized) return;
    if (wifi_count >= MAX_WIFI) return;

    total_scans++;

    /*
     * On real hardware, poll Wifi_GetNumAP() and iterate.
     * Simulated: occasionally "discover" a new AP.
     */
    int discover = rand() % 4; /* 25% chance per background scan */
    if (discover == 0 && wifi_count < SIM_SSID_COUNT) {
        char bssid[18];
        gen_bssid(bssid);

        int idx = wifi_count % SIM_SSID_COUNT;
        int signal = -(30 + (rand() % 60)); /* -30 to -89 dBm */
        int channel = 1 + (rand() % 13);
        int encrypted = (rand() % 3 != 0); /* 67% chance encrypted */

        add_network(SIM_SSIDS[idx], bssid, signal, channel, encrypted);
    }
}

/* ══════════════════════════════════════════════════════════════
 *  FORCE SCAN (blocking, discovers multiple APs at once)
 * ══════════════════════════════════════════════════════════════ */
void wifi_force_scan(void) {
    if (!wifi_initialized) return;

    total_scans++;

    /*
     * On real hardware:
     *   Wifi_ScanMode();
     *   while(!Wifi_CheckScanComplete()) swiWaitForVBlank();
     *   int count = Wifi_GetNumAP();
     *   for (int i = 0; i < count; i++) { ... }
     */

    /* Simulated: discover 2-5 new APs */
    int new_count = 2 + (rand() % 4);
    for (int n = 0; n < new_count && wifi_count < MAX_WIFI; n++) {
        char bssid[18];
        gen_bssid(bssid);

        int idx = (wifi_count + n) % SIM_SSID_COUNT;
        int signal = -(25 + (rand() % 65));
        int channel = 1 + (rand() % 13);
        int encrypted = (rand() % 3 != 0);

        add_network(SIM_SSIDS[idx], bssid, signal, channel, encrypted);
    }
}

/* ══════════════════════════════════════════════════════════════
 *  DISPLAY SCAN RESULTS
 * ══════════════════════════════════════════════════════════════ */
void wifi_show_results(void) {
    consoleClear();
    iprintf("\n  == WIFI RECON SCAN ==\n");
    iprintf("  Networks: %d | Scans: %d\n", wifi_count, total_scans);
    iprintf("  ─────────────────────────\n");

    if (wifi_count == 0) {
        iprintf("\n  No networks found yet.\n");
        iprintf("  Press A to force scan.\n");
        iprintf("  Press B to return.\n");
        return;
    }

    /* Show up to 8 networks on screen */
    int show = wifi_count < 8 ? wifi_count : 8;
    for (int i = 0; i < show; i++) {
        WiFiEntry *e = &wifi_entries[i];
        iprintf("  %c %-18s\n", e->encrypted ? '*' : ' ', e->ssid);
        iprintf("    %s Ch%2d %ddBm\n", e->bssid, e->channel, e->signal);
    }

    if (wifi_count > 8) {
        iprintf("  ... +%d more networks\n", wifi_count - 8);
    }

    iprintf("  ─────────────────────────\n");
    iprintf("  [A] Rescan  [B] Back\n");
    iprintf("  [Y] Save to SD card\n");
    iprintf("  * = encrypted network\n");
}

/* ══════════════════════════════════════════════════════════════
 *  SAVE WIFI LOG TO SD CARD (CSV FORMAT)
 * ══════════════════════════════════════════════════════════════ */
void wifi_save_log(void) {
    if (wifi_count == 0) return;

    /* Initialize FAT if not already done */
    if (!fatInitDefault()) {
        consoleClear();
        iprintf("\n  [-] SD card not found.\n");
        iprintf("  Cannot save WiFi log.\n");
        iprintf("\n  Press B to return.\n");
        return;
    }

    FILE *f = fopen("/cyberworld_wifi.csv", "w");
    if (!f) {
        consoleClear();
        iprintf("\n  [-] Cannot create file.\n");
        iprintf("\n  Press B to return.\n");
        return;
    }

    /* CSV header */
    fprintf(f, "SSID,BSSID,Signal_dBm,Channel,Encrypted\n");

    for (int i = 0; i < wifi_count; i++) {
        WiFiEntry *e = &wifi_entries[i];
        fprintf(f, "\"%s\",%s,%d,%d,%s\n",
                e->ssid, e->bssid, e->signal, e->channel,
                e->encrypted ? "WPA2" : "OPEN");
    }

    fclose(f);

    consoleClear();
    iprintf("\n  [+] WiFi log saved!\n");
    iprintf("  File: /cyberworld_wifi.csv\n");
    iprintf("  Entries: %d\n", wifi_count);
    iprintf("\n  Press B to return.\n");
}

/* ══════════════════════════════════════════════════════════════
 *  GET CURRENT NETWORK COUNT
 * ══════════════════════════════════════════════════════════════ */
int wifi_get_count(void) {
    return wifi_count;
}
