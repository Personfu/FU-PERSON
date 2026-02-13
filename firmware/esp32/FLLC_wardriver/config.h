/*
 * ============================================================================
 *  config.h — FLLC Wardriver v3.1 Configuration
 *
 *  BOARD:  ESP32 DevKit V1.1  (DIYMalls.com)
 *          Chip:  ESP-WROOM-32 (dual-core Xtensa LX6, 240 MHz)
 *          Flash: 4 MB
 *          SRAM:  520 KB
 *          WiFi:  802.11 b/g/n  (2.4 GHz)
 *          BLE:   4.2
 *          USB:   Micro-USB (CP2102 or CH340 UART bridge)
 *
 *  PIN MAP (DevKit V1.1 — 30-pin):
 *  ┌─────────────────────────────────────┐
 *  │         MICRO-USB (top)             │
 *  │  3V3 ─┤                     ├─ VIN  │
 *  │  GND ─┤                     ├─ GND  │
 *  │  D15 ─┤ GPIO15        GPIO13├─ D13  │
 *  │   D2 ─┤ GPIO2  (LED)  GPIO12├─ D12  │
 *  │   D4 ─┤ GPIO4         GPIO14├─ D14  │
 *  │  RX2 ─┤ GPIO16        GPIO27├─ D27  │
 *  │  TX2 ─┤ GPIO17        GPIO26├─ D26  │
 *  │   D5 ─┤ GPIO5  (CS)   GPIO25├─ D25  │
 *  │  D18 ─┤ GPIO18 (CLK)  GPIO33├─ D33  │
 *  │  D19 ─┤ GPIO19 (MISO) GPIO32├─ D32  │
 *  │  D21 ─┤ GPIO21 (SDA)  GPIO35├─ D35  │
 *  │  RX0 ─┤ GPIO3         GPIO34├─ D34  │
 *  │  TX0 ─┤ GPIO1         GPIO39├─ SVN  │
 *  │  D22 ─┤ GPIO22 (SCL)  GPIO36├─ SVP  │
 *  │  D23 ─┤ GPIO23 (MOSI)    EN ├─ EN   │
 *  └─────────────────────────────────────┘
 *
 *  All tunables in one place.  Edit this, not the .ino.
 * ============================================================================
 */

#ifndef CONFIG_H
#define CONFIG_H

// ──── Firmware Identity ──────────────────────────────────────────────────
#define FW_NAME        "FLLC-WD"
#define FW_VERSION     "3.1.0"

// ──── Board: ESP32 DevKit V1.1 (DIYMalls) ────────────────────────────────
#define BOARD_NAME     "ESP32-DevKitV1.1-DIYMalls"
#define BOARD_CHIP     "ESP-WROOM-32"
#define BOARD_FLASH_MB 4
#define BOARD_FREQ_MHZ 240

// ──── Serial ─────────────────────────────────────────────────────────────
#define SERIAL_BAUD    115200

// ──── LED (GPIO2 = onboard blue LED on DevKit V1.1) ─────────────────────
#define PIN_LED        2

// ──── SD Card Module  (standard SPI on DevKit V1.1 VSPI bus) ─────────────
//  Wire your SD breakout board:
//    SD CS   → GPIO5  (D5)
//    SD MOSI → GPIO23 (D23)
//    SD MISO → GPIO19 (D19)
//    SD CLK  → GPIO18 (D18)
//    SD VCC  → 3V3
//    SD GND  → GND
#define PIN_SD_CS      5           // VSPI CS0
#define PIN_SD_MOSI    23          // VSPI MOSI
#define PIN_SD_MISO    19          // VSPI MISO
#define PIN_SD_CLK     18          // VSPI CLK

// ──── Optional: I2C (if adding OLED/GPS later) ──────────────────────────
#define PIN_SDA        21          // I2C Data
#define PIN_SCL        22          // I2C Clock

// ──── Optional: UART2 (for GPS module or Flipper GPIO) ──────────────────
#define PIN_RX2        16          // UART2 RX
#define PIN_TX2        17          // UART2 TX

// ──── Optional: Extra GPIO (for external antenna switch, buzzer, etc) ────
#define PIN_AUX1       25          // General purpose
#define PIN_AUX2       26          // General purpose
#define PIN_AUX3       27          // General purpose

// ──── WiFi Engine ────────────────────────────────────────────────────────
#define WIFI_CHANNEL_MIN   1
#define WIFI_CHANNEL_MAX   13      // 14 for Japan only
#define CHANNEL_DWELL_MS   200     // ms per channel during sweep (faster on V1.1)
#define MAX_APS            256
#define MAX_STATIONS       512
#define MAX_PROBES         2048
#define MAX_PMKIDS         128
#define MAX_HANDSHAKES     64

// ──── BLE ────────────────────────────────────────────────────────────────
#define MAX_BLE_DEVICES    256
#define BLE_SCAN_SECS      8

// ──── PCAP ───────────────────────────────────────────────────────────────
#define PCAP_SNAP_LEN      2500    // max captured bytes per frame
#define PCAP_LINKTYPE      105     // LINKTYPE_IEEE802_11 (raw 802.11)

// ──── Deauth ─────────────────────────────────────────────────────────────
#define DEAUTH_BURST       10      // frames per burst (×2 directions)
#define DEAUTH_DELAY_US    400     // µs between frames in burst

// ──── Beacon Spam ────────────────────────────────────────────────────────
#define BEACON_INTERVAL_MS 80      // ms between full beacon rounds

// ──── Evil Twin ──────────────────────────────────────────────────────────
#define EVIL_TWIN_CHANNEL  6
#define DNS_PORT           53
#define WEB_PORT           80

// ──── Autopilot ──────────────────────────────────────────────────────────
#define AUTOPILOT          1       // 1 = start autopilot on boot, 0 = manual
#define AP_CYCLE_MS        45000   // milliseconds between autopilot cycles (45s)

// ──── Watchdog ───────────────────────────────────────────────────────────
#define WATCHDOG_TIMEOUT_S 30

// ──── Memory Budget ──────────────────────────────────────────────────────
//  ESP-WROOM-32 has 520 KB SRAM total.
//  Static table allocation:
//    AP table:     256 × ~72 B  =  ~18 KB
//    STA table:    512 × ~40 B  =  ~20 KB
//    Probe table:  2048 × ~44 B =  ~88 KB
//    PMKID table:  128 × ~40 B  =  ~5 KB
//    HS table:     64 × ~1100 B =  ~69 KB
//    BLE table:    256 × ~80 B  =  ~20 KB
//    ─────────────────────────────────
//    Total static: ~220 KB
//    Heap remaining: ~200 KB+ (plenty for stack, WiFi, BLE, SD buffers)
//
//  If you hit OOM, reduce MAX_PROBES or MAX_HANDSHAKES first.

#endif // CONFIG_H
