/*
 * ═══════════════════════════════════════════════════════════════════════
 *  FLLC | FU PERSON | ESP32 PINEAPPLE MODE CONFIG
 *  ╔══════════════════════════════════════════════════════════════════╗
 *  ║  Evil Twin + Captive Portal + Deauth Config                     ║
 *  ║  For DIYMalls ESP32 DevKit V1.1                                 ║
 *  ╚══════════════════════════════════════════════════════════════════╝
 * ═══════════════════════════════════════════════════════════════════════
 */

#ifndef PINEAPPLE_H
#define PINEAPPLE_H

// ── PINEAPPLE MODE ───────────────────────────────────────────────────
#define PINEAPPLE_ENABLED       true
#define PINEAPPLE_AUTO_START    false

// ── EVIL TWIN CONFIG ─────────────────────────────────────────────────
#define EVIL_TWIN_ENABLED       true
#define EVIL_TWIN_CHANNEL       6
#define EVIL_TWIN_HIDDEN        false
#define EVIL_TWIN_MAX_CLIENTS   10
// SSID will be cloned from target — set dynamically
#define EVIL_TWIN_DEFAULT_SSID  "Free WiFi"
#define EVIL_TWIN_AUTH_OPEN     true

// ── CAPTIVE PORTAL CONFIG ────────────────────────────────────────────
#define CAPTIVE_PORTAL_ENABLED  true
#define CAPTIVE_PORTAL_PORT     80
#define CAPTIVE_PORTAL_TITLE    "Network Login"
#define CAPTIVE_PORTAL_SUBTITLE "Please sign in to continue"
// Portal style: 0=generic login, 1=hotel wifi, 2=coffee shop, 3=corporate
#define CAPTIVE_PORTAL_STYLE    0
#define CAPTIVE_LOG_CREDS       true
#define CAPTIVE_LOG_PATH        "/loot/portal_creds.csv"

// ── DEAUTH CONFIG ────────────────────────────────────────────────────
#define DEAUTH_ENABLED          true
#define DEAUTH_REASON           1
#define DEAUTH_PACKETS          5
#define DEAUTH_DELAY_MS         100
#define DEAUTH_ALL_CHANNELS     false
// Target specific BSSID or broadcast
#define DEAUTH_TARGET_BSSID     "FF:FF:FF:FF:FF:FF"

// ── BEACON SPAM CONFIG ───────────────────────────────────────────────
#define BEACON_SPAM_ENABLED     true
#define BEACON_SPAM_COUNT       30
#define BEACON_SPAM_DELAY_MS    50
#define BEACON_SPAM_RANDOM      true
// Predefined SSIDs for confusion/cover
static const char* BEACON_SSIDS[] = {
    "FBI Surveillance Van #3",
    "DEA Task Force",
    "NSA_PRISM_Node_7",
    "Totally Not Spying",
    "Free Bitcoin Here",
    "Virus Distribution Center",
    "Hidden Network",
    "IT Department Test",
    "Guest_WiFi_5G",
    "Starbucks WiFi",
    "xfinitywifi",
    "ATT-WiFi-Passpoint",
    "DIRECT-roku-",
    "HP-Print-",
    "Samsung_Setup",
    NULL
};
#define BEACON_SSID_COUNT       15

// ── PROBE CAPTURE CONFIG ─────────────────────────────────────────────
#define PROBE_CAPTURE_ENABLED   true
#define PROBE_LOG_PATH          "/loot/probes.csv"
#define PROBE_DEDUP             true
#define PROBE_LOG_SIGNAL        true

// ── PMKID CAPTURE CONFIG ─────────────────────────────────────────────
#define PMKID_CAPTURE_ENABLED   true
#define PMKID_LOG_PATH          "/loot/pmkid.16800"
#define PMKID_TARGET_ALL        true

// ── KARMA ATTACK CONFIG ──────────────────────────────────────────────
#define KARMA_ENABLED           true
#define KARMA_RESPOND_ALL       false
// Only respond to probes matching these patterns
static const char* KARMA_WHITELIST[] = {
    "Free",
    "Guest",
    "Public",
    "Open",
    "WiFi",
    NULL
};

// ── LED STATUS INDICATORS ────────────────────────────────────────────
#define LED_PINEAPPLE_MODE      0x00FF00  // Green = pineapple active
#define LED_EVIL_TWIN_ACTIVE    0xFF0000  // Red = evil twin running
#define LED_CAPTIVE_PORTAL      0xFF00FF  // Magenta = portal serving
#define LED_DEAUTH_ACTIVE       0xFFFF00  // Yellow = deauthing
#define LED_CREDENTIAL_CAPTURED 0x00FFFF  // Cyan = cred captured (flash)

// ── SERIAL OUTPUT ────────────────────────────────────────────────────
#define SERIAL_BANNER_ENABLED   true
#define SERIAL_VERBOSE          true
#define SERIAL_KALI_STYLE       true

// ── SAFETY LIMITS ────────────────────────────────────────────────────
#define MAX_RUNTIME_MINUTES     60
#define MAX_DEAUTH_BURST        100
#define COOLDOWN_BETWEEN_ATTACKS_MS  5000
#define AUTO_STOP_ON_LOW_BATTERY    true
#define LOW_BATTERY_THRESHOLD       15

#endif // PINEAPPLE_H
