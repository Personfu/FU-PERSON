/*
 * CyberWorld — Daemon Data
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * All daemon species, moves, items, and type effectiveness chart.
 */
#include "types.h"

/* ══════════════════════════════════════════════════════════════
 *  TYPE NAMES
 * ══════════════════════════════════════════════════════════════ */
const char *TYPE_NAMES[TYPE_COUNT] = {
    "Network", "Web", "Binary", "Social",
    "Crypto", "Wireless", "Physical", "Zero-Day"
};

/* ══════════════════════════════════════════════════════════════
 *  TYPE EFFECTIVENESS CHART  [attacker_type][defender_type]
 *  0 = normal (1x), 1 = super effective (2x),
 *  2 = not very effective (0.5x), 3 = immune (0x)
 *
 *             NET  WEB  BIN  SOC  CRY  WIR  PHY  ZER
 * ══════════════════════════════════════════════════════════════ */
const u8 TYPE_CHART[TYPE_COUNT][TYPE_COUNT] = {
    /*           NET  WEB  BIN  SOC  CRY  WIR  PHY  ZER */
    /* NET */ {  0,   1,   0,   2,   2,   1,   0,   0  },
    /* WEB */ {  2,   0,   1,   1,   0,   0,   2,   0  },
    /* BIN */ {  0,   2,   0,   0,   1,   2,   1,   0  },
    /* SOC */ {  1,   0,   0,   0,   2,   1,   1,   2  },
    /* CRY */ {  1,   0,   2,   1,   0,   0,   2,   0  },
    /* WIR */ {  2,   0,   1,   2,   0,   0,   1,   0  },
    /* PHY */ {  0,   1,   2,   2,   1,   2,   0,   0  },
    /* ZER */ {  1,   1,   1,   0,   1,   1,   0,   2  },
};

/* ══════════════════════════════════════════════════════════════
 *  MOVE DEFINITIONS (60+ moves)
 *  { name, type, power, accuracy, pp_max, pp_current,
 *    status_chance, inflicts }
 * ══════════════════════════════════════════════════════════════ */
Move ALL_MOVES[] = {
    /* === ID  0-7: Network Moves === */
    /* 0  */ { "Ping",           TYPE_NETWORK,   40,  100, 35, 35,  0, STATUS_NONE },
    /* 1  */ { "Traceroute",     TYPE_NETWORK,   55,   95, 25, 25,  0, STATUS_NONE },
    /* 2  */ { "Port Scan",      TYPE_NETWORK,   70,   90, 20, 20, 10, STATUS_SANDBOXED },
    /* 3  */ { "SYN Flood",      TYPE_NETWORK,   85,   85, 15, 15, 20, STATUS_ENCRYPTED },
    /* 4  */ { "DDoS Blast",     TYPE_NETWORK,  110,   75, 10, 10,  0, STATUS_NONE },
    /* 5  */ { "Packet Storm",   TYPE_NETWORK,  130,   70,  5,  5, 15, STATUS_SANDBOXED },
    /* 6  */ { "ARP Spoof",      TYPE_NETWORK,   60,   95, 20, 20, 30, STATUS_HONEYPOTTED },
    /* 7  */ { "DNS Poison",     TYPE_NETWORK,   75,   90, 15, 15, 25, STATUS_ENCRYPTED },

    /* === ID  8-15: Web Moves === */
    /* 8  */ { "Script Inject",  TYPE_WEB,       40,  100, 35, 35,  0, STATUS_NONE },
    /* 9  */ { "XSS Strike",     TYPE_WEB,       55,   95, 25, 25, 10, STATUS_SANDBOXED },
    /* 10 */ { "SQL Inject",     TYPE_WEB,       70,   90, 20, 20, 15, STATUS_ENCRYPTED },
    /* 11 */ { "CSRF Attack",    TYPE_WEB,       85,   85, 15, 15, 20, STATUS_HONEYPOTTED },
    /* 12 */ { "RFI Exploit",    TYPE_WEB,      100,   80, 10, 10,  0, STATUS_NONE },
    /* 13 */ { "DOM Clobber",    TYPE_WEB,      120,   75,  5,  5, 25, STATUS_SANDBOXED },
    /* 14 */ { "Webshell",       TYPE_WEB,       65,   95, 20, 20, 30, STATUS_ENCRYPTED },
    /* 15 */ { "Defacement",     TYPE_WEB,       90,   85, 10, 10,  0, STATUS_NONE },

    /* === ID 16-23: Binary Moves === */
    /* 16 */ { "Stack Smash",    TYPE_BINARY,    40,  100, 35, 35,  0, STATUS_NONE },
    /* 17 */ { "Buffer Overfl",  TYPE_BINARY,    60,   95, 25, 25, 10, STATUS_SANDBOXED },
    /* 18 */ { "Heap Spray",     TYPE_BINARY,    75,   90, 20, 20,  0, STATUS_NONE },
    /* 19 */ { "ROP Chain",      TYPE_BINARY,    90,   85, 15, 15, 15, STATUS_ENCRYPTED },
    /* 20 */ { "Shellcode Exec", TYPE_BINARY,   110,   80, 10, 10,  0, STATUS_NONE },
    /* 21 */ { "Format String",  TYPE_BINARY,    65,   95, 20, 20, 25, STATUS_SANDBOXED },
    /* 22 */ { "Use After Free", TYPE_BINARY,   125,   70,  5,  5, 20, STATUS_ENCRYPTED },
    /* 23 */ { "Race Condition", TYPE_BINARY,    80,   85, 15, 15, 30, STATUS_HONEYPOTTED },

    /* === ID 24-31: Social Moves === */
    /* 24 */ { "Phish Mail",     TYPE_SOCIAL,    40,  100, 35, 35, 10, STATUS_HONEYPOTTED },
    /* 25 */ { "Spear Phish",    TYPE_SOCIAL,    60,   95, 25, 25, 20, STATUS_HONEYPOTTED },
    /* 26 */ { "Pretexting",     TYPE_SOCIAL,    55,   95, 25, 25, 30, STATUS_SANDBOXED },
    /* 27 */ { "Vishing Call",   TYPE_SOCIAL,    70,   90, 20, 20, 15, STATUS_ENCRYPTED },
    /* 28 */ { "Deepfake Lure",  TYPE_SOCIAL,    95,   80, 10, 10, 25, STATUS_HONEYPOTTED },
    /* 29 */ { "Whaling Shot",   TYPE_SOCIAL,   115,   75,  5,  5, 10, STATUS_ENCRYPTED },
    /* 30 */ { "Clickjack",      TYPE_SOCIAL,    50,  100, 30, 30, 35, STATUS_SANDBOXED },
    /* 31 */ { "Tailgate",       TYPE_SOCIAL,    80,   85, 15, 15,  0, STATUS_NONE },

    /* === ID 32-39: Crypto Moves === */
    /* 32 */ { "Hash Crack",     TYPE_CRYPTO,    40,  100, 35, 35,  0, STATUS_NONE },
    /* 33 */ { "Brute Force",    TYPE_CRYPTO,    55,   90, 25, 25,  0, STATUS_NONE },
    /* 34 */ { "Rainbow Table",  TYPE_CRYPTO,    75,   90, 20, 20, 15, STATUS_ENCRYPTED },
    /* 35 */ { "Side Channel",   TYPE_CRYPTO,    85,   85, 15, 15, 20, STATUS_SANDBOXED },
    /* 36 */ { "Key Extraction", TYPE_CRYPTO,   110,   75, 10, 10,  0, STATUS_NONE },
    /* 37 */ { "Cipher Break",   TYPE_CRYPTO,   130,   65,  5,  5, 25, STATUS_ENCRYPTED },
    /* 38 */ { "Padding Oracle", TYPE_CRYPTO,    65,   95, 20, 20, 30, STATUS_SANDBOXED },
    /* 39 */ { "Replay Attack",  TYPE_CRYPTO,    70,   90, 20, 20, 20, STATUS_HONEYPOTTED },

    /* === ID 40-47: Wireless Moves === */
    /* 40 */ { "Beacon Flood",   TYPE_WIRELESS,  40,  100, 35, 35,  0, STATUS_NONE },
    /* 41 */ { "Deauth Blast",   TYPE_WIRELESS,  60,   95, 25, 25, 15, STATUS_ENCRYPTED },
    /* 42 */ { "Evil Twin",      TYPE_WIRELESS,  75,   90, 20, 20, 25, STATUS_HONEYPOTTED },
    /* 43 */ { "KRACK Attack",   TYPE_WIRELESS,  90,   85, 15, 15, 20, STATUS_SANDBOXED },
    /* 44 */ { "WPS Crack",      TYPE_WIRELESS,  50,  100, 30, 30, 10, STATUS_ENCRYPTED },
    /* 45 */ { "Karma Attack",   TYPE_WIRELESS, 105,   80, 10, 10, 30, STATUS_HONEYPOTTED },
    /* 46 */ { "Jamming Wave",   TYPE_WIRELESS, 120,   70,  5,  5,  0, STATUS_NONE },
    /* 47 */ { "Bluejack",       TYPE_WIRELESS,  55,   95, 25, 25, 20, STATUS_SANDBOXED },

    /* === ID 48-55: Physical Moves === */
    /* 48 */ { "USB Drop",       TYPE_PHYSICAL,  40,  100, 35, 35, 15, STATUS_HONEYPOTTED },
    /* 49 */ { "Rubber Ducky",   TYPE_PHYSICAL,  60,   95, 25, 25,  0, STATUS_NONE },
    /* 50 */ { "Lock Pick",      TYPE_PHYSICAL,  55,   95, 25, 25, 20, STATUS_SANDBOXED },
    /* 51 */ { "Dumpster Dive",  TYPE_PHYSICAL,  45,  100, 30, 30, 10, STATUS_ENCRYPTED },
    /* 52 */ { "Badge Clone",    TYPE_PHYSICAL,  75,   90, 20, 20, 25, STATUS_HONEYPOTTED },
    /* 53 */ { "Hardware Impl",  TYPE_PHYSICAL,  95,   80, 10, 10,  0, STATUS_NONE },
    /* 54 */ { "Shoulder Surf",  TYPE_PHYSICAL,  50,  100, 30, 30, 30, STATUS_SANDBOXED },
    /* 55 */ { "Flipper Blast",  TYPE_PHYSICAL, 115,   75,  5,  5, 15, STATUS_ENCRYPTED },

    /* === ID 56-63: Zero-Day Moves === */
    /* 56 */ { "Zero Exploit",   TYPE_ZERODAY,  100,   85, 10, 10,  0, STATUS_NONE },
    /* 57 */ { "Rootkit Embed",  TYPE_ZERODAY,  120,   80,  5,  5, 30, STATUS_ENCRYPTED },
    /* 58 */ { "APT Strike",     TYPE_ZERODAY,  140,   75,  5,  5, 20, STATUS_SANDBOXED },
    /* 59 */ { "Kernel Panic",   TYPE_ZERODAY,  150,   70,  3,  3, 25, STATUS_ENCRYPTED },

    /* === ID 60-67: Utility / Status Moves === */
    /* 60 */ { "Firewall Up",    TYPE_NETWORK,    0,  100, 20, 20,100, STATUS_FIREWALLED },
    /* 61 */ { "Sandbox Trap",   TYPE_BINARY,     0,  100, 15, 15,100, STATUS_SANDBOXED },
    /* 62 */ { "Encrypt Lock",   TYPE_CRYPTO,     0,   90, 15, 15,100, STATUS_ENCRYPTED },
    /* 63 */ { "Honeypot Set",   TYPE_SOCIAL,     0,   90, 15, 15,100, STATUS_HONEYPOTTED },
    /* 64 */ { "Patch Defense",  TYPE_NETWORK,    0,  100, 20, 20,100, STATUS_PATCHED },
    /* 65 */ { "Recon Scan",     TYPE_NETWORK,   30,  100, 40, 40,  0, STATUS_NONE },
    /* 66 */ { "Obfuscate",      TYPE_BINARY,    35,  100, 30, 30, 15, STATUS_SANDBOXED },
    /* 67 */ { "Social Recon",   TYPE_SOCIAL,    35,  100, 30, 30, 20, STATUS_HONEYPOTTED },
};

int MOVE_COUNT = 68;

/* ══════════════════════════════════════════════════════════════
 *  DAEMON SPECIES (60 species, indices 0-59)
 *
 *  { id, name, type, base_hp, base_atk, base_def, base_spd,
 *    base_spec, evolves_at, evolves_to,
 *    { move_ids x8 }, { move_levels x8 }, lore }
 * ══════════════════════════════════════════════════════════════ */
DaemonSpecies ALL_SPECIES[] = {

    /* ────── NETWORK TYPE (0-8) ────── */
    /* 0: Ping */
    { 0, "Ping", TYPE_NETWORK,
      45, 49, 49, 45, 40, 16, 1,
      { 0, 65, 1, 6, 2, 3, 60, 4 },
      { 1, 5, 10, 14, 18, 22, 26, 30 },
      "Sends ICMP echo requests. First sign of network recon." },

    /* 1: Tracert */
    { 1, "Tracert", TYPE_NETWORK,
      60, 62, 63, 60, 55, 32, 2,
      { 0, 1, 6, 2, 7, 3, 60, 4 },
      { 1, 1, 14, 18, 22, 26, 30, 36 },
      "Maps every hop between hosts. Reveals network topology." },

    /* 2: Nmap */
    { 2, "Nmap", TYPE_NETWORK,
      80, 82, 83, 80, 75, 0, -1,
      { 0, 1, 2, 7, 3, 4, 60, 5 },
      { 1, 1, 1, 22, 26, 32, 36, 42 },
      "The ultimate network mapper. Sees all open ports and services." },

    /* 3: Portknock */
    { 3, "Portknock", TYPE_NETWORK,
      40, 45, 55, 50, 42, 14, 4,
      { 65, 0, 60, 1, 6, 2, 64, 3 },
      { 1, 4, 8, 12, 16, 20, 24, 28 },
      "Knocks on port sequences to unlock hidden services." },

    /* 4: Portscan */
    { 4, "Portscan", TYPE_NETWORK,
      55, 60, 68, 62, 56, 30, 5,
      { 65, 0, 1, 6, 2, 7, 3, 4 },
      { 1, 1, 12, 16, 20, 24, 28, 34 },
      "Systematically probes all 65535 ports for vulnerabilities." },

    /* 5: Masscan */
    { 5, "Masscan", TYPE_NETWORK,
      75, 78, 80, 85, 72, 0, -1,
      { 0, 1, 2, 6, 7, 3, 4, 5 },
      { 1, 1, 1, 16, 20, 28, 34, 40 },
      "Scans the entire internet in minutes. Unmatched speed." },

    /* 6: Sniffer */
    { 6, "Sniffer", TYPE_NETWORK,
      42, 48, 42, 55, 50, 15, 7,
      { 65, 0, 6, 1, 7, 2, 62, 3 },
      { 1, 4, 8, 12, 16, 20, 25, 30 },
      "Passively captures packets flowing across the wire." },

    /* 7: Wireshark */
    { 7, "Wireshark", TYPE_NETWORK,
      58, 62, 55, 70, 68, 34, 8,
      { 0, 6, 1, 7, 2, 3, 62, 4 },
      { 1, 1, 12, 16, 20, 26, 30, 38 },
      "Deep packet inspector. Decodes every protocol known." },

    /* 8: Pcapture */
    { 8, "Pcapture", TYPE_NETWORK,
      78, 80, 72, 88, 85, 0, -1,
      { 0, 6, 7, 1, 2, 3, 4, 5 },
      { 1, 1, 1, 12, 20, 28, 36, 44 },
      "Captures and analyzes all traffic. Nothing escapes its gaze." },

    /* ────── WEB TYPE (9-17) ────── */
    /* 9: XSSling */
    { 9, "XSSling", TYPE_WEB,
      39, 52, 43, 50, 48, 16, 10,
      { 8, 9, 14, 10, 30, 11, 12, 13 },
      { 1, 5, 10, 14, 18, 22, 28, 34 },
      "Injects tiny scripts into unsanitized web inputs." },

    /* 10: CrossSite */
    { 10, "CrossSite", TYPE_WEB,
      54, 67, 58, 65, 62, 32, 11,
      { 8, 9, 10, 14, 11, 30, 12, 13 },
      { 1, 1, 14, 18, 22, 26, 32, 38 },
      "Rides across origins, exploiting trust between sites." },

    /* 11: DOMinator */
    { 11, "DOMinator", TYPE_WEB,
      74, 87, 75, 82, 80, 0, -1,
      { 8, 9, 10, 14, 11, 13, 12, 15 },
      { 1, 1, 1, 18, 22, 30, 36, 44 },
      "Rules the Document Object Model. Rewrites reality itself." },

    /* 12: SQLimp */
    { 12, "SQLimp", TYPE_WEB,
      44, 50, 45, 48, 52, 16, 13,
      { 8, 10, 9, 14, 11, 62, 12, 13 },
      { 1, 5, 10, 14, 18, 22, 28, 34 },
      "Slips queries through input fields to access databases." },

    /* 13: Injection */
    { 13, "Injection", TYPE_WEB,
      58, 65, 60, 62, 68, 32, 14,
      { 8, 10, 9, 14, 11, 12, 62, 13 },
      { 1, 1, 10, 14, 22, 28, 32, 38 },
      "Injects arbitrary commands into backend systems." },

    /* 14: Sqlmap */
    { 14, "Sqlmap", TYPE_WEB,
      78, 85, 78, 80, 88, 0, -1,
      { 8, 10, 9, 14, 11, 12, 13, 15 },
      { 1, 1, 1, 14, 22, 30, 38, 44 },
      "Automated SQL injection. Dumps entire databases at will." },

    /* 15: Crawlr */
    { 15, "Crawlr", TYPE_WEB,
      40, 44, 48, 52, 44, 14, 16,
      { 8, 65, 9, 14, 10, 30, 11, 12 },
      { 1, 4, 8, 12, 16, 20, 24, 28 },
      "Slowly indexes every page of a website for secrets." },

    /* 16: Spider */
    { 16, "Spider", TYPE_WEB,
      55, 58, 62, 68, 58, 30, 17,
      { 8, 9, 14, 10, 30, 11, 15, 12 },
      { 1, 1, 12, 16, 20, 24, 30, 36 },
      "Weaves across links, mapping entire web applications." },

    /* 17: Webworm */
    { 17, "Webworm", TYPE_WEB,
      72, 75, 78, 85, 75, 0, -1,
      { 8, 9, 10, 14, 11, 30, 15, 13 },
      { 1, 1, 1, 12, 20, 26, 34, 42 },
      "Self-replicating web exploit. Spreads through every link." },

    /* ────── BINARY TYPE (18-26) ────── */
    /* 18: Stacksmash */
    { 18, "Stacksmash", TYPE_BINARY,
      44, 48, 65, 35, 45, 16, 19,
      { 16, 17, 66, 21, 18, 19, 61, 20 },
      { 1, 5, 10, 14, 18, 22, 26, 30 },
      "Overwrites the return address on the call stack." },

    /* 19: Overflow */
    { 19, "Overflow", TYPE_BINARY,
      59, 64, 80, 45, 60, 32, 20,
      { 16, 17, 21, 18, 19, 66, 61, 20 },
      { 1, 1, 14, 18, 22, 26, 32, 38 },
      "Spills data past buffer boundaries into executable memory." },

    /* 20: BufferKing */
    { 20, "BufferKing", TYPE_BINARY,
      79, 82, 100, 55, 78, 0, -1,
      { 16, 17, 18, 21, 19, 23, 20, 22 },
      { 1, 1, 1, 14, 22, 28, 36, 44 },
      "Master of memory corruption. No bounds can contain it." },

    /* 21: Shellcode */
    { 21, "Shellcode", TYPE_BINARY,
      42, 55, 40, 52, 48, 15, 22,
      { 16, 66, 17, 20, 18, 21, 19, 22 },
      { 1, 4, 8, 12, 16, 20, 25, 32 },
      "Raw machine instructions injected into vulnerable processes." },

    /* 22: Payload */
    { 22, "Payload", TYPE_BINARY,
      56, 72, 52, 65, 62, 32, 23,
      { 16, 17, 20, 18, 21, 19, 23, 22 },
      { 1, 1, 12, 16, 20, 26, 32, 38 },
      "Weaponized code delivered through exploitation chains." },

    /* 23: Meterpreter */
    { 23, "Meterpreter", TYPE_BINARY,
      76, 90, 68, 82, 80, 0, -1,
      { 16, 17, 20, 18, 19, 21, 22, 23 },
      { 1, 1, 1, 16, 22, 28, 36, 44 },
      "Advanced post-exploitation shell. Full system control." },

    /* 24: Debugger */
    { 24, "Debugger", TYPE_BINARY,
      46, 42, 50, 48, 55, 15, 25,
      { 16, 66, 61, 17, 21, 18, 19, 20 },
      { 1, 4, 8, 12, 16, 20, 24, 30 },
      "Steps through code instruction by instruction." },

    /* 25: Reverser */
    { 25, "Reverser", TYPE_BINARY,
      60, 58, 65, 62, 72, 32, 26,
      { 16, 66, 17, 61, 21, 18, 19, 20 },
      { 1, 1, 12, 16, 20, 24, 30, 36 },
      "Decompiles binaries back into readable logic." },

    /* 26: Ghidra */
    { 26, "Ghidra", TYPE_BINARY,
      80, 75, 82, 78, 92, 0, -1,
      { 16, 17, 66, 18, 19, 21, 22, 20 },
      { 1, 1, 1, 16, 22, 28, 36, 44 },
      "NSA-grade reverse engineering. Understands all architectures." },

    /* ────── SOCIAL TYPE (27-35) ────── */
    /* 27: Phishling */
    { 27, "Phishling", TYPE_SOCIAL,
      45, 50, 42, 55, 52, 16, 28,
      { 24, 67, 25, 26, 30, 27, 28, 31 },
      { 1, 5, 10, 14, 18, 22, 28, 34 },
      "Sends convincing fake emails to harvest credentials." },

    /* 28: Spearphish */
    { 28, "Spearphish", TYPE_SOCIAL,
      60, 65, 55, 70, 68, 32, 29,
      { 24, 25, 26, 67, 30, 27, 28, 29 },
      { 1, 1, 14, 18, 22, 26, 32, 38 },
      "Targeted phishing aimed at specific high-value individuals." },

    /* 29: Whalemail */
    { 29, "Whalemail", TYPE_SOCIAL,
      80, 82, 70, 85, 88, 0, -1,
      { 24, 25, 26, 27, 30, 28, 29, 31 },
      { 1, 1, 1, 14, 22, 30, 38, 44 },
      "Targets C-suite executives. The ultimate social exploit." },

    /* 30: Pretextr */
    { 30, "Pretextr", TYPE_SOCIAL,
      42, 48, 45, 50, 55, 15, 31,
      { 24, 26, 67, 30, 25, 27, 63, 28 },
      { 1, 4, 8, 12, 16, 20, 25, 30 },
      "Creates elaborate false identities and cover stories." },

    /* 31: Impersonatr */
    { 31, "Impersonatr", TYPE_SOCIAL,
      58, 62, 58, 65, 72, 32, 32,
      { 24, 26, 30, 25, 67, 27, 63, 28 },
      { 1, 1, 12, 16, 20, 24, 28, 34 },
      "Perfectly mimics trusted contacts and authority figures." },

    /* 32: Deepfake */
    { 32, "Deepfake", TYPE_SOCIAL,
      78, 80, 72, 82, 90, 0, -1,
      { 24, 26, 25, 27, 30, 28, 29, 31 },
      { 1, 1, 1, 14, 20, 28, 36, 42 },
      "AI-generated impersonation. Indistinguishable from real." },

    /* 33: Baiter */
    { 33, "Baiter", TYPE_SOCIAL,
      40, 52, 38, 58, 48, 14, 34,
      { 24, 67, 30, 26, 25, 63, 27, 28 },
      { 1, 4, 8, 12, 16, 20, 24, 28 },
      "Leaves infected media in parking lots and lobbies." },

    /* 34: Clickjack */
    { 34, "Clickjack", TYPE_SOCIAL,
      55, 68, 50, 72, 62, 30, 35,
      { 24, 30, 26, 67, 25, 27, 63, 28 },
      { 1, 1, 12, 16, 20, 24, 30, 36 },
      "Invisible overlays that hijack user interactions." },

    /* 35: Waterhole */
    { 35, "Waterhole", TYPE_SOCIAL,
      74, 85, 65, 88, 78, 0, -1,
      { 24, 30, 26, 25, 27, 28, 29, 31 },
      { 1, 1, 1, 12, 20, 28, 36, 42 },
      "Compromises sites that targets are known to visit." },

    /* ────── CRYPTO TYPE (36-44) ────── */
    /* 36: Hashling */
    { 36, "Hashling", TYPE_CRYPTO,
      43, 50, 48, 42, 55, 16, 37,
      { 32, 33, 62, 34, 38, 35, 39, 36 },
      { 1, 5, 10, 14, 18, 22, 26, 30 },
      "Computes message digests with naive enthusiasm." },

    /* 37: Hasher */
    { 37, "Hasher", TYPE_CRYPTO,
      58, 65, 62, 55, 72, 32, 38,
      { 32, 33, 34, 62, 38, 35, 39, 36 },
      { 1, 1, 14, 18, 22, 26, 32, 38 },
      "Cracks weak hashes using dictionary attacks." },

    /* 38: Hashcat */
    { 38, "Hashcat", TYPE_CRYPTO,
      78, 85, 78, 70, 92, 0, -1,
      { 32, 33, 34, 38, 35, 62, 36, 37 },
      { 1, 1, 1, 14, 22, 28, 36, 44 },
      "GPU-accelerated hash cracker. Billions of hashes per second." },

    /* 39: Cipher */
    { 39, "Cipher", TYPE_CRYPTO,
      44, 42, 52, 48, 58, 15, 40,
      { 32, 62, 33, 38, 34, 39, 35, 36 },
      { 1, 4, 8, 12, 16, 20, 25, 30 },
      "Wraps data in layers of mathematical obfuscation." },

    /* 40: Encryptor */
    { 40, "Encryptor", TYPE_CRYPTO,
      58, 55, 68, 60, 75, 32, 41,
      { 32, 62, 33, 34, 38, 35, 39, 36 },
      { 1, 1, 12, 16, 20, 24, 28, 34 },
      "Locks files with unbreakable symmetric encryption." },

    /* 41: AESdragon */
    { 41, "AESdragon", TYPE_CRYPTO,
      78, 72, 88, 75, 95, 0, -1,
      { 32, 33, 62, 34, 35, 38, 36, 37 },
      { 1, 1, 1, 14, 22, 28, 36, 44 },
      "256-bit encryption incarnate. Mathematically invincible." },

    /* 42: Keylogr */
    { 42, "Keylogr", TYPE_CRYPTO,
      38, 55, 35, 60, 52, 14, 43,
      { 32, 38, 33, 62, 34, 39, 35, 36 },
      { 1, 4, 8, 12, 16, 20, 24, 30 },
      "Records every keystroke. Steals passwords silently." },

    /* 43: Cracker */
    { 43, "Cracker", TYPE_CRYPTO,
      52, 72, 48, 75, 68, 30, 44,
      { 32, 33, 38, 34, 62, 35, 39, 36 },
      { 1, 1, 12, 16, 20, 24, 30, 36 },
      "Breaks encryption through sheer computational force." },

    /* 44: JohnRipper */
    { 44, "JohnRipper", TYPE_CRYPTO,
      72, 90, 62, 88, 85, 0, -1,
      { 32, 33, 34, 35, 38, 36, 37, 39 },
      { 1, 1, 1, 14, 22, 28, 36, 44 },
      "The legendary password cracker. No hash is safe." },

    /* ────── WIRELESS TYPE (45-50) ────── */
    /* 45: Beacon */
    { 45, "Beacon", TYPE_WIRELESS,
      42, 48, 44, 55, 50, 16, 46,
      { 40, 47, 41, 44, 42, 43, 45, 46 },
      { 1, 5, 10, 14, 18, 22, 28, 34 },
      "Broadcasts SSIDs to lure unsuspecting clients." },

    /* 46: Deauther */
    { 46, "Deauther", TYPE_WIRELESS,
      58, 65, 58, 70, 65, 32, 47,
      { 40, 41, 47, 44, 42, 43, 45, 46 },
      { 1, 1, 14, 18, 22, 26, 32, 38 },
      "Kicks devices off WiFi with spoofed management frames." },

    /* 47: Pineapple */
    { 47, "Pineapple", TYPE_WIRELESS,
      78, 82, 75, 88, 82, 0, -1,
      { 40, 41, 42, 44, 47, 43, 45, 46 },
      { 1, 1, 1, 18, 22, 28, 36, 44 },
      "WiFi auditing platform. Creates rogue access points." },

    /* 48: Probe */
    { 48, "Probe", TYPE_WIRELESS,
      40, 45, 42, 52, 48, 14, 49,
      { 40, 65, 47, 41, 44, 42, 43, 45 },
      { 1, 4, 8, 12, 16, 20, 24, 28 },
      "Listens for probe requests to identify nearby devices." },

    /* 49: WifiSniff */
    { 49, "WifiSniff", TYPE_WIRELESS,
      55, 60, 55, 68, 62, 30, 50,
      { 40, 47, 41, 44, 42, 43, 45, 46 },
      { 1, 1, 12, 16, 20, 24, 30, 36 },
      "Captures wireless packets in monitor mode." },

    /* 50: Aircrack */
    { 50, "Aircrack", TYPE_WIRELESS,
      72, 78, 70, 85, 80, 0, -1,
      { 40, 41, 42, 44, 47, 43, 45, 46 },
      { 1, 1, 1, 16, 22, 28, 36, 44 },
      "Cracks WEP and WPA keys. The WiFi audit legend." },

    /* ────── PHYSICAL TYPE (51-56) ────── */
    /* 51: Rubberduck */
    { 51, "Rubberduck", TYPE_PHYSICAL,
      44, 52, 42, 50, 45, 16, 52,
      { 48, 49, 50, 54, 51, 52, 53, 55 },
      { 1, 5, 10, 14, 18, 22, 28, 34 },
      "Looks like a USB drive. Injects keystrokes on plug-in." },

    /* 52: BadUSB */
    { 52, "BadUSB", TYPE_PHYSICAL,
      58, 68, 55, 65, 60, 32, 53,
      { 48, 49, 50, 51, 54, 52, 53, 55 },
      { 1, 1, 14, 18, 22, 26, 32, 38 },
      "Reprogrammed USB firmware. Emulates any device type." },

    /* 53: FlipperZero */
    { 53, "FlipperZero", TYPE_PHYSICAL,
      78, 85, 72, 82, 78, 0, -1,
      { 48, 49, 50, 51, 52, 54, 53, 55 },
      { 1, 1, 1, 14, 22, 28, 36, 44 },
      "Multi-tool for hardware hacking. RFID, IR, Sub-GHz, GPIO." },

    /* 54: Lockpick */
    { 54, "Lockpick", TYPE_PHYSICAL,
      40, 45, 50, 48, 42, 14, 55,
      { 50, 48, 54, 51, 49, 52, 53, 55 },
      { 1, 4, 8, 12, 16, 20, 24, 30 },
      "Manipulates pin tumblers to bypass physical locks." },

    /* 55: Bypass */
    { 55, "Bypass", TYPE_PHYSICAL,
      55, 60, 65, 62, 55, 30, 56,
      { 50, 48, 49, 54, 51, 52, 53, 55 },
      { 1, 1, 12, 16, 20, 24, 30, 36 },
      "Circumvents physical security controls and access barriers." },

    /* 56: PhysAccess */
    { 56, "PhysAccess", TYPE_PHYSICAL,
      72, 78, 82, 75, 70, 0, -1,
      { 48, 49, 50, 51, 52, 54, 53, 55 },
      { 1, 1, 1, 14, 20, 26, 34, 42 },
      "Full physical breach specialist. No door stays locked." },

    /* ────── ZERO-DAY LEGENDARY (57-59) ────── */
    /* 57: ZeroDawn */
    { 57, "ZeroDawn", TYPE_ZERODAY,
      106, 110, 100, 105, 108, 0, -1,
      { 56, 57, 58, 4, 20, 59, 36, 46 },
      { 1, 1, 1, 20, 30, 40, 50, 60 },
      "Born from an unpatched flaw. Exists before any defense." },

    /* 58: Rootkit */
    { 58, "Rootkit", TYPE_ZERODAY,
      100, 115, 95, 110, 112, 0, -1,
      { 57, 56, 22, 58, 19, 59, 37, 5 },
      { 1, 1, 1, 20, 30, 40, 50, 60 },
      "Hides deep in the kernel. Invisible to all detection." },

    /* 59: APTdragon */
    { 59, "APTdragon", TYPE_ZERODAY,
      110, 120, 105, 100, 118, 0, -1,
      { 58, 59, 56, 57, 29, 13, 5, 22 },
      { 1, 1, 1, 20, 30, 40, 50, 60 },
      "State-sponsored threat. The apex predator of cyberspace." },
};

int SPECIES_COUNT = 60;

/* ══════════════════════════════════════════════════════════════
 *  ITEM DEFINITIONS
 * ══════════════════════════════════════════════════════════════ */
Item ALL_ITEMS[] = {
    /* Healing Items */
    /* 0 */ { 0, "Patch",        0,  30,   100 },
    /* 1 */ { 1, "Hotfix",       0,  60,   250 },
    /* 2 */ { 2, "Service Pack",  0, 120,   500 },
    /* 3 */ { 3, "DebugKit",     0, 9999,  1000 },

    /* Capture Items */
    /* 4 */ { 4, "Capture.exe",  1,  10,   200 },
    /* 5 */ { 5, "RootKit.exe",  1,  25,   600 },
    /* 6 */ { 6, "ZeroDay.exe",  1, 100,  2000 },

    /* Battle Items */
    /* 7 */ { 7, "Firewall",     2,   0,   350 },
    /* 8 */ { 8, "Antivirus",    2,   0,   400 },
    /* 9 */ { 9, "VPN",          2,   0,   300 },

    /* Status Cure */
    /* 10 */ { 10, "Decryptor",   0,   0,  200 },

    /* PP Restore */
    /* 11 */ { 11, "Bandwidth",   0,  10,  300 },

    /* Key Items */
    /* 12 */ { 12, "Server Key",  3,   0,     0 },
    /* 13 */ { 13, "Root Cert",   3,   0,     0 },
    /* 14 */ { 14, "SSH Key",     3,   0,     0 },

    /* Stat Boost */
    /* 15 */ { 15, "Overclock",   2,   0,  500 },
    /* 16 */ { 16, "RAM Upgrade",  2,   0,  500 },
    /* 17 */ { 17, "SSD Cache",   2,   0,  500 },

    /* Revive */
    /* 18 */ { 18, "Reboot.exe",  0,   1,  800 },
    /* 19 */ { 19, "Full Reboot",  0,   2, 1500 },
};

int ITEM_COUNT = 20;
