# CYBERWORLD
## Game Design Document | FLLC | FU PERSON | DSi Operations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗    ██╗ ██████╗ ██████╗ ██╗     │
│ ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║    ██║██╔═══██╗██╔══██╗██║     │
│ ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║ █╗ ██║██║   ██║██████╔╝██║     │
│ ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║███╗██║██║   ██║██╔══██╗██║     │
│ ╚██████╗   ██║   ██║  ██║███████╗██║  ██║╚███╔███╔╝╚██████╔╝██║  ██║███████╗│
│  ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝│
│                                                                             │
│  [+]* POKÉMON-STYLE RPG * DAEMON BATTLES * COVERT WIFI RECON * [+]*         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## CONCEPT OVERVIEW

**[+]** CyberWorld is a Pokémon-style RPG where you capture, train, and battle **Daemons** — digital entities based on real exploits, tools, and security concepts — instead of Pokémon. The twist: your DSi runs WiFi reconnaissance in the background while you play. To any observer, you're just another kid playing a game. **[+]**

| Aspect | Pokémon | CyberWorld |
|--------|---------|------------|
| Creatures | Pokémon | **Daemons** |
| Battles | Type matchups | Type effectiveness (8 types) |
| World | Kanto, Johto... | CyberWorld regions |
| Goal | Champion | CISO (Chief Info Sec Officer) |
| Gyms | Gym Leaders | **Sysadmins** |
| Elite Four | Elite Four | **SOC Analysts** |
| Background | — | **WiFi probe capture** |

---

## COVER STORY

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  COVER STORY — OPERATIONAL SECURITY                                        ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  You're sitting in a café, airport lounge, or office lobby. To anyone     ║
║  watching, you're a casual gamer enjoying a retro Pokémon-style RPG on     ║
║  your Nintendo DSi. The screen shows colorful monsters, turn-based        ║
║  battles, and a fantasy world.                                            ║
║                                                                            ║
║  What they don't see:                                                      ║
║  • The DSi's WiFi chip passively scanning for access points                ║
║  • Probe requests being logged to a hidden directory                      ║
║  • SSIDs, BSSIDs, signal strength, channels — all captured                ║
║  • Data exfiltrated later via FTP to FU PERSON loot aggregation            ║
║                                                                            ║
║  [*] You're just playing a game. The game just happens to do recon. [*]    ║
║                                                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## THE WORLD: CYBERWORLD REGIONS

```
┌──────────────────────────────────────────────────────────────────────────┐
│  REGION MAP — CyberWorld                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   [LAN Valley] ──┬── [Packet Plains] ── [Firewall Fortress]             │
│         │         │           │                     │                     │
│         │         │           └─────────────────────┼── [Zero-Day Peaks]  │
│         │         │                                 │         ▲           │
│         v         v                                 v         │           │
│   [Wireless Woods] ────────── [WAN Wasteland] ──────┴─────────┘           │
│         │                     │                                          │
│         │                     │                                           │
│         v                     v                                           │
│   [Darknet Depths] ───── [Cloud Citadel]                                  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

| Region | Theme | Difficulty | Description |
|--------|-------|------------|-------------|
| **LAN Valley** | Local network basics | ★☆☆☆☆ | Starting area. ARP, ICMP, basic scanning. |
| **WAN Wasteland** | Wide area, routing | ★★☆☆☆ | BGP hijacking, routing exploits, remote attacks. |
| **Darknet Depths** | Hidden services | ★★★★☆ | Tor-style anonymity, .onion domains, underground markets. |
| **Cloud Citadel** | Cloud infrastructure | ★★★★☆ | AWS, Azure, container escapes, final story area. |
| **Wireless Woods** | WiFi / BLE hunting | ★★☆☆☆ | SSIDs, probe requests, deauth, wardriving. |
| **Packet Plains** | Traffic analysis | ★★★☆☆ | Wireshark, packet inspection, protocol fuzzing. |
| **Firewall Fortress** | Defense challenges | ★★★☆☆ | IDS evasion, rule bypass, stateful inspection. |
| **Zero-Day Peaks** | Endgame | ★★★★★ | 0-days, APTs, kernel exploits. Most dangerous. |

---

## CREATURES: DAEMONS

Daemons are digital entities modeled after real exploits, tools, and security concepts. You capture them with **Capture.exe**, train them in battle, and evolve them through exposure to vulnerabilities.

**[+]** Example evolution chain: **Ping** → **Tracert** → **Nmap** **[+]**

---

## TYPE SYSTEM (8 TYPES)

```
┌─────────┬────────┬──────┬───────┬───────┬─────────┬──────────┬─────────┬──────────┐
│ Attck \ │Network │ Web  │Binary │Social │ Crypto  │ Wireless │Physical │ Zero-Day │
├─────────┼────────┼──────┼───────┼───────┼─────────┼──────────┼─────────┼──────────┤
│Network  │   —    │ 2×   │ 1×    │ 0.5×  │  0.5×   │   2×     │  1×     │   0.5×   │
│ Web     │  0.5×  │  —   │ 2×    │ 1×    │  0.5×   │   1×     │  0.5×   │   1×     │
│ Binary  │  1×    │ 0.5× │  —    │ 0.5×  │  1×     │   0.5×   │  2×     │   0.5×   │
│ Social  │  2×    │ 1×   │ 2×    │  —    │  2×     │   1×     │  0.5×   │   1×     │
│ Crypto  │  2×    │ 2×   │ 1×    │ 0.5×  │   —     │   0.5×   │  1×     │   0.5×   │
│Wireless │  0.5×  │ 1×   │ 2×    │ 1×    │  2×     │    —     │  2×     │   1×     │
│Physical │  1×    │ 2×   │ 0.5×  │ 2×    │  1×     │   0.5×   │   —     │   2×     │
│Zero-Day │  2×    │ 1×   │ 2×    │ 1×    │  2×     │   1×     │  1×     │    —     │
└─────────┴────────┴──────┴───────┴───────┴─────────┴──────────┴─────────┴──────────┘

Legend: 2× = super effective | 0.5× = not very effective | 1× = normal | — = same type
```

---

## BATTLE SYSTEM

| Mechanic | Description |
|----------|-------------|
| **Turns** | Classic turn-based (you → enemy → you → …) |
| **Moves** | 4 moves per Daemon, each with PP (Power Points) |
| **Stats** | HP, ATK, DEF, SPD, SPEC |
| **PP** | 5–40 PP per move; 0 = cannot use |

### Status Conditions

| Status | Effect |
|--------|--------|
| **Encrypted** | Damage reduced; harder to hit. |
| **Sandboxed** | Cannot use certain moves. |
| **Patched** | Heal over time; vulnerability removed. |
| **Firewalled** | Incoming damage reduced. |
| **Honeypotted** | Attracted to fake targets; accuracy drop. |

---

## PROGRESSION

### 8 GYM LEADERS (SYSTEM ADMINISTRATORS)

| # | Leader | Type | Region |
|---|--------|------|--------|
| 1 | **LAN Larry** | Network | LAN Valley |
| 2 | **Web Wendy** | Web | Packet Plains |
| 3 | **Binary Bob** | Binary | Firewall Fortress |
| 4 | **Social Sarah** | Social | Wireless Woods |
| 5 | **Crypto Carl** | Crypto | Cloud Citadel outskirts |
| 6 | **Wire Will** | Wireless | Wireless Woods depths |
| 7 | **Physic Phil** | Physical | Darknet Depths |
| 8 | **Zero Zara** | Zero-Day | Zero-Day Peaks |

### ELITE FOUR (SOC ANALYSTS)

Each member uses a **mixed-type** team (2–3 types per analyst):

- **Monitor Mike** — Network + Binary
- **Alert Annie** — Web + Wireless
- **Incident Ian** — Crypto + Social
- **Responder Rita** — Physical + Zero-Day

### CHAMPION (CISO)

**CISO** — Chief Information Security Officer. Full balanced team with Daemons from all 8 types. Ultimate challenge.

---

## STARTER DAEMONS

```
  ╭─────────────╮    ╭─────────────╮    ╭─────────────╮
  │    PING     │    │   XSSLING   │    │ STACKSMASH  │
  │  (Network)  │    │    (Web)    │    │  (Binary)   │
  │   [ICMP]    │    │   [XSS]     │    │  [Buffer]   │
  ╰─────────────╯    ╰─────────────╯    ╰─────────────╯
```

| Starter | Type | Signature Move | Evolution |
|---------|------|----------------|-----------|
| **Ping** | Network | ICMP Echo | → Tracert → Nmap |
| **XSSling** | Web | Script Inject | → CrossSite → DOMinator |
| **Stacksmash** | Binary | Buffer Overflow | → Overflow → BufferKing |

---

## ITEMS

| Item | Effect |
|------|--------|
| **Wireshark Lens** | See hidden packets; reveal opponent's next move. |
| **Burp Proxy Shield** | Block one Web-type attack. |
| **Hashcat Hammer** | Boost Crypto-type moves for one battle. |
| **Nmap Scanner** | Discover wild Daemon types in area. |
| **Metasploit Module** | One-use exploit; massive damage. |
| **John's Cracker** | Break Encrypted status. |
| **Tor Router** | Evade capture; escape any battle. |

---

## BACKGROUND WIFI INTEGRATION

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  COVERT RECON — DSi WiFi Integration                                       ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  The CyberWorld ROM launches via TWiLight Menu++ with autolaunch.ini.     ║
║  A companion process (covert_scan.py) runs in the background:             ║
║                                                                            ║
║  [+]* SCAN_INTERVAL_MS=5000 — Poll every 5 seconds (low CPU)              ║
║  [+]* LOG_PATH=sd:/.cyberworld/.scan_data/ — Hidden directory             ║
║  [+]* LOG_FORMAT=csv — Compatible with FU PERSON loot aggregation         ║
║  [+]* PROBE_CAPTURE=1 — Log probe requests from nearby devices            ║
║  [+]* HIDDEN_DIR=1 — .cyberworld not visible in standard file browser     ║
║                                                                            ║
║  Data logged per entry:                                                    ║
║  • timestamp_utc, ssid, bssid, signal_dbm, channel, encryption            ║
║  • probe_ssid (if probe request captured)                                 ║
║                                                                            ║
║  [*] Game runs normally. Scanner sleeps between polls. Plausible deny. [*]║
║                                                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## HACKER TERMINAL FORMATTING

Throughout the game UI:
- `[+]` — Success / confirmed action
- `[*]` — Information / flavor text
- `[!]` — Warning / critical
- Box-drawing: `═`, `─`, `│`, `╔`, `╗`, `╚`, `╝`, `┌`, `┐`, `└`, `┘`, `├`, `┤`, `┬`, `┴`

---

*FLLC | FU PERSON | DSi Operations | CyberWorld GDD v1.0*
