# CYBERWORLD ROM HACK GUIDE
## Creating Custom Pokémon ROM Hacks with CyberWorld Theme
### FLLC | FU PERSON | DSi Operations

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  [+]* POKÉMON FIRERED → CYBERWORLD ROM HACK * TOOLS * PATCHES [*]+        ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## BASE ROM SELECTION

| Option | ROM | Pros | Cons |
|--------|-----|------|------|
| **Recommended** | Pokémon FireRed (USA) | Stable, well-documented, many tools | GBA not DSi-native (use GBARunner2) |
| Alternative | Pokémon LeafGreen (USA) | Same engine as FireRed | Same as above |
| DSi Native | Pokémon Diamond/Pearl | Runs natively on DSi | Fewer hacking tools; more complex |

**[+]** For TWiLight Menu++ on DSi: Use **FireRed** patched to `.nds` format via GBARunner2, or a DS-native Pokemon ROM (D/P/Pl/HGSS/BW) if hacking DS games. **[+]**

---

## TOOLS REQUIRED

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ESSENTIAL TOOLS                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  • PKHeX          — Save editor; modify Pokémon/Daemon data               │
│  • Advance Map    — Map editor; change locations, names                   │
│  • Advance Text   — Text editor; dialogue, items, moves                    │
│  • G3T            — Sprite/overworld editor                               │
│  • Free Space Finder — Locate free ROM space for new data                  │
│  • PKSV / Porymap — Alternative map/script editors                        │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  OPTIONAL / ADVANCED                                                      │
├──────────────────────────────────────────────────────────────────────────┤
│  • XSE (eXtreme Script Editor) — Scripting for events                     │
│  • Gen 3 Hacking Suite — All-in-one toolset                               │
│  • Tile Layer Pro — Custom tilesets                                       │
│  • Nameless Sprite Editor — Sprite creation                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## NAME REPLACEMENT TABLE

### Pokémon → Daemon (151 Kanto + Extras)

| # | Original | CyberWorld Daemon |
|---|----------|------------------|
| 1 | Bulbasaur | Ping |
| 2 | Ivysaur | Tracert |
| 3 | Venusaur | Nmap |
| 4 | Charmander | XSSling |
| 5 | Charmeleon | CrossSite |
| 6 | Charizard | DOMinator |
| 7 | Squirtle | Stacksmash |
| 8 | Wartortle | Overflow |
| 9 | Blastoise | BufferKing |
| 10 | Caterpie | Portknock |
| 11 | Metapod | Portscan |
| 12 | Butterfree | Masscan |
| 13 | Weedle | SQLimp |
| 14 | Kakuna | Injection |
| 15 | Beedrill | Sqlmap |
| 16 | Pidgey | Beacon |
| 17 | Pidgeotto | Deauther |
| 18 | Pidgeot | Pineapple |
| 19 | Rattata | Phishling |
| 20 | Raticate | Spearphish |
| 21 | Spearow | Hashling |
| 22 | Fearow | Hashcat |
| 23 | Ekans | Rubberduck |
| 24 | Arbok | BadUSB |
| 25 | Pikachu | Sniffer |
| 26 | Raichu | Wireshark |
| 27 | Sandshrew | Crawlr |
| 28 | Sandslash | Webworm |
| 29 | Nidoran♀ | Keylogger |
| 30 | Nidorina | Cracker |
| 31 | Nidoqueen | JohnRipper |
| 32 | Nidoran♂ | Shellcode |
| 33 | Nidorino | Payload |
| 34 | Nidoking | Meterpreter |
| 35 | Clefairy | Pretextr |
| 36 | Clefable | Deepfake |
| 37 | Vulpix | Cipher |
| 38 | Ninetales | AESdragon |
| 39 | Jigglypuff | Baiter |
| 40 | Wigglytuff | Waterhole |
| 41 | Zubat | Probe |
| 42 | Golbat | Aircrack |
| 43 | Oddish | Debugger |
| 44 | Gloom | Reverser |
| 45 | Vileplume | Ghidra |
| 46 | Paras | Bluetooth |
| 47 | Parasect | UberBLE |
| 48 | Venonat | Lockpick |
| 49 | Venomoth | PhysAccess |
| 50 | Diglett | Tailgater |
| 51 | Dugtrio | Insider |
| 52 | Meowth | LogicBomb |
| 53 | Persian | Ransomlord |
| 54 | Psyduck | ZeroDawn |
| 55 | Golduck | Rootkit |
| 56 | Mankey | APTdragon |
| 57 | Primeape | → (assign remaining) |
| 58 | Growlithe | ARPspoof |
| 59 | Arcanine | Netcat |
| 60 | Poliwag | Fuzzer |
| 61 | Poliwhirl | ROPgadget |
| 62 | Poliwrath | Dirbuster |
| 63 | Abra | Nikto |
| 64 | Kadabra | Burpbeast |
| 65 | Alakazam | CertSpoof |
| 66 | Machop | Wardriver |
| 67 | Machoke | USBdropper |
| 68 | Machamp | Wormlord |
| 69 | Bellsprout | Backdoor |
| 70 | Weepinbell | Trojanlord |
| 71 | Victreebel | BSOD |
| 72 | Tentacool | 404 |
| 73 | Tentacruel | Pwn2Own |
| 74 | Geodude | Stackoverflow |
| 75 | Graveler | Dialup |
| 76 | Golem | Nethack |
| 77 | Ponyta | KernelPanic |
| 78 | Rapidash | Coinhive |
| 79 | Slowpoke | Shodan |
| 80 | Slowbro | Clippy |
| 81-151 | (others) | Map remaining per DAEMONS.md |

---

## TYPE CHART REMAPPING

Pokémon has 15 types → CyberWorld has 8. Remap as follows:

| Pokemon Type | CyberWorld Type |
|--------------|-----------------|
| Normal | Network |
| Fire | Binary |
| Water | Web |
| Electric | Wireless |
| Grass | Physical |
| Ice | Crypto |
| Fighting | Physical |
| Poison | Social |
| Ground | Physical |
| Flying | Wireless |
| Psychic | Zero-Day |
| Bug | Web |
| Rock | Binary |
| Ghost | Zero-Day |
| Dragon | Zero-Day |

**[!]** Type effectiveness must be manually edited in ROM; use a type chart editor or hex patch. **[!]**

---

## REGION NAME CHANGES

### Kanto → CyberWorld

| Original | CyberWorld |
|----------|------------|
| Kanto | CyberWorld |
| Pallet Town | 127.0.0.1 |
| Viridian City | LAN Valley |
| Pewter City | Packet Plains |
| Cerulean City | Wireless Woods |
| Lavender Town | Darknet Depths |
| Celadon City | Cloud Citadel |
| Vermilion City | Firewall Fortress |
| Fuchsia City | WAN Wasteland |
| Cinnabar Island | Zero-Day Peaks |
| Victory Road | SOC Corridor |
| Indigo Plateau | CISO Tower |
| Route 1 | Subnet 1 |
| Route 2 | Subnet 2 |
| ... | Subnet N |
| Mt. Moon | Firewall Mountain |
| Rock Tunnel | Encrypted Tunnel |
| Safari Zone | Honeypot Zone |
| Pokémon Tower | Log Tower |
| Silph Co. | Silph.Sec |
| Pokémon League | Security League |

---

## TOWN / CITY NAME MAPPINGS

| Original | CyberWorld |
|----------|------------|
| Oak's Lab | Prof. Kernel's Lab |
| Pokémon Center | Daemon Center |
| Pokémon Mart | Module Mart |
| Gym | Sysadmin HQ |
| Elite Four | SOC Analysts |
| Champion Room | CISO Chamber |
| Professor Oak | Professor Kernel |
| Rival | Rival Script |
| Nurse Joy | Nurse Patch |
| Officer Jenny | Officer Firewall |

---

## ITEM RENAMES

| Original | CyberWorld |
|----------|------------|
| Potion | Patch |
| Super Potion | Kernel Patch |
| Hyper Potion | Full Patch |
| Max Potion | Zero-Day Patch |
| Poké Ball | Capture.exe |
| Great Ball | Capture Pro |
| Ultra Ball | Capture Elite |
| Master Ball | Root Capture |
| Antidote | Decrypt |
| Paralyze Heal | Unblock |
| Awakening | Reboot |
| Burn Heal | Firewall Restore |
| Ice Heal | Thaw |
| Full Heal | Full Restore |
| Revive | Reboot Daemon |
| Max Revive | Full Reboot |
| Escape Rope | Tor Router |
| Poke Flute | Wireshark Lens |
| Silph Scope | Nmap Scanner |
| Rare Candy | Exploit Candy |
| TM/HM | Module (TM = Temp, HM = Permanent) |

---

## MOVE RENAMES (Key Moves)

| Original | CyberWorld |
|----------|------------|
| Tackle | Ping |
| Scratch | Probe |
| Ember | Burn |
| Water Gun | Inject |
| Vine Whip | Sniff |
| Thunder Shock | Deauth |
| Poison Sting | Phish |
| Psychic | Rootkit |
| Hyper Beam | Full Scan |
| Explosion | Logic Bomb |
| Surf | Flood |
| Fly | Evade |
| Strength | Brute Force |
| Flash | Beacon |
| Cut | Cut Connection |
| Rock Smash | Break Wall |
| Fire Blast | Ransom |
| Blizzard | Freeze |
| Thunder | Overload |
| Earthquake | DDoS |
| Fissure | Kernel Panic |
| Guillotine | Kill -9 |
| Horn Drill | Port Drill |
| Wrap | Encrypt |
| Bite | Sniff Packet |
| Mega Drain | Data Exfil |
| Leech Seed | Keylogger |
| Confusion | Social Engine |
| Hypnosis | Honeypot |
| Dream Eater | Data Harvest |
| Night Shade | Darknet Strike |
| Mimic | Replay Attack |
| Rest | Idle |
| Substitute | Sandbox |
| Transform | Spoof |

---

## SPRITE CONCEPT DESCRIPTIONS

### Starter Daemons

| Daemon | Sprite Concept |
|--------|----------------|
| **Ping** | Small spherical packet with antenna; ICMP echo look; green/gray palette |
| **XSSling** | Serpentine creature made of `<script>` tags; orange/yellow; injects from mouth |
| **Stacksmash** | Blocky cube with crack; binary 0/1 pattern; red warning colors |

### Key Evolutions

| Daemon | Sprite Concept |
|--------|----------------|
| **Nmap** | Robotic scanner with multiple antennae; port icons on body; stealth gray |
| **Sqlmap** | Serpent with SQL syntax markings; union/inject visual |
| **BufferKing** | Crowned buffer overflow; stack frames as armor; royal purple |
| **Meterpreter** | Multi-armed post-exploit entity; shell icons; stealth black/red |
| **Pineapple** | WiFi pineapple aesthetic; glowing LEDs; pineapple-shaped AP |
| **FlipperZero** | Dolphin-like device; LCD screen on belly; cyan/black |
| **ZeroDawn** | Glowing question mark; unknown vulnerability; purple/gold |
| **Rootkit** | Invisible silhouette; kernel ring; barely visible |
| **APTdragon** | Dragon with nation-state insignia; persistent flames |

### General Style

- **Network**: Circuit patterns, packets, antennae
- **Web**: Script tags, URLs, spiders
- **Binary**: Hex values, stack frames, assembly
- **Social**: Masks, emails, phones
- **Crypto**: Lock icons, hash symbols, keys
- **Wireless**: Radio waves, antennas, signals
- **Physical**: USB, keys, doors
- **Zero-Day**: Glowing, mysterious, high contrast

---

## HACKER TERMINAL FORMATTING IN-GAME

Use box-drawing and symbols in dialogue/text where possible:

- `[+]` — Success
- `[*]` — Info
- `[!]` — Warning
- `═══` — Section dividers
- `>>>` — Prompt style for battles

Example battle text:
```
════════════════════════════════
[*] LAN Larry wants to battle!
[+] LAN Larry sent out Portscan!
>>> Your move, Trainer.
════════════════════════════════
```

---

## FU PERSON INTEGRATION

- ROM should be named `CyberWorld_FireRed.nds` for `autolaunch.ini`
- Place in `sd:/roms/nds/` or `sd:/roms/gba/` (if GBA + GBARunner2)
- Ensure compatibility with `covert_scan.py` background process
- Loot from WiFi scans syncs to main FU PERSON aggregation

---

*FLLC | FU PERSON | DSi Operations | ROM Hack Guide v1.0*
