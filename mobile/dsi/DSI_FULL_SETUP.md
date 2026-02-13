# Nintendo DSi — Full Jailbreak + Game Library Setup

**FLLC | Complete guide from stock to fully loaded.**

---

## Phase 1: Jailbreak the DSi

### What You Need

- Nintendo DSi (any region)
- SD card (up to 32GB, FAT32 formatted)
- PC with SD card reader
- Internet connection

### Step 1: Install Unlaunch (Permanent Exploit)

Unlaunch is a NAND-level exploit. Once installed, it runs before the DSi OS loads.

1. **Check firmware**: Settings > System Settings > Page 4 > System Information
2. **Download Memory Pit**: https://dsi.cfw.guide/assets/files/memory_pit/
   - Pick the file matching your firmware version
3. **Copy to SD**: Place `pit.bin` in `sd:/private/ds/app/484E494A/`
   - Create these folders if they don't exist
4. **Trigger exploit**: 
   - Insert SD into DSi
   - Open DSi Camera app
   - Select "SD Card" view
   - Exploit triggers automatically
5. **Install Unlaunch**:
   - Download: https://problemkaputt.de/unlaunch.zip
   - Copy `UNLAUNCH.DSI` to SD root
   - Boot HiyaCFW Helper (from Memory Pit)
   - Select "Install Unlaunch"
   - **Power off when complete** (do NOT touch anything during install)
6. **Verify**: Hold A+B on boot → Unlaunch menu appears

### Step 2: Install TWiLight Menu++

This is your homebrew launcher — runs DS/DSi/GBA/SNES/NES/GB games.

1. **Download**: https://github.com/DS-Homebrew/TWiLightMenu/releases
   - Get `TWiLightMenu.7z`
2. **Extract to SD**: Copy the `_nds` and `roms` folders to SD root
3. **Boot**: Unlaunch auto-launches TWiLight Menu++ on power-on

### Step 3: Install HiyaCFW (Optional — NAND Redirect)

Redirects DSi system NAND to the SD card. Safer, more storage.

1. **Download HiyaCFW Helper**: https://github.com/mondul/HiyaCFW-Helper/releases
2. **Dump your NAND** (via Unlaunch menu > NAND backup)
3. **Run HiyaCFW Helper** on PC with your NAND dump
4. **Copy output to SD**

---

## Phase 2: Game Library — Hundreds of Classics

### Directory Structure

```
SD:\
├── _nds\                    TWiLight Menu++ system files
├── roms\
│   ├── nds\                 Nintendo DS games (.nds)
│   ├── gba\                 Game Boy Advance (.gba)
│   ├── gb\                  Game Boy / Color (.gb, .gbc)
│   ├── nes\                 NES games (.nes)
│   ├── snes\                SNES games (.smc, .sfc)
│   ├── sega\                Sega Genesis/MD (.gen, .md)
│   └── homebrew\            Homebrew .nds apps
└── tools\                   FLLC pentest tools
```

### Pokemon Collection (COMPLETE)

| Game | System | File |
|------|--------|------|
| Pokemon Red | GB | `roms/gb/Pokemon_Red.gb` |
| Pokemon Blue | GB | `roms/gb/Pokemon_Blue.gb` |
| Pokemon Yellow | GB | `roms/gb/Pokemon_Yellow.gb` |
| Pokemon Gold | GBC | `roms/gb/Pokemon_Gold.gbc` |
| Pokemon Silver | GBC | `roms/gb/Pokemon_Silver.gbc` |
| Pokemon Crystal | GBC | `roms/gb/Pokemon_Crystal.gbc` |
| Pokemon Pinball | GBC | `roms/gb/Pokemon_Pinball.gbc` |
| Pokemon TCG | GBC | `roms/gb/Pokemon_TCG.gbc` |
| Pokemon Puzzle Challenge | GBC | `roms/gb/Pokemon_Puzzle.gbc` |
| Pokemon Ruby | GBA | `roms/gba/Pokemon_Ruby.gba` |
| Pokemon Sapphire | GBA | `roms/gba/Pokemon_Sapphire.gba` |
| Pokemon Emerald | GBA | `roms/gba/Pokemon_Emerald.gba` |
| Pokemon FireRed | GBA | `roms/gba/Pokemon_FireRed.gba` |
| Pokemon LeafGreen | GBA | `roms/gba/Pokemon_LeafGreen.gba` |
| Pokemon Mystery Dungeon: Red Rescue Team | GBA | `roms/gba/Pokemon_MD_Red.gba` |
| Pokemon Pinball: Ruby & Sapphire | GBA | `roms/gba/Pokemon_Pinball_RS.gba` |
| Pokemon Diamond | NDS | `roms/nds/Pokemon_Diamond.nds` |
| Pokemon Pearl | NDS | `roms/nds/Pokemon_Pearl.nds` |
| Pokemon Platinum | NDS | `roms/nds/Pokemon_Platinum.nds` |
| Pokemon HeartGold | NDS | `roms/nds/Pokemon_HeartGold.nds` |
| Pokemon SoulSilver | NDS | `roms/nds/Pokemon_SoulSilver.nds` |
| Pokemon Black | NDS | `roms/nds/Pokemon_Black.nds` |
| Pokemon White | NDS | `roms/nds/Pokemon_White.nds` |
| Pokemon Black 2 | NDS | `roms/nds/Pokemon_Black2.nds` |
| Pokemon White 2 | NDS | `roms/nds/Pokemon_White2.nds` |
| Pokemon Conquest | NDS | `roms/nds/Pokemon_Conquest.nds` |
| Pokemon Ranger | NDS | `roms/nds/Pokemon_Ranger.nds` |
| Pokemon Ranger: SoA | NDS | `roms/nds/Pokemon_Ranger_SoA.nds` |
| Pokemon Ranger: Guardian Signs | NDS | `roms/nds/Pokemon_Ranger_GS.nds` |
| Pokemon Mystery Dungeon: Blue | NDS | `roms/nds/Pokemon_MD_Blue.nds` |
| Pokemon MD: Explorers of Time | NDS | `roms/nds/Pokemon_MD_Time.nds` |
| Pokemon MD: Explorers of Darkness | NDS | `roms/nds/Pokemon_MD_Darkness.nds` |
| Pokemon MD: Explorers of Sky | NDS | `roms/nds/Pokemon_MD_Sky.nds` |
| Pokemon Dash | NDS | `roms/nds/Pokemon_Dash.nds` |
| Pokemon Trozei | NDS | `roms/nds/Pokemon_Trozei.nds` |
| Pokemon Typing Adventure | NDS | `roms/nds/Pokemon_Typing.nds` |

**35+ Pokemon games** across every generation the DSi can play.

### Classic Game Library (200+ Titles)

#### Nintendo DS (Top 50)

| # | Game | Genre |
|---|------|-------|
| 1 | Mario Kart DS | Racing |
| 2 | New Super Mario Bros | Platformer |
| 3 | Super Mario 64 DS | Platformer |
| 4 | The Legend of Zelda: Phantom Hourglass | Adventure |
| 5 | The Legend of Zelda: Spirit Tracks | Adventure |
| 6 | Animal Crossing: Wild World | Simulation |
| 7 | Kirby Super Star Ultra | Platformer |
| 8 | Kirby: Canvas Curse | Platformer |
| 9 | Castlevania: Dawn of Sorrow | Action |
| 10 | Castlevania: Portrait of Ruin | Action |
| 11 | Castlevania: Order of Ecclesia | Action |
| 12 | Metroid Prime Hunters | FPS |
| 13 | Advance Wars: Dual Strike | Strategy |
| 14 | Advance Wars: Days of Ruin | Strategy |
| 15 | Fire Emblem: Shadow Dragon | Strategy |
| 16 | Final Fantasy III | RPG |
| 17 | Final Fantasy IV | RPG |
| 18 | Final Fantasy Tactics A2 | Strategy RPG |
| 19 | Dragon Quest IV | RPG |
| 20 | Dragon Quest V | RPG |
| 21 | Dragon Quest IX | RPG |
| 22 | Chrono Trigger | RPG |
| 23 | The World Ends With You | Action RPG |
| 24 | Mario & Luigi: Partners in Time | RPG |
| 25 | Mario & Luigi: Bowser's Inside Story | RPG |
| 26 | Professor Layton and the Curious Village | Puzzle |
| 27 | Professor Layton and the Diabolical Box | Puzzle |
| 28 | Professor Layton and the Unwound Future | Puzzle |
| 29 | Phoenix Wright: Ace Attorney | Visual Novel |
| 30 | Phoenix Wright: Justice for All | Visual Novel |
| 31 | Phoenix Wright: Trials and Tribulations | Visual Novel |
| 32 | Apollo Justice: Ace Attorney | Visual Novel |
| 33 | Ghost Trick: Phantom Detective | Puzzle |
| 34 | 999: Nine Hours, Nine Persons, Nine Doors | Visual Novel |
| 35 | Sonic Rush | Platformer |
| 36 | Sonic Rush Adventure | Platformer |
| 37 | Mega Man ZX | Action |
| 38 | Mega Man ZX Advent | Action |
| 39 | Mega Man Star Force | RPG |
| 40 | Contra 4 | Action |
| 41 | Ninja Gaiden: Dragon Sword | Action |
| 42 | WarioWare: Touched! | Minigames |
| 43 | Tetris DS | Puzzle |
| 44 | Picross 3D | Puzzle |
| 45 | Scribblenauts | Puzzle |
| 46 | Elite Beat Agents | Rhythm |
| 47 | Rhythm Heaven | Rhythm |
| 48 | Yoshi's Island DS | Platformer |
| 49 | Diddy Kong Racing DS | Racing |
| 50 | Star Fox Command | Shooter |

#### Game Boy Advance (Top 50)

| # | Game | Genre |
|---|------|-------|
| 1 | The Legend of Zelda: Minish Cap | Adventure |
| 2 | The Legend of Zelda: A Link to the Past + Four Swords | Adventure |
| 3 | Metroid Fusion | Action |
| 4 | Metroid: Zero Mission | Action |
| 5 | Super Mario Advance 4: SMB3 | Platformer |
| 6 | Super Mario Advance 3: Yoshi's Island | Platformer |
| 7 | Super Mario Advance 2: SMW | Platformer |
| 8 | Mario & Luigi: Superstar Saga | RPG |
| 9 | Mario Kart: Super Circuit | Racing |
| 10 | Kirby & the Amazing Mirror | Platformer |
| 11 | Kirby: Nightmare in Dream Land | Platformer |
| 12 | Fire Emblem | Strategy |
| 13 | Fire Emblem: Sacred Stones | Strategy |
| 14 | Golden Sun | RPG |
| 15 | Golden Sun: The Lost Age | RPG |
| 16 | Advance Wars | Strategy |
| 17 | Advance Wars 2: Black Hole Rising | Strategy |
| 18 | Final Fantasy Tactics Advance | Strategy RPG |
| 19 | Final Fantasy I & II: Dawn of Souls | RPG |
| 20 | Final Fantasy IV Advance | RPG |
| 21 | Final Fantasy V Advance | RPG |
| 22 | Final Fantasy VI Advance | RPG |
| 23 | Castlevania: Aria of Sorrow | Action |
| 24 | Castlevania: Harmony of Dissonance | Action |
| 25 | Castlevania: Circle of the Moon | Action |
| 26 | Mega Man Zero | Action |
| 27 | Mega Man Zero 2 | Action |
| 28 | Mega Man Zero 3 | Action |
| 29 | Mega Man Zero 4 | Action |
| 30 | Mega Man Battle Network | RPG |
| 31 | Mega Man Battle Network 3: Blue | RPG |
| 32 | Sonic Advance | Platformer |
| 33 | Sonic Advance 2 | Platformer |
| 34 | Sonic Advance 3 | Platformer |
| 35 | Wario Land 4 | Platformer |
| 36 | WarioWare Inc: Mega Microgames | Minigames |
| 37 | Harvest Moon: Friends of Mineral Town | Simulation |
| 38 | Drill Dozer | Action |
| 39 | Astro Boy: Omega Factor | Action |
| 40 | Gunstar Super Heroes | Action |
| 41 | F-Zero: Maximum Velocity | Racing |
| 42 | F-Zero: GP Legend | Racing |
| 43 | Tony Hawk's Pro Skater 2 | Sports |
| 44 | Riviera: The Promised Land | RPG |
| 45 | Breath of Fire | RPG |
| 46 | Breath of Fire II | RPG |
| 47 | Mother 3 (Fan Translation) | RPG |
| 48 | Summon Night: Swordcraft Story | RPG |
| 49 | Tactics Ogre: The Knight of Lodis | Strategy RPG |
| 50 | Kingdom Hearts: Chain of Memories | Action RPG |

#### Game Boy / Game Boy Color (Top 40)

| # | Game | Genre |
|---|------|-------|
| 1 | The Legend of Zelda: Link's Awakening DX | Adventure |
| 2 | The Legend of Zelda: Oracle of Seasons | Adventure |
| 3 | The Legend of Zelda: Oracle of Ages | Adventure |
| 4 | Super Mario Land | Platformer |
| 5 | Super Mario Land 2: 6 Golden Coins | Platformer |
| 6 | Wario Land: Super Mario Land 3 | Platformer |
| 7 | Wario Land II | Platformer |
| 8 | Wario Land 3 | Platformer |
| 9 | Kirby's Dream Land | Platformer |
| 10 | Kirby's Dream Land 2 | Platformer |
| 11 | Kirby Tilt 'n' Tumble | Platformer |
| 12 | Metroid II: Return of Samus | Action |
| 13 | Donkey Kong (1994) | Puzzle Platformer |
| 14 | Donkey Kong Country (GBC) | Platformer |
| 15 | Dragon Warrior I & II | RPG |
| 16 | Dragon Warrior III | RPG |
| 17 | Dragon Warrior Monsters | RPG |
| 18 | Dragon Warrior Monsters 2 | RPG |
| 19 | Final Fantasy Legend | RPG |
| 20 | Final Fantasy Legend II | RPG |
| 21 | Final Fantasy Adventure | Action RPG |
| 22 | Mega Man: Dr. Wily's Revenge | Action |
| 23 | Mega Man V | Action |
| 24 | Castlevania: The Adventure | Action |
| 25 | Castlevania II: Belmont's Revenge | Action |
| 26 | Shantae | Platformer |
| 27 | Metal Gear Solid (GBC) | Action |
| 28 | R-Type DX | Shooter |
| 29 | Tetris | Puzzle |
| 30 | Dr. Mario | Puzzle |
| 31 | Harvest Moon GBC | Simulation |
| 32 | Game & Watch Gallery 2 | Minigames |
| 33 | Game & Watch Gallery 3 | Minigames |
| 34 | Trip World | Platformer |
| 35 | Gargoyle's Quest | Action |
| 36 | Mole Mania | Puzzle |
| 37 | Kid Dracula | Platformer |
| 38 | Survival Kids | Adventure |
| 39 | Bionic Commando: Elite Forces | Action |
| 40 | Mario Tennis | Sports |

#### NES Classics (Top 30)

| # | Game |
|---|------|
| 1 | Super Mario Bros |
| 2 | Super Mario Bros 2 |
| 3 | Super Mario Bros 3 |
| 4 | The Legend of Zelda |
| 5 | Zelda II: The Adventure of Link |
| 6 | Metroid |
| 7 | Mega Man 2 |
| 8 | Mega Man 3 |
| 9 | Castlevania |
| 10 | Castlevania III: Dracula's Curse |
| 11 | Contra |
| 12 | Super Contra |
| 13 | Ninja Gaiden |
| 14 | Ninja Gaiden II |
| 15 | Final Fantasy |
| 16 | Dragon Quest (Dragon Warrior) |
| 17 | Mike Tyson's Punch-Out!! |
| 18 | Kirby's Adventure |
| 19 | Kid Icarus |
| 20 | Excitebike |
| 21 | Bubble Bobble |
| 22 | DuckTales |
| 23 | River City Ransom |
| 24 | Battletoads |
| 25 | Double Dragon II |
| 26 | Tecmo Bowl |
| 27 | R.C. Pro-Am |
| 28 | Blaster Master |
| 29 | StarTropics |
| 30 | Tetris |

#### SNES Classics (Top 30)

| # | Game |
|---|------|
| 1 | Super Mario World |
| 2 | Super Mario World 2: Yoshi's Island |
| 3 | Super Metroid |
| 4 | A Link to the Past |
| 5 | Chrono Trigger |
| 6 | Final Fantasy VI |
| 7 | Final Fantasy IV |
| 8 | EarthBound |
| 9 | Secret of Mana |
| 10 | Super Mario RPG |
| 11 | Donkey Kong Country |
| 12 | Donkey Kong Country 2 |
| 13 | Donkey Kong Country 3 |
| 14 | Mega Man X |
| 15 | Mega Man X2 |
| 16 | Mega Man X3 |
| 17 | Super Castlevania IV |
| 18 | Contra III: The Alien Wars |
| 19 | Star Fox |
| 20 | F-Zero |
| 21 | Super Mario Kart |
| 22 | Kirby Super Star |
| 23 | Kirby's Dream Land 3 |
| 24 | Super Punch-Out!! |
| 25 | Breath of Fire |
| 26 | Breath of Fire II |
| 27 | Lufia II: Rise of the Sinistrals |
| 28 | Illusion of Gaia |
| 29 | Terranigma |
| 30 | Tactics Ogre: Let Us Cling Together |

**TOTAL: 200+ curated titles across 6 systems.**

---

## Phase 3: Homebrew Tools

Place these `.nds` files in `roms/homebrew/`:

| Tool | Purpose | Download |
|------|---------|----------|
| **DSLinux** | Full Linux terminal | dslinux.org |
| **DSOrganize** | File manager + WiFi browser | gamebrew.org |
| **DSFTP** | FTP client/server | gamebrew.org |
| **Colors!** | Drawing app (cover story) | gamebrew.org |
| **Moonshell** | Media player | gamebrew.org |
| **Still Alive DS** | Portal tribute (cover) | gamebrew.org |
| **NesDS** | NES emulator | gamebrew.org |
| **GameYob** | GB/GBC emulator | github.com |
| **StellaDS** | Atari 2600 emulator | gamebrew.org |
| **jEnesisDS** | Sega Genesis emulator | gamebrew.org |
| **SNEmulDS** | SNES emulator | gamebrew.org |

### FLLC Custom WiFi Scanner

Compile from source in `tools/scripts/wifi_scanner.c`:

```bash
# Install devkitPro
# Windows: https://github.com/devkitPro/installer/releases
# Linux: sudo dkp-pacman -S nds-dev

export DEVKITARM=/opt/devkitpro/devkitARM
cd tools/scripts
make
# Output: wifi_scanner.nds → copy to roms/homebrew/
```

---

## Phase 4: Operational Use

### Cover Stories

The DSi is the ultimate covert device because **nobody suspects a gaming console**.

| Scenario | What You're "Doing" | What's Actually Happening |
|----------|---------------------|---------------------------|
| Waiting room | Playing Mario Kart | WiFi scanner logging all networks |
| Coffee shop | Playing Pokemon | Continuous scan + probe sniffing |
| Office lobby | Browsing homebrew | DSLinux running nmap on local subnet |
| Target building | Drawing in Colors! | Camera recon + WiFi logging |
| Public space | Playing Tetris | Data exfil via DSFTP to phone |

### Data Recovery

All scan data saves to `tools/data/` on the SD card. Pull the card to analyze:

```
tools/data/wifi_scans/scan_log.csv    → WiFi network database
tools/data/wifi_scans/probes.csv      → Device probe requests
tools/data/recon/                     → Network scan results
```

---

## Quick Checklist

- [ ] DSi firmware checked
- [ ] SD card formatted FAT32
- [ ] Memory Pit exploit loaded
- [ ] Unlaunch installed
- [ ] TWiLight Menu++ installed
- [ ] ROM folders created and populated
- [ ] Pokemon collection (35+ games)
- [ ] Classic library (200+ games)
- [ ] Homebrew tools installed
- [ ] FLLC WiFi scanner compiled
- [ ] DSLinux loaded
- [ ] Test boot successful

---

**FLLC** | Built for operators. Play games. Scan networks. Nobody suspects a thing.
