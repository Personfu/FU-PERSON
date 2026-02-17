# Universal Remotes - Infrared Reference | FLLC FU PERSON Arsenal

> **AUTHORIZED PENETRATION TESTING USE ONLY**
> FLLC - Furulie LLC | IR transmission in public spaces may have legal implications.

---

## Table of Contents

1. [IR Fundamentals](#ir-fundamentals)
2. [Flipper Zero IR Capabilities](#flipper-zero-ir-capabilities)
3. [TV Power Off - Universal Database](#tv-power-off---universal-database)
4. [Air Conditioner Control](#air-conditioner-control)
5. [Projector Control](#projector-control)
6. [Soundbar / Audio](#soundbar--audio)
7. [Set-Top Box / Streaming](#set-top-box--streaming)
8. [Fan Control](#fan-control)
9. [LED Strip Control](#led-strip-control)
10. [Security / Surveillance Cameras](#security--surveillance-cameras)
11. [Digital Signage](#digital-signage)
12. [Engagement Scenarios](#engagement-scenarios)
13. [IR Signal Capture Guide](#ir-signal-capture-guide)
14. [File Reference](#file-reference)

---

## IR Fundamentals

### How IR Remotes Work

| Component | Description |
|-----------|-------------|
| **Carrier Frequency** | 36-40 kHz modulated infrared light (typically 38 kHz) |
| **Protocol** | Encoding scheme (NEC, Samsung, RC5, RC6, Sony SIRC, etc.) |
| **Address** | Device identifier (which TV brand/model) |
| **Command** | Action to perform (power, volume, channel, etc.) |
| **Range** | 1-10 meters (line of sight, can bounce off walls) |

### Common IR Protocols

| Protocol | Carrier | Bits | Encoding | Used By |
|----------|---------|------|----------|---------|
| **NEC** | 38 kHz | 32 | Pulse-distance | LG, Samsung, Toshiba, many Chinese brands |
| **NECext** | 38 kHz | 32 | Pulse-distance | Extended NEC addressing |
| **Samsung32** | 38 kHz | 32 | Pulse-distance | Samsung TVs |
| **RC5** | 36 kHz | 13 | Manchester | Philips, Bang & Olufsen |
| **RC5X** | 36 kHz | 20 | Manchester | Extended Philips |
| **RC6** | 36 kHz | 16-32 | Manchester | Philips, Microsoft MCE |
| **Sony SIRC** | 40 kHz | 12/15/20 | Pulse-width | Sony (all devices) |
| **Kaseikyo** | 38 kHz | 48 | Pulse-distance | Panasonic, Sharp, JVC, Denon |
| **DISH** | 56 kHz | 16 | Unique | DISH Network boxes |
| **Pioneer** | 40 kHz | 32 | NEC variant | Pioneer audio/video |
| **Epson** | 38 kHz | 32 | NEC variant | Epson projectors |
| **RCA** | 56 kHz | 12 | Pulse-width | RCA devices (older) |
| **Mitsubishi** | 33 kHz | 16 | Pulse-width | Mitsubishi HVAC/projectors |

### IR Signal Anatomy (NEC Protocol Example)

```
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚  9ms AGC  â”‚ 4.5ms â”‚  Address  â”‚  ~Address â”‚       â”‚
  â”‚  burst    â”‚ space  â”‚  8 bits   â”‚  8 bits   â”‚  ...  â”‚
  â”‚           â”‚        â”‚  Command  â”‚ ~Command  â”‚       â”‚
  â”‚           â”‚        â”‚  8 bits   â”‚  8 bits   â”‚       â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
  
  Logic 0: 562.5us pulse + 562.5us space
  Logic 1: 562.5us pulse + 1687.5us space
  Repeat:  9ms pulse + 2.25ms space + 562.5us pulse
```

---

## Flipper Zero IR Capabilities

### Built-in Features
- **Universal Remotes:** Pre-loaded databases for TVs, ACs, projectors, audio
- **Learn:** Capture any IR signal from existing remotes
- **Saved:** Store and replay captured signals
- **Send:** Transmit from universal database or saved files

### File Format (.ir)

Flipper IR files support two signal types:

**Parsed (known protocol):**
```
name: Power
type: parsed
protocol: Samsung32
address: 07 00 00 00
command: 02 00 00 00
```

**Raw (unknown protocol):**
```
name: Power
type: raw
frequency: 38000
duty_cycle: 0.330000
data: 8958 4476 562 560 562 1680 562 560 ...
```

### Signal Range Enhancement
- Flipper stock IR LED: ~5 meters (narrow cone)
- With external IR LED module: 10-15 meters
- Line of sight required (IR bounces off walls/ceiling)
- Aim at device's IR receiver (usually front-center, lower right)

---

## TV Power Off - Universal Database

The "TV Kill" feature cycles through power codes for all major manufacturers.

### Coverage by Brand

| Brand | Protocol | Address | Power Command | Notes |
|-------|----------|---------|---------------|-------|
| **Samsung** | Samsung32 | 07 00 | 02 00 | Most models 2008+ |
| **Samsung** (older) | NEC | 07 07 | 02 FD | Pre-2008 models |
| **LG** | NEC | 04 00 | 08 F7 | WebOS and older |
| **Sony** | SIRC15 | 01 00 | 15 00 | Bravia series |
| **Sony** | SIRC20 | 01 00 | 15 00 | Newer 4K models |
| **Vizio** | NEC | 04 08 | 00 FF | SmartCast models |
| **Vizio** (older) | NECext | 00 20 | 00 FF | Older models |
| **TCL** | NEC | 00 40 | 40 BF | Roku TV built-in |
| **Hisense** | NEC | 00 00 | 00 FF | All models |
| **Panasonic** | Kaseikyo | 4004 00 | 00 3D | Viera series |
| **Sharp** | Kaseikyo | 4004 AA | 00 FF | AQUOS models |
| **Toshiba** | NEC | 40 BF | 12 ED | Fire TV Edition |
| **Philips** | RC6 | 00 00 | 0C 00 | Ambilight series |
| **Philips** (older) | RC5 | 00 00 | 0C 00 | Older CRT/LCD |
| **JVC** | NEC | 03 FC | 03 FC | Older models |
| **Hitachi** | NEC | 0E F1 | 0E F1 | Various |
| **Sanyo** | NEC | 1C E3 | 01 FE | Budget models |
| **Insignia** | NEC | 04 FB | 02 FD | Best Buy brand |
| **Magnavox** | RC6/NEC | Varies | Varies | Philips subsidiary |
| **Haier** | NEC | 00 FF | 08 F7 | Budget models |
| **RCA** | RCA | 0F | 00 | Older models |
| **Westinghouse** | NEC | 04 FB | 00 FF | Budget models |
| **Element** | NEC | 04 08 | 00 FF | Budget models |
| **Sceptre** | NEC | 40 00 | 1C E3 | Budget models |
| **Funai** | NEC | 1C E3 | 02 FD | Emerson/Funai brands |
| **Pioneer** | Pioneer | 00 | 1C | A/V receivers |
| **Denon** | Kaseikyo | 2A4C 00 | 00 FF | A/V receivers |
| **Yamaha** | NEC | 7E 81 | 1E E1 | Receivers/soundbars |

### "TV-B-Gone" Strategy

To kill all TVs in a room, send power commands in this order (optimized for speed):

1. Samsung32 (most common in US)
2. NEC generic (covers LG, Vizio, TCL, Hisense, Toshiba)
3. Sony SIRC (all bit widths)
4. Kaseikyo (Panasonic, Sharp, JVC)
5. RC5/RC6 (Philips)
6. Remaining brands

> **Flipper's Universal Remote > TV > Power** already does this automatically, cycling through all known codes.

---

## Air Conditioner Control

### Complexity Note
AC IR signals are significantly more complex than TV signals. A single AC command encodes:
- Temperature setting (16-30C)
- Fan speed (auto/low/med/high)
- Mode (cool/heat/fan/dry/auto)
- Swing (on/off/angle)
- Timer settings

This results in very long IR signals (100-200+ raw values).

### Common AC Brands

| Brand | Protocol | Notes |
|-------|----------|-------|
| **Samsung** | Samsung AC | Complex, mode-dependent |
| **LG** | LG AC | Multiple sub-protocols |
| **Daikin** | Daikin (proprietary) | Very long signals |
| **Mitsubishi** | Mitsubishi AC | Different from TV protocol |
| **Fujitsu** | Fujitsu (proprietary) | General/ASYG series |
| **Carrier** | Carrier | Often NEC-variant |
| **Toshiba** | Toshiba AC | Separate from TV |
| **Hitachi** | Hitachi AC | Multiple series |
| **Panasonic** | Kaseikyo variant | Extended data |
| **Gree** | Gree (proprietary) | Chinese brand, very common |
| **Midea** | Midea (proprietary) | Chinese brand |
| **Haier** | Haier AC | Budget systems |
| **Whirlpool** | Whirlpool (proprietary) | Varies by region |
| **York** | York (proprietary) | Commercial HVAC |
| **Sharp** | Kaseikyo variant | AQUOS climate |

### Key AC Commands

| Command | Pentest Use |
|---------|------------|
| **Power Off** | Disable climate control in server rooms, offices |
| **Set to max heat (30C)** | Physical discomfort -> force evacuation |
| **Set to max cool (16C)** | Same concept, different season |
| **Fan only** | Disable actual cooling in server rooms |

---

## Projector Control

### Common Projector Brands

| Brand | Protocol | Power On | Power Off | Notes |
|-------|----------|----------|-----------|-------|
| **Epson** | NEC variant | Varies by model | Double-press required | Most common brand |
| **BenQ** | NEC | Model-specific | Double-press required | Popular in classrooms |
| **Optoma** | NEC | Model-specific | Single press | Business projectors |
| **ViewSonic** | NEC | Model-specific | Double-press | Budget models |
| **Acer** | NEC | Model-specific | Double-press | Portable models |
| **NEC** (brand) | NEC | Model-specific | Varies | Enterprise models |
| **InFocus** | NEC | Model-specific | Single press | Conference rooms |
| **Sony** | SIRC | 01/4D | Model-specific | Home theater |
| **Panasonic** | Kaseikyo | Model-specific | Double-press | Education/enterprise |
| **Casio** | NEC | Model-specific | Single press | Lamp-free models |
| **LG** | NEC | 04 | 08 | CineBeam series |
| **XGIMI** | NEC variant | Model-specific | Single press | Portable/home |

> **Note:** Most projectors require a CONFIRMATION press (send Power Off twice within 3-5 seconds) to actually turn off. Flipper handles this in Universal Remote mode.

---

## Soundbar / Audio

| Brand | Protocol | Notes |
|-------|----------|-------|
| **Samsung** | Samsung32 | Same family as TV, different address |
| **LG** | NEC | SK/SN/SP series |
| **Sony** | SIRC | HT-series |
| **Bose** | Bose (proprietary) | SoundTouch, Smart Soundbar |
| **JBL** | NEC variant | Bar series |
| **Yamaha** | NEC | YAS/YSP series |
| **Sonos** | Limited IR support | Beam has IR learning |
| **Denon** | Kaseikyo | DHT/HEOS series |
| **Vizio** | NEC | V/M series |
| **Polk** | NEC | Signa/MagniFi series |
| **Harman Kardon** | NEC | Citation/Enchant series |
| **TCL** | NEC | Alto series |

---

## Set-Top Box / Streaming

| Device | Protocol | Common Commands |
|--------|----------|----------------|
| **Xfinity/Comcast** | XMP-1 | Power, channel, volume |
| **DirecTV** | RC6 | Power, channel, DVR |
| **Dish Network** | DISH (56 kHz) | Power, channel |
| **Spectrum** | NEC variant | Power, channel |
| **Roku** (with IR) | NEC | Power, home, back, select |
| **Fire TV Stick** | NEC | Limited IR (mainly CEC) |
| **Apple TV** | No IR | Bluetooth only |
| **Nvidia Shield** | No IR | Bluetooth/WiFi only |
| **TiVo** | NEC | Power, TiVo button |

---

## Fan Control

| Brand | Protocol | Speeds | Notes |
|-------|----------|--------|-------|
| **Hampton Bay** | FAN (custom) | 3-speed + light | DIP switch address |
| **Hunter** | NEC variant | 3-speed + light | Model dependent |
| **Dyson** | Dyson (custom) | 10-speed | Complex protocol |
| **Honeywell** | NEC | 3-speed | Portable fans |
| **Lasko** | NEC | 3-speed | Tower fans |
| **Vornado** | NEC | Multi-speed | Circulation fans |

> **DIP switch fans (Hampton Bay, Harbor Breeze):** Flipper can learn and replay, but the address is set by physical DIP switches on the fan receiver. Brute-force all DIP combinations to control any fan in range.

---

## LED Strip Control

### 24-Key IR Controller

| Button | Function | Hex Code |
|--------|----------|----------|
| Brightness + | Increase | F700FF |
| Brightness - | Decrease | F7807F |
| Off | Power off | F740BF |
| On | Power on | F7C03F |
| Red | Set red | F720DF |
| Green | Set green | F7A05F |
| Blue | Set blue | F7609F |
| White | Set white | F7E01F |
| Flash | Strobe effect | F7D02F |
| Fade | Fade effect | F7F00F |
| Smooth | Smooth transition | F7C837 |

### 44-Key IR Controller

Extended color palette plus DIY color programming, speed control, and more effects. All use NEC protocol at 38 kHz.

---

## Security / Surveillance Cameras

Some IP cameras and DVR/NVR systems have IR remote interfaces:

| Brand | IR Remote | Commands |
|-------|-----------|----------|
| **Hikvision** (DVR/NVR) | Yes (for menu) | Navigate, playback, PTZ |
| **Dahua** (DVR/NVR) | Yes (for menu) | Navigate, playback, PTZ |
| **Swann** (DVR) | Yes | Menu, playback |
| **Night Owl** (DVR) | Yes | Menu, playback |

> **Pentest use:** If DVR is accessible via IR, could navigate to settings, disable recording, or change network config.

---

## Digital Signage

| System | IR Controllable | Notes |
|--------|----------------|-------|
| Samsung SMART Signage | Yes (same as Samsung TV) | Commercial displays |
| LG Commercial Display | Yes (LG protocol) | webOS Signage |
| NEC MultiSync | Yes (NEC protocol) | Large format displays |
| BenQ Smart Signage | Yes | Android-based |
| ViewSonic ViewBoard | Yes | Interactive displays |

> **Pentest use:** Power off lobby/reception displays, change input source to attacker-controlled HDMI, or cycle through menus visible to security cameras as distraction.

---

## Engagement Scenarios

### Scenario 1: Conference Room Disruption Test
**Objective:** Demonstrate physical security impact of unsecured AV equipment.
1. Capture projector/TV remote codes (learn from existing remote or use universal)
2. During authorized test: power off presentation equipment
3. Change input source to HDMI (if HDMI implant placed)
4. Demonstrate that IR has no authentication

### Scenario 2: Server Room Climate Attack
**Objective:** Demonstrate risk of IR-controllable HVAC in data centers.
1. Identify AC units with IR receivers in server room
2. Capture AC remote codes
3. Demonstrate ability to disable cooling or set to max heat
4. Report: "IR-controllable HVAC in server room poses thermal risk"

### Scenario 3: Physical Access via Digital Signage
**Objective:** Use IR to enable attacker content on public displays.
1. Identify displays in lobby/public areas
2. Power off display or switch input source
3. If HDMI accessible: connect device, switch input via IR
4. Demonstrate unauthorized content on corporate displays

### Scenario 4: Surveillance System Manipulation
**Objective:** Demonstrate DVR/NVR IR vulnerability.
1. Identify DVR systems with IR receivers
2. Navigate menus to disable recording
3. Change playback to cover tracks
4. Report: "DVR accessible via unprotected IR"

---

## IR Signal Capture Guide

### Capturing Unknown Remotes

1. **Flipper -> Infrared -> Learn New Remote**
2. Name the remote (e.g., "ConferenceRoom_Projector")
3. Point existing remote at Flipper's IR receiver (top of device)
4. Press each button on original remote
5. Name each signal (Power, Vol_Up, Vol_Down, Input, etc.)
6. Save to SD card

### Tips for Reliable Capture
- Hold remote 2-5 cm from Flipper's IR receiver
- Aim directly at the IR sensor (top center of Flipper)
- Press button firmly and briefly (don't hold)
- Test captured signal immediately against target device
- If signal doesn't work, try raw capture mode
- Some remotes use 56 kHz carrier (DISH, some Bose) - Flipper handles this

### Building a Custom IR Database

For each target environment during engagement:
1. Photograph all IR-controllable devices
2. Note manufacturer and model
3. Try universal remote first
4. If universal fails, learn from device's remote (social eng to borrow)
5. If no remote available, search online IR databases
6. Save all working codes to a per-site .ir file

---

## File Reference

### Files in `flipper/infrared/`

| File | Signals | Coverage |
|------|---------|----------|
| `tv_off_universal.ir` | 40+ | All major TV brands - power off |
| `ac_universal.ir` | 30+ | AC brands - power/temp/mode |
| `projector_universal.ir` | 40+ | Projector brands - power on/off |
| `soundbar_universal.ir` | 55+ | Soundbar/audio - power/volume |
| `fan_universal.ir` | 35+ | Fan brands - power/speed |
| `settopbox_universal.ir` | 50+ | Cable/streaming - power/input |
| `led_universal.ir` | 40+ | LED controllers - color/mode |

**Total library: 290+ IR signals**

### How to Use on Flipper
1. Copy `.ir` files to `SD Card/infrared/`
2. Flipper -> Infrared -> Saved Remotes
3. Select file -> choose signal -> Send
4. Or use "Send All" to cycle through all signals in file

---

*FLLC - FU PERSON Arsenal | Universal IR Remote Reference v2.0*
*Authorized penetration testing use only.*
