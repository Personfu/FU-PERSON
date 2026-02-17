# Sub-GHz Frequency Database - FLLC FU PERSON Arsenal

> **AUTHORIZED PENETRATION TESTING USE ONLY**
> FLLC - Furulie LLC | Legal compliance required in all jurisdictions.

---

## Table of Contents

1. [North America (FCC Region 2)](#north-america-fcc-region-2)
2. [Europe (ETSI Region 1)](#europe-etsi-region-1)
3. [Asia-Pacific](#asia-pacific)
4. [Garage Door / Gate Systems](#garage-door--gate-systems)
5. [Vehicle Key Fobs (RKE)](#vehicle-key-fobs-rke)
6. [Security / Alarm Systems](#security--alarm-systems)
7. [IoT & Smart Home](#iot--smart-home)
8. [Weather Stations & Sensors](#weather-stations--sensors)
9. [TPMS (Tire Pressure)](#tpms-tire-pressure)
10. [Pager Systems](#pager-systems)
11. [Utility & AMR Meters](#utility--amr-meters)
12. [Amateur Radio](#amateur-radio)
13. [Flipper Zero Presets](#flipper-zero-presets)
14. [Protocol Reference](#protocol-reference)
15. [Attack Methodology](#attack-methodology)

---

## North America (FCC Region 2)

### ISM Bands (License-Free)

| Frequency | Band | Common Uses | Max Power |
|-----------|------|-------------|-----------|
| 260-270 MHz | - | Older garage doors (Chamberlain, Sears) | 10 mW |
| 288-310 MHz | 300 MHz ISM | Garage doors, car remotes, sensors | 25 mW |
| 310-318 MHz | - | Vehicle RKE (GM, Ford, Toyota) | 25 mW |
| 315 MHz | ISM | **Primary US automotive/garage** | 25 mW |
| 318 MHz | - | Toyota/Lexus key fobs | 25 mW |
| 390 MHz | - | Some GM key fobs (older) | 25 mW |
| 418 MHz | - | Some sensors, medical telemetry | 25 mW |
| 426 MHz | - | Japanese imports (Honda, Subaru NA) | 25 mW |
| 433.05-434.79 MHz | 433 MHz ISM | Weather stations, EU imports | 10 mW |
| 433.92 MHz | ISM | **IoT sensors, remotes (EU standard)** | 10 mW |
| 868 MHz | - | EU only (not legal in US) | - |
| 902-928 MHz | 915 MHz ISM | **LoRa, Zigbee, Z-Wave, meters** | 1 W |
| 916.5 MHz | ISM | Z-Wave US frequency | 1 mW |

### FRS / GMRS (Two-Way Radio)

| Channel | Frequency | Service | Power |
|---------|-----------|---------|-------|
| FRS 1-7 | 462.5625-462.7125 MHz | FRS/GMRS shared | 2W FRS / 5W GMRS |
| FRS 8-14 | 467.5625-467.7125 MHz | FRS only | 0.5W |
| GMRS 15-22 | 462.550-462.725 MHz | GMRS repeater | 50W |
| MURS 1-5 | 151.820-154.600 MHz | Multi-Use Radio | 2W |

---

## Europe (ETSI Region 1)

### ISM / SRD Bands

| Frequency | Band | Common Uses | Max Power (ERP) |
|-----------|------|-------------|-----------------|
| 169.4-169.8125 MHz | - | Smart meters, IoT | 10 mW |
| 315 MHz | - | **Not legal in EU** | - |
| 433.05-434.79 MHz | ISM | **Primary EU: remotes, sensors, IoT** | 10 mW |
| 433.92 MHz | ISM | Garage doors, car fobs, weather | 10 mW |
| 868.0-868.6 MHz | SRD | **Primary EU IoT, alarms, sensors** | 25 mW (1% duty) |
| 868.7-869.2 MHz | SRD | High-reliability alarms | 25 mW (0.1% duty) |
| 869.4-869.65 MHz | SRD | Social alarms, high power | 500 mW (10% duty) |
| 869.7-870.0 MHz | SRD | General SRD | 25 mW (1% duty) |

### Vehicle Frequencies (EU)

| Frequency | Use |
|-----------|-----|
| 433.92 MHz | **Most EU car key fobs** (VW, BMW, Mercedes, Renault, Peugeot) |
| 434.42 MHz | Some BMW, Mercedes |
| 868.35 MHz | Some newer European vehicles |

---

## Asia-Pacific

| Region | Primary Freq | Secondary | Notes |
|--------|-------------|-----------|-------|
| Japan | 315 MHz | 426 MHz | 315 for automotive, 426 for IoT |
| China | 315 MHz | 433.92 MHz | Both widely used |
| Australia | 433.92 MHz | 915 MHz | Same as EU for remotes |
| South Korea | 315 MHz | 433.92 MHz | Similar to US/EU split |
| India | 433.92 MHz | 865-867 MHz | ISM band varies by regulation |

---

## Garage Door / Gate Systems

### North America

| Manufacturer | Frequency | Protocol | Security | Flipper Capturable |
|-------------|-----------|----------|----------|-------------------|
| **Chamberlain/LiftMaster** (pre-1993) | 300 MHz | Fixed code | None | YES - direct replay |
| **Chamberlain/LiftMaster** (1993-2011) | 315 MHz | Security+ | Rolling code | Partial (rolljam) |
| **Chamberlain/LiftMaster** (2011+) | 310/315/390 MHz | Security+ 2.0 | Rolling + encryption | NO - encrypted |
| **Genie** (pre-1997) | 390 MHz | Fixed 12-bit | None (4096 codes) | YES - replay or brute |
| **Genie** (Intellicode) | 315 MHz | Rolling code | Keeloq variant | Partial (rolljam) |
| **Genie** (Intellicode 2) | 315 MHz | AES rolling | AES-128 | NO |
| **Linear/GTO** (MegaCode) | 318 MHz | Fixed code | Minimal | YES - direct replay |
| **Linear** (Multi-Code) | 300 MHz | Fixed code (DIP) | None | YES - replay or set DIPs |
| **Stanley** | 310 MHz | Fixed code | None | YES - direct replay |
| **Overhead Door** (CodeDodger) | 315/390 MHz | Rolling code | Keeloq | Partial |
| **Craftsman/Sears** (older) | 315 MHz | Fixed code | None | YES |

### Europe

| Manufacturer | Frequency | Protocol | Security | Flipper Capturable |
|-------------|-----------|----------|----------|-------------------|
| **Nice** (FLO) | 433.92 MHz | Fixed code | None | YES - direct replay |
| **Nice** (FLOR-S) | 433.92 MHz | Rolling (KeeLoq) | Rolling code | Partial |
| **CAME** (TOP) | 433.92 MHz | Fixed 12-bit | None | YES - replay/brute |
| **CAME** (TOP EV) | 433.92 MHz | Rolling | Rolling code | Partial |
| **Hormann** (HSM/HSE) | 868.3 MHz | BiSecur | AES-128 | NO |
| **FAAC** (SLH) | 433.92 MHz | Rolling (SLH) | Proprietary rolling | Partial |
| **BFT** (Mitto) | 433.92 MHz | Rolling (KeeLoq) | Rolling code | Partial |
| **Marantec** | 433.92/868.3 MHz | Rolling | Proprietary | NO (868 model) |
| **Beninca** | 433.92 MHz | Fixed/Rolling | Varies by model | YES (fixed) / Partial (rolling) |
| **Ditec** | 433.92 MHz | Fixed code | None | YES |
| **DEA** | 433.92 MHz | Fixed/Rolling | Varies | Model dependent |

### Gate / Barrier Systems

| System | Frequency | Notes |
|--------|-----------|-------|
| Parking garage gates | 315/433.92 MHz | Often fixed code - easy replay |
| Apartment complex | 315/433.92 MHz | Usually fixed or simple rolling |
| Industrial/commercial | 315/433.92 MHz | May use proprietary protocols |
| Toll systems | 915 MHz (US) / 868 MHz (EU) | ETC - encrypted, don't attempt |

---

## Vehicle Key Fobs (RKE)

### Frequency by Manufacturer

| Manufacturer | NA Frequency | EU Frequency | Protocol |
|-------------|-------------|-------------|----------|
| **GM** (Chevrolet, GMC, Cadillac, Buick) | 315 MHz | 433.92 MHz | Rolling (varies by year) |
| **Ford** (Lincoln, Mercury) | 315 MHz | 433.92 MHz | Rolling code |
| **Chrysler/FCA** (Dodge, Jeep, Ram) | 315 MHz | 433.92 MHz | KeeLoq-based |
| **Toyota** (Lexus) | 312/314.35 MHz | 433.92 MHz | Proprietary rolling |
| **Honda** (Acura) | 313.85/314.35 MHz | 433.92 MHz | Rolling code |
| **Nissan** (Infiniti) | 315 MHz | 433.92 MHz | Rolling code |
| **BMW** | 315 MHz | 433.92/868 MHz | Rolling + CAS/FEM |
| **Mercedes-Benz** | 315 MHz | 433.92 MHz | IR + RF rolling |
| **Volkswagen/Audi** | 315 MHz | 433.92/434.42 MHz | MQB/Megamos |
| **Hyundai/Kia** | 315 MHz | 433.92 MHz | Rolling code |
| **Subaru** | 314.35 MHz | 433.92 MHz | Rolling code |
| **Mazda** | 315 MHz | 433.92 MHz | Rolling code |

### TPMS Frequencies

| Region | Frequency | Modulation |
|--------|-----------|------------|
| North America | 315 MHz | OOK/FSK |
| Europe | 433.92 MHz | OOK/FSK |

> **Note:** TPMS signals include unique sensor IDs. Can be used for vehicle tracking/identification. Broadcast continuously while driving.

---

## Security / Alarm Systems

| System | Frequency | Protocol | Encryption | Notes |
|--------|-----------|----------|-----------|-------|
| **Honeywell/Ademco** (5800 series) | 345 MHz | Fixed code | None | Replay vulnerable |
| **DSC** (PowerG) | 912-919 MHz | Freq-hopping | AES-128 | NOT capturable |
| **DSC** (Classic) | 433.92 MHz | Fixed code | None | Replay vulnerable |
| **ADT** (varies by hardware) | 319.5/345/433 MHz | Varies | Varies | Model dependent |
| **SimpliSafe** (Gen 1) | 433.92 MHz | Fixed code | None | Fully replay vulnerable |
| **SimpliSafe** (Gen 2) | 433.92 MHz | Rolling | None | PIN replay attack documented |
| **SimpliSafe** (Gen 3) | 433.92 MHz | Encrypted | AES | Significantly harder |
| **Ring Alarm** | Z-Wave (908.42 MHz) | Z-Wave S2 | AES-128 | Requires Z-Wave exploit |
| **Interlogix/GE** (319.5 series) | 319.5 MHz | Fixed code | None | Replay vulnerable |
| **2GIG** | 345 MHz | Fixed code | None | Replay vulnerable |
| **Qolsys** (IQ Panel) | 319.5/345 MHz | Varies | Varies | Backward compatible = vulnerable |
| **Visonic** (PowerMax) | 315/433/868 MHz | Proprietary | Rolling | Partial vulnerability |

### Sensor Types & Behaviors

| Sensor | Signal Pattern | Intelligence Value |
|--------|---------------|-------------------|
| Door/Window contact | Triggers on open | Entry points, occupancy |
| PIR motion detector | Triggers on movement | Room usage patterns |
| Glass break | Triggers on impact frequency | Window locations |
| Smoke/CO | Periodic supervisory check-in | Device inventory |
| Key fob panic button | On-demand | Social engineering trigger |
| Kepad arm/disarm | Fixed code | **Capture = full system control** |

---

## IoT & Smart Home

| Device Category | Frequency | Protocol | Flipper Compatible |
|----------------|-----------|----------|-------------------|
| **Smart plugs** (older 433 MHz) | 433.92 MHz | OOK fixed code | YES |
| **Smart plugs** (WiFi/Zigbee) | 2.4 GHz | WiFi/Zigbee | NO (use ESP32) |
| **Wireless doorbells** | 315/433.92 MHz | OOK/ASK fixed | YES - replay |
| **Ceiling fan remotes** | 303/315/434 MHz | OOK DIP switches | YES - set DIPs or brute |
| **Wireless thermostats** | 315/433 MHz | Varies | Some models |
| **Irrigation controllers** | 433.92 MHz | OOK fixed | YES |
| **Pet doors** | 433.92 MHz | RFID trigger | Some models |
| **Z-Wave devices** | 908.42 MHz (US) / 868.42 MHz (EU) | Z-Wave | NO (encrypted) |
| **Zigbee devices** | 2.4 GHz | Zigbee | NO (use ESP32) |
| **LoRa devices** | 915 MHz (US) / 868 MHz (EU) | LoRa/LoRaWAN | Capture only |

---

## Weather Stations & Sensors

| Brand/Type | Frequency | Protocol | Capture |
|-----------|-----------|----------|---------|
| **Acurite** | 433.92 MHz | OOK | YES |
| **Oregon Scientific** | 433.92 MHz | Manchester | YES |
| **LaCrosse** | 433.92 MHz | OOK | YES |
| **Ambient Weather** | 433.92 MHz | OOK/FSK | YES |
| **AcuRite Atlas** | 433.92 MHz | OOK | YES |
| **Davis Instruments** | 915 MHz | FHSS | NO (freq hopping) |
| **Wireless soil moisture** | 433.92 MHz | OOK | YES |
| **Pool thermometers** | 433.92 MHz | OOK | YES |

> Weather stations transmit temperature, humidity, wind, rain data every 30-60 seconds. Good for practice captures.

---

## TPMS (Tire Pressure)

| Protocol | Frequency | Modulation | Data |
|----------|-----------|------------|------|
| NA Standard | 315 MHz | OOK/FSK | Sensor ID, pressure, temp |
| EU Standard | 433.92 MHz | OOK/FSK | Sensor ID, pressure, temp |

### Vehicle Tracking via TPMS
- Each TPMS sensor has a unique 32-bit ID
- Transmitted every 60 seconds while driving
- Range: 10-30 meters with SDR, 100+ meters with directional antenna
- Can correlate sensor IDs to specific vehicles across locations

---

## Pager Systems

| System | Frequency | Protocol | Encryption |
|--------|-----------|----------|-----------|
| POCSAG pagers | 152-163 MHz | POCSAG | **NONE** - cleartext |
| FLEX pagers | 929-932 MHz | FLEX | **NONE** - cleartext |
| Hospital pagers | 152-163 MHz | POCSAG | **NONE** - HIPAA violations everywhere |
| Restaurant pagers | 433/467 MHz | Proprietary | None |
| Fire/EMS pagers | 152-160 MHz | POCSAG/FLEX | Usually none |

> **Intelligence note:** Hospital and emergency pager traffic is almost universally unencrypted. Can capture patient names, conditions, room numbers, and PHI with an RTL-SDR. Flipper can detect the signal but full decode requires SDR.

---

## Utility & AMR Meters

| System | Frequency | Protocol | Notes |
|--------|-----------|----------|-------|
| Itron/Silver Spring | 902-928 MHz | FSK | AMI mesh network |
| Sensus FlexNet | 902-928 MHz | Proprietary | Fixed network |
| Neptune | 902-928 MHz | FHSS | Frequency hopping |
| Badger Meter (ORION) | 902-928 MHz | OOK | Walk-by/drive-by reading |
| Elster/Honeywell | 902-928 MHz | Varies | Multiple protocols |

> AMR data includes meter serial number, current reading, tamper flags, and sometimes customer account info. Typically unencrypted.

---

## Amateur Radio (Reference Only)

| Band | Frequency | Allocation |
|------|-----------|-----------|
| 2m | 144-148 MHz | Voice, packet, APRS |
| 1.25m | 222-225 MHz | Voice, digital |
| 70cm | 420-450 MHz | Voice, ATV, packet, digital |
| 33cm | 902-928 MHz | Overlaps ISM! |
| 23cm | 1240-1300 MHz | Microwave |

> **APRS (144.390 MHz NA):** Automatic Packet Reporting System. Broadcasts GPS coordinates, callsigns, and telemetry. All cleartext, publicly logged at aprs.fi.

---

## Flipper Zero Presets

### Built-in Modulation Presets

| Preset | Modulation | Bandwidth | Use Case |
|--------|-----------|-----------|----------|
| `AM270` | OOK (AM) | 270 kHz | Remotes, doorbells, fixed code |
| `AM650` | OOK (AM) | 650 kHz | Wide-band remotes, some sensors |
| `FM238` | 2-FSK | 238 kHz | Weather stations, some IoT |
| `FM476` | 2-FSK | 476 kHz | TPMS, some security sensors |

### Custom Frequency Presets (add to `setting_user` on SD)

```
# Good capture frequencies for wardriving
Frequency: 300000000   # 300 MHz - old garage doors
Frequency: 303875000   # 303.875 MHz - ceiling fans
Frequency: 310000000   # 310 MHz - linear/GTO gates
Frequency: 312000000   # 312 MHz - Toyota (some)
Frequency: 314350000   # 314.35 MHz - Toyota/Honda
Frequency: 315000000   # 315 MHz - US primary
Frequency: 318000000   # 318 MHz - Toyota/Lexus
Frequency: 319500000   # 319.5 MHz - Interlogix/GE alarm
Frequency: 345000000   # 345 MHz - Honeywell/Ademco alarm
Frequency: 390000000   # 390 MHz - GM fobs (older)
Frequency: 433920000   # 433.92 MHz - EU/universal
Frequency: 868350000   # 868.35 MHz - EU SRD
Frequency: 915000000   # 915 MHz - ISM US
```

---

## Protocol Reference

### Common Protocols Decoded by Flipper

| Protocol | Encoding | Code Length | Security | Devices |
|----------|----------|-------------|----------|---------|
| **Princeton** | OOK | 24-bit | Fixed code | Cheap remotes, outlets, doorbells |
| **Nice FLO** | OOK | 12-bit | Fixed code (4096) | Gates, garage doors (EU) |
| **Nice FloR-S** | OOK | Rolling | KeeLoq rolling | Newer Nice gates |
| **CAME 12bit** | OOK | 12-bit | Fixed code (4096) | Gates (EU) |
| **CAME Atomo** | OOK | Rolling | AES-128 | Newer CAME gates |
| **Linear** | OOK | 10-bit | Fixed (DIP switches) | Garage doors (US) |
| **GE Security** | OOK | 24-bit | Fixed code | Alarm sensors |
| **Honeywell** | OOK | 44-bit | Fixed code | 5800 series sensors |
| **KeeLoq** | OOK | Rolling | 32-bit rolling + 28-bit fixed | Many car fobs, gates |
| **Security+** | OOK | Rolling | Proprietary rolling | Chamberlain/LiftMaster |
| **Security+ 2.0** | OOK | Rolling + encrypted | AES | Modern Chamberlain |
| **Holtek HT12E** | OOK | 12-bit | Fixed (DIP) | Cheap remotes, sensors |
| **SMC5326** | OOK | 25-bit | Fixed | Asian remotes, parking |
| **Ansonic** | OOK | 12-bit | Fixed | EU remotes |
| **Scher-Khan** | OOK/FSK | Rolling | Proprietary | Vehicle aftermarket |

### Modulation Types

| Type | Description | Use Cases |
|------|-------------|-----------|
| **OOK (On-Off Keying)** | Binary AM - signal on = 1, off = 0 | Most remotes, fixed code |
| **ASK (Amplitude Shift)** | Variable amplitude levels | Some weather stations |
| **FSK (Frequency Shift)** | Two frequencies = 0 and 1 | TPMS, medical, some IoT |
| **GFSK** | Gaussian-filtered FSK | BLE, some smart home |
| **Manchester** | Self-clocking, edge-encoded | Oregon Scientific, some sensors |
| **Differential Manchester** | Direction of transition matters | Some industrial |

---

## Attack Methodology

### Phase 1: Reconnaissance
1. Open Flipper **Sub-GHz > Frequency Analyzer**
2. Walk the target area - note active frequencies
3. For each active frequency, switch to **Sub-GHz > Read**
4. Set appropriate frequency and modulation preset
5. Catalog all captured signals - note time, location, protocol

### Phase 2: Signal Identification
1. Check if Flipper auto-decodes the protocol
2. If decoded: note protocol name, code bits, and key value
3. If not decoded: capture RAW signal for offline analysis
4. Cross-reference frequency + protocol with this database

### Phase 3: Replay Testing
1. For fixed-code signals: **Sub-GHz > Saved > Send**
2. Observe if target device responds
3. Note effective range (typically 1-50 meters with Flipper's antenna)
4. Test at different distances and angles

### Phase 4: Rolling Code Analysis
1. Capture multiple button presses (5-10 minimum)
2. Compare code values - if they change, it's rolling code
3. For KeeLoq: research manufacturer-specific keys
4. For proprietary rolling: document for further research
5. Consider rolljam technique (requires signal jammer + 2 captures)

### Phase 5: Documentation
1. Record all findings with timestamps
2. Note which signals are replayable vs. rolling
3. Map physical locations of transmitters/receivers
4. Photograph target devices when possible
5. Recommend security upgrades in final report

---

## Legal Notice

**Frequency transmission laws vary by jurisdiction.** This reference is for **authorized penetration testing** where explicit written permission has been obtained.

- **Receiving** Sub-GHz signals is legal in most jurisdictions
- **Transmitting/Replaying** may require specific authorization
- Some frequencies are restricted (e.g., 868 MHz is EU-only, not legal in US)
- Amateur radio frequencies require a license to transmit
- Jamming is **illegal everywhere** under federal law (47 USC 333 in US)

**Always verify local regulations before any transmission testing.**

---

*FLLC - FU PERSON Arsenal | Sub-GHz Frequency Database v2.0*
*Authorized penetration testing use only.*
