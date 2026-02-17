# NFC Attack Playbook - FLLC FU PERSON Arsenal

> **AUTHORIZED PENETRATION TESTING USE ONLY**
> FLLC - Furulie LLC | Written authorization required before any NFC testing.

---

## Table of Contents

1. [NFC Fundamentals](#nfc-fundamentals)
2. [Card Technology Reference](#card-technology-reference)
3. [Attack Type 1: Badge Cloning (125 kHz + 13.56 MHz)](#attack-type-1-badge-cloning)
4. [Attack Type 2: MIFARE Classic Cracking](#attack-type-2-mifare-classic-cracking)
5. [Attack Type 3: EMV Contactless Reading](#attack-type-3-emv-contactless-reading)
6. [Attack Type 4: NTAG/NDEF Manipulation](#attack-type-4-ntagndef-manipulation)
7. [Attack Type 5: Reader Attack (Credential Harvest)](#attack-type-5-reader-attack)
8. [Attack Type 6: Relay / Proxy Attack](#attack-type-6-relay--proxy-attack)
9. [MIFARE Classic Key Database](#mifare-classic-key-database)
10. [Wiegand Protocol Reference](#wiegand-protocol-reference)
11. [Practical Engagement Playbook](#practical-engagement-playbook)
12. [Countermeasures & Recommendations](#countermeasures--recommendations)

---

## NFC Fundamentals

### Frequency Bands

| Frequency | Technology | Range | Common Use |
|-----------|-----------|-------|------------|
| **125 kHz** (LF) | EM4100, HID Prox, Indala | 1-10 cm | Building access, time clocks |
| **13.56 MHz** (HF) | MIFARE, DESFire, NTAG, ISO 14443 | 1-10 cm | Access cards, payment, transit |
| **860-960 MHz** (UHF) | EPC Gen2 | 1-12 m | Inventory, toll, asset tracking |

### ISO Standards

| Standard | Description | Cards |
|----------|-------------|-------|
| ISO 14443-A | Type A modulation, anti-collision | MIFARE, NTAG, DESFire |
| ISO 14443-B | Type B modulation | Calypso, some gov IDs |
| ISO 15693 | Vicinity cards (longer range) | Library cards, some badges |
| ISO 18092 | NFC peer-to-peer | Phone NFC communication |

### Card UID Types

| Type | UID Length | Notes |
|------|-----------|-------|
| Single-size | 4 bytes | MIFARE Classic, most HID iCLASS |
| Double-size | 7 bytes | MIFARE DESFire, NTAG, UL |
| Triple-size | 10 bytes | Rare, some high-security |

> **Key concept:** Many access control systems authenticate based ONLY on the card UID, not the card's cryptographic capabilities. This means a simple UID clone defeats the system.

---

## Card Technology Reference

### 125 kHz (Low Frequency) Cards

| Technology | Security | Cloneable | Blank Card | Method |
|-----------|----------|-----------|------------|--------|
| **EM4100** | ZERO - read-only serial | YES - trivial | T5577 | Read -> Write to T5577 |
| **HID ProxCard II** (26-bit) | ZERO - fixed code | YES - trivial | T5577 | Read -> Write to T5577 |
| **HID ProxCard** (34/37-bit) | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |
| **Indala** | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |
| **AWID** | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |
| **Viking** | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |
| **Pyramid** | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |
| **Keri** | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |
| **Nexwatch** | ZERO - fixed code | YES | T5577 | Read -> Write to T5577 |

> **125 kHz cards have ZERO authentication.** Any card within range broadcasts its code. Clone in under 3 seconds.

### 13.56 MHz (High Frequency) Cards

| Technology | Security | Attack Difficulty | Blank Card |
|-----------|----------|------------------|------------|
| **MIFARE Classic 1K** | Crypto1 (broken) | EASY - dictionary + nested | Gen2/CUID |
| **MIFARE Classic 4K** | Crypto1 (broken) | EASY - dictionary + nested | Gen2/CUID |
| **MIFARE Classic EV1** | Crypto1 (broken) | EASY - same attacks | Gen2/CUID |
| **MIFARE Ultralight** | None (read/write) | TRIVIAL | NTAG/UL blanks |
| **MIFARE Ultralight C** | 3DES auth | MODERATE | Requires key |
| **MIFARE Ultralight EV1** | Password (32-bit) | MODERATE | Brute possible |
| **MIFARE DESFire EV1** | AES-128 / 3DES | HARD | UID-changeable blanks (rare) |
| **MIFARE DESFire EV2** | AES-128 | VERY HARD | Requires application keys |
| **MIFARE DESFire EV3** | AES-128 + secure messaging | VERY HARD | Current generation |
| **MIFARE Plus** | AES-128 | HARD | Depends on security level |
| **HID iCLASS** (legacy) | Weak crypto | MODERATE | iCLASS blanks |
| **HID iCLASS SE** | AES + SAM | HARD | Requires SE program |
| **HID SEOS** | PKI + AES | VERY HARD | Requires mobile credential |
| **NTAG213/215/216** | Optional password | EASY (no auth) / MODERATE (auth) | NTAG blanks |
| **Java Card / JCOP** | App-level crypto | Application dependent | JCOP blanks |
| **Calypso** (transit) | DES/3DES | MODERATE to HARD | Not easily available |
| **EMV (payment)** | RSA + DDA/CDA | Cannot clone usefully | N/A |

---

## Attack Type 1: Badge Cloning

### 125 kHz Clone (EM4100, HID Prox)

**Equipment needed:**
- Flipper Zero
- T5577 blank cards ($0.50-1.00 each)

**Steps:**
1. **Read the badge:**
   - Flipper -> 125 kHz RFID -> Read
   - Hold Flipper within 1-3 cm of target badge
   - Flipper displays card type, data, and UID
   - Save the read data

2. **Clone to blank:**
   - Flipper -> 125 kHz RFID -> Saved -> [select card]
   - Select "Write" 
   - Hold T5577 blank against Flipper back
   - Wait for confirmation

3. **Test:**
   - Present cloned T5577 to target reader
   - Should behave identically to original

**Field techniques for reading badges:**
- Pretend to bump into target (badge on lanyard = 1 second read)
- Sit next to target in meeting/cafeteria
- Ask to "look at their badge" with social pretext
- Read badge left on desk when target steps away

### 13.56 MHz Clone (MIFARE Classic)

**Equipment needed:**
- Flipper Zero with Mfkey32 capability
- Gen2/CUID blank MIFARE cards ($2-3 each)

**Steps:**
1. **Read and detect card type:**
   - Flipper -> NFC -> Read
   - Flipper identifies card (Classic 1K, 4K, etc.)
   - Attempts to read sectors with default keys

2. **Crack unknown keys:**
   - If dictionary attack fails, use Mfkey32 nonce attack
   - Read card 3-4 times to collect nonces
   - Flipper calculates keys from nonce pairs
   - Each read may reveal 1-2 new sector keys

3. **Full dump:**
   - Once all keys found, perform full card dump
   - All 16 sectors (1K) or 40 sectors (4K) read

4. **Write to blank:**
   - Flipper -> NFC -> Saved -> [select dump]
   - Write to Gen2/CUID card (supports UID change)
   - Verify all sectors written correctly

---

## Attack Type 2: MIFARE Classic Cracking

### Dictionary Attack

Flipper Zero attempts known keys against each sector. The built-in dictionary covers most common deployments.

**Process:**
1. NFC -> Read -> detect as MIFARE Classic
2. Flipper runs dictionary attack automatically
3. Found keys displayed per sector
4. Save partial dump

### Nested Attack (Mfkey32)

When some sectors are readable but others aren't:

1. Read card repeatedly (3-5 times)
2. Flipper collects encrypted nonces from locked sectors
3. Navigate to NFC -> Detect Reader -> Mfkey32
4. Present card to a legitimate reader
5. Capture authentication exchange
6. Flipper computes sector keys offline

### Darkside Attack

When NO sector keys are known (all sectors locked):

1. Requires extended interaction with card
2. Exploits weakness in Crypto1 PRNG
3. May require external tool (libnfc + mfoc)
4. Usually recovers at least one key
5. Then use nested attack for remaining sectors

### Key Recovery Flow

```
Card Detected as MIFARE Classic
        |
        v
  Dictionary Attack
  /               \
SUCCESS          FAIL (all sectors locked)
  |                    |
  v                    v
Read accessible    Darkside Attack
sectors            (get 1 key)
  |                    |
  v                    v
Nested Attack      Got 1 key!
(get remaining)    -> Nested Attack
  |                    |
  v                    v
  Full Card Dump Complete
        |
        v
  Write to Gen2/CUID Blank
```

---

## Attack Type 3: EMV Contactless Reading

### What Can Be Read

| Field | Readable | Example |
|-------|----------|---------|
| Card number (PAN) | YES | 4111 1111 1111 1111 |
| Cardholder name | SOMETIMES | JOHN Q DOE |
| Expiration date | YES | 12/28 |
| Transaction history | SOMETIMES (older cards) | Last 10 transactions |
| Card type / AID | YES | Visa, Mastercard, Amex |
| Track 2 equivalent | YES | Used for mag stripe emulation |

### What CANNOT Be Read

| Field | Why |
|-------|-----|
| CVV/CVC (printed) | Never stored on chip |
| iCVV (chip CVV) | Cryptographically generated per transaction |
| PIN | Encrypted, never transmitted to reader |
| Full track data | DDA/CDA cards use dynamic signatures |

### EMV Read with Flipper

1. Flipper -> NFC -> Read
2. Hold Flipper near wallet/card (1-3 cm)
3. Flipper reads and displays:
   - Card type (Visa/MC/Amex)
   - Partial PAN
   - Expiration
   - AID (Application Identifier)

### EMV Application Identifiers (AIDs)

| AID | Network |
|-----|---------|
| A0000000031010 | Visa Credit/Debit |
| A0000000032010 | Visa Electron |
| A0000000041010 | Mastercard Credit/Debit |
| A0000000042010 | Mastercard Maestro |
| A000000025010801 | American Express |
| A0000001523010 | Discover |
| A0000000651010 | JCB |
| A0000000031010 | Interac (Canada) |

> **Note:** Modern EMV cards use Dynamic Data Authentication (DDA/CDA). The data read cannot be used to create a functional clone. This is primarily useful for card identification and social engineering (knowing card type, bank, etc.).

---

## Attack Type 4: NTAG/NDEF Manipulation

### Evil NFC Tag Templates

NTAG213/215/216 tags can be written with NDEF records that trigger actions on smartphones.

**URL redirect (phishing):**
```
NDEF Type: URI
Payload: https://portal-login.example.com/auth
```

**WiFi network auto-connect:**
```
NDEF Type: WiFi Simple Config
SSID: Corporate-Guest
Auth: WPA2-PSK
Password: (attacker-controlled)
```

**Phone call trigger:**
```
NDEF Type: URI
Payload: tel:+15551234567
```

**SMS auto-send:**
```
NDEF Type: URI
Payload: sms:+15551234567?body=Account+verification+code+is+
```

**Bluetooth pairing:**
```
NDEF Type: Bluetooth OOB
MAC: XX:XX:XX:XX:XX:XX
Device: "Wireless Speaker"
```

**vCard injection (contact add):**
```
NDEF Type: vCard
Name: IT Support
Phone: +1-555-EVIL
Email: itsupport@evil.com
```

### Deployment Scenarios
- Place evil tag on back of legitimate NFC payment terminal
- Swap NFC poster tags in public areas
- Leave "tap to connect" WiFi tags in target building lobby
- Attach tag inside conference room (auto-connect to rogue AP)

---

## Attack Type 5: Reader Attack

### Credential Harvest from NFC Readers

When you have access to a card reader (physical pentest):

1. **Flipper -> NFC -> Detect Reader**
2. Present Flipper to the reader
3. Flipper captures:
   - Reader commands
   - Authentication protocol used
   - Key attempts (if MIFARE Classic)
   - Challenge-response pairs

4. Use captured data:
   - Extract reader keys (Mfkey32)
   - Determine card type expected
   - Craft compatible emulation

### Reader Reconnaissance

| Observation | Intelligence |
|-------------|-------------|
| Reader model/brand visible | Look up known vulnerabilities |
| LED color on read | Distinguish accept/reject |
| Beep on read | Audio confirmation of read attempt |
| Multiple readers on one door | May have LF + HF (dual-frequency) |
| Wiring visible | Possible Wiegand interception point |
| Reader mounted outside | Physical tamper access |

---

## Attack Type 6: Relay / Proxy Attack

### Concept
Relay a card's authentication over distance using two NFC devices:
- **Mole device:** Near the victim's card (reader emulator)
- **Proxy device:** At the target door (card emulator)
- Communication: Over WiFi/Bluetooth/Internet

### Practical Implementation
1. Device A (near victim): Reads card, sends data over network
2. Device B (at reader): Emulates card responses in real-time
3. Latency must be < 1 second for most readers

> This attack bypasses ALL card-level crypto because the legitimate card performs the authentication. Requires specialized hardware (not just Flipper alone).

---

## MIFARE Classic Key Database

### Factory Default Keys (All Manufacturers)

```
FFFFFFFFFFFF   (universal factory default)
000000000000   (some manufacturers)
A0A1A2A3A4A5   (MAD - MIFARE Application Directory)
D3F7D3F7D3F7   (MIFARE standard key B)
B0B1B2B3B4B5   (common alternative)
4D3A99C351DD   (some transit systems)
1A2B3C4D5E6F   (common custom)
AABBCCDDEEFF   (common test key)
```

### Transit System Keys (Known/Published)

```
# These keys have been publicly disclosed in security research papers

# Generic transit
484558414354   (HEXACT)
564C504B4453   (VLPKDS)

# Access control systems
A0478CC39091   (common access control)
0297927C0F77   (HID multiClass reader)
484944204953   (HID IS)

# Hotel / Hospitality
A22AE129C013   (common hotel lock system)
49FAE4E3849F   (hospitality system)

# Parking / Elevator
8829DA9DAF76   (parking systems)
314B49474956   (elevator access)

# Vending / Payment
A0A1A2A3A4A5   (MAD - payment applications)
FC00018778F7   (common vending)

# Common brute-force candidates
010203040506
0A0B0C0D0E0F
111111111111
222222222222
333333333333
999999999999
AAAAAAAAAAAA
BBBBBBBBBBBB
```

### Key Recovery Tools (External)

| Tool | Platform | Method |
|------|----------|--------|
| **mfoc** | Linux | Nested attack (with 1 known key) |
| **mfcuk** | Linux | Darkside attack (0 known keys) |
| **proxmark3** | Hardware | All attacks + sniffing |
| **libnfc** | Linux | Low-level NFC library |
| **MFKEY** | Windows/Linux | Offline key recovery from nonces |
| **CryptoRF** | Research | Academic Crypto1 analysis |

---

## Wiegand Protocol Reference

### Wiegand Formats

Most access control systems transmit credentials from reader to controller via Wiegand protocol over 2-3 wires.

| Format | Bits | Structure | Common In |
|--------|------|-----------|-----------|
| **26-bit** (H10301) | 26 | P(1) + FC(8) + CN(16) + P(1) | 90% of HID installations |
| **34-bit** (H10306) | 34 | P(1) + FC(16) + CN(16) + P(1) | Government, large enterprise |
| **35-bit** (Corporate 1000) | 35 | P(2) + FC(12) + CN(20) + P(1) | HID Corporate 1000 |
| **37-bit** (H10302) | 37 | P(1) + FC(16) + CN(19) + P(1) | Large installations |

### 26-bit Wiegand Layout

```
  P | FFFFFFFF | CCCCCCCCCCCCCCCC | P
  1     8              16           1

P = Parity bit
F = Facility code (0-255)
C = Card number (0-65535)

Even parity: bits 1-13
Odd parity: bits 14-26
```

### Wiegand Interception
If physical access to reader wiring exists:
1. Tap DATA0 (green wire) and DATA1 (white wire)
2. Ground reference (black wire)
3. Capture bit stream on each badge swipe
4. Decode facility code + card number
5. Program T5577 or emulate with Flipper

---

## Practical Engagement Playbook

### Pre-Engagement
- [ ] Written authorization from client
- [ ] Scope defined (which doors, which systems)
- [ ] Rules of engagement (hours, escalation contacts)
- [ ] Blank cards procured (T5577, Gen2 MIFARE, NTAG)
- [ ] Flipper Zero charged and NFC dictionary updated

### Phase 1: Reconnaissance (Day 1)
- [ ] Identify all NFC/RFID readers on-site
- [ ] Photograph reader models
- [ ] Note reader placement (inside/outside)
- [ ] Observe badge usage patterns
- [ ] Identify card technology (125 kHz vs 13.56 MHz vs dual)
- [ ] Test if UID-only or sector authentication

### Phase 2: Card Capture (Day 1-2)
- [ ] Attempt to read sample badge (with permission or social eng)
- [ ] Run dictionary attack on MIFARE Classic cards
- [ ] Attempt nested/darkside attacks if needed
- [ ] Read EMV cards for device identification
- [ ] Test Flipper emulation against readers

### Phase 3: Cloning & Testing (Day 2-3)
- [ ] Clone captured credentials to blank cards
- [ ] Test cloned cards against target readers
- [ ] Verify access level obtained
- [ ] Attempt privilege escalation (clone admin badge)
- [ ] Test multi-factor (badge + PIN) bypass

### Phase 4: Advanced Attacks (Day 3-5)
- [ ] Place evil NFC tags for WiFi credential harvest
- [ ] Test reader-side credential capture
- [ ] Attempt Wiegand interception (if wiring accessible)
- [ ] Test relay attack feasibility
- [ ] Check for default reader passwords

### Phase 5: Reporting
- [ ] Document all findings with evidence
- [ ] Risk-rate each vulnerability
- [ ] Recommend remediations
- [ ] Destroy all cloned credentials
- [ ] Deliver report to client

---

## Countermeasures & Recommendations

### For Client Reporting

| Vulnerability | Risk | Remediation |
|--------------|------|------------|
| 125 kHz badges (EM4100/HID Prox) | CRITICAL | Upgrade to DESFire EV2/EV3 or SEOS |
| MIFARE Classic (Crypto1) | HIGH | Upgrade to DESFire EV2/EV3 |
| UID-only authentication | CRITICAL | Enable sector-level authentication |
| Exposed Wiegand wiring | HIGH | Use OSDP protocol, encrypt reader-controller |
| No multi-factor | MEDIUM | Add PIN or biometric to high-security areas |
| Single-frequency readers | MEDIUM | Use dual-frequency with encryption |
| Badge not deactivated on termination | HIGH | Integrate access control with HR system |
| Reader mounted outside secured area | MEDIUM | Tamper detection, relocate if possible |

---

*FLLC - FU PERSON Arsenal | NFC Attack Playbook v2.0*
*Authorized penetration testing use only.*
