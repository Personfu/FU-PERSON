# Post-Quantum Cryptography (PQC) Readiness Guide

```
╔══════════════════════════════════════════════════════════════╗
║  FLLC — POST-QUANTUM CRYPTOGRAPHY READINESS GUIDE           ║
║  FU PERSON quantum_crypto.py | ML-KEM · ML-DSA · SLH-DSA   ║
╚══════════════════════════════════════════════════════════════╝
```

## `[root@fuperson]─[~/pqc/overview]`

### Why Quantum Computing Matters

RSA, ECDSA, ECDH, and DSA — the backbone of modern encryption — are **mathematically broken** by quantum algorithms that already exist on paper. The only missing piece is hardware.

| Quantum Algorithm | What It Breaks | Impact |
|-------------------|---------------|--------|
| **Shor's Algorithm** | RSA, ECDSA, ECDH, DSA, DH | Factors integers and solves discrete log in polynomial time. All public-key crypto based on these problems becomes trivial. |
| **Grover's Algorithm** | AES-128, SHA-1, all symmetric primitives | Provides quadratic speedup to brute-force. Halves effective key strength (AES-128 → 64-bit effective). AES-256 remains secure (128-bit effective). |

**NIST PQC Standardization (Finalized August 2024):**
- **FIPS 203** — ML-KEM (Kyber) — Key encapsulation
- **FIPS 204** — ML-DSA (Dilithium) — Digital signatures
- **FIPS 205** — SLH-DSA (SPHINCS+) — Hash-based signatures (stateless)

**"Harvest Now, Decrypt Later"** — Adversaries are capturing encrypted traffic today to decrypt once quantum hardware matures. Long-lived secrets (government, healthcare, financial, infrastructure) are already at risk. If your data needs to stay confidential for 10+ years, you are already late.

---

## `[root@fuperson]─[~/pqc/implementation]`

### FU PERSON PQC Implementation

The `quantum_crypto.py` module provides a complete post-quantum toolkit:

| Component | Class | Capability |
|-----------|-------|------------|
| Key Encapsulation | `PQKeyExchange` | ML-KEM (Kyber-512/768/1024) key generation, encapsulation, decapsulation |
| Digital Signatures | `PQSignature` | ML-DSA (Dilithium-2/3/5), SLH-DSA (SPHINCS+ 128s/192s/256s) |
| Hybrid Encryption | `HybridEncryption` | X25519 + Kyber combined KEM with HKDF key derivation |
| Symmetric Crypto | `AES256GCM` | AES-256-GCM authenticated encryption with AEAD support |
| Hashing | `SHA3Hasher` | SHA3-224/256/384/512, SHAKE128/256 |
| Migration Audit | `CryptoMigrator` | Scans codebases for vulnerable crypto patterns, generates reports |

**Backend priority:** liboqs (production) → pure-Python demo (educational fallback).
Install `oqs-python` and `liboqs` for production-grade post-quantum operations.

---

## `[root@fuperson]─[~/pqc/algorithms]`

### Algorithm Reference

#### ML-KEM (Kyber) — Key Encapsulation

| Algorithm | NIST Level | Public Key | Ciphertext | Shared Secret | Standard |
|-----------|-----------|------------|------------|---------------|----------|
| Kyber-512 | 1 (AES-128 equiv) | 800 B | 768 B | 32 B | FIPS 203 |
| Kyber-768 | 3 (AES-192 equiv) | 1,184 B | 1,088 B | 32 B | FIPS 203 |
| Kyber-1024 | 5 (AES-256 equiv) | 1,568 B | 1,568 B | 32 B | FIPS 203 |

#### ML-DSA (Dilithium) — Digital Signatures

| Algorithm | NIST Level | Public Key | Secret Key | Signature | Standard |
|-----------|-----------|------------|------------|-----------|----------|
| Dilithium-2 | 2 | 1,312 B | 2,528 B | 2,420 B | FIPS 204 |
| Dilithium-3 | 3 | 1,952 B | 4,000 B | 3,293 B | FIPS 204 |
| Dilithium-5 | 5 | 2,592 B | 4,864 B | 4,595 B | FIPS 204 |

#### SLH-DSA (SPHINCS+) — Hash-Based Signatures

| Algorithm | NIST Level | Public Key | Secret Key | Signature | Standard |
|-----------|-----------|------------|------------|-----------|----------|
| SPHINCS+-128s | 1 | 32 B | 64 B | 7,856 B | FIPS 205 |
| SPHINCS+-192s | 3 | 48 B | 96 B | 16,224 B | FIPS 205 |
| SPHINCS+-256s | 5 | 64 B | 128 B | 29,792 B | FIPS 205 |

> **Tradeoff:** Dilithium has small, fast signatures but relies on lattice assumptions. SPHINCS+ has larger signatures but relies only on hash function security — no new math required.

---

## `[root@fuperson]─[~/pqc/migration]`

### Migration Guide

#### Step 1 — Audit Current Crypto Usage

```bash
[root@fuperson]─# python3 core/quantum_crypto.py migrate -d /path/to/project -o audit_report.json
  [*] Scanning /path/to/project for cryptographic usage ...
  [+] Scanned 847 files, found 23 findings
       deprecated: 4
       quantum-vulnerable: 15
       acceptable: 4
```

#### Step 2 — Prioritize by Risk

The audit classifies findings into four tiers:

| Risk Level | Action | Examples |
|------------|--------|----------|
| `deprecated` | **Replace immediately** — broken today | MD5, SHA-1, DES, 3DES, RC4, Blowfish |
| `quantum-vulnerable` | **Migrate to PQC** — broken by quantum | RSA, ECDSA, ECDH, DSA, X25519 |
| `acceptable` | **Upgrade when possible** — weakened by quantum | AES-128 (→ AES-256) |
| `recommended` | **No action needed** | AES-256-GCM, SHA-3, ML-KEM, ML-DSA |

#### Step 3 — Deploy Hybrid Mode (Transition)

Hybrid mode combines classical X25519 with Kyber so you remain secure against both classical and quantum attacks during migration:

```python
from core.quantum_crypto import PQKeyExchange, HybridEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

kem = PQKeyExchange()
pq_keys = kem.generate_keypair("kyber768")
x_sk = X25519PrivateKey.generate()
x_pk = x_sk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

hybrid = HybridEncryption("kyber768")
payload = hybrid.encrypt(b"sensitive data", pq_keys.public_key, x_pk)
```

#### Step 4 — Full PQC Migration

Once hybrid mode is validated, drop the classical component:

```python
kem = PQKeyExchange()
keys = kem.generate_keypair("kyber768")
ct, shared_secret = kem.encapsulate(keys.public_key, "kyber768")
recovered = kem.decapsulate(keys.secret_key, ct, "kyber768")
assert shared_secret == recovered
```

#### Step 5 — Verify and Test

```bash
[root@fuperson]─# python3 core/quantum_crypto.py migrate -d /path/to/project -o post_migration.json
  [+] Scanned 847 files, found 0 findings
  [!] No vulnerable cryptographic patterns detected. Continue monitoring NIST PQC updates.
```

---

## `[root@fuperson]─[~/pqc/threat-timeline]`

### Quantum Threat Timeline

```
2024 ████░░░░░░░░░░░░░░░░ NIST PQC standards finalized (FIPS 203/204/205)
2026 ██████░░░░░░░░░░░░░░ No CRQC exists. Migration window is NOW.
2028 ████████░░░░░░░░░░░░ Early fault-tolerant machines (100-1K logical qubits)
2030 ██████████░░░░░░░░░░ RSA-1024 at risk. ECDSA P-256 potentially broken.
2033 █████████████░░░░░░░ RSA-2048 at risk. Harvest-now payloads decryptable.
2035 ███████████████░░░░░ Assume all classical public-key crypto is compromised.
```

| Timeframe | Status | Action Required |
|-----------|--------|-----------------|
| **Now (2026)** | No cryptographically relevant quantum computer (CRQC) exists | Begin PQC migration. Audit all systems. Deploy hybrid mode for high-value assets. |
| **2027–2030** | Early fault-tolerant machines; 100–1,000 logical qubits possible | Complete hybrid deployment. All new systems must be PQC-native. |
| **2030–2035** | Potential RSA-2048 break; ECDSA compromise likely | All classical public-key crypto must be fully replaced. Harvest-now data becomes decryptable. |

**Bottom line:** If you wait for a quantum computer to exist before migrating, you are already compromised. Migrate now.

---

## `[root@fuperson]─[~/pqc/usage]`

### Usage Examples

**Generate a Kyber-768 keypair:**
```bash
[root@fuperson]─# python3 core/quantum_crypto.py keygen -a kyber768 -o mykeys.json
  [*] Generating ML-KEM keypair (kyber768) ...
  [+] Keypair saved to mykeys.json
```

**Encrypt and decrypt a file:**
```bash
[root@fuperson]─# python3 core/quantum_crypto.py encrypt -i secret.txt -k mykeys.json -o secret.enc
[root@fuperson]─# python3 core/quantum_crypto.py decrypt -i secret.enc -k mykeys.json -o secret.dec
```

**Sign and verify:**
```bash
[root@fuperson]─# python3 core/quantum_crypto.py keygen -a dilithium3 -o sigkeys.json
[root@fuperson]─# python3 core/quantum_crypto.py sign -i document.pdf -k sigkeys.json
[root@fuperson]─# python3 core/quantum_crypto.py verify -i document.pdf -k sigkeys.json -s document.pdf.sig
  [+] Signature is VALID
```

**Hash with SHA-3:**
```bash
[root@fuperson]─# python3 core/quantum_crypto.py hash -i firmware.bin -a sha3_512
  [+] sha3_512: a1b2c3d4...
  [*]   Length: 64 bytes (512 bits)
```

**Run a full crypto audit:**
```bash
[root@fuperson]─# python3 core/quantum_crypto.py migrate -d ./src -o crypto_audit.json
```

---

## `[root@fuperson]─[~/pqc/dependencies]`

### Required Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| `liboqs` + `oqs-python` | Production PQC (Kyber, Dilithium, SPHINCS+) | `pip install oqs` (requires liboqs C library) |
| `pycryptodome` | Hardware-accelerated AES-256-GCM | `pip install pycryptodome` |
| `cryptography` | X25519 for hybrid mode, HKDF | `pip install cryptography` |

Without these, `quantum_crypto.py` falls back to pure-Python educational implementations. **Do not use demo mode in production.**

```
╔══════════════════════════════════════════════════════════════╗
║  FLLC — The quantum clock is ticking. Migrate or be owned.  ║
╚══════════════════════════════════════════════════════════════╝
```
