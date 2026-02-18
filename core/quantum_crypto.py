#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: POST-QUANTUM CRYPTOGRAPHY TOOLKIT v1.0
  ML-KEM (Kyber) | ML-DSA (Dilithium) | SLH-DSA (SPHINCS+) | Hybrid X25519
  AES-256-GCM | SHA-3 Family | Crypto Migration Analysis
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  Cryptographic tools are subject to export control regulations.
  This module is for AUTHORIZED security research, cryptographic migration
  planning, and post-quantum readiness assessments.

  FLLC
  Government-Cleared Security Operations
===============================================================================
"""

import os, sys, re, json, time, hmac, struct, hashlib, base64, argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any, Callable
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import oqs; HAS_OQS = True
except ImportError:
    HAS_OQS = False

try:
    from Crypto.Cipher import AES as PyCryptoAES
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _cg_hashes, serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# =============================================================================
#  ANSI COLORS & DISPLAY
# =============================================================================

class C:
    R   = "\033[0m"; BLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
    BLU = "\033[94m"; MAG = "\033[95m"; CYN = "\033[96m"; WHT = "\033[97m"

    @staticmethod
    def p(text: str):
        try: print(text)
        except UnicodeEncodeError: print(re.sub(r"\033\[[0-9;]*m", "", str(text)))

    @staticmethod
    def ok(msg: str):   C.p(f"  {C.GRN}[+]{C.R} {msg}")
    @staticmethod
    def info(msg: str): C.p(f"  {C.BLU}[*]{C.R} {msg}")
    @staticmethod
    def warn(msg: str): C.p(f"  {C.YLW}[!]{C.R} {msg}")
    @staticmethod
    def fail(msg: str): C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def banner(title: str):
        w = 70
        C.p(f"\n  {C.MAG}{C.BLD}{'=' * w}")
        C.p(f"  {'':>2}{title}")
        C.p(f"  {'=' * w}{C.R}")


# =============================================================================
#  DATA STRUCTURES
# =============================================================================

@dataclass
class KEMKeypair:
    public_key: bytes; secret_key: bytes; algorithm: str; key_size: int

@dataclass
class SigKeypair:
    public_key: bytes; secret_key: bytes; algorithm: str

@dataclass
class EncryptedPayload:
    pq_ciphertext: bytes; classical_ciphertext: Optional[bytes]
    nonce: bytes; tag: bytes; ciphertext: bytes; algorithm: str; hybrid: bool

@dataclass
class CryptoUsage:
    file: str; line: int; algorithm: str
    risk_level: str; replacement: str; description: str


# =============================================================================
#  CONSTANTS
# =============================================================================

KEM_ALGORITHMS: Dict[str, str] = {
    "kyber512": "Kyber512", "kyber768": "Kyber768", "kyber1024": "Kyber1024"}
SIG_ALGORITHMS: Dict[str, str] = {
    "dilithium2": "Dilithium2", "dilithium3": "Dilithium3", "dilithium5": "Dilithium5",
    "sphincssha2128s": "SPHINCS+-SHA2-128s-simple",
    "sphincssha2192s": "SPHINCS+-SHA2-192s-simple",
    "sphincssha2256s": "SPHINCS+-SHA2-256s-simple"}
LATTICE_PARAMS: Dict[str, Tuple[int, int, int]] = {
    "kyber512": (256, 2, 3329), "kyber768": (256, 3, 3329), "kyber1024": (256, 4, 3329)}
PBKDF2_ITERATIONS = 100_000
GCM_NONCE_SIZE = 12
AES_KEY_SIZE = 32


# =============================================================================
#  HELPER UTILITIES
# =============================================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    if HAS_CRYPTOGRAPHY:
        return HKDF(algorithm=_cg_hashes.SHA256(), length=length,
                     salt=salt, info=info).derive(ikm)
    if salt is None: salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def _pbkdf2_derive(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=AES_KEY_SIZE)

def _random_poly(n: int, q: int) -> List[int]:
    return [int.from_bytes(os.urandom(2), "little") % q for _ in range(n)]

def _poly_add(a: List[int], b: List[int], q: int) -> List[int]:
    return [(x + y) % q for x, y in zip(a, b)]

def _poly_sub(a: List[int], b: List[int], q: int) -> List[int]:
    return [(x - y) % q for x, y in zip(a, b)]

def _poly_mul(a: List[int], b: List[int], n: int, q: int) -> List[int]:
    r = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            r[idx] = (r[idx] + (1 if (i + j) < n else -1) * a[i] * b[j]) % q
    return r

def _small_noise(n: int, q: int, eta: int = 3) -> List[int]:
    return [(int.from_bytes(os.urandom(1), "little") % (2 * eta + 1) - eta) % q for _ in range(n)]

def _encode_poly(poly: List[int], q: int) -> bytes:
    return b"".join(struct.pack("<H", c % q) for c in poly)

def _decode_poly(data: bytes, n: int, q: int) -> List[int]:
    return [struct.unpack("<H", data[i*2:(i+1)*2])[0] % q for i in range(n)]


# =============================================================================
#  PQKeyExchange  -  Post-Quantum Key Encapsulation (ML-KEM / Kyber)
# =============================================================================

class PQKeyExchange:
    SUPPORTED = list(KEM_ALGORITHMS.keys())

    def __init__(self) -> None:
        self._backend = "oqs" if HAS_OQS else "demo"
        if not HAS_OQS:
            C.warn("oqs-python not found - using educational lattice-based KEM demo")
            C.warn("NOT production-grade. Install liboqs + oqs-python for real PQ crypto.")

    def generate_keypair(self, algorithm: str = "kyber768") -> KEMKeypair:
        if algorithm not in KEM_ALGORITHMS:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}. Use: {self.SUPPORTED}")
        if HAS_OQS:
            kem = oqs.KeyEncapsulation(KEM_ALGORITHMS[algorithm])
            pk = kem.generate_keypair(); sk = kem.export_secret_key()
            return KEMKeypair(public_key=pk, secret_key=sk, algorithm=algorithm, key_size=len(pk))
        return self._demo_keygen(algorithm)

    def encapsulate(self, public_key: bytes, algorithm: str = "kyber768") -> Tuple[bytes, bytes]:
        if HAS_OQS:
            kem = oqs.KeyEncapsulation(KEM_ALGORITHMS[algorithm])
            return kem.encap_secret(public_key)
        return self._demo_encaps(public_key, algorithm)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes, algorithm: str = "kyber768") -> bytes:
        if HAS_OQS:
            return oqs.KeyEncapsulation(KEM_ALGORITHMS[algorithm], secret_key).decap_secret(ciphertext)
        return self._demo_decaps(secret_key, ciphertext, algorithm)

    def _demo_keygen(self, algorithm: str) -> KEMKeypair:
        n, k, q = LATTICE_PARAMS[algorithm]
        a = [[_random_poly(n, q) for _ in range(k)] for _ in range(k)]
        s = [_small_noise(n, q) for _ in range(k)]
        e = [_small_noise(n, q) for _ in range(k)]
        b: List[List[int]] = []
        for i in range(k):
            acc = [0] * n
            for j in range(k):
                acc = _poly_add(acc, _poly_mul(a[i][j], s[j], n, q), q)
            b.append(_poly_add(acc, e[i], q))
        pk = b"".join(_encode_poly(p, q) for row in a for p in row)
        pk += b"".join(_encode_poly(p, q) for p in b)
        sk = b"".join(_encode_poly(p, q) for p in s)
        return KEMKeypair(public_key=pk, secret_key=sk, algorithm=algorithm, key_size=len(pk))

    def _demo_encaps(self, public_key: bytes, algorithm: str) -> Tuple[bytes, bytes]:
        n, k, q = LATTICE_PARAMS[algorithm]
        pb = n * 2; off = 0
        a: List[List[List[int]]] = []
        for i in range(k):
            row = []
            for j in range(k):
                row.append(_decode_poly(public_key[off:off+pb], n, q)); off += pb
            a.append(row)
        bv = [_decode_poly(public_key[off+i*pb:off+(i+1)*pb], n, q) for i in range(k)]
        rv = [_small_noise(n, q) for _ in range(k)]
        e1 = [_small_noise(n, q) for _ in range(k)]
        e2 = _small_noise(n, q)
        u: List[List[int]] = []
        for i in range(k):
            acc = [0] * n
            for j in range(k):
                acc = _poly_add(acc, _poly_mul(a[j][i], rv[j], n, q), q)
            u.append(_poly_add(acc, e1[i], q))
        v = [0] * n
        for j in range(k):
            v = _poly_add(v, _poly_mul(bv[j], rv[j], n, q), q)
        v = _poly_add(v, e2, q)
        coin = os.urandom(32)
        msg_bits: List[int] = []
        for bval in coin:
            for bit in range(8): msg_bits.append((bval >> bit) & 1)
        v = _poly_add(v, [(mb * (q // 2)) % q for mb in msg_bits[:n]], q)
        ct = b"".join(_encode_poly(p, q) for p in u) + _encode_poly(v, q)
        return ct, hashlib.sha256(coin).digest()

    def _demo_decaps(self, secret_key: bytes, ciphertext: bytes, algorithm: str) -> bytes:
        n, k, q = LATTICE_PARAMS[algorithm]
        pb = n * 2
        s = [_decode_poly(secret_key[i*pb:(i+1)*pb], n, q) for i in range(k)]
        u = [_decode_poly(ciphertext[i*pb:(i+1)*pb], n, q) for i in range(k)]
        v = _decode_poly(ciphertext[k*pb:(k+1)*pb], n, q)
        inner = [0] * n
        for j in range(k):
            inner = _poly_add(inner, _poly_mul(s[j], u[j], n, q), q)
        noisy = _poly_sub(v, inner, q)
        bits: List[int] = []
        hq = q // 2
        for c in noisy[:min(n, 256)]:
            bits.append(0 if min(c, q - c) < abs(c - hq) else 1)
        bits.extend([0] * (256 - len(bits)))
        coin = bytearray(32)
        for i in range(256):
            coin[i // 8] |= (bits[i] << (i % 8))
        return hashlib.sha256(bytes(coin)).digest()


# =============================================================================
#  PQSignature  -  Post-Quantum Digital Signatures (ML-DSA / SLH-DSA)
# =============================================================================

class PQSignature:
    SUPPORTED = list(SIG_ALGORITHMS.keys())
    _DEPTHS: Dict[str, int] = {"dilithium2": 4, "dilithium3": 6, "dilithium5": 8,
        "sphincssha2128s": 10, "sphincssha2192s": 14, "sphincssha2256s": 18}

    def __init__(self) -> None:
        self._backend = "oqs" if HAS_OQS else "demo"
        if not HAS_OQS:
            C.warn("oqs-python not found - using educational hash-based signature demo")
            C.warn("NOT production-grade. Install liboqs + oqs-python for real PQ sigs.")

    def generate_keypair(self, algorithm: str = "dilithium3") -> SigKeypair:
        if algorithm not in SIG_ALGORITHMS:
            raise ValueError(f"Unsupported sig algorithm: {algorithm}. Use: {self.SUPPORTED}")
        if HAS_OQS:
            sig = oqs.Signature(SIG_ALGORITHMS[algorithm])
            pk = sig.generate_keypair(); sk = sig.export_secret_key()
            return SigKeypair(public_key=pk, secret_key=sk, algorithm=algorithm)
        return self._demo_keygen(algorithm)

    def sign(self, secret_key: bytes, message: bytes, algorithm: str = "dilithium3") -> bytes:
        if HAS_OQS:
            return oqs.Signature(SIG_ALGORITHMS[algorithm], secret_key).sign(message)
        return self._demo_sign(secret_key, message, algorithm)

    def verify(self, public_key: bytes, message: bytes, signature: bytes,
               algorithm: str = "dilithium3") -> bool:
        if HAS_OQS:
            return oqs.Signature(SIG_ALGORITHMS[algorithm]).verify(message, signature, public_key)
        return self._demo_verify(public_key, message, signature, algorithm)

    def _demo_keygen(self, algorithm: str) -> SigKeypair:
        seed = os.urandom(48)
        tag = algorithm.encode("utf-8")
        sk_seed = hashlib.sha512(seed + b"SK" + tag).digest()
        sk_keys = [hashlib.sha256(sk_seed + struct.pack("<H", i)).digest() for i in range(512)]
        depth = self._DEPTHS.get(algorithm, 6)
        pk_hashes: List[bytes] = []
        for k in sk_keys:
            val = k
            for _ in range(depth):
                val = hashlib.sha256(val).digest()
            pk_hashes.append(val)
        trailer = struct.pack("<I", depth) + tag.ljust(32, b"\x00")
        return SigKeypair(public_key=b"".join(pk_hashes) + trailer,
                          secret_key=b"".join(sk_keys) + trailer, algorithm=algorithm)

    def _demo_sign(self, secret_key: bytes, message: bytes, algorithm: str) -> bytes:
        depth = self._DEPTHS.get(algorithm, 6)
        sk_keys = [secret_key[i*32:(i+1)*32] for i in range(512)]
        msg_bits = self._msg_bits(message)
        parts: List[bytes] = []
        for i in range(512):
            val = sk_keys[i]
            iters = msg_bits[i] if i < len(msg_bits) else 0
            for _ in range(iters):
                val = hashlib.sha256(val).digest()
            parts.append(val)
        return b"".join(parts) + hashlib.sha256(message).digest()

    def _demo_verify(self, public_key: bytes, message: bytes, signature: bytes,
                     algorithm: str) -> bool:
        depth = self._DEPTHS.get(algorithm, 6)
        pk_hashes = [public_key[i*32:(i+1)*32] for i in range(512)]
        sig_parts = [signature[i*32:(i+1)*32] for i in range(512)]
        msg_bits = self._msg_bits(message)
        for i in range(512):
            val = sig_parts[i]
            remaining = depth - (msg_bits[i] if i < len(msg_bits) else 0)
            for _ in range(remaining):
                val = hashlib.sha256(val).digest()
            if val != pk_hashes[i]: return False
        return True

    @staticmethod
    def _msg_bits(message: bytes) -> List[int]:
        h = hashlib.sha512(message).digest()
        bits: List[int] = []
        for bval in h:
            for bit in range(8): bits.append((bval >> bit) & 1)
        return bits


# =============================================================================
#  AES256GCM  -  Authenticated Encryption with Associated Data
# =============================================================================

_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
_MIX = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]

def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def _aes_block(key: bytes, block: bytes) -> bytes:
    Nk, Nr = 8, 14
    sw = lambda w: (_SBOX[(w>>24)&0xff]<<24|_SBOX[(w>>16)&0xff]<<16|_SBOX[(w>>8)&0xff]<<8|_SBOX[w&0xff])
    rw = lambda w: ((w << 8) | (w >> 24)) & 0xffffffff
    wk = [int.from_bytes(key[4*i:4*i+4], "big") for i in range(Nk)]
    for i in range(Nk, 4*(Nr+1)):
        t = wk[i-1]
        if i % Nk == 0: t = sw(rw(t)) ^ (_RCON[i//Nk-1] << 24)
        elif i % Nk == 4: t = sw(t)
        wk.append(wk[i-Nk] ^ t)
    st = [list(block[i::4]) for i in range(4)]
    for r in range(4):
        rk = wk[r]
        for c in range(4): st[c][r] ^= (rk >> (24 - 8*c)) & 0xff
    for rnd in range(1, Nr+1):
        for r in range(4):
            for c in range(4): st[c][r] = _SBOX[st[c][r]]
        for r in range(1, 4):
            row = [st[c][r] for c in range(4)]
            shifted = row[r:] + row[:r]
            for c in range(4): st[c][r] = shifted[c]
        if rnd < Nr:
            ns = [[0]*4 for _ in range(4)]
            for c in range(4):
                col = [st[c][r] for r in range(4)]
                for r in range(4):
                    ns[c][r] = _gf_mul(_MIX[r][0],col[0])^_gf_mul(_MIX[r][1],col[1])^_gf_mul(_MIX[r][2],col[2])^_gf_mul(_MIX[r][3],col[3])
            st = ns
        for r in range(4):
            rk = wk[4*rnd+r]
            for c in range(4): st[c][r] ^= (rk >> (24-8*c)) & 0xff
    out = bytearray(16)
    for c in range(4):
        for r in range(4): out[r+4*c] = st[c][r]
    return bytes(out)

def _ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    R_POLY = 0xe1000000000000000000000000000000
    def gf128(x_b: bytes, y_b: bytes) -> bytes:
        x, y = int.from_bytes(x_b, "big"), int.from_bytes(y_b, "big")
        z, v = 0, y
        for i in range(128):
            if (x >> (127-i)) & 1: z ^= v
            carry = v & 1; v >>= 1
            if carry: v ^= R_POLY
        return z.to_bytes(16, "big")
    def pad16(d: bytes) -> bytes:
        r = len(d) % 16; return d + b"\x00"*(16-r) if r else d
    tag = b"\x00" * 16
    for blk in (pad16(aad), pad16(ct)):
        for i in range(0, len(blk), 16):
            tag = gf128(_xor_bytes(tag, blk[i:i+16]), h)
    lb = struct.pack(">Q", len(aad)*8) + struct.pack(">Q", len(ct)*8)
    return gf128(_xor_bytes(tag, lb), h)

def _gcm_ctr(key: bytes, nonce: bytes, data: bytes, ctr: int = 2) -> bytes:
    result = bytearray()
    for i in range(0, len(data), 16):
        ks = _aes_block(key, nonce + struct.pack(">I", ctr))
        chunk = data[i:i+16]; result.extend(_xor_bytes(ks[:len(chunk)], chunk)); ctr += 1
    return bytes(result)


class AES256GCM:

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
        nonce = os.urandom(GCM_NONCE_SIZE)
        if HAS_PYCRYPTODOME:
            cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
            if aad: cipher.update(aad)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return ct, nonce, tag
        aad_b = aad or b""
        h = _aes_block(key, b"\x00"*16)
        ct = _gcm_ctr(key, nonce, plaintext)
        ghash_val = _ghash(h, aad_b, ct)
        tag = _xor_bytes(ghash_val, _aes_block(key, nonce + struct.pack(">I", 1)))
        return ct, nonce, tag

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes,
                aad: Optional[bytes] = None) -> bytes:
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
        if HAS_PYCRYPTODOME:
            cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
            if aad: cipher.update(aad)
            return cipher.decrypt_and_verify(ciphertext, tag)
        aad_b = aad or b""
        h = _aes_block(key, b"\x00"*16)
        ghash_val = _ghash(h, aad_b, ciphertext)
        expected = _xor_bytes(ghash_val, _aes_block(key, nonce + struct.pack(">I", 1)))
        if not hmac.compare_digest(tag, expected):
            raise ValueError("GCM authentication failed: tag mismatch")
        return _gcm_ctr(key, nonce, ciphertext)

    @staticmethod
    def key_from_passphrase(passphrase: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if salt is None: salt = os.urandom(16)
        return _pbkdf2_derive(passphrase, salt), salt


# =============================================================================
#  HybridEncryption  -  Classical (X25519) + PQ (Kyber) Hybrid
# =============================================================================

class HybridEncryption:

    def __init__(self, kem_algorithm: str = "kyber768") -> None:
        self._kem = PQKeyExchange(); self._alg = kem_algorithm

    def encrypt(self, plaintext: bytes, recipient_pq_pubkey: bytes,
                recipient_classical_pubkey: Optional[bytes] = None) -> EncryptedPayload:
        pq_ct, pq_shared = self._kem.encapsulate(recipient_pq_pubkey, self._alg)
        classical_ct: Optional[bytes] = None; combined = pq_shared
        if recipient_classical_pubkey is not None and HAS_CRYPTOGRAPHY:
            eph_sk = X25519PrivateKey.generate()
            eph_pk = eph_sk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            classical_shared = eph_sk.exchange(
                X25519PublicKey.from_public_bytes(recipient_classical_pubkey))
            classical_ct = eph_pk; combined = pq_shared + classical_shared
        dk = _hkdf_sha256(combined, None, b"FU-PERSON hybrid encryption v1", AES_KEY_SIZE)
        ct, nonce, tag = AES256GCM.encrypt(plaintext, dk)
        return EncryptedPayload(pq_ciphertext=pq_ct, classical_ciphertext=classical_ct,
            nonce=nonce, tag=tag, ciphertext=ct, algorithm=self._alg,
            hybrid=classical_ct is not None)

    def decrypt(self, payload: EncryptedPayload, pq_secret_key: bytes,
                classical_secret_key: Optional[bytes] = None) -> bytes:
        pq_shared = self._kem.decapsulate(pq_secret_key, payload.pq_ciphertext, payload.algorithm)
        combined = pq_shared
        if payload.hybrid and classical_secret_key is not None and HAS_CRYPTOGRAPHY:
            sk = X25519PrivateKey.from_private_bytes(classical_secret_key)
            combined = pq_shared + sk.exchange(
                X25519PublicKey.from_public_bytes(payload.classical_ciphertext))
        dk = _hkdf_sha256(combined, None, b"FU-PERSON hybrid encryption v1", AES_KEY_SIZE)
        return AES256GCM.decrypt(payload.ciphertext, dk, payload.nonce, payload.tag)


# =============================================================================
#  SHA3Hasher  -  SHA-3 Family (built into hashlib)
# =============================================================================

class SHA3Hasher:
    SUPPORTED = ["sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake128", "shake256"]

    @staticmethod
    def hash(data: bytes, algorithm: str = "sha3_256", output_length: int = 32) -> bytes:
        if algorithm not in SHA3Hasher.SUPPORTED:
            raise ValueError(f"Unsupported hash: {algorithm}. Use: {SHA3Hasher.SUPPORTED}")
        h = hashlib.new(algorithm); h.update(data)
        return h.digest(output_length) if algorithm.startswith("shake") else h.digest()

    @staticmethod
    def file_hash(filepath: str, algorithm: str = "sha3_256",
                  output_length: int = 32, chunk_size: int = 65536) -> bytes:
        if algorithm not in SHA3Hasher.SUPPORTED:
            raise ValueError(f"Unsupported hash: {algorithm}. Use: {SHA3Hasher.SUPPORTED}")
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                h.update(chunk)
        return h.digest(output_length) if algorithm.startswith("shake") else h.digest()

    @staticmethod
    def verify(data: bytes, expected_hash: bytes, algorithm: str = "sha3_256",
               output_length: int = 32) -> bool:
        return hmac.compare_digest(SHA3Hasher.hash(data, algorithm, output_length), expected_hash)


# =============================================================================
#  CryptoMigrator  -  Post-Quantum Migration Analysis
# =============================================================================

CRYPTO_PATTERNS: List[Dict[str, Any]] = [
    {"pat": r"\bMD5\b|\.md5\(|hashlib\.md5", "alg": "MD5",
     "risk": "deprecated", "repl": "SHA3-256", "desc": "Broken hash, collision attacks trivial"},
    {"pat": r"\bSHA[\-_]?1\b|\.sha1\(|hashlib\.sha1", "alg": "SHA-1",
     "risk": "deprecated", "repl": "SHA3-256", "desc": "Collision attacks demonstrated (SHAttered)"},
    {"pat": r"\bDES\b(?!3)|DES\.MODE|DES_CBC", "alg": "DES",
     "risk": "deprecated", "repl": "AES-256-GCM", "desc": "56-bit key, brute-force trivial"},
    {"pat": r"\b3DES\b|Triple.?DES|DES3|DESede", "alg": "3DES",
     "risk": "deprecated", "repl": "AES-256-GCM", "desc": "Sweet32 attack, NIST deprecated 2023"},
    {"pat": r"\bRC4\b|ARC4|ARCFOUR", "alg": "RC4",
     "risk": "deprecated", "repl": "AES-256-GCM / ChaCha20", "desc": "Statistical biases, broken for TLS"},
    {"pat": r"\bRSA[\-_]?1024\b|rsa.*1024|key.?size.*1024.*rsa", "alg": "RSA-1024",
     "risk": "quantum-vulnerable", "repl": "ML-KEM-768 + ML-DSA",
     "desc": "Factorable classically; trivial for quantum computers"},
    {"pat": r"\bRSA[\-_]?2048\b|rsa.*2048|key.?size.*2048.*rsa", "alg": "RSA-2048",
     "risk": "quantum-vulnerable", "repl": "ML-KEM-768 + ML-DSA",
     "desc": "Secure classically but broken by Shor's algorithm"},
    {"pat": r"\bAES[\-_]?128\b|aes.*128|key.?size.*128.*aes", "alg": "AES-128",
     "risk": "acceptable", "repl": "AES-256-GCM",
     "desc": "Grover halves security to 64-bit effective; upgrade to 256"},
    {"pat": r"\bECDSA\b.*P[\-_]?256|secp256r1|prime256v1|NIST.?P[\-_]?256", "alg": "ECDSA P-256",
     "risk": "quantum-vulnerable", "repl": "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)",
     "desc": "Broken by Shor's algorithm on elliptic curves"},
    {"pat": r"\bECDH\b|X25519|Curve25519|x25519", "alg": "X25519/ECDH",
     "risk": "quantum-vulnerable", "repl": "ML-KEM-768 or hybrid X25519+Kyber",
     "desc": "Broken by quantum Shor; use hybrid for transition"},
    {"pat": r"\bDSA\b(?!.*ML)(?!.*Dilithium)", "alg": "DSA",
     "risk": "quantum-vulnerable", "repl": "ML-DSA (Dilithium)",
     "desc": "Discrete log broken by Shor's algorithm"},
    {"pat": r"\bBlowfish\b|BLOWFISH|\.bf\(", "alg": "Blowfish",
     "risk": "deprecated", "repl": "AES-256-GCM",
     "desc": "64-bit block, Sweet32 birthday attacks"},
]
RISK_ORDER = {"deprecated": 0, "quantum-vulnerable": 1, "acceptable": 2, "recommended": 3}


class CryptoMigrator:

    def analyze_file(self, filepath: str) -> List[CryptoUsage]:
        findings: List[CryptoUsage] = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (OSError, IOError):
            return findings
        for num, text in enumerate(lines, 1):
            for e in CRYPTO_PATTERNS:
                if re.search(e["pat"], text, re.IGNORECASE):
                    findings.append(CryptoUsage(file=filepath, line=num, algorithm=e["alg"],
                        risk_level=e["risk"], replacement=e["repl"], description=e["desc"]))
        return findings

    @staticmethod
    def classify_risk(algorithm: str) -> str:
        for e in CRYPTO_PATTERNS:
            if e["alg"].lower() == algorithm.lower(): return e["risk"]
        pq_safe = {"aes-256", "aes-256-gcm", "sha3-256", "sha3-384", "sha3-512",
                    "ml-kem", "kyber", "ml-dsa", "dilithium", "slh-dsa", "sphincs+"}
        return "recommended" if algorithm.lower() in pq_safe else "acceptable"

    @staticmethod
    def recommend_replacement(algorithm: str) -> str:
        for e in CRYPTO_PATTERNS:
            if e["alg"].lower() == algorithm.lower(): return e["repl"]
        return "No specific recommendation - algorithm may already be PQ-safe"

    def generate_report(self, directory: str) -> Dict[str, Any]:
        all_findings: List[CryptoUsage] = []; scanned = 0
        exts = {".py",".js",".ts",".java",".c",".cpp",".h",".go",".rs",".rb",".php",
                ".cs",".swift",".kt",".scala",".sh",".yaml",".yml",".json",".xml",
                ".toml",".cfg",".conf",".ini",".env",".dockerfile",".tf"}
        for root, _, files in os.walk(directory):
            for fname in files:
                if os.path.splitext(fname)[1].lower() not in exts: continue
                scanned += 1; all_findings.extend(self.analyze_file(os.path.join(root, fname)))
        all_findings.sort(key=lambda u: RISK_ORDER.get(u.risk_level, 99))
        summary: Dict[str, int] = {}
        for f in all_findings: summary[f.risk_level] = summary.get(f.risk_level, 0) + 1
        recs: List[str] = []
        if summary.get("deprecated", 0):
            recs.append("CRITICAL: Replace all deprecated algorithms (MD5, SHA-1, DES, 3DES, RC4) immediately.")
        if summary.get("quantum-vulnerable", 0):
            recs.append("HIGH: Migrate quantum-vulnerable algorithms (RSA, ECDSA, ECDH, DSA) to PQ alternatives.")
        if summary.get("acceptable", 0):
            recs.append("MEDIUM: Consider upgrading acceptable-but-suboptimal algorithms (AES-128 -> AES-256).")
        if not all_findings:
            recs.append("No vulnerable cryptographic patterns detected. Continue monitoring NIST PQC updates.")
        return {"scan_directory": directory, "files_scanned": scanned,
                "total_findings": len(all_findings), "risk_summary": summary,
                "findings": [asdict(f) for f in all_findings], "recommendations": recs}


# =============================================================================
#  SERIALIZATION  -  Key / Payload I/O
# =============================================================================

def save_keypair(keypair: Any, path: str) -> None:
    if isinstance(keypair, KEMKeypair):
        data = {"type": "kem", "algorithm": keypair.algorithm,
                "public_key": base64.b64encode(keypair.public_key).decode(),
                "secret_key": base64.b64encode(keypair.secret_key).decode(),
                "key_size": keypair.key_size}
    else:
        data = {"type": "sig", "algorithm": keypair.algorithm,
                "public_key": base64.b64encode(keypair.public_key).decode(),
                "secret_key": base64.b64encode(keypair.secret_key).decode()}
    with open(path, "w") as f: json.dump(data, f, indent=2)

def load_keypair(path: str) -> Any:
    with open(path, "r") as f: data = json.load(f)
    if data["type"] == "kem":
        return KEMKeypair(public_key=base64.b64decode(data["public_key"]),
            secret_key=base64.b64decode(data["secret_key"]),
            algorithm=data["algorithm"], key_size=data.get("key_size", 0))
    return SigKeypair(public_key=base64.b64decode(data["public_key"]),
        secret_key=base64.b64decode(data["secret_key"]), algorithm=data["algorithm"])

def save_encrypted(payload: EncryptedPayload, path: str) -> None:
    data = {"algorithm": payload.algorithm, "hybrid": payload.hybrid,
            "pq_ciphertext": base64.b64encode(payload.pq_ciphertext).decode(),
            "classical_ciphertext": (base64.b64encode(payload.classical_ciphertext).decode()
                                     if payload.classical_ciphertext else None),
            "nonce": base64.b64encode(payload.nonce).decode(),
            "tag": base64.b64encode(payload.tag).decode(),
            "ciphertext": base64.b64encode(payload.ciphertext).decode()}
    with open(path, "w") as f: json.dump(data, f, indent=2)

def load_encrypted(path: str) -> EncryptedPayload:
    with open(path, "r") as f: data = json.load(f)
    return EncryptedPayload(
        pq_ciphertext=base64.b64decode(data["pq_ciphertext"]),
        classical_ciphertext=(base64.b64decode(data["classical_ciphertext"])
                              if data.get("classical_ciphertext") else None),
        nonce=base64.b64decode(data["nonce"]), tag=base64.b64decode(data["tag"]),
        ciphertext=base64.b64decode(data["ciphertext"]),
        algorithm=data["algorithm"], hybrid=data.get("hybrid", False))


# =============================================================================
#  CLI HANDLERS
# =============================================================================

def _cli_keygen(args: argparse.Namespace) -> None:
    alg = args.algorithm; out = args.output or f"{alg}_keypair.json"
    if alg in KEM_ALGORITHMS:
        C.info(f"Generating ML-KEM keypair ({alg}) ...")
        kem = PQKeyExchange(); kp = kem.generate_keypair(alg)
        save_keypair(kp, out); C.ok(f"Keypair saved to {out}")
        C.info(f"  Public key: {len(kp.public_key)} bytes  |  Secret key: {len(kp.secret_key)} bytes")
    elif alg in SIG_ALGORITHMS:
        C.info(f"Generating signature keypair ({alg}) ...")
        sig = PQSignature(); kp = sig.generate_keypair(alg)
        save_keypair(kp, out); C.ok(f"Keypair saved to {out}")
        C.info(f"  Public key: {len(kp.public_key)} bytes  |  Secret key: {len(kp.secret_key)} bytes")
    else:
        C.fail(f"Unknown algorithm: {alg}")
        C.info(f"KEM: {list(KEM_ALGORITHMS.keys())}  |  Sig: {list(SIG_ALGORITHMS.keys())}")

def _cli_encrypt(args: argparse.Namespace) -> None:
    kp = load_keypair(args.key)
    if not isinstance(kp, KEMKeypair): C.fail("Encryption requires a KEM keypair"); return
    with open(args.input, "rb") as f: plaintext = f.read()
    C.info(f"Encrypting {len(plaintext)} bytes with {kp.algorithm} ...")
    payload = HybridEncryption(kp.algorithm).encrypt(plaintext, kp.public_key)
    out = args.output or args.input + ".enc"
    save_encrypted(payload, out); C.ok(f"Encrypted -> {out}")
    C.info(f"  Mode: {'hybrid' if payload.hybrid else 'PQ-only'}  |  Payload: {len(payload.ciphertext)} bytes")

def _cli_decrypt(args: argparse.Namespace) -> None:
    kp = load_keypair(args.key)
    if not isinstance(kp, KEMKeypair): C.fail("Decryption requires a KEM keypair"); return
    payload = load_encrypted(args.input)
    C.info(f"Decrypting with {payload.algorithm} ...")
    plaintext = HybridEncryption(payload.algorithm).decrypt(payload, kp.secret_key)
    out = args.output or args.input.replace(".enc", ".dec")
    with open(out, "wb") as f: f.write(plaintext)
    C.ok(f"Decrypted -> {out} ({len(plaintext)} bytes)")

def _cli_sign(args: argparse.Namespace) -> None:
    kp = load_keypair(args.key)
    if not isinstance(kp, SigKeypair): C.fail("Signing requires a signature keypair"); return
    with open(args.input, "rb") as f: message = f.read()
    C.info(f"Signing {len(message)} bytes with {kp.algorithm} ...")
    signer = PQSignature(); signature = signer.sign(kp.secret_key, message, kp.algorithm)
    sig_path = args.signature or args.input + ".sig"
    with open(sig_path, "w") as f:
        json.dump({"algorithm": kp.algorithm, "signature": base64.b64encode(signature).decode(),
                    "message_hash": hashlib.sha3_256(message).hexdigest()}, f, indent=2)
    C.ok(f"Signature saved to {sig_path} ({len(signature)} bytes)")

def _cli_verify(args: argparse.Namespace) -> None:
    kp = load_keypair(args.key)
    if not isinstance(kp, SigKeypair): C.fail("Verification requires a signature keypair"); return
    with open(args.input, "rb") as f: message = f.read()
    with open(args.signature, "r") as f: sig_data = json.load(f)
    signature = base64.b64decode(sig_data["signature"])
    alg = sig_data.get("algorithm", kp.algorithm)
    C.info(f"Verifying signature ({alg}) ...")
    valid = PQSignature().verify(kp.public_key, message, signature, alg)
    C.ok("Signature is VALID") if valid else C.fail("Signature is INVALID")

def _cli_hash(args: argparse.Namespace) -> None:
    C.info(f"Hashing {args.input} with {args.algorithm} ...")
    digest = SHA3Hasher.file_hash(args.input, args.algorithm)
    C.ok(f"{args.algorithm}: {digest.hex()}")
    C.info(f"  Length: {len(digest)} bytes ({len(digest)*8} bits)")

def _cli_migrate(args: argparse.Namespace) -> None:
    C.info(f"Scanning {args.directory} for cryptographic usage ...")
    report = CryptoMigrator().generate_report(args.directory)
    C.ok(f"Scanned {report['files_scanned']} files, found {report['total_findings']} findings")
    rc = {"deprecated": C.RED, "quantum-vulnerable": C.YLW, "acceptable": C.BLU, "recommended": C.GRN}
    for risk, cnt in report["risk_summary"].items():
        C.p(f"    {rc.get(risk, C.WHT)}{risk:>20s}{C.R}: {cnt}")
    C.p("")
    for rec in report["recommendations"]: C.warn(rec)
    if report["findings"]:
        C.p(f"\n  {C.BLD}Top findings:{C.R}")
        for fd in report["findings"][:15]:
            clr = rc.get(fd["risk_level"], C.WHT)
            C.p(f"    {clr}[{fd['risk_level']}]{C.R} {fd['file']}:{fd['line']} "
                f"- {fd['algorithm']} -> {fd['replacement']}")
    if args.output:
        with open(args.output, "w") as f: json.dump(report, f, indent=2)
        C.ok(f"Full report saved to {args.output}")


# =============================================================================
#  ARGPARSE CLI BUILDER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quantum_crypto",
        description="Post-Quantum Cryptography Toolkit - FLLC",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", help="Available commands")

    kg = sub.add_parser("keygen", help="Generate post-quantum keypair")
    kg.add_argument("--algorithm", "-a", default="kyber768")
    kg.add_argument("--output", "-o")

    enc = sub.add_parser("encrypt", help="Encrypt a file with PQ crypto")
    enc.add_argument("--input", "-i", required=True); enc.add_argument("--output", "-o")
    enc.add_argument("--key", "-k", required=True); enc.add_argument("--hybrid", action="store_true")

    dec = sub.add_parser("decrypt", help="Decrypt a file with PQ crypto")
    dec.add_argument("--input", "-i", required=True); dec.add_argument("--output", "-o")
    dec.add_argument("--key", "-k", required=True)

    sg = sub.add_parser("sign", help="Sign a file with PQ signature")
    sg.add_argument("--input", "-i", required=True); sg.add_argument("--key", "-k", required=True)
    sg.add_argument("--signature", "-s")

    vf = sub.add_parser("verify", help="Verify a PQ signature")
    vf.add_argument("--input", "-i", required=True); vf.add_argument("--key", "-k", required=True)
    vf.add_argument("--signature", "-s", required=True)

    hs = sub.add_parser("hash", help="Hash a file with SHA-3")
    hs.add_argument("--input", "-i", required=True)
    hs.add_argument("--algorithm", "-a", default="sha3_256")

    mg = sub.add_parser("migrate", help="Scan for quantum-vulnerable crypto")
    mg.add_argument("--directory", "-d", required=True); mg.add_argument("--output", "-o")
    return p


# =============================================================================
#  ENTRY POINT
# =============================================================================

def main() -> None:
    C.banner("FU PERSON :: POST-QUANTUM CRYPTOGRAPHY TOOLKIT v1.0")
    C.p(f"  {C.DIM}oqs-python:    {'available' if HAS_OQS else 'not installed (demo fallback)'}")
    C.p(f"  PyCryptodome: {'available' if HAS_PYCRYPTODOME else 'not installed (pure-Python AES)'}")
    C.p(f"  cryptography: {'available' if HAS_CRYPTOGRAPHY else 'not installed (hybrid disabled)'}{C.R}\n")
    parser = build_parser(); args = parser.parse_args()
    dispatch: Dict[str, Callable[[argparse.Namespace], None]] = {
        "keygen": _cli_keygen, "encrypt": _cli_encrypt, "decrypt": _cli_decrypt,
        "sign": _cli_sign, "verify": _cli_verify, "hash": _cli_hash, "migrate": _cli_migrate}
    handler = dispatch.get(args.command)
    if handler: handler(args)
    else: parser.print_help()


if __name__ == "__main__":
    main()
