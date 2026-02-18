#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: CRYPTOGRAPHIC VULNERABILITY AUDITOR v1.0
  TLS/SSL Analysis | Weak Crypto Detection | Quantum Threat Assessment
  Certificate Monitoring | Migration Planning
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  Unauthorized security scanning and network probing is ILLEGAL.
  Only use this tool against:
    1. Your own infrastructure
    2. Client systems with explicit written authorization
    3. Training environments you control

  FLLC
  Government-Cleared Security Operations
===============================================================================
"""

import os, sys, re, ssl, json, time, socket, argparse, hashlib
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _cg_hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import requests; HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=False)
except ImportError:
    pass


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
    def info(msg: str): C.p(f"  {C.CYN}[*]{C.R} {msg}")
    @staticmethod
    def warn(msg: str): C.p(f"  {C.YLW}[!]{C.R} {msg}")
    @staticmethod
    def fail(msg: str): C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def banner(title: str):
        w = 70
        C.p(f"\n  {C.MAG}{C.BLD}{'=' * w}")
        C.p(f"  {'':>2}{title}")
        C.p(f"  {'=' * w}{C.R}\n")


# =============================================================================
#  DATA CLASSES
# =============================================================================

@dataclass
class TLSResult:
    host: str; port: int
    protocols_supported: List[str] = field(default_factory=list)
    cipher_suites: List[Dict[str, Any]] = field(default_factory=list)
    cert_info: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    hsts_enabled: bool = False; hsts_max_age: int = 0; grade: str = "F"

@dataclass
class CryptoFinding:
    file: str; line: int; column: int; pattern: str
    algorithm: str; risk_level: str; description: str; recommendation: str

@dataclass
class QuantumAssessment:
    algorithm: str; quantum_vulnerable: bool; threat: str
    post_quantum_bits: int; migration_priority: str; recommended_replacement: str

@dataclass
class CertStatus:
    host: str; port: int; subject: str; issuer: str
    not_before: str; not_after: str; days_remaining: int; status: str

@dataclass
class MigrationTask:
    priority: str; algorithm: str; affected_files: List[str]
    description: str; replacement: str; estimated_loc: int; requires_tests: bool
    depends_on: List[str] = field(default_factory=list)


# =============================================================================
#  PROTOCOL / CIPHER CONSTANTS
# =============================================================================

def _build_proto_map() -> Dict[str, Any]:
    mapping: Dict[str, Any] = {}
    for name, attr in [("SSLv2", "PROTOCOL_SSLv2"), ("SSLv3", "PROTOCOL_SSLv3"),
                       ("TLSv1.0", "PROTOCOL_TLSv1"), ("TLSv1.1", "PROTOCOL_TLSv1_1"),
                       ("TLSv1.2", "PROTOCOL_TLSv1_2")]:
        if hasattr(ssl, attr):
            mapping[name] = getattr(ssl, attr)
    return mapping

_PROTO_MAP = _build_proto_map()
WEAK_CIPHERS_RE = re.compile(r"(RC4|DES(?!3)|3DES|DES-CBC3|EXP|EXPORT|NULL|anon|MD5)", re.I)
WEAK_SIG_ALGOS = {"md5WithRSAEncryption", "sha1WithRSAEncryption", "md5", "sha1"}


# =============================================================================
#  TLS SCANNER
# =============================================================================

class TLSScanner:
    """Full TLS/SSL configuration analysis for a remote host."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int = 443) -> TLSResult:
        result = TLSResult(host=host, port=port)
        C.banner(f"TLS SCAN  ::  {host}:{port}")
        self._probe_protocols(result)
        self._enumerate_ciphers(result)
        self._analyze_certificate(result)
        self._check_hsts(result)
        self._compute_grade(result)
        return result

    def _probe_protocols(self, r: TLSResult) -> None:
        C.info("Probing supported protocols ...")
        for name, proto in _PROTO_MAP.items():
            if self._try_protocol(r.host, r.port, proto):
                r.protocols_supported.append(name)
                C.ok(f"{name} supported")
            else:
                C.p(f"  {C.DIM}  [-] {name} not supported{C.R}")
        if self._try_tls13(r.host, r.port):
            r.protocols_supported.append("TLSv1.3")
            C.ok("TLSv1.3 supported")
        else:
            C.p(f"  {C.DIM}  [-] TLSv1.3 not supported{C.R}")
        for p in r.protocols_supported:
            if p in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}:
                r.vulnerabilities.append(f"Deprecated protocol enabled: {p}")

    def _try_protocol(self, host: str, port: int, protocol: int) -> bool:
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:COMPLEMENTOFALL")
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake(); return True
        except (ssl.SSLError, OSError, ConnectionError):
            return False

    def _try_tls13(self, host: str, port: int) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake(); return ssock.version() == "TLSv1.3"
        except (ssl.SSLError, OSError, AttributeError, ConnectionError):
            return False

    def _enumerate_ciphers(self, r: TLSResult) -> None:
        C.info("Enumerating cipher suites ...")
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:COMPLEMENTOFALL")
            with socket.create_connection((r.host, r.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=r.host) as ssock:
                    ssock.do_handshake()
                    for ci in ssock.context.get_ciphers():
                        entry = {"name": ci.get("name", ""), "protocol": ci.get("protocol", ""),
                                 "bits": ci.get("alg_bits", 0), "description": ci.get("description", "")}
                        r.cipher_suites.append(entry)
                        if WEAK_CIPHERS_RE.search(entry["name"]):
                            vuln = f"Weak cipher accepted: {entry['name']}"
                            if vuln not in r.vulnerabilities:
                                r.vulnerabilities.append(vuln)
        except (ssl.SSLError, OSError, ConnectionError) as exc:
            C.warn(f"Cipher enumeration error: {exc}")
        C.ok(f"Found {len(r.cipher_suites)} cipher suites")
        weak = sum(1 for c in r.cipher_suites if WEAK_CIPHERS_RE.search(c["name"]))
        if weak:
            C.warn(f"{weak} weak cipher(s) detected")

    def _analyze_certificate(self, r: TLSResult) -> None:
        C.info("Analyzing certificate ...")
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((r.host, r.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=r.host) as ssock:
                    ssock.do_handshake()
                    der = ssock.getpeercert(binary_form=True)
                    pem_info = ssock.getpeercert(binary_form=False)
            ci: Dict[str, Any] = {}
            if pem_info:
                subj = dict(x[0] for x in pem_info.get("subject", ()))
                issr = dict(x[0] for x in pem_info.get("issuer", ()))
                ci["subject"] = subj.get("commonName", "")
                ci["issuer"] = issr.get("organizationName", issr.get("commonName", ""))
                ci["not_before"] = pem_info.get("notBefore", "")
                ci["not_after"] = pem_info.get("notAfter", "")
                ci["serial"] = pem_info.get("serialNumber", "")
                ci["san"] = [f"{t}:{v}" for t, v in pem_info.get("subjectAltName", ())]
                na = _parse_ssl_date(ci["not_after"])
                if na:
                    days_left = (na - datetime.now(timezone.utc)).days
                    ci["days_until_expiry"] = days_left
                    if days_left < 0:
                        r.vulnerabilities.append("Certificate EXPIRED")
                    elif days_left < 30:
                        r.vulnerabilities.append(f"Certificate expires in {days_left} days")
            if der and HAS_CRYPTOGRAPHY:
                self._deep_cert_analysis(der, ci, r)
            r.cert_info = ci
            C.ok(f"Subject: {ci.get('subject', 'N/A')}")
            C.ok(f"Issuer:  {ci.get('issuer', 'N/A')}")
            C.ok(f"Expires: {ci.get('not_after', 'N/A')} ({ci.get('days_until_expiry', '?')} days)")
        except (ssl.SSLError, OSError, ConnectionError) as exc:
            C.warn(f"Certificate retrieval failed: {exc}")

    def _deep_cert_analysis(self, der: bytes, ci: Dict[str, Any], r: TLSResult) -> None:
        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        key_size = getattr(pub, "key_size", 0)
        key_type = type(pub).__name__.replace("_", " ")
        sig_algo = (cert.signature_algorithm_oid._name
                    if hasattr(cert.signature_algorithm_oid, "_name")
                    else str(cert.signature_algorithm_oid.dotted_string))
        ci["key_type"] = key_type; ci["key_size"] = key_size; ci["signature_algorithm"] = sig_algo
        try:
            cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            ci["has_aia"] = True
        except x509.ExtensionNotFound:
            ci["has_aia"] = False
        try:
            cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
            ci["certificate_transparency"] = True; C.ok("Certificate Transparency SCTs present")
        except (x509.ExtensionNotFound, Exception):
            ci["certificate_transparency"] = False
            r.vulnerabilities.append("No Certificate Transparency SCTs")
        if key_size and key_size < 2048:
            r.vulnerabilities.append(f"Weak key size: {key_size}-bit {key_type}")
        if sig_algo.lower() in WEAK_SIG_ALGOS or "md5" in sig_algo.lower():
            r.vulnerabilities.append(f"Weak signature algorithm: {sig_algo}")

    def _check_hsts(self, r: TLSResult) -> None:
        C.info("Checking HSTS header ...")
        try:
            if HAS_REQUESTS:
                resp = requests.head(f"https://{r.host}:{r.port}", timeout=self.timeout,
                                     verify=False, allow_redirects=True)
                hsts = resp.headers.get("Strict-Transport-Security", "")
            else:
                import http.client
                conn = http.client.HTTPSConnection(r.host, r.port, timeout=self.timeout,
                                                   context=ssl._create_unverified_context())
                conn.request("HEAD", "/"); resp = conn.getresponse()
                hsts = resp.getheader("Strict-Transport-Security", "") or ""; conn.close()
            if hsts:
                r.hsts_enabled = True
                m = re.search(r"max-age=(\d+)", hsts)
                if m: r.hsts_max_age = int(m.group(1))
                C.ok(f"HSTS enabled (max-age={r.hsts_max_age})")
            else:
                r.vulnerabilities.append("HSTS not enabled"); C.warn("HSTS not enabled")
        except Exception as exc:
            C.warn(f"HSTS check failed: {exc}")

    def _compute_grade(self, r: TLSResult) -> None:
        score = 100
        for p in r.protocols_supported:
            if p in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}: score -= 20
        score -= sum(5 for c in r.cipher_suites if WEAK_CIPHERS_RE.search(c["name"]))
        score -= len(r.vulnerabilities) * 8
        if not r.hsts_enabled: score -= 5
        ks = r.cert_info.get("key_size", 4096)
        if ks < 2048: score -= 15
        elif ks < 4096: score -= 3
        r.grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
        clr = {"A": C.GRN, "B": C.GRN, "C": C.YLW, "D": C.YLW, "F": C.RED}.get(r.grade, C.WHT)
        C.p(f"\n  {C.BLD}Grade: {clr}{r.grade}{C.R}  (score {max(score, 0)}/100)")


# =============================================================================
#  WEAK CRYPTO DETECTOR
# =============================================================================

_CRYPTO_PATTERNS: List[Dict[str, str]] = [
    {"p": r"\bhashlib\.md5\b",             "a": "MD5",      "r": "high",     "d": "MD5 hash usage",                "rc": "Replace with SHA-256 or SHA-3"},
    {"p": r"\bMD5\(\b",                    "a": "MD5",      "r": "high",     "d": "MD5 constructor",               "rc": "Replace with SHA-256 or SHA-3"},
    {"p": r"Digest::MD5",                  "a": "MD5",      "r": "high",     "d": "Ruby MD5 digest",               "rc": "Replace with Digest::SHA256"},
    {"p": r"\bmd5\(",                      "a": "MD5",      "r": "high",     "d": "MD5 function call",             "rc": "Replace with SHA-256 or SHA-3"},
    {"p": r"createHash\(['\"]md5['\"]\)",  "a": "MD5",      "r": "high",     "d": "Node.js MD5 hash",             "rc": "Use createHash('sha256')"},
    {"p": r"\bhashlib\.sha1\b",            "a": "SHA-1",    "r": "high",     "d": "SHA-1 hash usage",              "rc": "Replace with SHA-256 or SHA-3"},
    {"p": r"\bSHA1\(\b",                   "a": "SHA-1",    "r": "high",     "d": "SHA-1 constructor",             "rc": "Replace with SHA-256 or SHA-3"},
    {"p": r"\bsha1\(",                     "a": "SHA-1",    "r": "high",     "d": "SHA-1 function call",           "rc": "Replace with SHA-256 or SHA-3"},
    {"p": r"createHash\(['\"]sha1['\"]\)", "a": "SHA-1",    "r": "high",     "d": "Node.js SHA-1 hash",           "rc": "Use createHash('sha256')"},
    {"p": r"\bDES\.new\b",                 "a": "DES",      "r": "critical", "d": "DES encryption (56-bit key)",   "rc": "Replace with AES-256-GCM"},
    {"p": r"\bDES\(",                      "a": "DES",      "r": "critical", "d": "DES constructor",               "rc": "Replace with AES-256-GCM"},
    {"p": r"\bdes-cbc\b",                  "a": "DES",      "r": "critical", "d": "DES-CBC mode",                  "rc": "Replace with AES-256-GCM"},
    {"p": r"\bdes-ede\b",                  "a": "3DES",     "r": "high",     "d": "3DES / Triple-DES",             "rc": "Replace with AES-256-GCM"},
    {"p": r"\bDES3\.new\b",               "a": "3DES",     "r": "high",     "d": "PyCryptodome Triple-DES",       "rc": "Replace with AES-256-GCM"},
    {"p": r"\bTriple_DES\b",              "a": "3DES",     "r": "high",     "d": "Triple-DES reference",          "rc": "Replace with AES-256-GCM"},
    {"p": r"\b3des\b",                     "a": "3DES",     "r": "high",     "d": "3DES reference",                "rc": "Replace with AES-256-GCM"},
    {"p": r"\bdes-ede3\b",                "a": "3DES",     "r": "high",     "d": "3DES EDE3 mode",                "rc": "Replace with AES-256-GCM"},
    {"p": r"\bARC4\.new\b",               "a": "RC4",      "r": "critical", "d": "RC4 stream cipher",             "rc": "Replace with ChaCha20-Poly1305 or AES-GCM"},
    {"p": r"\bRC4\(",                      "a": "RC4",      "r": "critical", "d": "RC4 constructor",               "rc": "Replace with ChaCha20-Poly1305 or AES-GCM"},
    {"p": r"\brc4\b",                      "a": "RC4",      "r": "critical", "d": "RC4 reference",                 "rc": "Replace with ChaCha20-Poly1305 or AES-GCM"},
    {"p": r"rsa\.generate\(\s*1024\b",     "a": "RSA-1024", "r": "critical", "d": "RSA with 1024-bit key",         "rc": "Use RSA-4096 or Ed25519"},
    {"p": r"RSA\(\s*1024\b",              "a": "RSA-1024", "r": "critical", "d": "RSA with 1024-bit key",         "rc": "Use RSA-4096 or Ed25519"},
    {"p": r"key_size\s*=\s*1024\b",       "a": "RSA-1024", "r": "critical", "d": "1024-bit key generation",       "rc": "Use minimum 2048, prefer 4096"},
    {"p": r"\baes-128\b",                  "a": "AES-128",  "r": "medium",   "d": "AES-128 (post-quantum concern)","rc": "Upgrade to AES-256"},
    {"p": r"MODE_ECB\b",                  "a": "ECB",      "r": "critical", "d": "ECB mode (no diffusion)",       "rc": "Use GCM, CTR, or CBC with HMAC"},
    {"p": r"\baes-ecb\b",                 "a": "ECB",      "r": "critical", "d": "AES-ECB mode",                  "rc": "Use AES-GCM or AES-CTR"},
    {"p": r"\becb\(",                      "a": "ECB",      "r": "critical", "d": "ECB mode function",             "rc": "Use GCM, CTR, or CBC with HMAC"},
    {"p": r"\biv\s*=\s*b['\"]",           "a": "Hardcoded-IV",  "r": "high",     "d": "Hardcoded initialization vector", "rc": "Generate IV with os.urandom()"},
    {"p": r"\bkey\s*=\s*b['\"]",          "a": "Hardcoded-Key", "r": "critical", "d": "Hardcoded encryption key",       "rc": "Use a key management system or KDF"},
]

_COMPILED_PATTERNS = [(re.compile(m["p"], re.IGNORECASE), m) for m in _CRYPTO_PATTERNS]

DEFAULT_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".go",
    ".rb", ".rs", ".cs", ".php", ".swift", ".kt", ".scala",
    ".sh", ".yaml", ".yml", ".json", ".xml", ".conf", ".cfg",
}


class WeakCryptoDetector:
    """Recursively scan source code for deprecated or weak cryptographic usage."""

    def scan_file(self, filepath: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []
        try:
            text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return findings
        for line_no, line in enumerate(text.splitlines(), start=1):
            for compiled_re, meta in _COMPILED_PATTERNS:
                match = compiled_re.search(line)
                if match:
                    findings.append(CryptoFinding(
                        file=filepath, line=line_no, column=match.start() + 1,
                        pattern=match.group(0), algorithm=meta["a"],
                        risk_level=meta["r"], description=meta["d"],
                        recommendation=meta["rc"]))
        return findings

    def scan_directory(self, directory: str, extensions: Optional[Set[str]] = None) -> List[CryptoFinding]:
        exts = extensions or DEFAULT_EXTENSIONS
        root = Path(directory)
        if not root.is_dir():
            C.fail(f"Directory not found: {directory}"); return []
        all_findings: List[CryptoFinding] = []; files_scanned = 0
        C.banner(f"WEAK CRYPTO SCAN  ::  {directory}")
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv"}
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if skip_dirs & set(path.parts):
                continue
            all_findings.extend(self.scan_file(str(path))); files_scanned += 1

        by_risk: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            by_risk[f.risk_level] = by_risk.get(f.risk_level, 0) + 1
        C.ok(f"Scanned {files_scanned} files, {len(all_findings)} findings")
        if by_risk["critical"]: C.fail(f"  CRITICAL: {by_risk['critical']}")
        if by_risk["high"]:     C.warn(f"  HIGH:     {by_risk['high']}")
        if by_risk["medium"]:   C.info(f"  MEDIUM:   {by_risk['medium']}")
        if by_risk["low"]:      C.p(f"  {C.DIM}  LOW:      {by_risk['low']}{C.R}")
        for f in all_findings:
            clr = {"critical": C.RED, "high": C.YLW, "medium": C.BLU, "low": C.DIM}.get(f.risk_level, C.WHT)
            C.p(f"  {clr}[{f.risk_level.upper():>8}]{C.R} {f.file}:{f.line}:{f.column} - {f.description} ({f.pattern})")
        return all_findings


# =============================================================================
#  QUANTUM VULNERABILITY ASSESSOR
# =============================================================================

_SHOR_VULNERABLE = {"RSA", "RSA-1024", "RSA-2048", "RSA-4096", "ECDSA", "ECDH",
                    "DSA", "DH", "Diffie-Hellman", "Ed25519", "Ed448", "X25519", "X448"}
_GROVER_AFFECTED: Dict[str, Tuple[int, int]] = {
    "AES-128": (128, 64), "AES-192": (192, 96), "AES-256": (256, 128),
    "3DES": (112, 56), "DES": (56, 28),
}
_QUANTUM_SAFE: Dict[str, int] = {
    "AES-256": 128, "SHA-256": 128, "SHA-3": 128, "SHA-384": 192,
    "SHA-512": 256, "ChaCha20-Poly1305": 128, "HMAC-SHA256": 128,
}
_SHOR_REPLACEMENTS: Dict[str, str] = {
    "RSA": "ML-KEM (Kyber) + ML-DSA (Dilithium)", "RSA-1024": "ML-KEM (Kyber) + ML-DSA (Dilithium)",
    "RSA-2048": "ML-KEM (Kyber) + ML-DSA (Dilithium)", "RSA-4096": "ML-KEM (Kyber) + ML-DSA (Dilithium)",
    "ECDSA": "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)", "ECDH": "ML-KEM (Kyber)",
    "DSA": "ML-DSA (Dilithium)", "DH": "ML-KEM (Kyber)",
    "Ed25519": "ML-DSA (Dilithium)", "Ed448": "ML-DSA (Dilithium)",
    "X25519": "ML-KEM (Kyber)", "X448": "ML-KEM (Kyber)",
}


class QuantumVulnAssessor:
    """Classify cryptographic findings against quantum computing threats."""

    def assess(self, findings: List[CryptoFinding]) -> List[QuantumAssessment]:
        assessments: List[QuantumAssessment] = []; seen: Set[str] = set()
        C.banner("QUANTUM THREAT ASSESSMENT")
        for f in findings:
            algo = f.algorithm
            if algo in seen: continue
            seen.add(algo)
            qa = self._assess_algorithm(algo); assessments.append(qa)
            if qa.quantum_vulnerable:
                clr = C.RED if qa.migration_priority in ("immediate", "high") else C.YLW
                C.p(f"  {clr}[VULN]{C.R} {algo}: {qa.threat}'s algorithm -> "
                    f"{qa.post_quantum_bits}-bit post-quantum (migrate: {qa.migration_priority})")
            else:
                C.ok(f"{algo}: quantum-safe ({qa.post_quantum_bits}-bit post-quantum)")
        return assessments

    def _assess_algorithm(self, algo: str) -> QuantumAssessment:
        base = algo.split("-")[0].upper() if "-" in algo else algo.upper()
        if algo in _SHOR_VULNERABLE or base in ("RSA", "EC", "DSA", "DH", "ECDSA", "ECDH"):
            return QuantumAssessment(algo, True, "Shor", 0, "immediate",
                                    _SHOR_REPLACEMENTS.get(algo, "ML-KEM (Kyber) + ML-DSA (Dilithium)"))
        if algo in _GROVER_AFFECTED:
            _, pq = _GROVER_AFFECTED[algo]
            pri = "immediate" if pq < 64 else ("high" if pq < 100 else "low")
            return QuantumAssessment(algo, pq < 128, "Grover", pq, pri,
                                    "AES-256" if "AES" in algo else "AES-256-GCM")
        if algo in _QUANTUM_SAFE:
            return QuantumAssessment(algo, False, "none", _QUANTUM_SAFE[algo], "low",
                                    "Already quantum-resistant")
        if algo in ("MD5", "SHA-1"):
            return QuantumAssessment(algo, True, "Grover", 0, "immediate", "SHA-3-256 or SHA-256")
        if algo in ("RC4", "DES"):
            return QuantumAssessment(algo, True, "Grover", 0, "immediate",
                                    "AES-256-GCM or ChaCha20-Poly1305")
        if algo in ("ECB", "Hardcoded-IV", "Hardcoded-Key"):
            return QuantumAssessment(algo, False, "none", 0, "immediate",
                                    "Use GCM/CTR mode with proper key management")
        return QuantumAssessment(algo, False, "unknown", 0, "medium", "Review manually")


# =============================================================================
#  CERTIFICATE MONITOR
# =============================================================================

class CertificateMonitor:
    """Monitor certificate lifecycle and expiration across hosts."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check_expiry(self, host: str, port: int = 443) -> CertStatus:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake(); info = ssock.getpeercert(binary_form=False)
            if not info:
                return CertStatus(host, port, "N/A", "N/A", "N/A", "N/A", -1, "critical")
            subj = dict(x[0] for x in info.get("subject", ()))
            issr = dict(x[0] for x in info.get("issuer", ()))
            nb_str, na_str = info.get("notBefore", ""), info.get("notAfter", "")
            na_dt = _parse_ssl_date(na_str)
            days_left = (na_dt - datetime.now(timezone.utc)).days if na_dt else -9999
            status = "critical" if days_left < 0 else "high" if days_left < 30 else "medium" if days_left < 90 else "ok"
            return CertStatus(host, port, subj.get("commonName", ""),
                              issr.get("organizationName", issr.get("commonName", "")),
                              nb_str, na_str, days_left, status)
        except (ssl.SSLError, OSError, ConnectionError) as exc:
            return CertStatus(host, port, "ERROR", str(exc), "N/A", "N/A", -1, "critical")

    def bulk_check(self, hosts: List[Tuple[str, int]]) -> List[CertStatus]:
        results: List[CertStatus] = []
        C.banner("CERTIFICATE EXPIRY MONITOR")
        with ThreadPoolExecutor(max_workers=min(10, max(len(hosts), 1))) as pool:
            futs = {pool.submit(self.check_expiry, h, p): (h, p) for h, p in hosts}
            for fut in as_completed(futs):
                cs = fut.result(); results.append(cs)
                clr = {"critical": C.RED, "high": C.YLW, "medium": C.BLU, "ok": C.GRN}.get(cs.status, C.WHT)
                C.p(f"  {clr}[{cs.status.upper():>8}]{C.R} {cs.host}:{cs.port} "
                    f"- {cs.subject} - {cs.days_remaining}d remaining")
        results.sort(key=lambda x: x.days_remaining); return results


# =============================================================================
#  MIGRATION PLANNER
# =============================================================================

_EFFORT: Dict[str, Tuple[int, bool]] = {
    "MD5": (5, True), "SHA-1": (5, True), "DES": (20, True), "3DES": (20, True),
    "RC4": (15, True), "RSA-1024": (40, True), "AES-128": (10, True),
    "ECB": (25, True), "Hardcoded-IV": (10, True), "Hardcoded-Key": (30, True),
}
_DEPS: Dict[str, List[str]] = {
    "Hardcoded-Key": ["Hardcoded-IV"], "AES-128": ["ECB"],
}


class MigrationPlanner:
    """Generate a prioritized cryptographic migration roadmap."""

    def plan(self, findings: List[CryptoFinding], assessments: List[QuantumAssessment]) -> List[MigrationTask]:
        C.banner("CRYPTO MIGRATION PLAN")
        amap: Dict[str, QuantumAssessment] = {a.algorithm: a for a in assessments}
        algo_files: Dict[str, Set[str]] = {}; algo_counts: Dict[str, int] = {}
        for f in findings:
            algo_files.setdefault(f.algorithm, set()).add(f.file)
            algo_counts[f.algorithm] = algo_counts.get(f.algorithm, 0) + 1

        tasks: List[MigrationTask] = []
        for algo, files in algo_files.items():
            qa = amap.get(algo)
            loc, tests = _EFFORT.get(algo, (15, True))
            total = loc * algo_counts.get(algo, 1)
            repl = qa.recommended_replacement if qa else "Review manually"
            pri = qa.migration_priority if qa else self._risk_pri(
                next((f.risk_level for f in findings if f.algorithm == algo), "medium"))
            tasks.append(MigrationTask(pri, algo, sorted(files), f"Replace {algo} with {repl}",
                                       repl, total, tests, _DEPS.get(algo, [])))

        order = {"immediate": 0, "high": 1, "medium": 2, "low": 3}
        tasks.sort(key=lambda t: order.get(t.priority, 99))
        self._print_plan(tasks); return tasks

    def _risk_pri(self, risk: str) -> str:
        return {"critical": "immediate", "high": "high", "medium": "medium", "low": "low"}.get(risk, "medium")

    def _print_plan(self, tasks: List[MigrationTask]) -> None:
        cur = ""
        for i, t in enumerate(tasks, 1):
            if t.priority != cur:
                cur = t.priority
                clr = {"immediate": C.RED, "high": C.YLW, "medium": C.BLU, "low": C.DIM}.get(cur, C.WHT)
                C.p(f"\n  {clr}{C.BLD}=== {cur.upper()} PRIORITY ==={C.R}")
            C.p(f"  {C.BLD}Task {i}:{C.R} {t.description}")
            C.p(f"    Files: {len(t.affected_files)}  |  LOC: ~{t.estimated_loc}  |  Tests: {'Yes' if t.requires_tests else 'No'}")
            if t.depends_on: C.p(f"    Depends on: {', '.join(t.depends_on)}")
            for fp in t.affected_files[:5]:
                C.p(f"      {C.DIM}{fp}{C.R}")
            if len(t.affected_files) > 5:
                C.p(f"      {C.DIM}... and {len(t.affected_files) - 5} more{C.R}")

    def to_json(self, tasks: List[MigrationTask]) -> str:
        return json.dumps([asdict(t) for t in tasks], indent=2, default=str)

    def to_text(self, tasks: List[MigrationTask]) -> str:
        lines: List[str] = ["CRYPTOGRAPHIC MIGRATION PLAN", "=" * 50, ""]
        cur = ""
        for i, t in enumerate(tasks, 1):
            if t.priority != cur:
                cur = t.priority; lines.append(f"\n--- {cur.upper()} PRIORITY ---\n")
            lines.append(f"Task {i}: {t.description}")
            lines.append(f"  Algorithm:      {t.algorithm}")
            lines.append(f"  Replacement:    {t.replacement}")
            lines.append(f"  Files affected: {len(t.affected_files)}")
            lines.append(f"  Estimated LOC:  ~{t.estimated_loc}")
            lines.append(f"  Tests required: {'Yes' if t.requires_tests else 'No'}")
            if t.depends_on: lines.append(f"  Depends on:     {', '.join(t.depends_on)}")
            for fp in t.affected_files: lines.append(f"    - {fp}")
            lines.append("")
        return "\n".join(lines)


# =============================================================================
#  HELPERS
# =============================================================================

def _parse_ssl_date(date_str: str) -> Optional[datetime]:
    if not date_str: return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z",
                "%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    return None


def _results_summary(**kw: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if kw.get("tls"):       out["tls"] = asdict(kw["tls"])
    if kw.get("findings"):  out["findings"] = [asdict(f) for f in kw["findings"]]
    if kw.get("assessments"): out["quantum"] = [asdict(a) for a in kw["assessments"]]
    if kw.get("certs"):     out["certificates"] = [asdict(c) for c in kw["certs"]]
    if kw.get("tasks"):     out["migration_plan"] = [asdict(t) for t in kw["tasks"]]
    return out


# =============================================================================
#  CLI
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto_audit",
        description="FU-PERSON Cryptographic Vulnerability Auditor (FLLC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s tls --host example.com --port 443\n"
               "  %(prog)s scan --directory ./src --extensions .py,.js\n"
               "  %(prog)s quantum --directory ./src\n"
               "  %(prog)s certs --hosts example.com,google.com\n"
               "  %(prog)s plan --directory ./src --output report.json\n")
    sub = parser.add_subparsers(dest="command", help="subcommand")

    tp = sub.add_parser("tls", help="TLS/SSL configuration analysis")
    tp.add_argument("--host", required=True, help="Target hostname")
    tp.add_argument("--port", type=int, default=443, help="Target port")
    tp.add_argument("--json", action="store_true", help="Output as JSON")

    sp = sub.add_parser("scan", help="Scan source code for weak crypto")
    sp.add_argument("--directory", required=True, help="Directory to scan")
    sp.add_argument("--extensions", default=None, help="Comma-separated extensions")
    sp.add_argument("--json", action="store_true", help="Output as JSON")

    qp = sub.add_parser("quantum", help="Quantum threat assessment")
    qp.add_argument("--directory", required=True, help="Directory to scan")
    qp.add_argument("--extensions", default=None, help="Comma-separated extensions")
    qp.add_argument("--json", action="store_true", help="Output as JSON")

    cp = sub.add_parser("certs", help="Certificate expiry monitoring")
    cp.add_argument("--hosts", required=True, help="Comma-separated host[:port]")
    cp.add_argument("--json", action="store_true", help="Output as JSON")

    pp = sub.add_parser("plan", help="Migration planning")
    pp.add_argument("--directory", required=True, help="Directory to scan")
    pp.add_argument("--extensions", default=None, help="Comma-separated extensions")
    pp.add_argument("--output", default=None, help="Output file (JSON/text by extension)")
    return parser


def _parse_exts(s: Optional[str]) -> Optional[Set[str]]:
    if not s: return None
    return {e.strip() if e.strip().startswith(".") else "." + e.strip() for e in s.split(",")}


def _parse_hosts(s: str) -> List[Tuple[str, int]]:
    hosts: List[Tuple[str, int]] = []
    for entry in s.split(","):
        entry = entry.strip()
        if not entry: continue
        if ":" in entry:
            parts = entry.rsplit(":", 1)
            try: hosts.append((parts[0], int(parts[1])))
            except ValueError: hosts.append((entry, 443))
        else:
            hosts.append((entry, 443))
    return hosts


def main() -> None:
    parser = _build_parser(); args = parser.parse_args()
    if not args.command:
        parser.print_help(); sys.exit(1)
    C.p(f"\n  {C.MAG}{C.BLD}FU-PERSON Cryptographic Vulnerability Auditor{C.R}")
    C.p(f"  {C.DIM}FLLC - Government-Cleared Security Operations{C.R}\n")

    if args.command == "tls":
        res = TLSScanner().scan(args.host, args.port)
        if args.json: print(json.dumps(asdict(res), indent=2, default=str))

    elif args.command == "scan":
        findings = WeakCryptoDetector().scan_directory(args.directory, _parse_exts(args.extensions))
        if args.json: print(json.dumps([asdict(f) for f in findings], indent=2, default=str))

    elif args.command == "quantum":
        findings = WeakCryptoDetector().scan_directory(args.directory, _parse_exts(args.extensions))
        assessments = QuantumVulnAssessor().assess(findings)
        if args.json:
            print(json.dumps(_results_summary(findings=findings, assessments=assessments), indent=2, default=str))

    elif args.command == "certs":
        results = CertificateMonitor().bulk_check(_parse_hosts(args.hosts))
        if args.json: print(json.dumps([asdict(c) for c in results], indent=2, default=str))

    elif args.command == "plan":
        findings = WeakCryptoDetector().scan_directory(args.directory, _parse_exts(args.extensions))
        assessments = QuantumVulnAssessor().assess(findings)
        tasks = MigrationPlanner().plan(findings, assessments)
        if args.output:
            p = Path(args.output)
            content = MigrationPlanner().to_json(tasks) if p.suffix.lower() == ".json" else MigrationPlanner().to_text(tasks)
            p.write_text(content, encoding="utf-8"); C.ok(f"Plan written to {args.output}")
        else:
            print(MigrationPlanner().to_json(tasks))


if __name__ == "__main__":
    main()
