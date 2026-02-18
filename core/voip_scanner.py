#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: VoIP SCANNER & SIP ANALYSIS v1.0
  SIP Discovery | User Enumeration | RTP Analysis | Protocol Fuzzing
  Professional VoIP Reconnaissance & Security Assessment Framework
===============================================================================

LEGAL NOTICE:
  Unauthorized use of VoIP scanning and enumeration tools against systems you
  do not own or have explicit written permission to test is ILLEGAL. Only use
  against:
    1. Your own infrastructure
    2. Client systems with explicit written authorization
    3. Approved red-team / penetration-test engagements
    4. Training environments you control

FLLC - Government-Cleared Security Operations
===============================================================================
"""

import os
import sys
import json
import time
import struct
import socket
import random
import string
import argparse
import re
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any, Set
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network, IPv4Address

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=False)
except ImportError:
    pass


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
    def ok(msg: str):
        C.p(f"  {C.GRN}[+]{C.R} {msg}")

    @staticmethod
    def info(msg: str):
        C.p(f"  {C.CYN}[*]{C.R} {msg}")

    @staticmethod
    def warn(msg: str):
        C.p(f"  {C.YLW}[!]{C.R} {msg}")

    @staticmethod
    def fail(msg: str):
        C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def section(title: str):
        w = 70
        C.p(f"\n  {C.CYN}{C.BLD}{'=' * w}")
        C.p(f"  {'':>2}{title}")
        C.p(f"  {'=' * w}{C.R}")


# =============================================================================
#  HELPERS
# =============================================================================

def _rand_tag() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _rand_branch() -> str:
    return "z9hG4bK" + "".join(random.choices(string.hexdigits[:16], k=12))


def _rand_callid() -> str:
    return "".join(random.choices(string.hexdigits[:16], k=24)) + "@fuperson"


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 53))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


# =============================================================================
#  DATA CLASSES
# =============================================================================

@dataclass
class SIPServer:
    ip: str
    port: int
    user_agent: str = ""
    methods_allowed: List[str] = field(default_factory=list)
    server_software: str = ""
    transport: str = "UDP"
    status_code: int = 0
    extensions: List[str] = field(default_factory=list)


@dataclass
class SIPUser:
    extension: str
    display_name: str = ""
    auth_required: bool = False
    enum_method: str = "REGISTER"
    response_code: int = 0


@dataclass
class RTPStream:
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    ssrc: int = 0
    codec: str = "unknown"
    payload_type: int = 0
    packets: int = 0
    jitter_ms: float = 0.0
    loss_pct: float = 0.0
    duration_s: float = 0.0


@dataclass
class FuzzResult:
    test_name: str
    target: str
    port: int
    response_code: int = 0
    response_text: str = ""
    crashed: bool = False
    timed_out: bool = False
    anomaly: str = ""


# =============================================================================
#  PAYLOAD TYPE -> CODEC MAP
# =============================================================================

RTP_PAYLOAD_TYPES: Dict[int, str] = {
    0: "PCMU (G.711u)", 3: "GSM", 4: "G.723", 8: "PCMA (G.711a)",
    9: "G.722", 10: "L16/2ch", 11: "L16/1ch", 13: "Comfort Noise",
    18: "G.729", 31: "H.261", 32: "MPV", 33: "MP2T",
    34: "H.263", 96: "Dynamic (96)", 97: "Dynamic (97)",
    98: "Dynamic (98)", 99: "Dynamic (99)", 100: "Dynamic (100)",
    101: "telephone-event", 110: "Dynamic (110)", 111: "Dynamic (111)",
}


# =============================================================================
#  SIP MESSAGE BUILDER
# =============================================================================

class SIPMessageBuilder:
    """Constructs raw SIP messages from scratch."""

    @staticmethod
    def options(target: str, port: int, transport: str = "UDP",
                local_ip: Optional[str] = None) -> str:
        lip = local_ip or _local_ip()
        branch = _rand_branch()
        tag = _rand_tag()
        callid = _rand_callid()
        return (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/{transport} {lip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:scanner@{lip}>;tag={tag}\r\n"
            f"To: <sip:{target}:{port}>\r\n"
            f"Call-ID: {callid}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Contact: <sip:scanner@{lip}:5060>\r\n"
            f"Accept: application/sdp\r\n"
            f"Content-Length: 0\r\n\r\n"
        )

    @staticmethod
    def register(target: str, port: int, user: str,
                 transport: str = "UDP",
                 local_ip: Optional[str] = None) -> str:
        lip = local_ip or _local_ip()
        branch = _rand_branch()
        tag = _rand_tag()
        callid = _rand_callid()
        return (
            f"REGISTER sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/{transport} {lip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{user}@{target}>;tag={tag}\r\n"
            f"To: <sip:{user}@{target}>\r\n"
            f"Call-ID: {callid}\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Contact: <sip:{user}@{lip}:5060>\r\n"
            f"Expires: 3600\r\n"
            f"Content-Length: 0\r\n\r\n"
        )

    @staticmethod
    def invite(target: str, port: int, user: str,
               transport: str = "UDP",
               local_ip: Optional[str] = None) -> str:
        lip = local_ip or _local_ip()
        branch = _rand_branch()
        tag = _rand_tag()
        callid = _rand_callid()
        sdp = (
            f"v=0\r\n"
            f"o=fuperson 0 0 IN IP4 {lip}\r\n"
            f"s=session\r\n"
            f"c=IN IP4 {lip}\r\n"
            f"t=0 0\r\n"
            f"m=audio 8000 RTP/AVP 0 8 18 101\r\n"
            f"a=rtpmap:0 PCMU/8000\r\n"
            f"a=rtpmap:8 PCMA/8000\r\n"
            f"a=rtpmap:18 G729/8000\r\n"
            f"a=rtpmap:101 telephone-event/8000\r\n"
        )
        return (
            f"INVITE sip:{user}@{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/{transport} {lip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:scanner@{lip}>;tag={tag}\r\n"
            f"To: <sip:{user}@{target}>\r\n"
            f"Call-ID: {callid}\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Contact: <sip:scanner@{lip}:5060>\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
        )


# =============================================================================
#  SIP RESPONSE PARSER
# =============================================================================

class SIPResponseParser:
    """Parse raw SIP response bytes into structured data."""

    @staticmethod
    def parse(data: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "status_code": 0, "reason": "", "headers": {},
            "via": [], "from": "", "to": "", "call_id": "",
            "cseq": "", "user_agent": "", "allow": [],
            "supported": [], "server": "", "raw": "",
        }
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return result
        result["raw"] = text
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines:
            return result
        status_match = re.match(r"SIP/2\.0\s+(\d{3})\s+(.*)", lines[0])
        if status_match:
            result["status_code"] = int(status_match.group(1))
            result["reason"] = status_match.group(2).strip()
        for line in lines[1:]:
            if ":" not in line:
                continue
            hdr, _, val = line.partition(":")
            hdr = hdr.strip().lower()
            val = val.strip()
            if hdr == "via":
                result["via"].append(val)
            elif hdr == "from":
                result["from"] = val
            elif hdr == "to":
                result["to"] = val
            elif hdr == "call-id":
                result["call_id"] = val
            elif hdr == "cseq":
                result["cseq"] = val
            elif hdr == "user-agent":
                result["user_agent"] = val
            elif hdr == "server":
                result["server"] = val
            elif hdr == "allow":
                result["allow"] = [m.strip() for m in val.split(",")]
            elif hdr == "supported":
                result["supported"] = [s.strip() for s in val.split(",")]
            else:
                result["headers"][hdr] = val
        return result

    @staticmethod
    def fingerprint(parsed: Dict[str, Any]) -> str:
        ua = parsed.get("user_agent", "") or parsed.get("server", "")
        if not ua:
            allowed = parsed.get("allow", [])
            if "SUBSCRIBE" in allowed and "NOTIFY" in allowed:
                return "Asterisk-like (from Allow)"
            if "PRACK" in allowed:
                return "OpenSIPS/Kamailio-like (from Allow)"
            return "Unknown"
        ua_lower = ua.lower()
        signatures: Dict[str, str] = {
            "asterisk": "Asterisk PBX", "freeswitch": "FreeSWITCH",
            "opensips": "OpenSIPS", "kamailio": "Kamailio",
            "cisco": "Cisco", "avaya": "Avaya",
            "yealink": "Yealink Phone", "polycom": "Polycom Phone",
            "grandstream": "Grandstream", "snom": "Snom Phone",
            "3cx": "3CX PBX", "mitel": "Mitel",
            "microsip": "MicroSIP", "linphone": "Linphone",
            "pjsip": "PJSIP", "twilio": "Twilio",
        }
        for sig, name in signatures.items():
            if sig in ua_lower:
                return f"{name} ({ua})"
        return f"Unknown ({ua})"


# =============================================================================
#  SIP SCANNER - SERVICE DISCOVERY
# =============================================================================

class SIPScanner:
    """Discover SIP services on target hosts."""

    def __init__(self, timeout: float = 3.0, local_ip: Optional[str] = None):
        self.timeout: float = timeout
        self.local_ip: str = local_ip or _local_ip()

    def _send_udp(self, target: str, port: int, message: str) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(message.encode(), (target, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return data
        except (socket.timeout, OSError):
            return None

    def _send_tcp(self, target: str, port: int, message: str) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.sendall(message.encode())
            data = sock.recv(4096)
            sock.close()
            return data
        except (socket.timeout, OSError):
            return None

    def discover(self, target: str,
                 port_range: Tuple[int, int] = (5060, 5061)) -> List[SIPServer]:
        servers: List[SIPServer] = []
        for port in range(port_range[0], port_range[1] + 1):
            for transport, sender in [("UDP", self._send_udp),
                                      ("TCP", self._send_tcp)]:
                msg = SIPMessageBuilder.options(target, port, transport,
                                                self.local_ip)
                C.info(f"Probing {target}:{port}/{transport} ...")
                data = sender(target, port, msg)
                if data is None:
                    continue
                parsed = SIPResponseParser.parse(data)
                if parsed["status_code"] == 0:
                    continue
                sw = SIPResponseParser.fingerprint(parsed)
                srv = SIPServer(
                    ip=target, port=port,
                    user_agent=parsed["user_agent"] or parsed["server"],
                    methods_allowed=parsed["allow"],
                    server_software=sw, transport=transport,
                    status_code=parsed["status_code"],
                )
                servers.append(srv)
                C.ok(f"Found SIP on {target}:{port}/{transport} "
                     f"- {sw} (code {parsed['status_code']})")
        return servers

    def scan_range(self, targets: List[str],
                   port_range: Tuple[int, int] = (5060, 5061),
                   threads: int = 10) -> List[SIPServer]:
        all_servers: List[SIPServer] = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self.discover, t, port_range): t
                for t in targets
            }
            for fut in as_completed(futures):
                try:
                    all_servers.extend(fut.result())
                except Exception as exc:
                    C.fail(f"Error scanning {futures[fut]}: {exc}")
        return all_servers


# =============================================================================
#  SIP USER ENUMERATOR
# =============================================================================

class SIPUserEnumerator:
    """Enumerate valid SIP extensions/users on a target."""

    EXISTS_CODES: Set[int] = {200, 401, 407, 100, 180, 183}
    ABSENT_CODES: Set[int] = {403, 404, 480, 604}

    def __init__(self, timeout: float = 3.0, rate_limit: float = 0.15,
                 local_ip: Optional[str] = None):
        self.timeout: float = timeout
        self.rate_limit: float = rate_limit
        self.local_ip: str = local_ip or _local_ip()

    def _probe(self, target: str, port: int, user: str,
               method: str = "REGISTER") -> Optional[Dict[str, Any]]:
        builders = {
            "REGISTER": SIPMessageBuilder.register,
            "OPTIONS": SIPMessageBuilder.options,
            "INVITE": SIPMessageBuilder.invite,
        }
        builder = builders.get(method)
        if builder is None:
            return None
        if method == "OPTIONS":
            msg = builder(target, port, "UDP", self.local_ip)
        else:
            msg = builder(target, port, user, "UDP", self.local_ip)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(msg.encode(), (target, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return SIPResponseParser.parse(data)
        except (socket.timeout, OSError):
            return None

    def _check_user(self, target: str, port: int,
                    user: str) -> Optional[SIPUser]:
        for method in ("REGISTER", "INVITE", "OPTIONS"):
            parsed = self._probe(target, port, user, method)
            if parsed is None:
                continue
            code = parsed["status_code"]
            if code in self.EXISTS_CODES:
                return SIPUser(
                    extension=user,
                    display_name=parsed.get("to", ""),
                    auth_required=code in (401, 407),
                    enum_method=method,
                    response_code=code,
                )
            if code in self.ABSENT_CODES:
                break
            time.sleep(self.rate_limit)
        return None

    def enumerate(self, target: str, port: int = 5060,
                  start: int = 100, end: int = 200) -> List[SIPUser]:
        C.section("SIP USER ENUMERATION (NUMERIC)")
        C.info(f"Range {start}-{end} on {target}:{port}")
        found: List[SIPUser] = []
        for ext in range(start, end + 1):
            user = str(ext)
            C.info(f"Trying extension {user} ...")
            result = self._check_user(target, port, user)
            if result:
                found.append(result)
                auth_str = "auth required" if result.auth_required else "no auth"
                C.ok(f"Found: {user} via {result.enum_method} "
                     f"({result.response_code}, {auth_str})")
            time.sleep(self.rate_limit)
        C.info(f"Enumeration complete: {len(found)} users found")
        return found

    def enumerate_names(self, target: str, port: int = 5060,
                        names: Optional[List[str]] = None) -> List[SIPUser]:
        C.section("SIP USER ENUMERATION (NAMES)")
        if names is None:
            names = [
                "admin", "administrator", "root", "user", "test",
                "reception", "operator", "support", "helpdesk",
                "sales", "marketing", "hr", "finance", "ceo",
                "cfo", "cto", "it", "dev", "voicemail", "fax",
                "conference", "meeting", "ivr", "auto-attendant",
            ]
        C.info(f"Testing {len(names)} names on {target}:{port}")
        found: List[SIPUser] = []
        for name in names:
            C.info(f"Trying user '{name}' ...")
            result = self._check_user(target, port, name)
            if result:
                found.append(result)
                auth_str = "auth required" if result.auth_required else "no auth"
                C.ok(f"Found: {name} via {result.enum_method} "
                     f"({result.response_code}, {auth_str})")
            time.sleep(self.rate_limit)
        C.info(f"Enumeration complete: {len(found)} users found")
        return found


# =============================================================================
#  RTP ANALYZER
# =============================================================================

class RTPAnalyzer:
    """Detect and analyze RTP streams from captured UDP traffic."""

    MIN_RTP_SIZE: int = 12

    def __init__(self):
        self._streams: Dict[int, Dict[str, Any]] = {}

    @staticmethod
    def _parse_rtp_header(data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 12:
            return None
        first_byte, second_byte = data[0], data[1]
        version = (first_byte >> 6) & 0x03
        if version != 2:
            return None
        padding = bool((first_byte >> 5) & 0x01)
        extension = bool((first_byte >> 4) & 0x01)
        csrc_count = first_byte & 0x0F
        marker = bool((second_byte >> 7) & 0x01)
        payload_type = second_byte & 0x7F
        if payload_type > 127:
            return None
        seq, timestamp, ssrc = struct.unpack("!HII", data[2:12])
        return {
            "version": version, "padding": padding,
            "extension": extension, "csrc_count": csrc_count,
            "marker": marker, "payload_type": payload_type,
            "sequence": seq, "timestamp": timestamp, "ssrc": ssrc,
        }

    @staticmethod
    def _codec_name(pt: int) -> str:
        return RTP_PAYLOAD_TYPES.get(pt, f"Unknown ({pt})")

    def _update_stream(self, ssrc: int, rtp: Dict[str, Any],
                       src: str, dst: str,
                       src_port: int, dst_port: int,
                       recv_time: float) -> None:
        if ssrc not in self._streams:
            self._streams[ssrc] = {
                "src_ip": src, "dst_ip": dst,
                "src_port": src_port, "dst_port": dst_port,
                "ssrc": ssrc,
                "payload_type": rtp["payload_type"],
                "packets": 0, "first_seq": rtp["sequence"],
                "last_seq": rtp["sequence"],
                "expected_seq": rtp["sequence"],
                "lost": 0, "jitter_samples": [],
                "last_recv": recv_time, "first_recv": recv_time,
                "last_ts": rtp["timestamp"],
            }
        stream = self._streams[ssrc]
        stream["packets"] += 1
        expected = (stream["last_seq"] + 1) & 0xFFFF
        if rtp["sequence"] != expected and stream["packets"] > 1:
            gap = (rtp["sequence"] - expected) & 0xFFFF
            if gap < 1000:
                stream["lost"] += gap
        stream["last_seq"] = rtp["sequence"]
        if stream["packets"] > 1:
            transit_diff = abs(
                (recv_time - stream["last_recv"]) -
                (rtp["timestamp"] - stream["last_ts"]) / 8000.0
            )
            stream["jitter_samples"].append(transit_diff * 1000.0)
        stream["last_recv"] = recv_time
        stream["last_ts"] = rtp["timestamp"]

    def detect(self, interface: str = "0.0.0.0",
               duration: float = 30.0,
               port_range: Tuple[int, int] = (10000, 20000)) -> List[RTPStream]:
        C.section("RTP STREAM DETECTION")
        C.info(f"Listening for RTP on {interface} for {duration}s "
               f"(ports {port_range[0]}-{port_range[1]})")
        self._streams.clear()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((interface, port_range[0]))
            sock.settimeout(1.0)
        except OSError as exc:
            C.fail(f"Cannot bind UDP socket: {exc}")
            C.info("Falling back to raw socket capture (requires admin)")
            return self._detect_raw(duration, port_range)

        start = time.monotonic()
        pkt_count = 0
        while time.monotonic() - start < duration:
            try:
                data, (src_ip, src_port) = sock.recvfrom(2048)
                recv_time = time.monotonic()
                rtp = self._parse_rtp_header(data)
                if rtp is None:
                    continue
                pkt_count += 1
                self._update_stream(
                    rtp["ssrc"], rtp, src_ip, interface,
                    src_port, port_range[0], recv_time,
                )
            except socket.timeout:
                continue
            except OSError:
                break
        sock.close()
        C.info(f"Captured {pkt_count} RTP packets")
        return self._build_results()

    def _detect_raw(self, duration: float,
                    port_range: Tuple[int, int]) -> List[RTPStream]:
        """Raw socket fallback for broader capture (requires privileges)."""
        if sys.platform == "win32":
            proto = socket.IPPROTO_IP
        else:
            proto = socket.IPPROTO_UDP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if sys.platform == "win32":
                sock.bind((_local_ip(), 0))
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except (OSError, PermissionError) as exc:
            C.fail(f"Raw socket unavailable: {exc}")
            return []

        start = time.monotonic()
        pkt_count = 0
        sock.settimeout(1.0)
        while time.monotonic() - start < duration:
            try:
                data, addr = sock.recvfrom(65535)
                recv_time = time.monotonic()
                if len(data) < 28:
                    continue
                ihl = (data[0] & 0x0F) * 4
                protocol = data[9]
                if protocol != 17:
                    continue
                udp_offset = ihl
                src_port = struct.unpack("!H", data[udp_offset:udp_offset + 2])[0]
                dst_port = struct.unpack("!H", data[udp_offset + 2:udp_offset + 4])[0]
                if not (port_range[0] <= dst_port <= port_range[1] or
                        port_range[0] <= src_port <= port_range[1]):
                    continue
                payload = data[udp_offset + 8:]
                rtp = self._parse_rtp_header(payload)
                if rtp is None:
                    continue
                src_ip = socket.inet_ntoa(data[12:16])
                dst_ip = socket.inet_ntoa(data[16:20])
                pkt_count += 1
                self._update_stream(
                    rtp["ssrc"], rtp, src_ip, dst_ip,
                    src_port, dst_port, recv_time,
                )
            except socket.timeout:
                continue
            except OSError:
                break

        if sys.platform == "win32":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()
        C.info(f"Raw capture: {pkt_count} RTP packets")
        return self._build_results()

    def _build_results(self) -> List[RTPStream]:
        results: List[RTPStream] = []
        for ssrc, s in self._streams.items():
            total_expected = (s["last_seq"] - s["first_seq"]) & 0xFFFF
            loss = (s["lost"] / max(total_expected, 1)) * 100.0 if total_expected else 0.0
            jitter = 0.0
            if s["jitter_samples"]:
                jitter = sum(s["jitter_samples"]) / len(s["jitter_samples"])
            dur = s["last_recv"] - s["first_recv"]
            stream = RTPStream(
                src_ip=s["src_ip"], dst_ip=s["dst_ip"],
                src_port=s["src_port"], dst_port=s["dst_port"],
                ssrc=ssrc, codec=self._codec_name(s["payload_type"]),
                payload_type=s["payload_type"],
                packets=s["packets"], jitter_ms=round(jitter, 2),
                loss_pct=round(loss, 2), duration_s=round(dur, 2),
            )
            results.append(stream)
            C.ok(f"Stream SSRC=0x{ssrc:08X}: {stream.codec}, "
                 f"{stream.packets} pkts, jitter={stream.jitter_ms}ms, "
                 f"loss={stream.loss_pct}%")
        return results


# =============================================================================
#  SIP FUZZER
# =============================================================================

class SIPFuzzer:
    """Fuzz SIP protocol to find parsing vulnerabilities."""

    def __init__(self, timeout: float = 3.0,
                 local_ip: Optional[str] = None):
        self.timeout: float = timeout
        self.local_ip: str = local_ip or _local_ip()
        self.results: List[FuzzResult] = []

    def _send(self, target: str, port: int,
              payload: str, test_name: str) -> FuzzResult:
        result = FuzzResult(test_name=test_name, target=target, port=port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(payload.encode("utf-8", errors="replace"),
                        (target, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            parsed = SIPResponseParser.parse(data)
            result.response_code = parsed["status_code"]
            result.response_text = parsed["reason"]
            if parsed["status_code"] >= 500:
                result.anomaly = f"Server error {parsed['status_code']}"
        except socket.timeout:
            result.timed_out = True
            result.anomaly = "No response (possible crash)"
        except ConnectionResetError:
            result.crashed = True
            result.anomaly = "Connection reset (likely crash)"
        except OSError as exc:
            result.anomaly = f"OS error: {exc}"
        self.results.append(result)
        return result

    def fuzz_headers(self, target: str, port: int = 5060) -> List[FuzzResult]:
        C.section("SIP HEADER FUZZING")
        lip = self.local_ip
        cases: List[Tuple[str, str]] = []

        oversized_via = "X" * 4096
        cases.append(("oversized-via", (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {oversized_via};branch=z9hG4bK0000\r\n"
            f"From: <sip:fuzz@{lip}>;tag=fuzz1\r\n"
            f"To: <sip:{target}>\r\nCall-ID: fuzz1@{lip}\r\n"
            f"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )))

        cases.append(("malformed-from-uri", (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"From: <sip:@@@invalid:::uri>;tag=fuzz2\r\n"
            f"To: <sip:{target}>\r\nCall-ID: fuzz2@{lip}\r\n"
            f"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )))

        cases.append(("negative-cseq", (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"From: <sip:fuzz@{lip}>;tag=fuzz3\r\n"
            f"To: <sip:{target}>\r\nCall-ID: fuzz3@{lip}\r\n"
            f"CSeq: -1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )))

        cases.append(("max-int-cseq", (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"From: <sip:fuzz@{lip}>;tag=fuzz4\r\n"
            f"To: <sip:{target}>\r\nCall-ID: fuzz4@{lip}\r\n"
            f"CSeq: 4294967295 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )))

        cases.append(("null-bytes-callid", (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"From: <sip:fuzz@{lip}>;tag=fuzz5\r\n"
            f"To: <sip:{target}>\r\n"
            f"Call-ID: \x00\x00\x00\x00@{lip}\r\n"
            f"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )))

        cases.append(("duplicate-headers", (
            f"OPTIONS sip:{target}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
            f"From: <sip:fuzz@{lip}>;tag=fuzz6\r\n"
            f"To: <sip:{target}>\r\nCall-ID: fuzz6@{lip}\r\n"
            f"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )))

        results: List[FuzzResult] = []
        for name, payload in cases:
            C.info(f"Fuzz test: {name}")
            r = self._send(target, port, payload, name)
            tag = C.RED + "ANOMALY" if r.anomaly else C.GRN + "OK"
            C.p(f"    {tag}{C.R}: code={r.response_code} "
                f"{'timeout' if r.timed_out else ''} "
                f"{'CRASH' if r.crashed else ''} {r.anomaly}")
            results.append(r)
            time.sleep(0.2)
        return results

    def fuzz_methods(self, target: str, port: int = 5060) -> List[FuzzResult]:
        C.section("SIP METHOD FUZZING")
        lip = self.local_ip
        bad_methods = [
            "FOOBAR", "GET", "POST", "DELETE", "PATCH",
            "A" * 2048, "", "\r\n\r\n",
            "OPTIONS" * 100, "INVITE\x00BYE",
        ]
        results: List[FuzzResult] = []
        for method in bad_methods:
            safe_name = repr(method)[:40]
            payload = (
                f"{method} sip:{target}:{port} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
                f"From: <sip:fuzz@{lip}>;tag=mfuzz\r\n"
                f"To: <sip:{target}>\r\nCall-ID: mfuzz@{lip}\r\n"
                f"CSeq: 1 {method[:20]}\r\nContent-Length: 0\r\n\r\n"
            )
            C.info(f"Fuzz method: {safe_name}")
            r = self._send(target, port, payload, f"method-{safe_name}")
            tag = C.RED + "ANOMALY" if r.anomaly else C.GRN + "OK"
            C.p(f"    {tag}{C.R}: code={r.response_code} {r.anomaly}")
            results.append(r)
            time.sleep(0.2)
        return results

    def fuzz_body(self, target: str, port: int = 5060) -> List[FuzzResult]:
        C.section("SIP BODY FUZZING")
        lip = self.local_ip
        bodies: List[Tuple[str, str]] = []

        bodies.append(("oversized-sdp", "v=0\r\n" + "a=fuzz:" + "B" * 8192 + "\r\n"))
        bodies.append(("negative-port-sdp",
                        "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\n"
                        "c=IN IP4 0.0.0.0\r\nt=0 0\r\n"
                        "m=audio -1 RTP/AVP 0\r\n"))
        bodies.append(("format-string-sdp",
                        "v=0\r\no=%s%s%s%n%n%n IN IP4 0.0.0.0\r\ns=-\r\n"
                        "c=IN IP4 0.0.0.0\r\nt=0 0\r\n"
                        "m=audio 8000 RTP/AVP 0\r\n"))
        bodies.append(("binary-body", "\x00\x01\x02\xff\xfe\xfd" * 500))
        bodies.append(("wrong-content-length",
                        "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\n"))

        results: List[FuzzResult] = []
        for name, body in bodies:
            cl = len(body) if name != "wrong-content-length" else 99999
            payload = (
                f"INVITE sip:fuzz@{target}:{port} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {lip}:5060;branch={_rand_branch()}\r\n"
                f"From: <sip:fuzz@{lip}>;tag=bfuzz\r\n"
                f"To: <sip:fuzz@{target}>\r\nCall-ID: bfuzz@{lip}\r\n"
                f"CSeq: 1 INVITE\r\n"
                f"Content-Type: application/sdp\r\n"
                f"Content-Length: {cl}\r\n\r\n{body}"
            )
            C.info(f"Fuzz body: {name}")
            r = self._send(target, port, payload, name)
            tag = C.RED + "ANOMALY" if r.anomaly else C.GRN + "OK"
            C.p(f"    {tag}{C.R}: code={r.response_code} {r.anomaly}")
            results.append(r)
            time.sleep(0.2)
        return results


# =============================================================================
#  VOIP RECON ORCHESTRATOR
# =============================================================================

class VoIPRecon:
    """Orchestrates all VoIP scanning modules into a unified recon."""

    def __init__(self, timeout: float = 3.0):
        self.timeout: float = timeout
        self.scanner = SIPScanner(timeout=timeout)
        self.enumerator = SIPUserEnumerator(timeout=timeout)
        self.rtp = RTPAnalyzer()
        self.fuzzer = SIPFuzzer(timeout=timeout)

    def full_scan(self, target: str, port: int = 5060,
                  enum_start: int = 100,
                  enum_end: int = 120) -> Dict[str, Any]:
        C.section("FULL VoIP RECONNAISSANCE")
        C.info(f"Target: {target}:{port}")
        report: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target, "port": port, "servers": [],
            "users": [], "fuzz_results": [], "rtp_streams": [],
        }

        C.info("Phase 1: SIP Discovery")
        servers = self.scanner.discover(target, (port, port))
        report["servers"] = [asdict(s) for s in servers]

        if servers:
            C.info("Phase 2: User Enumeration")
            users = self.enumerator.enumerate(target, port,
                                              enum_start, enum_end)
            report["users"] = [asdict(u) for u in users]

            C.info("Phase 3: Name-Based Enumeration")
            named = self.enumerator.enumerate_names(target, port)
            report["users"].extend([asdict(u) for u in named])

            C.info("Phase 4: Protocol Fuzzing")
            hdr_fuzz = self.fuzzer.fuzz_headers(target, port)
            method_fuzz = self.fuzzer.fuzz_methods(target, port)
            body_fuzz = self.fuzzer.fuzz_body(target, port)
            all_fuzz = hdr_fuzz + method_fuzz + body_fuzz
            report["fuzz_results"] = [asdict(f) for f in all_fuzz]
        else:
            C.warn("No SIP servers found - skipping enum & fuzz phases")

        return report

    def network_scan(self, cidr: str,
                     port_range: Tuple[int, int] = (5060, 5061),
                     threads: int = 20) -> Dict[str, Any]:
        C.section("NETWORK-WIDE VoIP SCAN")
        try:
            net = IPv4Network(cidr, strict=False)
        except ValueError as exc:
            C.fail(f"Invalid CIDR: {exc}")
            return {"error": str(exc)}

        hosts = [str(ip) for ip in net.hosts()]
        C.info(f"Scanning {len(hosts)} hosts in {cidr}")
        servers = self.scanner.scan_range(hosts, port_range, threads)

        report: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cidr": cidr, "hosts_scanned": len(hosts),
            "servers_found": len(servers),
            "servers": [asdict(s) for s in servers],
        }
        return report

    @staticmethod
    def save_report(report: Dict[str, Any], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        C.ok(f"Report saved to {path}")


# =============================================================================
#  CLI
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="voip_scanner",
        description="FU PERSON :: VoIP Scanner & SIP Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s discover -t 10.0.0.1\n"
            "  %(prog)s enumerate -t 10.0.0.1 -s 100 -e 500\n"
            "  %(prog)s rtp --duration 60\n"
            "  %(prog)s fuzz -t 10.0.0.1\n"
            "  %(prog)s recon -t 10.0.0.1 --cidr 10.0.0.0/24\n"
        ),
    )
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Socket timeout in seconds (default: 3)")
    parser.add_argument("-o", "--output", type=str, default="",
                        help="Output JSON report path")

    subs = parser.add_subparsers(dest="command", required=True)

    # -- discover --
    p_disc = subs.add_parser("discover", help="Discover SIP services")
    p_disc.add_argument("-t", "--target", required=True, help="Target IP/host")
    p_disc.add_argument("--port-start", type=int, default=5060)
    p_disc.add_argument("--port-end", type=int, default=5061)
    p_disc.add_argument("--threads", type=int, default=10)

    # -- enumerate --
    p_enum = subs.add_parser("enumerate", help="Enumerate SIP users")
    p_enum.add_argument("-t", "--target", required=True)
    p_enum.add_argument("-p", "--port", type=int, default=5060)
    p_enum.add_argument("-s", "--start", type=int, default=100,
                        help="Start extension (default: 100)")
    p_enum.add_argument("-e", "--end", type=int, default=200,
                        help="End extension (default: 200)")
    p_enum.add_argument("--names", nargs="*",
                        help="Additional names to enumerate")

    # -- rtp --
    p_rtp = subs.add_parser("rtp", help="Detect RTP streams")
    p_rtp.add_argument("-i", "--interface", default="0.0.0.0")
    p_rtp.add_argument("--duration", type=float, default=30.0)
    p_rtp.add_argument("--port-start", type=int, default=10000)
    p_rtp.add_argument("--port-end", type=int, default=20000)

    # -- fuzz --
    p_fuzz = subs.add_parser("fuzz", help="Fuzz SIP protocol")
    p_fuzz.add_argument("-t", "--target", required=True)
    p_fuzz.add_argument("-p", "--port", type=int, default=5060)
    p_fuzz.add_argument("--headers", action="store_true", default=True)
    p_fuzz.add_argument("--methods", action="store_true", default=True)
    p_fuzz.add_argument("--body", action="store_true", default=True)

    # -- recon --
    p_recon = subs.add_parser("recon", help="Full VoIP recon")
    p_recon.add_argument("-t", "--target", required=True)
    p_recon.add_argument("-p", "--port", type=int, default=5060)
    p_recon.add_argument("--cidr", type=str, default="",
                         help="Scan entire subnet (e.g. 10.0.0.0/24)")
    p_recon.add_argument("-s", "--start", type=int, default=100)
    p_recon.add_argument("-e", "--end", type=int, default=120)
    p_recon.add_argument("--threads", type=int, default=20)

    return parser


def main() -> None:
    banner = (
        f"\n  {C.CYN}{C.BLD}"
        f"{'=' * 60}\n"
        f"  FU PERSON :: VoIP Scanner & SIP Analysis v1.0\n"
        f"  FLLC - Government-Cleared Security Operations\n"
        f"  {'=' * 60}{C.R}\n"
    )
    C.p(banner)

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "discover":
        scanner = SIPScanner(timeout=args.timeout)
        targets = [args.target]
        servers = scanner.scan_range(targets,
                                     (args.port_start, args.port_end),
                                     args.threads)
        C.section("DISCOVERY RESULTS")
        for s in servers:
            C.ok(f"{s.ip}:{s.port}/{s.transport} - {s.server_software}")
            if s.methods_allowed:
                C.info(f"  Allow: {', '.join(s.methods_allowed)}")
        report = {"servers": [asdict(s) for s in servers]}

    elif args.command == "enumerate":
        enum = SIPUserEnumerator(timeout=args.timeout)
        users = enum.enumerate(args.target, args.port, args.start, args.end)
        if args.names:
            users.extend(enum.enumerate_names(args.target, args.port,
                                              args.names))
        C.section("ENUMERATION RESULTS")
        for u in users:
            auth = "auth-required" if u.auth_required else "no-auth"
            C.ok(f"{u.extension} [{u.enum_method}] "
                 f"code={u.response_code} ({auth})")
        report = {"users": [asdict(u) for u in users]}

    elif args.command == "rtp":
        analyzer = RTPAnalyzer()
        streams = analyzer.detect(args.interface, args.duration,
                                  (args.port_start, args.port_end))
        C.section("RTP RESULTS")
        for s in streams:
            C.ok(f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port} "
                 f"SSRC=0x{s.ssrc:08X} codec={s.codec} "
                 f"pkts={s.packets} jitter={s.jitter_ms}ms "
                 f"loss={s.loss_pct}%")
        report = {"rtp_streams": [asdict(s) for s in streams]}

    elif args.command == "fuzz":
        fuzzer = SIPFuzzer(timeout=args.timeout)
        results: List[FuzzResult] = []
        if args.headers:
            results.extend(fuzzer.fuzz_headers(args.target, args.port))
        if args.methods:
            results.extend(fuzzer.fuzz_methods(args.target, args.port))
        if args.body:
            results.extend(fuzzer.fuzz_body(args.target, args.port))
        C.section("FUZZ RESULTS SUMMARY")
        anomalies = [r for r in results if r.anomaly]
        C.info(f"Total tests: {len(results)}, Anomalies: {len(anomalies)}")
        for a in anomalies:
            C.warn(f"{a.test_name}: {a.anomaly}")
        report = {"fuzz_results": [asdict(r) for r in results]}

    elif args.command == "recon":
        recon = VoIPRecon(timeout=args.timeout)
        if args.cidr:
            report = recon.network_scan(args.cidr, threads=args.threads)
        else:
            report = recon.full_scan(args.target, args.port,
                                     args.start, args.end)
    else:
        parser.print_help()
        return

    if args.output:
        VoIPRecon.save_report(report, args.output)
    else:
        C.p(f"\n{C.DIM}{json.dumps(report, indent=2, default=str)}{C.R}")

    C.p(f"\n  {C.GRN}{C.BLD}Scan complete.{C.R}\n")


if __name__ == "__main__":
    main()
