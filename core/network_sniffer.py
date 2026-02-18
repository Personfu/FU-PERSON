#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: NETWORK SNIFFER & SPOOFING DETECTION v1.0
  Packet Capture | ARP Scanning | DNS Monitoring | OS Fingerprinting
  Traffic Analysis | Protocol Dissection | PCAP Export
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  Unauthorized network sniffing and packet capture is ILLEGAL.
  Only use this tool against:
    1. Your own infrastructure
    2. Client systems with explicit written authorization
    3. Training environments you control

  FLLC
  Government-Cleared Security Operations
===============================================================================
"""

import os
import sys
import json
import time
import struct
import socket
import argparse
import platform
import subprocess
import re
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import (
    List, Dict, Optional, Tuple, Any, Set, Callable, Iterator,
)
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network, IPv4Address
import binascii

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from scapy.all import (
        sniff as scapy_sniff, ARP, Ether, srp, IP, TCP, UDP, DNS,
        DNSQR, DNSRR, wrpcap, conf as scapy_conf,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

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


BANNER = rf"""
{C.CYN}{C.BLD}
    ███╗   ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗
    ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝
    ██╔██╗ ██║█████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗
    ██║╚██╗██║██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝
    ██║ ╚████║███████╗   ██║       ███████║██║ ╚████║██║██║     ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝
{C.R}{C.GRN}    ──────────── NETWORK SNIFFER & SPOOF DETECT v1.0 ──────────────{C.R}
{C.DIM}    FLLC  |  Authorized Use Only  |  Packet Analysis{C.R}
"""


# =============================================================================
#  CONSTANTS & FINGERPRINT DATABASE
# =============================================================================

ETHER_TYPES: Dict[int, str] = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q",
}

IP_PROTOCOLS: Dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
    89: "OSPF", 132: "SCTP",
}

TCP_FLAGS: Dict[int, str] = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
    0x10: "ACK", 0x20: "URG", 0x40: "ECE", 0x80: "CWR",
}

OS_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "Linux 2.6+":    {"ttl": 64,  "window": 5840,  "df": True,  "options_order": ["MSS", "SAckOK", "TS", "NOP", "WS"]},
    "Linux 4.x+":    {"ttl": 64,  "window": 29200, "df": True,  "options_order": ["MSS", "SAckOK", "TS", "NOP", "WS"]},
    "Linux 5.x+":    {"ttl": 64,  "window": 65160, "df": True,  "options_order": ["MSS", "SAckOK", "TS", "NOP", "WS"]},
    "Windows 10/11": {"ttl": 128, "window": 65535, "df": True,  "options_order": ["MSS", "NOP", "WS", "NOP", "NOP", "SAckOK"]},
    "Windows 7/8":   {"ttl": 128, "window": 8192,  "df": True,  "options_order": ["MSS", "NOP", "WS", "SAckOK", "TS"]},
    "macOS/iOS":     {"ttl": 64,  "window": 65535, "df": True,  "options_order": ["MSS", "NOP", "WS", "NOP", "NOP", "TS", "SAckOK"]},
    "FreeBSD":       {"ttl": 64,  "window": 65535, "df": True,  "options_order": ["MSS", "NOP", "WS", "SAckOK", "TS"]},
    "Cisco IOS":     {"ttl": 255, "window": 4128,  "df": False, "options_order": ["MSS"]},
    "Solaris 10":    {"ttl": 255, "window": 49640, "df": True,  "options_order": ["NOP", "NOP", "TS", "MSS", "NOP", "WS", "SAckOK"]},
    "OpenBSD":       {"ttl": 64,  "window": 16384, "df": True,  "options_order": ["MSS", "NOP", "NOP", "SAckOK", "NOP", "WS", "NOP", "NOP", "TS"]},
}

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1
PCAP_SNAPLEN = 65535

DNS_TUNNEL_LABEL_THRESHOLD = 52
DNS_TUNNEL_TOTAL_THRESHOLD = 180


# =============================================================================
#  DATA CLASSES
# =============================================================================

@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ether_type: int
    ether_type_name: str
    payload: bytes = field(repr=False, default=b"")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dst_mac": self.dst_mac, "src_mac": self.src_mac,
            "ether_type": hex(self.ether_type),
            "ether_type_name": self.ether_type_name,
        }


@dataclass
class IPPacket:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    protocol_name: str
    checksum: int
    src_ip: str
    dst_ip: str
    df_flag: bool
    payload: bytes = field(repr=False, default=b"")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version, "ttl": self.ttl,
            "protocol": self.protocol_name, "src": self.src_ip,
            "dst": self.dst_ip, "length": self.total_length,
            "df": self.df_flag, "id": self.identification,
        }


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    flag_names: List[str]
    window: int
    checksum: int
    urgent: int
    options_raw: bytes = field(repr=False, default=b"")
    payload: bytes = field(repr=False, default=b"")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_port": self.src_port, "dst_port": self.dst_port,
            "seq": self.seq, "ack": self.ack, "flags": self.flag_names,
            "window": self.window, "data_offset": self.data_offset,
        }


@dataclass
class UDPDatagram:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes = field(repr=False, default=b"")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_port": self.src_port, "dst_port": self.dst_port,
            "length": self.length,
        }


@dataclass
class ICMPPacket:
    icmp_type: int
    code: int
    checksum: int
    rest: bytes = field(repr=False, default=b"")

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.icmp_type, "code": self.code}


@dataclass
class ARPPacket:
    hw_type: int
    proto_type: int
    hw_len: int
    proto_len: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    def to_dict(self) -> Dict[str, Any]:
        op = "request" if self.opcode == 1 else "reply"
        return {
            "opcode": op, "sender_mac": self.sender_mac,
            "sender_ip": self.sender_ip, "target_mac": self.target_mac,
            "target_ip": self.target_ip,
        }


@dataclass
class CapturedPacket:
    timestamp: float
    length: int
    raw: bytes = field(repr=False)
    ethernet: Optional[EthernetFrame] = None
    ip: Optional[IPPacket] = None
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPDatagram] = None
    icmp: Optional[ICMPPacket] = None
    arp: Optional[ARPPacket] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "timestamp": self.timestamp, "length": self.length,
        }
        if self.ethernet:
            d["ethernet"] = self.ethernet.to_dict()
        if self.ip:
            d["ip"] = self.ip.to_dict()
        if self.tcp:
            d["tcp"] = self.tcp.to_dict()
        if self.udp:
            d["udp"] = self.udp.to_dict()
        if self.icmp:
            d["icmp"] = self.icmp.to_dict()
        if self.arp:
            d["arp"] = self.arp.to_dict()
        return d


# =============================================================================
#  PACKET PARSING HELPERS
# =============================================================================

def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _parse_tcp_flags(flag_byte: int) -> List[str]:
    return [name for bit, name in TCP_FLAGS.items() if flag_byte & bit]


def _parse_tcp_options(raw: bytes) -> List[str]:
    opts: List[str] = []
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:
            break
        if kind == 1:
            opts.append("NOP")
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        length = raw[i + 1]
        if length < 2:
            break
        if kind == 2:
            opts.append("MSS")
        elif kind == 3:
            opts.append("WS")
        elif kind == 4:
            opts.append("SAckOK")
        elif kind == 5:
            opts.append("SAck")
        elif kind == 8:
            opts.append("TS")
        else:
            opts.append(f"Kind{kind}")
        i += length
    return opts


def parse_ethernet(raw: bytes) -> Optional[EthernetFrame]:
    if len(raw) < 14:
        return None
    dst = _mac_str(raw[0:6])
    src = _mac_str(raw[6:12])
    etype = struct.unpack("!H", raw[12:14])[0]
    return EthernetFrame(
        dst_mac=dst, src_mac=src, ether_type=etype,
        ether_type_name=ETHER_TYPES.get(etype, f"0x{etype:04x}"),
        payload=raw[14:],
    )


def parse_ip(raw: bytes) -> Optional[IPPacket]:
    if len(raw) < 20:
        return None
    vhl = raw[0]
    version = vhl >> 4
    ihl = (vhl & 0x0F) * 4
    if version != 4 or len(raw) < ihl:
        return None
    tos, total_len, ident, flags_frag = struct.unpack("!BBHHHH"[1:], raw[1:10])
    # re-unpack properly
    tos = raw[1]
    total_len = struct.unpack("!H", raw[2:4])[0]
    ident = struct.unpack("!H", raw[4:6])[0]
    flags_frag = struct.unpack("!H", raw[6:8])[0]
    flags = flags_frag >> 13
    frag_off = flags_frag & 0x1FFF
    ttl = raw[8]
    proto = raw[9]
    checksum = struct.unpack("!H", raw[10:12])[0]
    src = socket.inet_ntoa(raw[12:16])
    dst = socket.inet_ntoa(raw[16:20])
    return IPPacket(
        version=version, ihl=ihl, tos=tos, total_length=total_len,
        identification=ident, flags=flags, fragment_offset=frag_off,
        ttl=ttl, protocol=proto,
        protocol_name=IP_PROTOCOLS.get(proto, str(proto)),
        checksum=checksum, src_ip=src, dst_ip=dst,
        df_flag=bool(flags & 0x02), payload=raw[ihl:],
    )


def parse_tcp(raw: bytes) -> Optional[TCPSegment]:
    if len(raw) < 20:
        return None
    src_port, dst_port, seq, ack_num, offset_flags = struct.unpack(
        "!HHIIH", raw[0:14],
    )
    data_off = (offset_flags >> 12) * 4
    flag_byte = offset_flags & 0x01FF
    window = struct.unpack("!H", raw[14:16])[0]
    checksum = struct.unpack("!H", raw[16:18])[0]
    urgent = struct.unpack("!H", raw[18:20])[0]
    options_raw = raw[20:data_off] if data_off > 20 else b""
    return TCPSegment(
        src_port=src_port, dst_port=dst_port, seq=seq, ack=ack_num,
        data_offset=data_off, flags=flag_byte,
        flag_names=_parse_tcp_flags(flag_byte), window=window,
        checksum=checksum, urgent=urgent, options_raw=options_raw,
        payload=raw[data_off:],
    )


def parse_udp(raw: bytes) -> Optional[UDPDatagram]:
    if len(raw) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw[0:8])
    return UDPDatagram(
        src_port=src_port, dst_port=dst_port, length=length,
        checksum=checksum, payload=raw[8:],
    )


def parse_icmp(raw: bytes) -> Optional[ICMPPacket]:
    if len(raw) < 4:
        return None
    icmp_type, code, checksum = struct.unpack("!BBH", raw[0:4])
    return ICMPPacket(
        icmp_type=icmp_type, code=code, checksum=checksum, rest=raw[4:],
    )


def parse_arp(raw: bytes) -> Optional[ARPPacket]:
    if len(raw) < 28:
        return None
    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(
        "!HHBBH", raw[0:8],
    )
    sender_mac = _mac_str(raw[8:14])
    sender_ip = socket.inet_ntoa(raw[14:18])
    target_mac = _mac_str(raw[18:24])
    target_ip = socket.inet_ntoa(raw[24:28])
    return ARPPacket(
        hw_type=hw_type, proto_type=proto_type, hw_len=hw_len,
        proto_len=proto_len, opcode=opcode, sender_mac=sender_mac,
        sender_ip=sender_ip, target_mac=target_mac, target_ip=target_ip,
    )


def hexdump(data: bytes, width: int = 16) -> str:
    lines: List[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def dissect_packet(raw: bytes, timestamp: float) -> CapturedPacket:
    pkt = CapturedPacket(timestamp=timestamp, length=len(raw), raw=raw)
    eth = parse_ethernet(raw)
    if not eth:
        return pkt
    pkt.ethernet = eth

    if eth.ether_type == 0x0806:
        pkt.arp = parse_arp(eth.payload)
        return pkt

    if eth.ether_type == 0x0800:
        ip = parse_ip(eth.payload)
        if not ip:
            return pkt
        pkt.ip = ip
        if ip.protocol == 6:
            pkt.tcp = parse_tcp(ip.payload)
        elif ip.protocol == 17:
            pkt.udp = parse_udp(ip.payload)
        elif ip.protocol == 1:
            pkt.icmp = parse_icmp(ip.payload)
    return pkt


# =============================================================================
#  PCAP FILE WRITER
# =============================================================================

class PCAPWriter:
    def __init__(self, filepath: str):
        self._filepath = filepath
        self._fh = open(filepath, "wb")
        self._write_global_header()

    def _write_global_header(self) -> None:
        self._fh.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
            0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE_ETHERNET,
        ))

    def write_packet(self, raw: bytes, timestamp: float) -> None:
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        cap_len = len(raw)
        self._fh.write(struct.pack("<IIII", ts_sec, ts_usec, cap_len, cap_len))
        self._fh.write(raw)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# =============================================================================
#  PACKET CAPTURE ENGINE
# =============================================================================

class PacketCapture:
    """Raw socket / scapy packet capture engine."""

    def __init__(self):
        self.packets: List[CapturedPacket] = []

    def capture(
        self,
        interface: Optional[str] = None,
        count: int = 100,
        timeout: int = 30,
        bpf_filter: Optional[str] = None,
        pcap_file: Optional[str] = None,
    ) -> List[CapturedPacket]:
        self.packets.clear()
        writer: Optional[PCAPWriter] = None
        if pcap_file:
            writer = PCAPWriter(pcap_file)

        if HAS_SCAPY:
            self._capture_scapy(interface, count, timeout, bpf_filter, writer)
        else:
            self._capture_raw(interface, count, timeout, writer)

        if writer:
            writer.close()
            C.ok(f"Saved {len(self.packets)} packets to {pcap_file}")
        return self.packets

    def _capture_scapy(
        self,
        interface: Optional[str],
        count: int,
        timeout: int,
        bpf_filter: Optional[str],
        writer: Optional[PCAPWriter],
    ) -> None:
        C.info(f"Capturing via scapy (iface={interface or 'default'}, "
               f"count={count}, timeout={timeout}s)")
        kwargs: Dict[str, Any] = {"count": count, "timeout": timeout}
        if interface:
            kwargs["iface"] = interface
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        def _handler(pkt: Any) -> None:
            raw_bytes = bytes(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
            parsed = dissect_packet(raw_bytes, ts)
            self.packets.append(parsed)
            if writer:
                writer.write_packet(raw_bytes, ts)

        kwargs["prn"] = _handler
        kwargs["store"] = 0
        scapy_sniff(**kwargs)

    def _capture_raw(
        self,
        interface: Optional[str],
        count: int,
        timeout: int,
        writer: Optional[PCAPWriter],
    ) -> None:
        C.info(f"Capturing via raw socket (count={count}, timeout={timeout}s)")
        if sys.platform == "win32":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host = socket.gethostbyname(socket.gethostname())
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if interface:
                sock.bind((interface, 0))

        sock.settimeout(1.0)
        start = time.time()
        captured = 0
        try:
            while captured < count and (time.time() - start) < timeout:
                try:
                    raw_data = sock.recv(65535)
                except socket.timeout:
                    continue
                ts = time.time()
                if sys.platform == "win32":
                    fake_eth = b"\x00" * 12 + b"\x08\x00" + raw_data
                    parsed = dissect_packet(fake_eth, ts)
                else:
                    parsed = dissect_packet(raw_data, ts)
                self.packets.append(parsed)
                if writer:
                    writer.write_packet(raw_data, ts)
                captured += 1
        finally:
            if sys.platform == "win32":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            sock.close()

    def summary(self) -> str:
        proto_counts: Counter = Counter()
        for p in self.packets:
            if p.tcp:
                proto_counts["TCP"] += 1
            elif p.udp:
                proto_counts["UDP"] += 1
            elif p.icmp:
                proto_counts["ICMP"] += 1
            elif p.arp:
                proto_counts["ARP"] += 1
            else:
                proto_counts["Other"] += 1
        lines = [f"Captured {len(self.packets)} packets"]
        for proto, cnt in proto_counts.most_common():
            lines.append(f"  {proto}: {cnt}")
        return "\n".join(lines)


# =============================================================================
#  ARP SCANNER
# =============================================================================

class ARPScanner:
    """ARP network discovery and spoofing detection."""

    def scan_network(self, cidr: str, timeout: int = 3) -> List[Dict[str, str]]:
        C.section("ARP Network Scan")
        C.info(f"Scanning {cidr}")
        results: List[Dict[str, str]] = []

        if HAS_SCAPY:
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
            answered, _ = srp(arp_req, timeout=timeout, verbose=0)
            for sent, received in answered:
                results.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "vendor": self._oui_lookup(received.hwsrc),
                })
        else:
            net = IPv4Network(cidr, strict=False)
            with ThreadPoolExecutor(max_workers=64) as pool:
                futures = {
                    pool.submit(self._ping_host, str(ip)): str(ip)
                    for ip in net.hosts()
                }
                for future in as_completed(futures):
                    ip_str = futures[future]
                    if future.result():
                        mac = self._resolve_mac(ip_str)
                        results.append({
                            "ip": ip_str, "mac": mac,
                            "vendor": self._oui_lookup(mac),
                        })

        for host in results:
            C.ok(f"{host['ip']:>15}  {host['mac']}  {host['vendor']}")
        C.info(f"Found {len(results)} live hosts")
        return results

    def get_arp_table(self) -> List[Dict[str, str]]:
        C.section("System ARP Table")
        entries: List[Dict[str, str]] = []
        try:
            output = subprocess.check_output(
                ["arp", "-a"], text=True, errors="replace",
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            C.fail("Unable to read ARP table")
            return entries

        if sys.platform == "win32":
            for line in output.splitlines():
                m = re.match(
                    r"\s*([\d.]+)\s+([\w:-]+)\s+(\w+)", line,
                )
                if m and m.group(2) != "---":
                    entries.append({
                        "ip": m.group(1),
                        "mac": m.group(2).replace("-", ":"),
                        "type": m.group(3),
                    })
        else:
            for line in output.splitlines():
                m = re.match(
                    r".*?\(([\d.]+)\)\s+at\s+([\w:]+).*?on\s+(\S+)", line,
                )
                if m:
                    entries.append({
                        "ip": m.group(1), "mac": m.group(2),
                        "interface": m.group(3),
                    })

        for e in entries:
            C.ok(f"{e['ip']:>15}  {e['mac']}")
        return entries

    def detect_spoofing(self) -> List[Dict[str, Any]]:
        C.section("ARP Spoofing Detection")
        table = self.get_arp_table()
        mac_to_ips: Dict[str, List[str]] = defaultdict(list)
        ip_to_macs: Dict[str, List[str]] = defaultdict(list)

        for entry in table:
            mac = entry["mac"].lower()
            ip = entry["ip"]
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                mac_to_ips[mac].append(ip)
                ip_to_macs[ip].append(mac)

        alerts: List[Dict[str, Any]] = []

        for ip, macs in ip_to_macs.items():
            unique = list(set(macs))
            if len(unique) > 1:
                alert = {
                    "type": "duplicate_mac_for_ip",
                    "ip": ip, "macs": unique,
                    "severity": "HIGH",
                    "detail": f"IP {ip} maps to multiple MACs: {unique}",
                }
                alerts.append(alert)
                C.warn(f"{C.RED}SPOOF ALERT:{C.R} {alert['detail']}")

        for mac, ips in mac_to_ips.items():
            unique = list(set(ips))
            if len(unique) > 5:
                alert = {
                    "type": "mac_many_ips",
                    "mac": mac, "ips": unique,
                    "severity": "MEDIUM",
                    "detail": f"MAC {mac} claims {len(unique)} IPs (possible gateway spoof)",
                }
                alerts.append(alert)
                C.warn(f"{C.YLW}ANOMALY:{C.R} {alert['detail']}")

        if not alerts:
            C.ok("No ARP spoofing indicators detected")
        return alerts

    def detect_gratuitous_arp(
        self, interface: Optional[str] = None, duration: int = 30,
    ) -> List[Dict[str, Any]]:
        C.section("Gratuitous ARP Detection")
        C.info(f"Monitoring for {duration}s ...")
        alerts: List[Dict[str, Any]] = []

        if HAS_SCAPY:
            packets = scapy_sniff(
                filter="arp", timeout=duration,
                iface=interface, store=True,
            )
            for pkt in packets:
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    if arp.op == 2 and arp.psrc == arp.pdst:
                        alerts.append({
                            "type": "gratuitous_arp",
                            "ip": arp.psrc, "mac": arp.hwsrc,
                            "detail": f"Gratuitous ARP from {arp.hwsrc} for {arp.psrc}",
                        })
                        C.warn(f"Gratuitous ARP: {arp.hwsrc} -> {arp.psrc}")
        else:
            C.warn("Scapy not available; monitoring via raw socket (limited)")
            cap = PacketCapture()
            cap.capture(interface=interface, count=5000, timeout=duration)
            for p in cap.packets:
                if p.arp and p.arp.opcode == 2 and p.arp.sender_ip == p.arp.target_ip:
                    alerts.append({
                        "type": "gratuitous_arp",
                        "ip": p.arp.sender_ip, "mac": p.arp.sender_mac,
                        "detail": f"Gratuitous ARP from {p.arp.sender_mac}",
                    })
                    C.warn(f"Gratuitous ARP: {p.arp.sender_mac} -> {p.arp.sender_ip}")

        if not alerts:
            C.ok("No gratuitous ARP detected")
        C.info(f"Total alerts: {len(alerts)}")
        return alerts

    @staticmethod
    def _ping_host(ip: str) -> bool:
        flag = "-n" if sys.platform == "win32" else "-c"
        try:
            subprocess.check_output(
                ["ping", flag, "1", "-w", "500", ip],
                stderr=subprocess.DEVNULL,
            )
            return True
        except subprocess.SubprocessError:
            return False

    @staticmethod
    def _resolve_mac(ip: str) -> str:
        try:
            output = subprocess.check_output(
                ["arp", "-a", ip], text=True, errors="replace",
            )
            m = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", output)
            return m.group(0).replace("-", ":") if m else "unknown"
        except subprocess.SubprocessError:
            return "unknown"

    @staticmethod
    def _oui_lookup(mac: str) -> str:
        oui_map: Dict[str, str] = {
            "00:50:56": "VMware", "00:0c:29": "VMware",
            "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
            "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
            "00:1a:79": "Apple", "3c:22:fb": "Apple",
            "f8:ff:c2": "Apple", "ac:de:48": "Apple",
            "00:15:5d": "Hyper-V",
        }
        prefix = mac[:8].lower()
        return oui_map.get(prefix, "")


# =============================================================================
#  DNS INTERCEPTOR
# =============================================================================

class DNSInterceptor:
    """DNS traffic monitoring, tunneling detection, and poisoning detection."""

    def __init__(self):
        self.queries: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []

    def monitor(
        self,
        interface: Optional[str] = None,
        duration: int = 60,
    ) -> Dict[str, Any]:
        C.section("DNS Traffic Monitor")
        self.queries.clear()
        self.responses.clear()

        if HAS_SCAPY:
            C.info(f"Sniffing DNS on {'all' if not interface else interface} "
                   f"for {duration}s")
            packets = scapy_sniff(
                filter="udp port 53", timeout=duration,
                iface=interface, store=True,
            )
            for pkt in packets:
                if pkt.haslayer(DNS):
                    dns_layer = pkt[DNS]
                    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                    if dns_layer.qr == 0 and dns_layer.haslayer(DNSQR):
                        qname = dns_layer[DNSQR].qname.decode(errors="replace").rstrip(".")
                        self.queries.append({
                            "timestamp": ts,
                            "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                            "dst": pkt[IP].dst if pkt.haslayer(IP) else "?",
                            "query": qname,
                            "qtype": dns_layer[DNSQR].qtype,
                            "txid": dns_layer.id,
                        })
                    elif dns_layer.qr == 1:
                        answers = []
                        for i in range(dns_layer.ancount):
                            try:
                                rr = dns_layer.an[i]
                                answers.append({
                                    "name": rr.rrname.decode(errors="replace").rstrip("."),
                                    "rdata": str(rr.rdata),
                                    "ttl": rr.ttl,
                                })
                            except (IndexError, AttributeError):
                                break
                        qname = ""
                        if dns_layer.haslayer(DNSQR):
                            qname = dns_layer[DNSQR].qname.decode(errors="replace").rstrip(".")
                        self.responses.append({
                            "timestamp": ts,
                            "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                            "txid": dns_layer.id,
                            "query": qname,
                            "answers": answers,
                            "rcode": dns_layer.rcode,
                        })
        else:
            C.info("Capturing DNS via raw sockets (port 53 only)")
            cap = PacketCapture()
            cap.capture(interface=interface, count=10000, timeout=duration)
            for p in cap.packets:
                if p.udp and (p.udp.src_port == 53 or p.udp.dst_port == 53):
                    self._parse_dns_payload(p)

        C.ok(f"Queries: {len(self.queries)}  Responses: {len(self.responses)}")
        return {
            "queries": self.queries, "responses": self.responses,
            "unique_domains": list({q["query"] for q in self.queries}),
        }

    def _parse_dns_payload(self, pkt: CapturedPacket) -> None:
        payload = pkt.udp.payload if pkt.udp else b""
        if len(payload) < 12:
            return
        txid = struct.unpack("!H", payload[0:2])[0]
        flags = struct.unpack("!H", payload[2:4])[0]
        qr = (flags >> 15) & 1
        qdcount = struct.unpack("!H", payload[4:6])[0]

        offset = 12
        qname_parts: List[str] = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1
            qname_parts.append(payload[offset:offset + length].decode(errors="replace"))
            offset += length
        qname = ".".join(qname_parts)
        ts = pkt.timestamp
        src = pkt.ip.src_ip if pkt.ip else "?"

        if qr == 0:
            self.queries.append({
                "timestamp": ts, "src": src, "query": qname,
                "txid": txid, "qtype": 0, "dst": pkt.ip.dst_ip if pkt.ip else "?",
            })
        else:
            self.responses.append({
                "timestamp": ts, "src": src, "txid": txid,
                "query": qname, "answers": [], "rcode": flags & 0xF,
            })

    def extract_queries(self) -> List[str]:
        return list({q["query"] for q in self.queries})

    def detect_tunneling(self, threshold_label: int = DNS_TUNNEL_LABEL_THRESHOLD,
                         threshold_total: int = DNS_TUNNEL_TOTAL_THRESHOLD) -> List[Dict[str, Any]]:
        C.section("DNS Tunneling Detection")
        alerts: List[Dict[str, Any]] = []
        for q in self.queries:
            domain = q["query"]
            labels = domain.split(".")
            max_label = max((len(l) for l in labels), default=0)
            total_len = len(domain)

            suspicious = False
            reasons: List[str] = []
            if max_label > threshold_label:
                suspicious = True
                reasons.append(f"label length {max_label} > {threshold_label}")
            if total_len > threshold_total:
                suspicious = True
                reasons.append(f"total length {total_len} > {threshold_total}")
            entropy = self._shannon_entropy(domain.replace(".", ""))
            if entropy > 3.8 and total_len > 40:
                suspicious = True
                reasons.append(f"high entropy {entropy:.2f}")

            if suspicious:
                alert = {
                    "query": domain, "src": q.get("src", "?"),
                    "reasons": reasons, "entropy": round(entropy, 3),
                    "timestamp": q["timestamp"],
                }
                alerts.append(alert)
                C.warn(f"Possible tunnel: {domain[:60]}... ({', '.join(reasons)})")

        if not alerts:
            C.ok("No DNS tunneling indicators")
        else:
            C.warn(f"{len(alerts)} suspicious queries detected")
        return alerts

    def detect_poisoning(self) -> List[Dict[str, Any]]:
        C.section("DNS Poisoning Detection")
        alerts: List[Dict[str, Any]] = []
        txid_responses: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for r in self.responses:
            txid_responses[r["txid"]].append(r)

        for txid, resps in txid_responses.items():
            if len(resps) > 1:
                sources = list({r["src"] for r in resps})
                if len(sources) > 1:
                    alert = {
                        "type": "multiple_responders",
                        "txid": txid,
                        "sources": sources,
                        "detail": f"TXID {txid:#06x} answered by {len(sources)} sources: {sources}",
                    }
                    alerts.append(alert)
                    C.warn(f"{C.RED}POISON ALERT:{C.R} {alert['detail']}")

        query_txids = {q["txid"] for q in self.queries}
        for r in self.responses:
            if r["txid"] not in query_txids:
                alert = {
                    "type": "unsolicited_response",
                    "txid": r["txid"], "src": r["src"],
                    "detail": f"Response TXID {r['txid']:#06x} from {r['src']} has no matching query",
                }
                alerts.append(alert)
                C.warn(f"{C.YLW}UNSOLICITED:{C.R} {alert['detail']}")

        if not alerts:
            C.ok("No DNS poisoning indicators")
        return alerts

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: Counter = Counter(data)
        length = len(data)
        import math
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )


# =============================================================================
#  OS FINGERPRINTER
# =============================================================================

class OSFingerprinter:
    """Passive OS detection from observed TCP/IP parameters."""

    def fingerprint(self, ip: str, interface: Optional[str] = None,
                    timeout: int = 15) -> Dict[str, Any]:
        C.section(f"OS Fingerprint: {ip}")
        observed: Dict[str, Any] = {"ip": ip, "samples": []}

        cap = PacketCapture()
        bpf = f"host {ip}" if HAS_SCAPY else None
        cap.capture(interface=interface, count=500, timeout=timeout, bpf_filter=bpf)

        for p in cap.packets:
            if p.ip and p.ip.src_ip == ip and p.tcp and ("SYN" in p.tcp.flag_names):
                options = _parse_tcp_options(p.tcp.options_raw)
                observed["samples"].append({
                    "ttl": p.ip.ttl, "window": p.tcp.window,
                    "df": p.ip.df_flag, "options": options,
                    "flags": p.tcp.flag_names,
                })

        if not observed["samples"]:
            C.warn("No SYN packets observed from target")
            observed["guess"] = "Unknown"
            return observed

        best_match, best_score = "Unknown", 0.0
        sample = observed["samples"][0]
        for os_name, sig in OS_FINGERPRINTS.items():
            score = self._match_score(sample, sig)
            if score > best_score:
                best_score = score
                best_match = os_name

        observed["guess"] = best_match
        observed["confidence"] = round(best_score * 100, 1)
        observed["ttl_guess"] = self._ttl_guess(sample["ttl"])

        C.ok(f"Best match: {C.BLD}{best_match}{C.R} "
             f"(confidence: {observed['confidence']}%)")
        C.info(f"TTL={sample['ttl']} Window={sample['window']} "
               f"DF={sample['df']} Options={sample['options']}")
        return observed

    @staticmethod
    def _match_score(sample: Dict[str, Any], sig: Dict[str, Any]) -> float:
        score = 0.0
        ttl_diff = abs(sample["ttl"] - sig["ttl"])
        if ttl_diff == 0:
            score += 0.30
        elif ttl_diff <= 5:
            score += 0.20
        elif ttl_diff <= 15:
            score += 0.10

        if sample["window"] == sig["window"]:
            score += 0.25
        elif abs(sample["window"] - sig["window"]) < 1000:
            score += 0.10

        if sample["df"] == sig["df"]:
            score += 0.15

        if sample["options"] == sig["options_order"]:
            score += 0.30
        else:
            common = len(set(sample["options"]) & set(sig["options_order"]))
            total = max(len(sig["options_order"]), 1)
            score += 0.30 * (common / total) * 0.5
        return score

    @staticmethod
    def _ttl_guess(ttl: int) -> str:
        if ttl <= 64:
            return "Linux/macOS/Unix (base TTL 64)"
        if ttl <= 128:
            return "Windows (base TTL 128)"
        return "Cisco/Solaris/Network device (base TTL 255)"


# =============================================================================
#  NETWORK ANALYZER
# =============================================================================

class NetworkAnalyzer:
    """Traffic analysis: bandwidth, connections, protocol stats, top talkers."""

    def bandwidth_monitor(self, interface: Optional[str] = None,
                          duration: int = 10, interval: float = 1.0) -> Dict[str, Any]:
        C.section(f"Bandwidth Monitor ({duration}s)")
        samples: List[Dict[str, Any]] = []
        cap = PacketCapture()

        stop_event = threading.Event()
        capture_thread = threading.Thread(
            target=cap.capture,
            kwargs={"interface": interface, "count": 100_000, "timeout": duration},
            daemon=True,
        )
        capture_thread.start()

        start = time.time()
        prev_count = 0
        prev_bytes = 0
        while (time.time() - start) < duration:
            time.sleep(interval)
            cur_count = len(cap.packets)
            cur_bytes = sum(p.length for p in cap.packets)
            delta_pkts = cur_count - prev_count
            delta_bytes = cur_bytes - prev_bytes
            bps = delta_bytes / max(interval, 0.001)
            samples.append({
                "time": round(time.time() - start, 2),
                "packets_per_sec": delta_pkts / max(interval, 0.001),
                "bytes_per_sec": bps,
                "mbps": round(bps * 8 / 1_000_000, 3),
            })
            C.info(f"t={samples[-1]['time']:>6.1f}s  "
                   f"{delta_pkts:>5} pkt/s  {samples[-1]['mbps']:>8.3f} Mbps")
            prev_count = cur_count
            prev_bytes = cur_bytes

        capture_thread.join(timeout=3)
        total_bytes = sum(p.length for p in cap.packets)
        return {
            "duration": duration,
            "total_packets": len(cap.packets),
            "total_bytes": total_bytes,
            "avg_mbps": round(total_bytes * 8 / max(duration, 1) / 1_000_000, 3),
            "samples": samples,
        }

    def connection_tracker(self) -> List[Dict[str, Any]]:
        C.section("Active Connections")
        connections: List[Dict[str, Any]] = []
        try:
            if sys.platform == "win32":
                output = subprocess.check_output(
                    ["netstat", "-n", "-o"], text=True, errors="replace",
                )
            else:
                output = subprocess.check_output(
                    ["ss", "-tunap"], text=True, errors="replace",
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            try:
                output = subprocess.check_output(
                    ["netstat", "-tunap"], text=True, errors="replace",
                )
            except (subprocess.SubprocessError, FileNotFoundError):
                C.fail("Cannot retrieve connection data")
                return connections

        for line in output.splitlines()[2:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            if sys.platform == "win32" and parts[0] in ("TCP", "UDP"):
                entry: Dict[str, Any] = {
                    "proto": parts[0],
                    "local": parts[1],
                    "remote": parts[2],
                    "state": parts[3] if len(parts) > 3 else "",
                }
                if len(parts) > 4:
                    entry["pid"] = parts[4]
                connections.append(entry)
            elif parts[0] in ("tcp", "udp", "tcp6", "udp6"):
                entry = {
                    "proto": parts[0],
                    "state": parts[1] if "tcp" in parts[0] else "",
                    "local": parts[4] if len(parts) > 4 else "",
                    "remote": parts[5] if len(parts) > 5 else "",
                }
                connections.append(entry)

        for c in connections[:30]:
            state_color = C.GRN if c.get("state") == "ESTABLISHED" else C.YLW
            C.ok(f"{c['proto']:<6} {c['local']:<22} -> {c['remote']:<22} "
                 f"{state_color}{c.get('state', '')}{C.R}")
        if len(connections) > 30:
            C.info(f"... and {len(connections) - 30} more")
        C.info(f"Total connections: {len(connections)}")
        return connections

    def protocol_distribution(self, interface: Optional[str] = None,
                              duration: int = 15) -> Dict[str, Any]:
        C.section("Protocol Distribution")
        cap = PacketCapture()
        cap.capture(interface=interface, count=5000, timeout=duration)

        proto_bytes: Counter = Counter()
        proto_count: Counter = Counter()
        port_count: Counter = Counter()

        for p in cap.packets:
            size = p.length
            if p.tcp:
                proto_count["TCP"] += 1
                proto_bytes["TCP"] += size
                port_count[p.tcp.dst_port] += 1
            elif p.udp:
                proto_count["UDP"] += 1
                proto_bytes["UDP"] += size
                port_count[p.udp.dst_port] += 1
            elif p.icmp:
                proto_count["ICMP"] += 1
                proto_bytes["ICMP"] += size
            elif p.arp:
                proto_count["ARP"] += 1
                proto_bytes["ARP"] += size
            else:
                proto_count["Other"] += 1
                proto_bytes["Other"] += size

        total = sum(proto_count.values()) or 1
        dist: Dict[str, Any] = {}
        for proto, cnt in proto_count.most_common():
            pct = cnt / total * 100
            bar = "#" * int(pct / 2)
            C.ok(f"{proto:<8} {cnt:>6} pkts ({pct:>5.1f}%)  {C.CYN}{bar}{C.R}")
            dist[proto] = {
                "packets": cnt, "bytes": proto_bytes[proto],
                "percent": round(pct, 2),
            }

        C.info("Top destination ports:")
        for port, cnt in port_count.most_common(10):
            svc = self._port_service(port)
            C.info(f"  :{port:<6} ({svc:<12}) {cnt} packets")

        return {"protocols": dist, "top_ports": dict(port_count.most_common(20))}

    def top_talkers(self, n: int = 10, interface: Optional[str] = None,
                    duration: int = 15) -> List[Dict[str, Any]]:
        C.section(f"Top {n} Talkers")
        cap = PacketCapture()
        cap.capture(interface=interface, count=5000, timeout=duration)

        ip_bytes_sent: Counter = Counter()
        ip_bytes_recv: Counter = Counter()
        ip_pkts: Counter = Counter()

        for p in cap.packets:
            if p.ip:
                ip_pkts[p.ip.src_ip] += 1
                ip_bytes_sent[p.ip.src_ip] += p.length
                ip_bytes_recv[p.ip.dst_ip] += p.length

        talkers: List[Dict[str, Any]] = []
        for ip, pkts in ip_pkts.most_common(n):
            entry = {
                "ip": ip,
                "packets": pkts,
                "bytes_sent": ip_bytes_sent[ip],
                "bytes_recv": ip_bytes_recv.get(ip, 0),
            }
            talkers.append(entry)
            total_kb = (entry["bytes_sent"] + entry["bytes_recv"]) / 1024
            C.ok(f"{ip:<16} {pkts:>6} pkts  {total_kb:>8.1f} KB")

        return talkers

    @staticmethod
    def _port_service(port: int) -> str:
        services: Dict[int, str] = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
            80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        return services.get(port, "unknown")


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network_sniffer",
        description="FU PERSON :: Network Sniffer & Spoofing Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s capture -c 200 -t 30 -o capture.pcap
              %(prog)s arp-scan --cidr 192.168.1.0/24
              %(prog)s dns-monitor -d 120
              %(prog)s fingerprint --ip 10.0.0.1
              %(prog)s analyze --mode bandwidth -d 20
        """),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- capture --
    p_cap = sub.add_parser("capture", help="Capture network packets")
    p_cap.add_argument("-i", "--interface", default=None, help="Network interface")
    p_cap.add_argument("-c", "--count", type=int, default=100, help="Packet count")
    p_cap.add_argument("-t", "--timeout", type=int, default=30, help="Timeout (seconds)")
    p_cap.add_argument("-f", "--filter", default=None, help="BPF filter (scapy only)")
    p_cap.add_argument("-o", "--output", default=None, help="PCAP output file")
    p_cap.add_argument("--hex", action="store_true", help="Show hex dump")
    p_cap.add_argument("--json", action="store_true", dest="as_json", help="JSON output")

    # -- arp-scan --
    p_arp = sub.add_parser("arp-scan", help="ARP network discovery & spoof detection")
    p_arp.add_argument("--cidr", required=True, help="Target CIDR (e.g. 192.168.1.0/24)")
    p_arp.add_argument("--spoof-check", action="store_true", help="Run spoof detection")
    p_arp.add_argument("--gratuitous", action="store_true", help="Monitor gratuitous ARP")
    p_arp.add_argument("-d", "--duration", type=int, default=30, help="Monitor duration")
    p_arp.add_argument("-i", "--interface", default=None, help="Network interface")

    # -- dns-monitor --
    p_dns = sub.add_parser("dns-monitor", help="DNS traffic monitoring")
    p_dns.add_argument("-i", "--interface", default=None, help="Network interface")
    p_dns.add_argument("-d", "--duration", type=int, default=60, help="Monitor duration")
    p_dns.add_argument("--tunnel-check", action="store_true", help="Detect DNS tunneling")
    p_dns.add_argument("--poison-check", action="store_true", help="Detect DNS poisoning")
    p_dns.add_argument("--json", action="store_true", dest="as_json", help="JSON output")

    # -- fingerprint --
    p_fp = sub.add_parser("fingerprint", help="Passive OS fingerprinting")
    p_fp.add_argument("--ip", required=True, help="Target IP to fingerprint")
    p_fp.add_argument("-i", "--interface", default=None, help="Network interface")
    p_fp.add_argument("-t", "--timeout", type=int, default=15, help="Capture timeout")

    # -- analyze --
    p_an = sub.add_parser("analyze", help="Traffic analysis")
    p_an.add_argument(
        "--mode", choices=["bandwidth", "connections", "protocols", "talkers"],
        default="connections", help="Analysis mode",
    )
    p_an.add_argument("-i", "--interface", default=None, help="Network interface")
    p_an.add_argument("-d", "--duration", type=int, default=15, help="Capture duration")
    p_an.add_argument("-n", "--top", type=int, default=10, help="Top N talkers")
    p_an.add_argument("--json", action="store_true", dest="as_json", help="JSON output")

    return parser


import textwrap  # noqa: E402 (used in epilog above, imported here for clarity)


def main() -> None:
    C.p(BANNER)
    parser = _build_parser()
    args = parser.parse_args()

    result: Any = None

    if args.command == "capture":
        engine = PacketCapture()
        packets = engine.capture(
            interface=args.interface, count=args.count,
            timeout=args.timeout, bpf_filter=args.filter,
            pcap_file=args.output,
        )
        C.p(f"\n{engine.summary()}")
        if args.as_json:
            print(json.dumps([p.to_dict() for p in packets], indent=2, default=str))
        elif args.hex:
            for i, p in enumerate(packets[:50]):
                C.p(f"\n  {C.BLD}--- Packet {i + 1} ({p.length} bytes) ---{C.R}")
                C.p(hexdump(p.raw))
        else:
            for i, p in enumerate(packets[:50]):
                d = p.to_dict()
                proto = ""
                info = ""
                if p.tcp:
                    proto = "TCP"
                    info = (f"{p.ip.src_ip}:{p.tcp.src_port} -> "
                            f"{p.ip.dst_ip}:{p.tcp.dst_port} "
                            f"[{','.join(p.tcp.flag_names)}]")
                elif p.udp:
                    proto = "UDP"
                    info = (f"{p.ip.src_ip}:{p.udp.src_port} -> "
                            f"{p.ip.dst_ip}:{p.udp.dst_port}")
                elif p.icmp:
                    proto = "ICMP"
                    info = (f"{p.ip.src_ip} -> {p.ip.dst_ip} "
                            f"type={p.icmp.icmp_type} code={p.icmp.code}")
                elif p.arp:
                    proto = "ARP"
                    info = (f"{p.arp.sender_ip} ({p.arp.sender_mac}) -> "
                            f"{p.arp.target_ip}")
                C.ok(f"{i + 1:>4}  {proto:<5} {info}")

    elif args.command == "arp-scan":
        scanner = ARPScanner()
        scanner.scan_network(args.cidr)
        if args.spoof_check:
            scanner.detect_spoofing()
        if args.gratuitous:
            scanner.detect_gratuitous_arp(
                interface=args.interface, duration=args.duration,
            )

    elif args.command == "dns-monitor":
        interceptor = DNSInterceptor()
        result = interceptor.monitor(
            interface=args.interface, duration=args.duration,
        )
        if args.tunnel_check:
            interceptor.detect_tunneling()
        if args.poison_check:
            interceptor.detect_poisoning()
        if args.as_json:
            print(json.dumps(result, indent=2, default=str))
        else:
            C.info("Unique domains queried:")
            for domain in sorted(result["unique_domains"])[:50]:
                C.ok(f"  {domain}")

    elif args.command == "fingerprint":
        fp = OSFingerprinter()
        result = fp.fingerprint(
            ip=args.ip, interface=args.interface, timeout=args.timeout,
        )

    elif args.command == "analyze":
        analyzer = NetworkAnalyzer()
        if args.mode == "bandwidth":
            result = analyzer.bandwidth_monitor(
                interface=args.interface, duration=args.duration,
            )
        elif args.mode == "connections":
            result = analyzer.connection_tracker()
        elif args.mode == "protocols":
            result = analyzer.protocol_distribution(
                interface=args.interface, duration=args.duration,
            )
        elif args.mode == "talkers":
            result = analyzer.top_talkers(
                n=args.top, interface=args.interface, duration=args.duration,
            )
        if args.as_json and result:
            print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
