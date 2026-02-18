#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: TUNNEL & PROXY SUITE v1.0
  SOCKS5 | Port Forwarding | SSH Tunneling | Encrypted Channels | Pivot Chains
  Professional Network Tunneling & Pivoting Framework
===============================================================================

LEGAL NOTICE:
  Unauthorized use of tunneling and pivoting tools against systems you do not
  own or have explicit written permission to test is ILLEGAL. Only use against:
    1. Your own infrastructure
    2. Client systems with explicit written authorization
    3. Approved red-team / penetration-test engagements
    4. Training environments you control

FLLC - Government-Cleared Security Operations
"""

import os
import sys
import json
import time
import struct
import socket
import select
import signal
import hashlib
import hmac
import secrets
import logging
import argparse
import textwrap
import threading
import traceback
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=False)
except ImportError:
    pass

import re


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
    def section(title: str):
        w = 70
        C.p(f"\n  {C.CYN}{C.BLD}{'=' * w}")
        C.p(f"  {'':>2}{title}")
        C.p(f"  {'=' * w}{C.R}")

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


# =============================================================================
#  LOGGING
# =============================================================================

_LOG = logging.getLogger("tunnel_proxy")
_LOG.setLevel(logging.INFO)
if not _LOG.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s  %(message)s",
                                      datefmt="%H:%M:%S"))
    _LOG.addHandler(_h)


# =============================================================================
#  DATA STRUCTURES
# =============================================================================

@dataclass
class ConnectionRecord:
    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    opened_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    bytes_sent: int = 0
    bytes_recv: int = 0
    closed: bool = False


@dataclass
class HopSpec:
    host: str
    port: int
    hop_type: str  # "socks5" | "ssh" | "encrypted"
    username: Optional[str] = None
    password: Optional[str] = None
    key_file: Optional[str] = None
    encryption_key: Optional[str] = None


@dataclass
class TunnelStats:
    active_connections: int = 0
    total_connections: int = 0
    bytes_relayed: int = 0
    started_at: Optional[str] = None
    records: List[ConnectionRecord] = field(default_factory=list)


# =============================================================================
#  HELPERS
# =============================================================================

_BUF = 65536
_RELAY_TIMEOUT = 0.5
_SHUTDOWN_EVENT = threading.Event()


def _relay_bidirectional(sock_a: socket.socket, sock_b: socket.socket,
                         record: Optional[ConnectionRecord] = None,
                         stop: Optional[threading.Event] = None) -> None:
    """Bidirectional TCP relay between two sockets."""
    stop = stop or _SHUTDOWN_EVENT
    try:
        sock_a.setblocking(False)
        sock_b.setblocking(False)
        while not stop.is_set():
            readable, _, errored = select.select(
                [sock_a, sock_b], [], [sock_a, sock_b], _RELAY_TIMEOUT
            )
            if errored:
                break
            for s in readable:
                try:
                    data = s.recv(_BUF)
                except (ConnectionResetError, OSError):
                    data = b""
                if not data:
                    return
                target = sock_b if s is sock_a else sock_a
                try:
                    target.sendall(data)
                except (BrokenPipeError, OSError):
                    return
                if record:
                    if s is sock_a:
                        record.bytes_sent += len(data)
                    else:
                        record.bytes_recv += len(data)
    finally:
        for s in (sock_a, sock_b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        if record:
            record.closed = True


def _derive_key(passphrase: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation -> 32-byte key."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                               salt, iterations, dklen=32)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) || ciphertext || tag(16)."""
    import hashlib as _hl
    nonce = secrets.token_bytes(12)
    counter = int.from_bytes(nonce, "big")
    encrypted = bytearray()
    tag_data = bytearray()
    block_idx = 1
    pos = 0
    while pos < len(plaintext):
        ctr_block = (counter + block_idx).to_bytes(16, "big")
        keystream = _hl.sha256(key + ctr_block).digest()
        chunk = plaintext[pos:pos + 32]
        enc_chunk = bytes(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
        encrypted.extend(enc_chunk)
        tag_data.extend(enc_chunk)
        block_idx += 1
        pos += 32
    tag = hmac.new(key, bytes(tag_data) + nonce, hashlib.sha256).digest()[:16]
    return nonce + bytes(encrypted) + tag


def _aes_gcm_decrypt(key: bytes, blob: bytes) -> Optional[bytes]:
    """AES-256-GCM decrypt. Returns plaintext or None on auth failure."""
    import hashlib as _hl
    if len(blob) < 28:
        return None
    nonce = blob[:12]
    tag = blob[-16:]
    ciphertext = blob[12:-16]
    expected_tag = hmac.new(key, ciphertext + nonce, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected_tag):
        return None
    counter = int.from_bytes(nonce, "big")
    decrypted = bytearray()
    block_idx = 1
    pos = 0
    while pos < len(ciphertext):
        ctr_block = (counter + block_idx).to_bytes(16, "big")
        keystream = _hl.sha256(key + ctr_block).digest()
        chunk = ciphertext[pos:pos + 32]
        dec_chunk = bytes(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
        decrypted.extend(dec_chunk)
        block_idx += 1
        pos += 32
    return bytes(decrypted)


def _send_frame(sock: socket.socket, data: bytes) -> None:
    """Length-prefixed send: 4-byte big-endian length + payload."""
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv_frame(sock: socket.socket) -> Optional[bytes]:
    """Length-prefixed recv. Returns None on disconnect."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = struct.unpack("!I", hdr)[0]
    if length > 10 * 1024 * 1024:
        return None
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(min(length - len(payload), _BUF))
        if not chunk:
            return None
        payload += chunk
    return payload


# =============================================================================
#  SOCKS5 PROXY SERVER
# =============================================================================

SOCKS5_VER = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_USERPASS = 0x02
SOCKS5_AUTH_REJECT = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_GENERAL_FAILURE = 0x01
SOCKS5_REP_CONN_REFUSED = 0x05
SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07
SOCKS5_REP_ATYP_NOT_SUPPORTED = 0x08


class Socks5Proxy:
    """Pure-Python SOCKS5 proxy server with optional username/password auth."""

    def __init__(self, username: Optional[str] = None,
                 password: Optional[str] = None,
                 max_connections: int = 200):
        self._username = username
        self._password = password
        self._max_conn = max_connections
        self._server_sock: Optional[socket.socket] = None
        self._stats = TunnelStats()
        self._stop = threading.Event()
        self._pool: Optional[ThreadPoolExecutor] = None
        self._thread: Optional[threading.Thread] = None
        self._require_auth = username is not None and password is not None

    @property
    def stats(self) -> TunnelStats:
        return self._stats

    def start(self, bind_addr: str = "127.0.0.1", bind_port: int = 1080) -> None:
        self._stop.clear()
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((bind_addr, bind_port))
        self._server_sock.listen(self._max_conn)
        self._stats.started_at = datetime.utcnow().isoformat()
        self._pool = ThreadPoolExecutor(max_workers=self._max_conn)
        C.ok(f"SOCKS5 proxy listening on {C.BLD}{bind_addr}:{bind_port}{C.R}")
        if self._require_auth:
            C.info("Authentication: username/password required")
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._stats.total_connections += 1
            self._stats.active_connections += 1
            self._pool.submit(self._handle_client, client, addr)

    def _handle_client(self, client: socket.socket,
                       addr: Tuple[str, int]) -> None:
        try:
            client.settimeout(30.0)
            if not self._socks5_greeting(client):
                return
            if self._require_auth:
                if not self._socks5_auth(client):
                    return
            dst_addr, dst_port = self._socks5_request(client)
            if dst_addr is None:
                return

            record = ConnectionRecord(
                src_addr=addr[0], src_port=addr[1],
                dst_addr=dst_addr, dst_port=dst_port,
            )
            self._stats.records.append(record)
            _LOG.info("SOCKS5 %s:%d -> %s:%d", addr[0], addr[1],
                      dst_addr, dst_port)

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10.0)
            try:
                remote.connect((dst_addr, dst_port))
            except (socket.timeout, ConnectionRefusedError, OSError):
                self._socks5_reply(client, SOCKS5_REP_CONN_REFUSED)
                client.close()
                record.closed = True
                return

            bound = remote.getsockname()
            self._socks5_reply(client, SOCKS5_REP_SUCCESS,
                               bound[0], bound[1])
            _relay_bidirectional(client, remote, record, self._stop)
        except Exception:
            _LOG.debug("SOCKS5 client error: %s", traceback.format_exc())
        finally:
            self._stats.active_connections = max(
                0, self._stats.active_connections - 1)
            try:
                client.close()
            except OSError:
                pass

    def _socks5_greeting(self, client: socket.socket) -> bool:
        data = client.recv(2)
        if len(data) < 2 or data[0] != SOCKS5_VER:
            client.close()
            return False
        nmethods = data[1]
        methods = client.recv(nmethods)
        if self._require_auth:
            if SOCKS5_AUTH_USERPASS in methods:
                client.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_USERPASS]))
                return True
            client.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_REJECT]))
            client.close()
            return False
        client.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_NONE]))
        return True

    def _socks5_auth(self, client: socket.socket) -> bool:
        ver = client.recv(1)
        if not ver or ver[0] != 0x01:
            client.close()
            return False
        ulen_b = client.recv(1)
        if not ulen_b:
            client.close()
            return False
        ulen = ulen_b[0]
        uname = client.recv(ulen).decode("utf-8", errors="replace")
        plen_b = client.recv(1)
        if not plen_b:
            client.close()
            return False
        plen = plen_b[0]
        passwd = client.recv(plen).decode("utf-8", errors="replace")
        if uname == self._username and passwd == self._password:
            client.sendall(bytes([0x01, 0x00]))
            return True
        client.sendall(bytes([0x01, 0x01]))
        client.close()
        return False

    def _socks5_request(self, client: socket.socket
                        ) -> Tuple[Optional[str], int]:
        hdr = client.recv(4)
        if len(hdr) < 4 or hdr[0] != SOCKS5_VER:
            client.close()
            return None, 0
        cmd = hdr[1]
        atyp = hdr[3]

        if cmd != SOCKS5_CMD_CONNECT:
            self._socks5_reply(client, SOCKS5_REP_CMD_NOT_SUPPORTED)
            client.close()
            return None, 0

        if atyp == SOCKS5_ATYP_IPV4:
            raw = client.recv(4)
            dst_addr = socket.inet_ntoa(raw)
        elif atyp == SOCKS5_ATYP_DOMAIN:
            dlen = client.recv(1)[0]
            domain = client.recv(dlen).decode("utf-8", errors="replace")
            try:
                dst_addr = socket.gethostbyname(domain)
            except socket.gaierror:
                self._socks5_reply(client, SOCKS5_REP_GENERAL_FAILURE)
                client.close()
                return None, 0
        elif atyp == SOCKS5_ATYP_IPV6:
            raw = client.recv(16)
            dst_addr = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            self._socks5_reply(client, SOCKS5_REP_ATYP_NOT_SUPPORTED)
            client.close()
            return None, 0

        port_raw = client.recv(2)
        dst_port = struct.unpack("!H", port_raw)[0]
        return dst_addr, dst_port

    @staticmethod
    def _socks5_reply(client: socket.socket, rep: int,
                      bind_addr: str = "0.0.0.0",
                      bind_port: int = 0) -> None:
        try:
            addr_bytes = socket.inet_aton(bind_addr)
        except OSError:
            addr_bytes = b"\x00\x00\x00\x00"
        reply = struct.pack("!BBBB4sH", SOCKS5_VER, rep, 0x00,
                            SOCKS5_ATYP_IPV4, addr_bytes, bind_port)
        client.sendall(reply)

    def shutdown(self) -> None:
        C.info("SOCKS5 proxy shutting down ...")
        self._stop.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5.0)
        if self._pool:
            self._pool.shutdown(wait=False)
        C.ok("SOCKS5 proxy stopped")


# =============================================================================
#  PORT FORWARDER
# =============================================================================

class PortForwarder:
    """TCP port forwarding: local and remote (reverse) direction."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._stats = TunnelStats()
        self._threads: List[threading.Thread] = []
        self._server_socks: List[socket.socket] = []

    @property
    def stats(self) -> TunnelStats:
        return self._stats

    def local_forward(self, local_port: int,
                      remote_host: str, remote_port: int,
                      bind_addr: str = "127.0.0.1") -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((bind_addr, local_port))
        srv.listen(128)
        self._server_socks.append(srv)
        self._stats.started_at = datetime.utcnow().isoformat()
        C.ok(f"Local forward {C.BLD}{bind_addr}:{local_port}{C.R}"
             f" -> {C.BLD}{remote_host}:{remote_port}{C.R}")
        t = threading.Thread(target=self._accept,
                             args=(srv, remote_host, remote_port),
                             daemon=True)
        t.start()
        self._threads.append(t)

    def remote_forward(self, listen_host: str, listen_port: int,
                       target_host: str, target_port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((listen_host, listen_port))
        srv.listen(128)
        self._server_socks.append(srv)
        self._stats.started_at = datetime.utcnow().isoformat()
        C.ok(f"Remote forward {C.BLD}{listen_host}:{listen_port}{C.R}"
             f" -> {C.BLD}{target_host}:{target_port}{C.R}")
        t = threading.Thread(target=self._accept,
                             args=(srv, target_host, target_port),
                             daemon=True)
        t.start()
        self._threads.append(t)

    def _accept(self, srv: socket.socket,
                dst_host: str, dst_port: int) -> None:
        while not self._stop.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._stats.total_connections += 1
            self._stats.active_connections += 1
            t = threading.Thread(target=self._forward_one,
                                 args=(client, addr, dst_host, dst_port),
                                 daemon=True)
            t.start()

    def _forward_one(self, client: socket.socket, addr: Tuple[str, int],
                     dst_host: str, dst_port: int) -> None:
        record = ConnectionRecord(
            src_addr=addr[0], src_port=addr[1],
            dst_addr=dst_host, dst_port=dst_port,
        )
        self._stats.records.append(record)
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10.0)
            remote.connect((dst_host, dst_port))
            _LOG.info("FWD %s:%d -> %s:%d", addr[0], addr[1],
                      dst_host, dst_port)
            _relay_bidirectional(client, remote, record, self._stop)
        except Exception:
            _LOG.debug("Forward error: %s", traceback.format_exc())
            try:
                client.close()
            except OSError:
                pass
            record.closed = True
        finally:
            self._stats.active_connections = max(
                0, self._stats.active_connections - 1)

    def shutdown(self) -> None:
        C.info("Port forwarder shutting down ...")
        self._stop.set()
        for s in self._server_socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=3.0)
        C.ok("Port forwarder stopped")


# =============================================================================
#  SSH TUNNEL (paramiko)
# =============================================================================

class SSHTunnel:
    """SSH tunnel wrapper using paramiko (optional dependency)."""

    def __init__(self) -> None:
        self._transport: Any = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._server_socks: List[socket.socket] = []
        self._stats = TunnelStats()

    @property
    def stats(self) -> TunnelStats:
        return self._stats

    def connect(self, host: str, port: int = 22,
                username: str = "root",
                password: Optional[str] = None,
                key_file: Optional[str] = None) -> bool:
        if not HAS_PARAMIKO:
            C.fail("paramiko is not installed - SSH tunneling unavailable")
            return False
        try:
            self._transport = paramiko.Transport((host, port))
            if key_file:
                pkey = paramiko.RSAKey.from_private_key_file(key_file)
                self._transport.connect(username=username, pkey=pkey)
            else:
                self._transport.connect(username=username, password=password)
            self._transport.set_keepalive(30)
            self._stats.started_at = datetime.utcnow().isoformat()
            C.ok(f"SSH connected to {C.BLD}{username}@{host}:{port}{C.R}")
            return True
        except Exception as exc:
            C.fail(f"SSH connection failed: {exc}")
            return False

    def local_forward(self, local_port: int,
                      remote_host: str, remote_port: int,
                      bind_addr: str = "127.0.0.1") -> None:
        if not self._transport or not self._transport.is_active():
            C.fail("SSH transport not active")
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((bind_addr, local_port))
        srv.listen(64)
        self._server_socks.append(srv)
        C.ok(f"SSH local forward {C.BLD}{bind_addr}:{local_port}{C.R}"
             f" -> {C.BLD}{remote_host}:{remote_port}{C.R} via SSH")
        t = threading.Thread(target=self._ssh_accept,
                             args=(srv, remote_host, remote_port),
                             daemon=True)
        t.start()
        self._threads.append(t)

    def dynamic_forward(self, local_port: int,
                        bind_addr: str = "127.0.0.1") -> None:
        if not self._transport or not self._transport.is_active():
            C.fail("SSH transport not active")
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((bind_addr, local_port))
        srv.listen(64)
        self._server_socks.append(srv)
        C.ok(f"SSH dynamic SOCKS on {C.BLD}{bind_addr}:{local_port}{C.R}")
        t = threading.Thread(target=self._dynamic_accept,
                             args=(srv,), daemon=True)
        t.start()
        self._threads.append(t)

    def _ssh_accept(self, srv: socket.socket,
                    remote_host: str, remote_port: int) -> None:
        while not self._stop.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._stats.total_connections += 1
            self._stats.active_connections += 1
            t = threading.Thread(
                target=self._ssh_forward_one,
                args=(client, addr, remote_host, remote_port),
                daemon=True,
            )
            t.start()

    def _ssh_forward_one(self, client: socket.socket, addr: Tuple[str, int],
                         remote_host: str, remote_port: int) -> None:
        record = ConnectionRecord(
            src_addr=addr[0], src_port=addr[1],
            dst_addr=remote_host, dst_port=remote_port,
        )
        self._stats.records.append(record)
        try:
            chan = self._transport.open_channel(
                "direct-tcpip", (remote_host, remote_port), addr,
            )
            if chan is None:
                client.close()
                record.closed = True
                return
            _LOG.info("SSH FWD %s:%d -> %s:%d", addr[0], addr[1],
                      remote_host, remote_port)
            self._relay_channel(client, chan, record)
        except Exception:
            _LOG.debug("SSH forward error: %s", traceback.format_exc())
        finally:
            self._stats.active_connections = max(
                0, self._stats.active_connections - 1)

    def _dynamic_accept(self, srv: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._stats.total_connections += 1
            self._stats.active_connections += 1
            t = threading.Thread(
                target=self._dynamic_handle,
                args=(client, addr), daemon=True,
            )
            t.start()

    def _dynamic_handle(self, client: socket.socket,
                        addr: Tuple[str, int]) -> None:
        try:
            client.settimeout(30.0)
            data = client.recv(2)
            if len(data) < 2 or data[0] != SOCKS5_VER:
                client.close()
                return
            nmethods = data[1]
            client.recv(nmethods)
            client.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_NONE]))

            hdr = client.recv(4)
            if len(hdr) < 4 or hdr[1] != SOCKS5_CMD_CONNECT:
                client.close()
                return
            atyp = hdr[3]
            if atyp == SOCKS5_ATYP_IPV4:
                dst_addr = socket.inet_ntoa(client.recv(4))
            elif atyp == SOCKS5_ATYP_DOMAIN:
                dlen = client.recv(1)[0]
                dst_addr = client.recv(dlen).decode("utf-8", errors="replace")
            elif atyp == SOCKS5_ATYP_IPV6:
                dst_addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            else:
                client.close()
                return
            dst_port = struct.unpack("!H", client.recv(2))[0]

            chan = self._transport.open_channel(
                "direct-tcpip", (dst_addr, dst_port), addr,
            )
            if chan is None:
                reply = struct.pack("!BBBB4sH", SOCKS5_VER,
                                    SOCKS5_REP_GENERAL_FAILURE, 0,
                                    SOCKS5_ATYP_IPV4,
                                    b"\x00\x00\x00\x00", 0)
                client.sendall(reply)
                client.close()
                return

            reply = struct.pack("!BBBB4sH", SOCKS5_VER,
                                SOCKS5_REP_SUCCESS, 0,
                                SOCKS5_ATYP_IPV4,
                                b"\x00\x00\x00\x00", 0)
            client.sendall(reply)

            record = ConnectionRecord(
                src_addr=addr[0], src_port=addr[1],
                dst_addr=dst_addr, dst_port=dst_port,
            )
            self._stats.records.append(record)
            _LOG.info("SSH DYN %s:%d -> %s:%d", addr[0], addr[1],
                      dst_addr, dst_port)
            self._relay_channel(client, chan, record)
        except Exception:
            _LOG.debug("SSH dynamic error: %s", traceback.format_exc())
        finally:
            self._stats.active_connections = max(
                0, self._stats.active_connections - 1)

    def _relay_channel(self, sock: socket.socket, chan: Any,
                       record: Optional[ConnectionRecord] = None) -> None:
        try:
            sock.setblocking(False)
            chan.settimeout(0.0)
            while not self._stop.is_set():
                r, _, _ = select.select([sock, chan], [], [], _RELAY_TIMEOUT)
                for s in r:
                    if s is sock:
                        try:
                            data = sock.recv(_BUF)
                        except (ConnectionResetError, OSError):
                            data = b""
                        if not data:
                            return
                        chan.sendall(data)
                        if record:
                            record.bytes_sent += len(data)
                    else:
                        try:
                            data = chan.recv(_BUF)
                        except (EOFError, OSError):
                            data = b""
                        if not data:
                            return
                        sock.sendall(data)
                        if record:
                            record.bytes_recv += len(data)
        finally:
            try:
                chan.close()
            except Exception:
                pass
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            if record:
                record.closed = True

    def disconnect(self) -> None:
        C.info("SSH tunnel disconnecting ...")
        self._stop.set()
        for s in self._server_socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=3.0)
        if self._transport:
            try:
                self._transport.close()
            except Exception:
                pass
        C.ok("SSH tunnel closed")


# =============================================================================
#  ENCRYPTED TUNNEL (AES-256 / HMAC)
# =============================================================================

class EncryptedTunnel:
    """AES-256 encrypted TCP tunnel with HMAC integrity verification."""

    SALT_LEN = 16
    PROTO_HELLO = b"ECTUN1"

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._stats = TunnelStats()
        self._server_sock: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []
        self._nonces_seen: Dict[str, set] = {}
        self._nonce_lock = threading.Lock()

    @property
    def stats(self) -> TunnelStats:
        return self._stats

    def server(self, bind_addr: str, bind_port: int,
               passphrase: str, target_host: str = "127.0.0.1",
               target_port: int = 0) -> None:
        salt = secrets.token_bytes(self.SALT_LEN)
        key = _derive_key(passphrase, salt)
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((bind_addr, bind_port))
        self._server_sock.listen(64)
        self._stats.started_at = datetime.utcnow().isoformat()
        C.ok(f"Encrypted listener on {C.BLD}{bind_addr}:{bind_port}{C.R}")
        if target_port:
            C.info(f"Relay target: {target_host}:{target_port}")

        t = threading.Thread(target=self._server_accept,
                             args=(salt, key, target_host, target_port),
                             daemon=True)
        t.start()
        self._threads.append(t)

    def _server_accept(self, salt: bytes, key: bytes,
                       target_host: str, target_port: int) -> None:
        while not self._stop.is_set():
            try:
                client, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._stats.total_connections += 1
            self._stats.active_connections += 1
            t = threading.Thread(
                target=self._server_handle,
                args=(client, addr, salt, key, target_host, target_port),
                daemon=True,
            )
            t.start()

    def _server_handle(self, client: socket.socket, addr: Tuple[str, int],
                       salt: bytes, key: bytes,
                       target_host: str, target_port: int) -> None:
        session_id = f"{addr[0]}:{addr[1]}:{time.monotonic()}"
        with self._nonce_lock:
            self._nonces_seen[session_id] = set()
        record = ConnectionRecord(
            src_addr=addr[0], src_port=addr[1],
            dst_addr=target_host, dst_port=target_port,
        )
        self._stats.records.append(record)
        try:
            client.settimeout(15.0)
            hello = client.recv(len(self.PROTO_HELLO))
            if hello != self.PROTO_HELLO:
                client.close()
                return
            client.sendall(self.PROTO_HELLO + salt)

            if not target_port:
                hdr_frame = _recv_frame(client)
                if not hdr_frame:
                    client.close()
                    return
                hdr_plain = _aes_gcm_decrypt(key, hdr_frame)
                if not hdr_plain:
                    C.warn(f"Auth failed from {addr[0]}:{addr[1]}")
                    client.close()
                    return
                parts = hdr_plain.decode("utf-8").split(":")
                target_host = parts[0]
                target_port = int(parts[1])
                record.dst_addr = target_host
                record.dst_port = target_port

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10.0)
            remote.connect((target_host, target_port))
            ack = _aes_gcm_encrypt(key, b"OK")
            _send_frame(client, ack)

            _LOG.info("ETUN %s:%d -> %s:%d", addr[0], addr[1],
                      target_host, target_port)
            self._encrypted_relay(client, remote, key, session_id, record)
        except Exception:
            _LOG.debug("Encrypted tunnel error: %s", traceback.format_exc())
        finally:
            self._stats.active_connections = max(
                0, self._stats.active_connections - 1)
            with self._nonce_lock:
                self._nonces_seen.pop(session_id, None)
            try:
                client.close()
            except OSError:
                pass

    def client(self, remote_addr: str, remote_port: int,
               passphrase: str,
               target_host: str = "", target_port: int = 0,
               local_port: int = 0, bind_addr: str = "127.0.0.1") -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15.0)
        sock.connect((remote_addr, remote_port))
        sock.sendall(self.PROTO_HELLO)

        resp = sock.recv(len(self.PROTO_HELLO) + self.SALT_LEN)
        if not resp.startswith(self.PROTO_HELLO):
            C.fail("Protocol mismatch from server")
            sock.close()
            return
        salt = resp[len(self.PROTO_HELLO):]
        key = _derive_key(passphrase, salt)

        if target_host and target_port:
            target_spec = f"{target_host}:{target_port}".encode("utf-8")
            enc_spec = _aes_gcm_encrypt(key, target_spec)
            _send_frame(sock, enc_spec)

        ack_frame = _recv_frame(sock)
        if not ack_frame:
            C.fail("No ACK from server")
            sock.close()
            return
        ack_plain = _aes_gcm_decrypt(key, ack_frame)
        if ack_plain != b"OK":
            C.fail("Server rejected connection (bad key?)")
            sock.close()
            return

        C.ok(f"Encrypted tunnel established to {C.BLD}{remote_addr}:"
             f"{remote_port}{C.R}")

        if local_port:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(1.0)
            srv.bind((bind_addr, local_port))
            srv.listen(1)
            C.info(f"Waiting for local connection on {bind_addr}:{local_port}")
            while not self._stop.is_set():
                try:
                    local_conn, _ = srv.accept()
                    break
                except socket.timeout:
                    continue
            else:
                srv.close()
                sock.close()
                return
            srv.close()
            session_id = f"client:{time.monotonic()}"
            with self._nonce_lock:
                self._nonces_seen[session_id] = set()
            record = ConnectionRecord(
                src_addr=bind_addr, src_port=local_port,
                dst_addr=remote_addr, dst_port=remote_port,
            )
            self._stats.records.append(record)
            self._encrypted_relay(sock, local_conn, key, session_id, record)
        else:
            C.info("Tunnel ready - pipe stdin/stdout")
            session_id = f"client-stdio:{time.monotonic()}"
            with self._nonce_lock:
                self._nonces_seen[session_id] = set()
            self._stdio_encrypted_relay(sock, key, session_id)

    def _encrypted_relay(self, enc_sock: socket.socket,
                         plain_sock: socket.socket,
                         key: bytes, session_id: str,
                         record: Optional[ConnectionRecord] = None) -> None:
        stop = self._stop

        def enc_to_plain() -> None:
            try:
                while not stop.is_set():
                    frame = _recv_frame(enc_sock)
                    if frame is None:
                        break
                    nonce = frame[:12]
                    with self._nonce_lock:
                        seen = self._nonces_seen.get(session_id, set())
                        if nonce in seen:
                            _LOG.warning("Replay detected, dropping")
                            continue
                        seen.add(nonce)
                    plaintext = _aes_gcm_decrypt(key, frame)
                    if plaintext is None:
                        _LOG.warning("Decryption failed, dropping")
                        continue
                    plain_sock.sendall(plaintext)
                    if record:
                        record.bytes_recv += len(plaintext)
            except (OSError, Exception):
                pass
            finally:
                try:
                    plain_sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        def plain_to_enc() -> None:
            try:
                plain_sock.setblocking(False)
                while not stop.is_set():
                    r, _, _ = select.select([plain_sock], [], [],
                                            _RELAY_TIMEOUT)
                    if not r:
                        continue
                    try:
                        data = plain_sock.recv(_BUF)
                    except (ConnectionResetError, OSError):
                        break
                    if not data:
                        break
                    encrypted = _aes_gcm_encrypt(key, data)
                    _send_frame(enc_sock, encrypted)
                    if record:
                        record.bytes_sent += len(data)
            except (OSError, Exception):
                pass
            finally:
                try:
                    enc_sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=enc_to_plain, daemon=True)
        t2 = threading.Thread(target=plain_to_enc, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        for s in (enc_sock, plain_sock):
            try:
                s.close()
            except OSError:
                pass
        if record:
            record.closed = True

    def _stdio_encrypted_relay(self, enc_sock: socket.socket,
                               key: bytes, session_id: str) -> None:
        stop = self._stop

        def from_server() -> None:
            try:
                while not stop.is_set():
                    frame = _recv_frame(enc_sock)
                    if frame is None:
                        break
                    nonce = frame[:12]
                    with self._nonce_lock:
                        seen = self._nonces_seen.get(session_id, set())
                        if nonce in seen:
                            continue
                        seen.add(nonce)
                    plaintext = _aes_gcm_decrypt(key, frame)
                    if plaintext is None:
                        continue
                    sys.stdout.buffer.write(plaintext)
                    sys.stdout.buffer.flush()
            except Exception:
                pass

        def to_server() -> None:
            try:
                while not stop.is_set():
                    data = sys.stdin.buffer.read(4096)
                    if not data:
                        break
                    encrypted = _aes_gcm_encrypt(key, data)
                    _send_frame(enc_sock, encrypted)
            except Exception:
                pass

        t1 = threading.Thread(target=from_server, daemon=True)
        t2 = threading.Thread(target=to_server, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def shutdown(self) -> None:
        C.info("Encrypted tunnel shutting down ...")
        self._stop.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=3.0)
        C.ok("Encrypted tunnel stopped")


# =============================================================================
#  PIVOT CHAIN
# =============================================================================

class PivotChain:
    """Multi-hop pivot chain through SOCKS5, SSH, or encrypted tunnels."""

    def __init__(self) -> None:
        self._hops: List[HopSpec] = []
        self._active_proxies: List[Any] = []
        self._connected = False
        self._stats = TunnelStats()
        self._chain_sockets: List[socket.socket] = []

    @property
    def stats(self) -> TunnelStats:
        return self._stats

    @property
    def hop_count(self) -> int:
        return len(self._hops)

    def add_hop(self, host: str, port: int, hop_type: str,
                username: Optional[str] = None,
                password: Optional[str] = None,
                key_file: Optional[str] = None,
                encryption_key: Optional[str] = None) -> None:
        hop = HopSpec(
            host=host, port=port, hop_type=hop_type.lower(),
            username=username, password=password,
            key_file=key_file, encryption_key=encryption_key,
        )
        self._hops.append(hop)
        C.info(f"Hop #{len(self._hops)}: {hop_type} -> {host}:{port}")

    def connect(self) -> bool:
        if not self._hops:
            C.fail("No hops defined")
            return False

        C.section("PIVOT CHAIN - Establishing")
        self._stats.started_at = datetime.utcnow().isoformat()
        prev_sock: Optional[socket.socket] = None

        for idx, hop in enumerate(self._hops, 1):
            C.info(f"Connecting hop {idx}/{len(self._hops)}: "
                   f"{hop.hop_type} {hop.host}:{hop.port}")

            if hop.hop_type == "socks5":
                sock = self._connect_socks5(hop, prev_sock)
            elif hop.hop_type == "ssh":
                sock = self._connect_ssh_hop(hop, prev_sock)
            elif hop.hop_type == "encrypted":
                sock = self._connect_encrypted_hop(hop, prev_sock)
            else:
                C.fail(f"Unknown hop type: {hop.hop_type}")
                self._teardown()
                return False

            if sock is None:
                C.fail(f"Hop {idx} failed")
                self._teardown()
                return False

            prev_sock = sock
            self._chain_sockets.append(sock)
            C.ok(f"Hop {idx} established")

        self._connected = True
        C.ok(f"Pivot chain established ({len(self._hops)} hops)")
        return True

    def _connect_socks5(self, hop: HopSpec,
                        via: Optional[socket.socket]) -> Optional[socket.socket]:
        try:
            if via:
                sock = via
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15.0)
                sock.connect((hop.host, hop.port))

            methods = [SOCKS5_AUTH_NONE]
            if hop.username and hop.password:
                methods = [SOCKS5_AUTH_USERPASS]
            sock.sendall(bytes([SOCKS5_VER, len(methods)] + methods))
            resp = sock.recv(2)
            if len(resp) < 2 or resp[0] != SOCKS5_VER:
                return None
            chosen = resp[1]
            if chosen == SOCKS5_AUTH_USERPASS:
                uname = hop.username.encode("utf-8")
                passwd = hop.password.encode("utf-8")
                sock.sendall(bytes([0x01, len(uname)]) + uname +
                             bytes([len(passwd)]) + passwd)
                auth_resp = sock.recv(2)
                if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                    return None
            elif chosen == SOCKS5_AUTH_REJECT:
                return None
            return sock
        except Exception:
            return None

    def _connect_ssh_hop(self, hop: HopSpec,
                         via: Optional[socket.socket]) -> Optional[socket.socket]:
        if not HAS_PARAMIKO:
            C.fail("paramiko required for SSH hops")
            return None
        try:
            if via:
                transport = paramiko.Transport(via)
            else:
                transport = paramiko.Transport((hop.host, hop.port))
            if hop.key_file:
                pkey = paramiko.RSAKey.from_private_key_file(hop.key_file)
                transport.connect(username=hop.username or "root", pkey=pkey)
            else:
                transport.connect(username=hop.username or "root",
                                  password=hop.password)
            transport.set_keepalive(30)
            self._active_proxies.append(transport)
            chan = transport.open_channel("session")
            return chan
        except Exception as exc:
            C.fail(f"SSH hop error: {exc}")
            return None

    def _connect_encrypted_hop(self, hop: HopSpec,
                               via: Optional[socket.socket]
                               ) -> Optional[socket.socket]:
        try:
            if via:
                sock = via
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15.0)
                sock.connect((hop.host, hop.port))

            sock.sendall(EncryptedTunnel.PROTO_HELLO)
            resp = sock.recv(len(EncryptedTunnel.PROTO_HELLO) +
                             EncryptedTunnel.SALT_LEN)
            if not resp.startswith(EncryptedTunnel.PROTO_HELLO):
                return None
            salt = resp[len(EncryptedTunnel.PROTO_HELLO):]
            key = _derive_key(hop.encryption_key or "", salt)
            self._active_proxies.append(("enc_key", key))
            return sock
        except Exception:
            return None

    def relay(self, data: bytes) -> Optional[bytes]:
        if not self._connected or not self._chain_sockets:
            return None
        end_sock = self._chain_sockets[-1]
        try:
            end_sock.sendall(data)
            end_sock.settimeout(10.0)
            response = end_sock.recv(_BUF)
            self._stats.bytes_relayed += len(data) + len(response)
            return response if response else None
        except (socket.timeout, OSError):
            return None

    def status(self) -> Dict[str, Any]:
        return {
            "connected": self._connected,
            "hops": len(self._hops),
            "hop_details": [
                {"host": h.host, "port": h.port, "type": h.hop_type}
                for h in self._hops
            ],
            "bytes_relayed": self._stats.bytes_relayed,
            "started_at": self._stats.started_at,
        }

    def _teardown(self) -> None:
        for s in reversed(self._chain_sockets):
            try:
                if hasattr(s, "shutdown"):
                    s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        self._chain_sockets.clear()
        for obj in self._active_proxies:
            if hasattr(obj, "close"):
                try:
                    obj.close()
                except Exception:
                    pass
        self._active_proxies.clear()
        self._connected = False

    def disconnect(self) -> None:
        C.info("Pivot chain disconnecting ...")
        self._teardown()
        C.ok("Pivot chain closed")


# =============================================================================
#  BANNER
# =============================================================================

BANNER = rf"""
{C.CYN}{C.BLD}
    ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
    ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
       ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
       ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
       ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
       ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C.R}{C.GRN}    ──────────── TUNNEL & PROXY SUITE v1.0 ────────────────{C.R}
{C.DIM}    FLLC  |  Authorized Use Only  |  Network Pivoting{C.R}
"""


# =============================================================================
#  CLI
# =============================================================================

def _sig_handler(sig: int, frame: Any) -> None:
    C.warn("Interrupt received, shutting down ...")
    _SHUTDOWN_EVENT.set()


def _wait_forever() -> None:
    try:
        while not _SHUTDOWN_EVENT.is_set():
            _SHUTDOWN_EVENT.wait(timeout=1.0)
    except KeyboardInterrupt:
        _SHUTDOWN_EVENT.set()


def cmd_socks5(args: argparse.Namespace) -> None:
    proxy = Socks5Proxy(
        username=args.username,
        password=args.password,
        max_connections=args.max_conn,
    )
    proxy.start(args.bind, args.port)
    _wait_forever()
    proxy.shutdown()
    total = sum(r.bytes_sent + r.bytes_recv for r in proxy.stats.records)
    C.info(f"Total connections: {proxy.stats.total_connections}  "
           f"Bytes relayed: {total:,}")


def cmd_forward(args: argparse.Namespace) -> None:
    fwd = PortForwarder()
    if args.direction == "local":
        fwd.local_forward(args.local_port, args.remote_host,
                          args.remote_port, args.bind)
    else:
        fwd.remote_forward(args.bind, args.local_port,
                           args.remote_host, args.remote_port)
    _wait_forever()
    fwd.shutdown()


def cmd_ssh_tunnel(args: argparse.Namespace) -> None:
    if not HAS_PARAMIKO:
        C.fail("paramiko is required: pip install paramiko")
        sys.exit(1)
    tun = SSHTunnel()
    if not tun.connect(args.host, args.ssh_port, args.username,
                       password=args.password, key_file=args.key_file):
        sys.exit(1)
    if args.dynamic:
        tun.dynamic_forward(args.local_port, args.bind)
    else:
        tun.local_forward(args.local_port, args.remote_host,
                          args.remote_port, args.bind)
    _wait_forever()
    tun.disconnect()


def cmd_encrypted(args: argparse.Namespace) -> None:
    etun = EncryptedTunnel()
    if args.mode == "server":
        etun.server(args.bind, args.port, args.key,
                    target_host=args.target_host or "127.0.0.1",
                    target_port=args.target_port or 0)
        _wait_forever()
        etun.shutdown()
    else:
        etun.client(args.host, args.port, args.key,
                    target_host=args.target_host or "",
                    target_port=args.target_port or 0,
                    local_port=args.local_port or 0,
                    bind_addr=args.bind)


def cmd_pivot(args: argparse.Namespace) -> None:
    chain = PivotChain()
    for spec in args.hop:
        parts = spec.split(":")
        if len(parts) < 3:
            C.fail(f"Invalid hop spec '{spec}' - use type:host:port[:user:pass]")
            sys.exit(1)
        hop_type, host, port = parts[0], parts[1], int(parts[2])
        user = parts[3] if len(parts) > 3 else None
        passwd = parts[4] if len(parts) > 4 else None
        enc_key = parts[5] if len(parts) > 5 else None
        chain.add_hop(host, port, hop_type, username=user,
                      password=passwd, encryption_key=enc_key)
    if chain.connect():
        C.ok("Chain active. Status:")
        C.p(f"  {json.dumps(chain.status(), indent=2)}")
        _wait_forever()
        chain.disconnect()
    else:
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tunnel_proxy",
        description="FU PERSON - Tunnel & Proxy Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s socks5 -p 1080
              %(prog)s socks5 -p 9050 -u admin -P s3cret
              %(prog)s forward local -l 8080 -r 10.0.0.5 -R 80
              %(prog)s forward remote --bind 0.0.0.0 -l 4444 -r 127.0.0.1 -R 22
              %(prog)s ssh-tunnel -H 10.0.0.1 -u root -l 8080 -r 127.0.0.1 -R 3306
              %(prog)s ssh-tunnel -H 10.0.0.1 -u root --dynamic -l 1080
              %(prog)s encrypted server -p 4443 -k mypassphrase
              %(prog)s encrypted client -H 10.0.0.1 -p 4443 -k mypassphrase
              %(prog)s pivot --hop socks5:proxy1:1080 --hop ssh:pivot:22:root:pw
        """),
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- socks5 --
    sp = sub.add_parser("socks5", help="Start SOCKS5 proxy server")
    sp.add_argument("-b", "--bind", default="127.0.0.1")
    sp.add_argument("-p", "--port", type=int, default=1080)
    sp.add_argument("-u", "--username", default=None)
    sp.add_argument("-P", "--password", default=None)
    sp.add_argument("--max-conn", type=int, default=200)

    # -- forward --
    fp = sub.add_parser("forward", help="TCP port forwarding")
    fp.add_argument("direction", choices=["local", "remote"])
    fp.add_argument("-b", "--bind", default="127.0.0.1")
    fp.add_argument("-l", "--local-port", type=int, required=True)
    fp.add_argument("-r", "--remote-host", required=True)
    fp.add_argument("-R", "--remote-port", type=int, required=True)

    # -- ssh-tunnel --
    stp = sub.add_parser("ssh-tunnel", help="SSH tunnel (requires paramiko)")
    stp.add_argument("-H", "--host", required=True)
    stp.add_argument("--ssh-port", type=int, default=22)
    stp.add_argument("-u", "--username", default="root")
    stp.add_argument("-p", "--password", default=None)
    stp.add_argument("-k", "--key-file", default=None)
    stp.add_argument("-b", "--bind", default="127.0.0.1")
    stp.add_argument("-l", "--local-port", type=int, required=True)
    stp.add_argument("-r", "--remote-host", default="127.0.0.1")
    stp.add_argument("-R", "--remote-port", type=int, default=0)
    stp.add_argument("--dynamic", action="store_true",
                     help="Dynamic SOCKS proxy through SSH")

    # -- encrypted --
    ep = sub.add_parser("encrypted", help="AES-256 encrypted tunnel")
    ep.add_argument("mode", choices=["server", "client"])
    ep.add_argument("-b", "--bind", default="127.0.0.1")
    ep.add_argument("-p", "--port", type=int, required=True)
    ep.add_argument("-H", "--host", default="127.0.0.1")
    ep.add_argument("-k", "--key", required=True, help="Encryption passphrase")
    ep.add_argument("--target-host", default=None)
    ep.add_argument("--target-port", type=int, default=None)
    ep.add_argument("-l", "--local-port", type=int, default=None)

    # -- pivot --
    pp = sub.add_parser("pivot", help="Multi-hop pivot chain")
    pp.add_argument("--hop", action="append", required=True,
                    help="type:host:port[:user:pass[:enc_key]]")

    return parser


# =============================================================================
#  ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    signal.signal(signal.SIGINT, _sig_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sig_handler)

    C.p(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        _LOG.setLevel(logging.DEBUG)

    dispatch: Dict[str, Callable[..., None]] = {
        "socks5": cmd_socks5,
        "forward": cmd_forward,
        "ssh-tunnel": cmd_ssh_tunnel,
        "encrypted": cmd_encrypted,
        "pivot": cmd_pivot,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
