#!/usr/bin/env python3
"""
CyberWorld Covert WiFi Scanner
FLLC | FU PERSON | DSi Operations

Runs background WiFi reconnaissance while CyberWorld ROM is active.
Logs SSIDs, BSSIDs, signal strength, channels to hidden directory.
Output is compatible with main FU PERSON loot aggregation.

NOTE: DSi does not run Python natively. This script serves as:
  1. Reference implementation for C/C++ DSi homebrew port
  2. PC-side testing/development when simulating DSi WiFi capture
  3. Loot format specification for FU PERSON integration

On DSi, equivalent functionality would be implemented in C using
the DSi WiFi SDK (e.g., wifi_scan or similar APIs).
"""

import os
import sys
import time
import struct
import socket
import csv
import hashlib
import signal
import platform
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import List, Dict, Any

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION — matches autolaunch.ini
# ═══════════════════════════════════════════════════════════════════════════

CONFIG = {
    "scan_interval_ms": 5000,
    "log_path": ".cyberworld/.scan_data/",
    "log_format": "csv",
    "hidden_dir": True,
    "max_file_mb": 1,
    "scan_ssid": True,
    "scan_bssid": True,
    "scan_signal": True,
    "scan_channel": True,
    "scan_encryption": True,
    "probe_capture": True,
    "timestamp_utc": True,
    "stealth_mode": True,  # Minimize CPU between scans
}

# FU PERSON loot format header
FU_PERSON_HEADER = [
    "timestamp_utc",
    "source",
    "ssid",
    "bssid",
    "signal_dbm",
    "channel",
    "encryption",
    "probe_ssid",
    "hash_id",
]

# Panic shutdown event
shutdown_event = Event()

# Seen networks (for duplicate detection)
seen_networks = set()


def panic_handler(signum, frame):
    """Handle panic button (SELECT+START) — clean shutdown."""
    print("[!] PANIC: Shutdown requested", file=sys.stderr)
    shutdown_event.set()


def register_panic_handlers():
    """Register signal handlers for clean shutdown."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, panic_handler)
        except (ValueError, OSError):
            pass


def get_timestamp_utc() -> str:
    """Return UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_log_base_path() -> Path:
    """Resolve log path; use SD root if simulating DSi."""
    base = os.environ.get("CYBERWORLD_LOG_ROOT", ".")
    return Path(base) / CONFIG["log_path"].lstrip("./")


def ensure_log_directory() -> Path:
    """Create hidden log directory; return path to current log file."""
    log_dir = get_log_base_path()
    log_dir.mkdir(parents=True, exist_ok=True)
    if CONFIG["hidden_dir"] and platform.system() != "Windows":
        # Hide directory on Unix-like (leading dot)
        pass  # Path already has .cyberworld
    return log_dir


def make_hash_id(ssid: str, bssid: str) -> str:
    """Generate deterministic hash for duplicate detection."""
    raw = f"{ssid}|{bssid}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def is_duplicate(ssid: str, bssid: str) -> bool:
    """Check if network was already logged this session."""
    h = make_hash_id(ssid, bssid)
    if h in seen_networks:
        return True
    seen_networks.add(h)
    return False


def get_current_log_file(log_dir: Path) -> Path:
    """Return log file path; rotate if current file exceeds max size."""
    prefix = "scan"
    ext = ".csv"
    candidates = list(log_dir.glob(f"{prefix}_*{ext}"))
    if not candidates:
        f = log_dir / f"{prefix}_0001{ext}"
        return f
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    size_mb = latest.stat().st_size / (1024 * 1024)
    if size_mb >= CONFIG["max_file_mb"]:
        num = len(candidates) + 1
        return log_dir / f"{prefix}_{num:04d}{ext}"
    return latest


def write_csv_row(log_path: Path, row: dict, write_header: bool = False):
    """Append row to CSV; write header if new file."""
    with open(log_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FU_PERSON_HEADER)
        if write_header and log_path.stat().st_size == 0:
            w.writeheader()
        w.writerow(row)


# ═══════════════════════════════════════════════════════════════════════════
# WiFi SCANNING — Platform-specific
# ═══════════════════════════════════════════════════════════════════════════

def scan_wifi_linux() -> List[Dict[str, Any]]:
    """Scan WiFi on Linux using iwlist or nmcli."""
    results = []
    try:
        # Preferred: iwlist (if available)
        out = subprocess.run(
            ["iwlist", "scan"],
            capture_output=True,
            timeout=15,
            text=True,
        )
        if out.returncode != 0:
            # Fallback: nmcli
            out = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "dev", "wifi", "list"],
                capture_output=True,
                timeout=15,
                text=True,
            )
            for line in out.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) >= 5:
                    results.append({
                        "ssid": parts[0] or "<hidden>",
                        "bssid": parts[1],
                        "signal_dbm": _rssi_to_dbm(parts[2]) if parts[2] else "",
                        "channel": parts[4] if len(parts) > 4 else "",
                        "encryption": parts[3] if len(parts) > 3 else "",
                        "probe_ssid": "",
                    })
            return results

        # Parse iwlist output
        curr = {}
        for line in out.stdout.split("\n"):
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                if curr and curr.get("bssid"):
                    results.append(curr)
                curr = {"ssid": "", "bssid": "", "signal_dbm": "", "channel": "", "encryption": "", "probe_ssid": ""}
                m = re.search(r"Address: ([0-9A-Fa-f:]+)", line)
                if m:
                    curr["bssid"] = m.group(1)
            elif "ESSID:" in line:
                m = re.search(r'ESSID:"([^"]*)"', line)
                curr["ssid"] = m.group(1) if m and m.group(1) else "<hidden>"
            elif "Signal level:" in line:
                m = re.search(r"Signal level=(-?\d+)", line)
                if m:
                    curr["signal_dbm"] = str(int(m.group(1)))
            elif "Channel:" in line:
                m = re.search(r"Channel:(\d+)", line)
                if m:
                    curr["channel"] = m.group(1)
            elif "Encryption key:on" in line or "IE:" in line:
                if "WPA" in line or "WPA2" in line:
                    curr["encryption"] = "WPA2"
                elif "WEP" in line:
                    curr["encryption"] = "WEP"
                elif not curr.get("encryption"):
                    curr["encryption"] = "open" if "off" in line.lower() else "unknown"
        if curr and curr.get("bssid"):
            results.append(curr)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        pass  # Silently fail in stealth mode
    return results


def _rssi_to_dbm(s: str) -> str:
    """Convert percentage/signal string to approximate dBm."""
    try:
        pct = int(s)
        if 0 <= pct <= 100:
            return str(-100 + (pct * 2))
    except ValueError:
        pass
    return s


def scan_wifi_windows() -> List[Dict[str, Any]]:
    """Scan WiFi on Windows using netsh."""
    results = []
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            timeout=15,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        if out.returncode != 0:
            return results

        curr = {}
        for line in out.stdout.split("\n"):
            line = line.strip()
            if line.startswith("SSID"):
                idx = line.find(":")
                if idx >= 0:
                    val = line[idx + 1 :].strip()
                    if curr and curr.get("bssid"):
                        results.append(curr)
                        curr = {}
                    curr = {"ssid": val or "<hidden>", "bssid": "", "signal_dbm": "", "channel": "", "encryption": "", "probe_ssid": ""}
            elif "BSSID" in line:
                idx = line.find(":")
                if idx >= 0:
                    curr["bssid"] = line[idx + 1 :].strip()
            elif "Signal" in line:
                idx = line.find(":")
                if idx >= 0:
                    curr["signal_dbm"] = line[idx + 1 :].strip().replace("%", "")
            elif "Channel" in line:
                idx = line.find(":")
                if idx >= 0:
                    curr["channel"] = line[idx + 1 :].strip()
            elif "Authentication" in line or "Encryption" in line:
                idx = line.find(":")
                if idx >= 0:
                    val = line[idx + 1 :].strip()
                    if val and not curr.get("encryption"):
                        curr["encryption"] = val
        if curr and curr.get("bssid"):
            results.append(curr)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return results


def capture_probe_requests() -> List[Dict[str, Any]]:
    """Capture probe requests (requires monitor mode). Placeholder for DSi/PC."""
    # On real hardware: tcpdump, airodump-ng, or DSi WiFi API
    # Probe SSIDs from devices seeking known networks
    return []


def run_scan() -> List[Dict[str, Any]]:
    """Run platform-appropriate WiFi scan."""
    if platform.system() == "Linux":
        entries = scan_wifi_linux()
    elif platform.system() == "Windows":
        entries = scan_wifi_windows()
    else:
        entries = []

    if CONFIG["probe_capture"]:
        probes = capture_probe_requests()
        for p in probes:
            p.setdefault("ssid", "<probe>")
            p.setdefault("probe_ssid", p.get("ssid", ""))
        entries.extend(probes)

    return entries


# ═══════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main covert scan loop — stealth mode, minimal CPU between polls."""
    register_panic_handlers()
    log_dir = ensure_log_directory()
    log_path = get_current_log_file(log_dir)
    interval_sec = CONFIG["scan_interval_ms"] / 1000.0
    source = "cyberworld_dsi"

    print("[+] CyberWorld Covert Scanner — FLLC | FU PERSON", file=sys.stderr)
    print(f"[*] Log path: {log_dir}", file=sys.stderr)
    print(f"[*] Interval: {interval_sec}s | Stealth: {CONFIG['stealth_mode']}", file=sys.stderr)
    print("[*] Press Ctrl+C for panic shutdown", file=sys.stderr)

    first_write = True
    new_count = 0

    while not shutdown_event.is_set():
        try:
            entries = run_scan()
            ts = get_timestamp_utc()

            for e in entries:
                ssid = e.get("ssid", "") or "<hidden>"
                bssid = e.get("bssid", "") or ""
                if not bssid:
                    continue
                if is_duplicate(ssid, bssid):
                    continue
                new_count += 1
                row = {
                    "timestamp_utc": ts,
                    "source": source,
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal_dbm": e.get("signal_dbm", ""),
                    "channel": e.get("channel", ""),
                    "encryption": e.get("encryption", ""),
                    "probe_ssid": e.get("probe_ssid", ""),
                    "hash_id": make_hash_id(ssid, bssid),
                }
                write_csv_row(log_path, row, write_header=first_write)
                first_write = False

            # Rotate log if needed
            if log_path.exists() and log_path.stat().st_size >= CONFIG["max_file_mb"] * 1024 * 1024:
                log_path = get_current_log_file(log_dir)
                first_write = True

        except Exception as ex:
            if not CONFIG["stealth_mode"]:
                print(f"[!] Scan error: {ex}", file=sys.stderr)

        if CONFIG["stealth_mode"]:
            # Sleep in small chunks to allow quick panic response
            for _ in range(int(interval_sec)):
                if shutdown_event.is_set():
                    break
                time.sleep(1)
        else:
            shutdown_event.wait(timeout=interval_sec)

    print(f"[+] Shutdown complete. New networks logged: {new_count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
