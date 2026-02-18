#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: CVE MONITORING DAEMON v1.0
  NVD Polling | CISA KEV Tracking | Alert Engine | Digest Reports
  Watchlist Management | Background Monitoring | Desktop Notifications
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  This tool queries public vulnerability databases (NVD, CISA KEV) and
  generates alerts for security operations teams.  It does NOT perform
  any offensive testing.  Respect API rate limits and terms of service.

  FLLC
  Government-Cleared Security Operations
===============================================================================
"""

import os
import sys
import re
import json
import time
import signal
import hashlib
import logging
import argparse
import threading
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Callable, Set
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
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
#  PATHS & CONSTANTS
# =============================================================================

FU_HOME: Path            = Path.home() / ".fuperson"
WATCHLIST_PATH: Path     = FU_HOME / "watchlist.json"
SEEN_CVES_PATH: Path     = FU_HOME / "seen_cves.json"
ALERT_LOG_PATH: Path     = FU_HOME / "cve_alerts.log"
CONFIG_PATH: Path        = FU_HOME / "monitor_config.json"
PID_PATH: Path           = FU_HOME / "monitor.pid"
DIGEST_DIR: Path         = FU_HOME / "digests"

NVD_API_BASE: str        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_CATALOG_URL: str     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_POLL_HOURS: int  = 6
DEFAULT_SEVERITY: float  = 7.0
HTTP_TIMEOUT: int        = 30
MAX_NVD_RESULTS: int     = 50


# =============================================================================
#  DATA STRUCTURES
# =============================================================================

@dataclass
class WatchEntry:
    id: str
    vendor: Optional[str]  = None
    product: Optional[str] = None
    cpe: Optional[str]     = None
    keyword: Optional[str] = None
    added_date: str        = ""
    last_checked: str      = ""

    def __post_init__(self):
        if not self.added_date:
            self.added_date = datetime.now(timezone.utc).isoformat()


@dataclass
class CVERecord:
    cve_id: str
    description: str    = ""
    cvss_score: float   = 0.0
    severity: str       = "UNKNOWN"
    vendor: str         = ""
    product: str        = ""
    published: str      = ""
    references: List[str] = field(default_factory=list)
    kev: bool           = False


# =============================================================================
#  CONFIGURATION
# =============================================================================

class Config:
    DEFAULTS: Dict[str, Any] = {
        "poll_interval_hours": DEFAULT_POLL_HOURS,
        "severity_threshold": DEFAULT_SEVERITY,
        "alert_desktop": True,
        "alert_log": True,
        "nvd_api_key": "",
        "digest_interval": "daily",
    }

    def __init__(self) -> None:
        self._data: Dict[str, Any] = dict(self.DEFAULTS)
        self.load()

    @property
    def poll_interval(self) -> int:
        return int(self._data.get("poll_interval_hours", DEFAULT_POLL_HOURS))

    @property
    def severity_threshold(self) -> float:
        return float(self._data.get("severity_threshold", DEFAULT_SEVERITY))

    @property
    def alert_desktop(self) -> bool:
        return bool(self._data.get("alert_desktop", True))

    @property
    def alert_log(self) -> bool:
        return bool(self._data.get("alert_log", True))

    @property
    def nvd_api_key(self) -> str:
        return str(self._data.get("nvd_api_key", ""))

    @property
    def digest_interval(self) -> str:
        return str(self._data.get("digest_interval", "daily"))

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def load(self) -> None:
        if CONFIG_PATH.exists():
            try:
                self._data = {**self.DEFAULTS, **json.loads(CONFIG_PATH.read_text(encoding="utf-8"))}
            except (json.JSONDecodeError, OSError):
                self._data = dict(self.DEFAULTS)

    def save(self) -> None:
        FU_HOME.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def defaults(self) -> None:
        self._data = dict(self.DEFAULTS)
        self.save()

    def show(self) -> None:
        C.info("Current configuration:")
        for k, v in sorted(self._data.items()):
            display = "********" if k == "nvd_api_key" and v else v
            C.p(f"    {C.CYN}{k:<25}{C.R} {display}")


# =============================================================================
#  WATCHLIST MANAGER
# =============================================================================

class Watchlist:
    def __init__(self) -> None:
        self._entries: List[WatchEntry] = []
        self._load()

    def _load(self) -> None:
        if WATCHLIST_PATH.exists():
            try:
                raw = json.loads(WATCHLIST_PATH.read_text(encoding="utf-8"))
                self._entries = [WatchEntry(**e) for e in raw]
            except (json.JSONDecodeError, OSError, TypeError):
                self._entries = []

    def _save(self) -> None:
        FU_HOME.mkdir(parents=True, exist_ok=True)
        WATCHLIST_PATH.write_text(
            json.dumps([asdict(e) for e in self._entries], indent=2),
            encoding="utf-8",
        )

    def add(self, vendor: Optional[str] = None, product: Optional[str] = None,
            cpe: Optional[str] = None, keyword: Optional[str] = None) -> WatchEntry:
        if not any([vendor, product, cpe, keyword]):
            raise ValueError("At least one of vendor, product, cpe, or keyword required")
        uid = hashlib.sha256(
            f"{vendor}:{product}:{cpe}:{keyword}".encode()
        ).hexdigest()[:12]
        for e in self._entries:
            if e.id == uid:
                C.warn(f"Duplicate watch entry: {uid}")
                return e
        entry = WatchEntry(id=uid, vendor=vendor, product=product, cpe=cpe, keyword=keyword)
        self._entries.append(entry)
        self._save()
        C.ok(f"Added watch entry {C.CYN}{uid}{C.R}")
        return entry

    def remove(self, entry_id: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.id != entry_id]
        if len(self._entries) < before:
            self._save()
            C.ok(f"Removed watch entry {C.CYN}{entry_id}{C.R}")
            return True
        C.fail(f"Entry {entry_id} not found")
        return False

    def list_all(self) -> List[WatchEntry]:
        if not self._entries:
            C.info("Watchlist is empty")
            return []
        C.info(f"Watchlist ({len(self._entries)} entries):")
        for e in self._entries:
            parts = []
            if e.vendor:  parts.append(f"vendor={e.vendor}")
            if e.product: parts.append(f"product={e.product}")
            if e.cpe:     parts.append(f"cpe={e.cpe}")
            if e.keyword: parts.append(f"keyword={e.keyword}")
            checked = e.last_checked or "never"
            C.p(f"    {C.CYN}{e.id}{C.R}  {', '.join(parts)}  {C.DIM}(checked: {checked}){C.R}")
        return list(self._entries)

    @property
    def entries(self) -> List[WatchEntry]:
        return list(self._entries)

    def update_checked(self, entry_id: str) -> None:
        for e in self._entries:
            if e.id == entry_id:
                e.last_checked = datetime.now(timezone.utc).isoformat()
        self._save()


# =============================================================================
#  HTTP HELPER
# =============================================================================

def _http_get(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: int = HTTP_TIMEOUT) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header("User-Agent", "FU-PERSON-CVE-Monitor/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            OSError, TimeoutError) as exc:
        C.fail(f"HTTP error for {url[:80]}: {exc}")
        return None


# =============================================================================
#  CVE POLLER
# =============================================================================

class CVEPoller:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._seen: Set[str] = set()
        self._load_seen()

    def _load_seen(self) -> None:
        if SEEN_CVES_PATH.exists():
            try:
                self._seen = set(json.loads(SEEN_CVES_PATH.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                self._seen = set()

    def _save_seen(self) -> None:
        FU_HOME.mkdir(parents=True, exist_ok=True)
        SEEN_CVES_PATH.write_text(json.dumps(sorted(self._seen)), encoding="utf-8")

    def _mark_seen(self, cve_id: str) -> bool:
        if cve_id in self._seen:
            return False
        self._seen.add(cve_id)
        self._save_seen()
        return True

    def poll_nvd(self, entries: List[WatchEntry],
                 since: Optional[datetime] = None) -> List[CVERecord]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=self._config.poll_interval)
        results: List[CVERecord] = []
        headers: Dict[str, str] = {}
        if self._config.nvd_api_key:
            headers["apiKey"] = self._config.nvd_api_key

        for entry in entries:
            params: Dict[str, str] = {
                "resultsPerPage": str(MAX_NVD_RESULTS),
                "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
            }
            if entry.keyword:
                params["keywordSearch"] = entry.keyword
            if entry.cpe:
                params["cpeName"] = entry.cpe
            if entry.vendor and entry.product and not entry.cpe:
                params["keywordSearch"] = f"{entry.vendor} {entry.product}"

            url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
            C.info(f"Polling NVD for entry {C.CYN}{entry.id}{C.R} ...")
            data = _http_get(url, headers=headers)
            if not data:
                continue

            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id or not self._mark_seen(cve_id):
                    continue

                desc_list = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

                score, sev = self._extract_cvss(cve_data)
                refs = [r.get("url", "") for r in cve_data.get("references", [])[:5]]
                published = cve_data.get("published", "")

                rec = CVERecord(
                    cve_id=cve_id, description=desc[:300], cvss_score=score,
                    severity=sev, vendor=entry.vendor or "", product=entry.product or "",
                    published=published, references=refs,
                )
                results.append(rec)

            if not self._config.nvd_api_key:
                time.sleep(6)

        return results

    @staticmethod
    def _extract_cvss(cve_data: Dict[str, Any]) -> tuple:
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve_data.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss = metrics[0].get("cvssData", {})
                return (cvss.get("baseScore", 0.0),
                        cvss.get("baseSeverity", "UNKNOWN"))
        return (0.0, "UNKNOWN")

    def poll_kev(self, since: Optional[datetime] = None) -> List[CVERecord]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=self._config.poll_interval)
        C.info("Polling CISA KEV catalog ...")
        data = _http_get(KEV_CATALOG_URL)
        if not data:
            return []

        results: List[CVERecord] = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue
            added_str = vuln.get("dateAdded", "")
            try:
                added_dt = datetime.strptime(added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            if added_dt < since:
                continue
            if not self._mark_seen(f"KEV-{cve_id}"):
                continue

            rec = CVERecord(
                cve_id=cve_id,
                description=vuln.get("shortDescription", "")[:300],
                vendor=vuln.get("vendorProject", ""),
                product=vuln.get("product", ""),
                published=added_str,
                kev=True,
                severity="KEV",
            )
            results.append(rec)
        return results

    @property
    def seen_count(self) -> int:
        return len(self._seen)


# =============================================================================
#  ALERT ENGINE
# =============================================================================

class AlertEngine:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._alerted: Set[str] = set()
        self._alert_count: int = 0

    def alert(self, cve: CVERecord, severity_threshold: Optional[float] = None) -> bool:
        threshold = severity_threshold or self._config.severity_threshold
        if cve.cvss_score < threshold and not cve.kev:
            return False
        if cve.cve_id in self._alerted:
            return False
        self._alerted.add(cve.cve_id)
        self._alert_count += 1

        self._console_alert(cve)
        if self._config.alert_log:
            self._log_alert(cve)
        if self._config.alert_desktop:
            self._desktop_alert(cve)
        return True

    def _console_alert(self, cve: CVERecord) -> None:
        color = C.RED if cve.cvss_score >= 9.0 or cve.kev else (
            C.YLW if cve.cvss_score >= 7.0 else C.BLU)
        tag = f"{color}{C.BLD}[ALERT]{C.R}"
        C.p(f"\n  {tag} {C.WHT}{cve.cve_id}{C.R}  "
            f"CVSS: {color}{cve.cvss_score}{C.R}  "
            f"Severity: {color}{cve.severity}{C.R}"
            f"{'  [KEV]' if cve.kev else ''}")
        if cve.vendor or cve.product:
            C.p(f"        Vendor: {cve.vendor}  Product: {cve.product}")
        if cve.description:
            C.p(f"        {C.DIM}{cve.description[:200]}{C.R}")
        for ref in cve.references[:3]:
            C.p(f"        {C.DIM}{ref}{C.R}")

    def _log_alert(self, cve: CVERecord) -> None:
        FU_HOME.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        line = (f"[{ts}] {cve.cve_id} | CVSS={cve.cvss_score} | "
                f"{cve.severity} | {cve.vendor}/{cve.product} | "
                f"KEV={cve.kev} | {cve.description[:120]}\n")
        try:
            with open(ALERT_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            C.fail(f"Could not write alert log: {exc}")

    def _desktop_alert(self, cve: CVERecord) -> None:
        title = f"CVE Alert: {cve.cve_id}"
        body = f"CVSS {cve.cvss_score} - {cve.severity}"
        if cve.kev:
            body += " [KEV]"
        try:
            if sys.platform == "win32":
                self._notify_windows(title, body)
            elif sys.platform == "darwin":
                self._notify_macos(title, body)
            else:
                self._notify_linux(title, body)
        except Exception:
            pass

    @staticmethod
    def _notify_windows(title: str, body: str) -> None:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, body, title, 0x40)  # type: ignore[attr-defined]
        except Exception:
            import subprocess
            ps_script = (
                f"[Windows.UI.Notifications.ToastNotificationManager, "
                f"Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; "
                f"$t = [Windows.UI.Notifications.ToastNotification]::new("
                f"[Windows.Data.Xml.Dom.XmlDocument]::new()); "
                f"Write-Host '{title}: {body}'"
            )
            subprocess.Popen(
                ["powershell", "-Command", f'Add-Type -AssemblyName System.Windows.Forms; '
                 f'[System.Windows.Forms.MessageBox]::Show("{body}", "{title}")'],
                creationflags=0x08000000,
            )

    @staticmethod
    def _notify_macos(title: str, body: str) -> None:
        import subprocess
        subprocess.Popen([
            "osascript", "-e",
            f'display notification "{body}" with title "{title}"',
        ])

    @staticmethod
    def _notify_linux(title: str, body: str) -> None:
        import subprocess
        subprocess.Popen(["notify-send", title, body])

    @property
    def alert_count(self) -> int:
        return self._alert_count


# =============================================================================
#  DIGEST GENERATOR
# =============================================================================

class DigestGenerator:
    def __init__(self, config: Config) -> None:
        self._config = config

    def _collect_alerts(self, hours: int) -> List[Dict[str, Any]]:
        if not ALERT_LOG_PATH.exists():
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        entries: List[Dict[str, Any]] = []
        try:
            with open(ALERT_LOG_PATH, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    m = re.match(r"\[([^\]]+)\]\s+(\S+)\s+\|\s+CVSS=([0-9.]+)\s+\|\s+"
                                 r"(\S+)\s+\|\s+([^|]+)\|\s+KEV=(\S+)\s+\|\s+(.*)", line)
                    if not m:
                        continue
                    try:
                        ts = datetime.fromisoformat(m.group(1))
                    except ValueError:
                        continue
                    if ts < cutoff:
                        continue
                    entries.append({
                        "timestamp": m.group(1), "cve_id": m.group(2),
                        "cvss": float(m.group(3)), "severity": m.group(4).strip(),
                        "product": m.group(5).strip(), "kev": m.group(6) == "True",
                        "description": m.group(7).strip(),
                    })
        except OSError:
            pass
        return entries

    def daily_digest(self, fmt: str = "text") -> str:
        return self._build_digest(24, "Daily", fmt)

    def weekly_digest(self, fmt: str = "text") -> str:
        return self._build_digest(168, "Weekly", fmt)

    def _build_digest(self, hours: int, label: str, fmt: str) -> str:
        entries = self._collect_alerts(hours)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")

        if fmt == "json":
            content = self._digest_json(entries, label)
            ext = "json"
        elif fmt == "html":
            content = self._digest_html(entries, label)
            ext = "html"
        else:
            content = self._digest_text(entries, label)
            ext = "txt"

        DIGEST_DIR.mkdir(parents=True, exist_ok=True)
        path = DIGEST_DIR / f"{label.lower()}_digest_{ts}.{ext}"
        path.write_text(content, encoding="utf-8")
        C.ok(f"Digest saved to {C.CYN}{path}{C.R}")
        return content

    @staticmethod
    def _digest_text(entries: List[Dict[str, Any]], label: str) -> str:
        lines = [
            f"{'=' * 60}",
            f"  FU PERSON :: {label} CVE Digest",
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
            f"  Total CVEs: {len(entries)}",
            f"{'=' * 60}", "",
        ]
        if not entries:
            lines.append("  No new CVEs in this period.")
            return "\n".join(lines)

        critical = [e for e in entries if e["cvss"] >= 9.0]
        high     = [e for e in entries if 7.0 <= e["cvss"] < 9.0]
        medium   = [e for e in entries if 4.0 <= e["cvss"] < 7.0]
        low      = [e for e in entries if e["cvss"] < 4.0]
        kevs     = [e for e in entries if e["kev"]]

        lines.append(f"  CRITICAL ({len(critical)}) | HIGH ({len(high)}) | "
                     f"MEDIUM ({len(medium)}) | LOW ({len(low)}) | KEV ({len(kevs)})")
        lines.append("")

        for group_name, group in [("CRITICAL", critical), ("HIGH", high),
                                  ("MEDIUM", medium), ("LOW", low)]:
            if group:
                lines.append(f"  --- {group_name} ---")
                for e in sorted(group, key=lambda x: x["cvss"], reverse=True):
                    lines.append(f"    {e['cve_id']}  CVSS={e['cvss']:<5}  "
                                 f"{e['product']}  {'[KEV]' if e['kev'] else ''}")
                    lines.append(f"      {e['description'][:120]}")
                lines.append("")

        if kevs:
            lines.append("  --- NEW KEV ADDITIONS ---")
            for e in kevs:
                lines.append(f"    {e['cve_id']}  {e['product']}")
            lines.append("")

        top = sorted(entries, key=lambda x: x["cvss"], reverse=True)[:10]
        lines.append("  --- TOP 10 BY CVSS ---")
        for i, e in enumerate(top, 1):
            lines.append(f"    {i:>2}. {e['cve_id']}  CVSS={e['cvss']}")
        return "\n".join(lines)

    @staticmethod
    def _digest_json(entries: List[Dict[str, Any]], label: str) -> str:
        return json.dumps({
            "digest_type": label,
            "generated": datetime.now(timezone.utc).isoformat(),
            "total": len(entries),
            "critical": len([e for e in entries if e["cvss"] >= 9.0]),
            "high": len([e for e in entries if 7.0 <= e["cvss"] < 9.0]),
            "kev_additions": len([e for e in entries if e["kev"]]),
            "entries": entries,
        }, indent=2)

    @staticmethod
    def _digest_html(entries: List[Dict[str, Any]], label: str) -> str:
        rows = ""
        for e in sorted(entries, key=lambda x: x["cvss"], reverse=True):
            color = "#ff4444" if e["cvss"] >= 9.0 else (
                "#ff8800" if e["cvss"] >= 7.0 else "#4488ff")
            kev_badge = ' <span style="color:red;font-weight:bold">[KEV]</span>' if e["kev"] else ""
            rows += (f'<tr><td>{e["cve_id"]}{kev_badge}</td>'
                     f'<td style="color:{color};font-weight:bold">{e["cvss"]}</td>'
                     f'<td>{e["severity"]}</td><td>{e["product"]}</td>'
                     f'<td>{e["description"][:120]}</td></tr>\n')
        return (
            f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>FU PERSON {label} CVE Digest</title>"
            f"<style>body{{font-family:monospace;background:#111;color:#eee;padding:20px}}"
            f"table{{border-collapse:collapse;width:100%}}"
            f"th,td{{border:1px solid #444;padding:6px;text-align:left}}"
            f"th{{background:#222}}</style></head><body>"
            f"<h1>FU PERSON :: {label} CVE Digest</h1>"
            f"<p>Generated: {datetime.now(timezone.utc).isoformat()} | "
            f"Total: {len(entries)}</p>"
            f"<table><tr><th>CVE</th><th>CVSS</th><th>Severity</th>"
            f"<th>Product</th><th>Description</th></tr>{rows}</table>"
            f"</body></html>"
        )


# =============================================================================
#  MONITOR DAEMON
# =============================================================================

class MonitorDaemon:
    def __init__(self) -> None:
        self._config = Config()
        self._watchlist = Watchlist()
        self._poller = CVEPoller(self._config)
        self._alerts = AlertEngine(self._config)
        self._digest = DigestGenerator(self._config)
        self._running = threading.Event()
        self._start_time: Optional[datetime] = None
        self._last_poll: Optional[datetime] = None
        self._poll_count: int = 0

    def _write_pid(self) -> None:
        FU_HOME.mkdir(parents=True, exist_ok=True)
        PID_PATH.write_text(str(os.getpid()), encoding="utf-8")

    def _remove_pid(self) -> None:
        try:
            PID_PATH.unlink(missing_ok=True)
        except OSError:
            pass

    def _signal_handler(self, signum: int, frame: Any) -> None:
        C.warn(f"Received signal {signum}, shutting down ...")
        self.stop()

    def start(self, interval_hours: Optional[int] = None) -> None:
        interval = interval_hours or self._config.poll_interval
        self._running.set()
        self._start_time = datetime.now(timezone.utc)
        self._write_pid()

        if hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self._signal_handler)

        C.banner("FU PERSON :: CVE MONITOR DAEMON v1.0")
        C.info(f"PID:                {os.getpid()}")
        C.info(f"Poll interval:      {interval}h")
        C.info(f"Severity threshold: {self._config.severity_threshold}")
        C.info(f"Desktop alerts:     {self._config.alert_desktop}")
        C.info(f"Log alerts:         {self._config.alert_log}")
        C.info(f"Digest interval:    {self._config.digest_interval}")
        C.info(f"Watchlist entries:  {len(self._watchlist.entries)}")
        C.info(f"Seen CVEs:          {self._poller.seen_count}")
        C.info(f"NVD API key:        {'configured' if self._config.nvd_api_key else 'not set (rate-limited)'}")
        C.p(f"  {C.DIM}{'=' * 50}{C.R}\n")

        interval_sec = interval * 3600
        last_digest: Optional[datetime] = None

        try:
            while self._running.is_set():
                self._do_poll_cycle()

                if self._should_digest(last_digest):
                    self._run_digest()
                    last_digest = datetime.now(timezone.utc)

                C.info(f"Next poll in {interval}h. Waiting ...")
                for _ in range(interval_sec):
                    if not self._running.is_set():
                        break
                    time.sleep(1)
        except KeyboardInterrupt:
            C.warn("Keyboard interrupt received")
        finally:
            self._remove_pid()
            C.ok("Daemon stopped cleanly")

    def _do_poll_cycle(self) -> None:
        self._poll_count += 1
        now = datetime.now(timezone.utc)
        C.info(f"Poll cycle #{self._poll_count} at {now.isoformat()}")

        entries = self._watchlist.entries
        if not entries:
            C.warn("Watchlist is empty -- skipping NVD poll")
        else:
            since = self._last_poll or (now - timedelta(hours=self._config.poll_interval))
            cves = self._poller.poll_nvd(entries, since)
            C.info(f"NVD returned {len(cves)} new CVE(s)")
            for cve in cves:
                self._alerts.alert(cve)
            for entry in entries:
                self._watchlist.update_checked(entry.id)

        kev_cves = self._poller.poll_kev(
            self._last_poll or (now - timedelta(hours=self._config.poll_interval))
        )
        C.info(f"KEV returned {len(kev_cves)} new addition(s)")
        for cve in kev_cves:
            self._alerts.alert(cve, severity_threshold=0.0)

        self._last_poll = now
        C.ok(f"Poll cycle #{self._poll_count} complete. "
             f"Total alerts sent: {self._alerts.alert_count}")

    def _should_digest(self, last_digest: Optional[datetime]) -> bool:
        interval = self._config.digest_interval
        if interval == "none":
            return False
        if last_digest is None:
            return False
        now = datetime.now(timezone.utc)
        if interval == "daily" and (now - last_digest) >= timedelta(hours=24):
            return True
        if interval == "weekly" and (now - last_digest) >= timedelta(days=7):
            return True
        return False

    def _run_digest(self) -> None:
        C.info("Generating scheduled digest ...")
        if self._config.digest_interval == "daily":
            self._digest.daily_digest()
        else:
            self._digest.weekly_digest()

    def stop(self) -> None:
        self._running.clear()

    def status(self) -> None:
        pid: Optional[int] = None
        if PID_PATH.exists():
            try:
                pid = int(PID_PATH.read_text(encoding="utf-8").strip())
            except (ValueError, OSError):
                pass

        C.banner("FU PERSON :: CVE MONITOR STATUS")
        if pid:
            running = _pid_alive(pid)
            C.info(f"PID:           {pid} ({'running' if running else 'stale'})")
        else:
            C.info("PID:           not found (daemon not running)")

        if self._start_time:
            uptime = datetime.now(timezone.utc) - self._start_time
            C.info(f"Uptime:        {uptime}")
        C.info(f"Last poll:     {self._last_poll or 'never'}")
        C.info(f"Alerts sent:   {self._alerts.alert_count}")
        C.info(f"Poll cycles:   {self._poll_count}")
        C.info(f"Seen CVEs:     {self._poller.seen_count}")
        C.info(f"Watchlist:     {len(self._watchlist.entries)} entries")


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
        except Exception:
            pass
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False


def _stop_daemon() -> None:
    if not PID_PATH.exists():
        C.fail("No PID file found -- daemon not running?")
        return
    try:
        pid = int(PID_PATH.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        C.fail("Corrupt PID file")
        return

    if not _pid_alive(pid):
        C.warn(f"PID {pid} is not running (stale PID file)")
        PID_PATH.unlink(missing_ok=True)
        return

    C.info(f"Sending termination signal to PID {pid} ...")
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(1, False, pid)
            kernel32.TerminateProcess(handle, 0)
            kernel32.CloseHandle(handle)
        except Exception as exc:
            C.fail(f"Could not terminate process: {exc}")
            return
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    PID_PATH.unlink(missing_ok=True)
    C.ok(f"Stop signal sent to PID {pid}")


# =============================================================================
#  CLI HANDLERS
# =============================================================================

def _cli_watch(args: argparse.Namespace) -> None:
    wl = Watchlist()
    action = args.watch_action
    if action == "add":
        if not any([args.vendor, args.product, args.cpe, args.keyword]):
            C.fail("Provide at least one of --vendor, --product, --cpe, --keyword")
            return
        wl.add(vendor=args.vendor, product=args.product,
               cpe=args.cpe, keyword=args.keyword)
    elif action == "remove":
        if not args.entry_id:
            C.fail("--id is required for remove")
            return
        wl.remove(args.entry_id)
    elif action == "list":
        wl.list_all()


def _cli_start(args: argparse.Namespace) -> None:
    if PID_PATH.exists():
        try:
            pid = int(PID_PATH.read_text(encoding="utf-8").strip())
            if _pid_alive(pid):
                C.fail(f"Daemon already running (PID {pid})")
                return
        except (ValueError, OSError):
            pass
    daemon = MonitorDaemon()
    daemon.start(interval_hours=args.interval)


def _cli_stop(_args: argparse.Namespace) -> None:
    _stop_daemon()


def _cli_status(_args: argparse.Namespace) -> None:
    daemon = MonitorDaemon()
    daemon.status()


def _cli_digest(args: argparse.Namespace) -> None:
    config = Config()
    gen = DigestGenerator(config)
    fmt = args.format or "text"
    if args.period == "weekly":
        gen.weekly_digest(fmt=fmt)
    else:
        gen.daily_digest(fmt=fmt)


def _cli_config(args: argparse.Namespace) -> None:
    config = Config()
    if args.config_action == "show":
        config.show()
    elif args.config_action == "set":
        if not args.key or args.value is None:
            C.fail("--key and --value required")
            return
        val: Any = args.value
        if val.lower() in ("true", "false"):
            val = val.lower() == "true"
        else:
            try:
                val = float(val) if "." in val else int(val)
            except ValueError:
                pass
        config.set(args.key, val)
        config.save()
        C.ok(f"Set {C.CYN}{args.key}{C.R} = {val}")
    elif args.config_action == "reset":
        config.defaults()
        C.ok("Configuration reset to defaults")


# =============================================================================
#  ARGUMENT PARSER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cve_monitor",
        description="FU PERSON :: CVE Monitoring Daemon",
    )
    sub = p.add_subparsers(dest="command")

    # -- watch --
    w = sub.add_parser("watch", help="Manage watchlist")
    ws = w.add_subparsers(dest="watch_action")

    wa = ws.add_parser("add", help="Add watch entry")
    wa.add_argument("--vendor", "-V"); wa.add_argument("--product", "-P")
    wa.add_argument("--cpe", "-c"); wa.add_argument("--keyword", "-k")

    wr = ws.add_parser("remove", help="Remove watch entry")
    wr.add_argument("--id", dest="entry_id", required=True)

    ws.add_parser("list", help="List watchlist")

    # -- start --
    st = sub.add_parser("start", help="Start monitoring daemon")
    st.add_argument("--interval", "-i", type=int, default=None,
                    help="Poll interval in hours")

    # -- stop --
    sub.add_parser("stop", help="Stop monitoring daemon")

    # -- status --
    sub.add_parser("status", help="Show daemon status")

    # -- digest --
    dg = sub.add_parser("digest", help="Generate CVE digest")
    dg.add_argument("--period", choices=["daily", "weekly"], default="daily")
    dg.add_argument("--format", "-f", choices=["text", "json", "html"], default="text")

    # -- config --
    cf = sub.add_parser("config", help="Manage configuration")
    cs = cf.add_subparsers(dest="config_action")
    cs.add_parser("show", help="Show configuration")
    cset = cs.add_parser("set", help="Set configuration value")
    cset.add_argument("--key", "-k", required=True); cset.add_argument("--value", "-v", required=True)
    cs.add_parser("reset", help="Reset to defaults")

    return p


# =============================================================================
#  ENTRY POINT
# =============================================================================

def main() -> None:
    C.banner("FU PERSON :: CVE MONITORING DAEMON v1.0")
    C.p(f"  {C.DIM}Data directory: {FU_HOME}{C.R}\n")

    parser = build_parser()
    args = parser.parse_args()

    dispatch: Dict[str, Callable[[argparse.Namespace], None]] = {
        "watch": _cli_watch,
        "start": _cli_start,
        "stop": _cli_stop,
        "status": _cli_status,
        "digest": _cli_digest,
        "config": _cli_config,
    }
    handler = dispatch.get(args.command)  # type: ignore[arg-type]
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
