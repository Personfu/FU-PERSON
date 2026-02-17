#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: LIST CONSOLIDATOR v2.0
  Wordlist Merge, Deduplicate, Sort & Export Tool
  Multi-encoding | Smart Dedup | Frequency Analysis
===============================================================================
"""

import os
import sys
import json
import re
import argparse
import textwrap
import hashlib
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
from collections import Counter
import warnings

warnings.filterwarnings("ignore")

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
    UND = "\033[4m"
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
    def ok(msg):
        C.p(f"  {C.GRN}[+]{C.R} {msg}")

    @staticmethod
    def info(msg):
        C.p(f"  {C.CYN}[*]{C.R} {msg}")

    @staticmethod
    def warn(msg):
        C.p(f"  {C.YLW}[!]{C.R} {msg}")

    @staticmethod
    def fail(msg):
        C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def progress(current: int, total: int, label: str = ""):
        pct = current / max(total, 1)
        filled = int(30 * pct)
        bar = f"{C.GRN}{'█' * filled}{C.DIM}{'░' * (30 - filled)}{C.R}"
        sys.stdout.write(f"\r  {bar} {C.CYN}{current}/{total}{C.R} {label}  ")
        sys.stdout.flush()
        if current >= total:
            print()


BANNER = rf"""
{C.GRN}{C.BLD}
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.R}{C.GRN}    ──────────── LIST CONSOLIDATOR v2.0 ─── Wordlist Engine ────────────{C.R}
{C.DIM}    FLLC  |  Merge  |  Deduplicate  |  Sort  |  Multi-Encoding{C.R}
"""

DISCLAIMER = f"""{C.YLW}{C.BLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│  LIST CONSOLIDATOR - For authorized security testing and research only.      │
│  Wordlists are used for legitimate penetration testing, subdomain            │
│  enumeration, and security assessments with explicit authorization.          │
└──────────────────────────────────────────────────────────────────────────────┘{C.R}
"""


# =============================================================================
#  ENCODING DETECTOR
# =============================================================================

SUPPORTED_ENCODINGS = [
    "utf-8", "utf-8-sig", "ascii", "latin-1", "iso-8859-1", "iso-8859-2",
    "iso-8859-15", "cp1252", "cp1251", "cp437", "utf-16", "utf-16-le",
    "utf-16-be", "utf-32", "shift_jis", "euc-jp", "gb2312", "gbk",
    "euc-kr", "big5",
]


def detect_encoding(filepath: str) -> str:
    """Detect file encoding by trying multiple encodings."""
    with open(filepath, "rb") as f:
        raw = f.read(min(os.path.getsize(filepath), 65536))

    if raw[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if raw[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return "utf-32"

    for enc in ["utf-8", "ascii"]:
        try:
            raw.decode(enc)
            return enc
        except (UnicodeDecodeError, ValueError):
            continue

    for enc in SUPPORTED_ENCODINGS:
        try:
            raw.decode(enc)
            return enc
        except (UnicodeDecodeError, ValueError):
            continue

    return "utf-8"


# =============================================================================
#  WORDLIST READER
# =============================================================================

class WordlistReader:
    """Read wordlists from various file formats and encodings."""

    @staticmethod
    def read_file(filepath: str, encoding: str = None, strip_comments: bool = True,
                  strip_empty: bool = True, lowercase: bool = False) -> Tuple[List[str], Dict]:
        """Read a single wordlist file and return lines + metadata."""
        if not os.path.isfile(filepath):
            C.fail(f"File not found: {filepath}")
            return [], {"error": f"File not found: {filepath}"}

        file_size = os.path.getsize(filepath)
        if encoding is None:
            encoding = detect_encoding(filepath)

        meta = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "encoding": encoding,
            "size_bytes": file_size,
            "size_mb": round(file_size / (1024 * 1024), 2),
        }

        lines = []
        errors = 0
        try:
            with open(filepath, "r", encoding=encoding, errors="replace") as f:
                for raw_line in f:
                    line = raw_line.rstrip("\n\r")

                    if strip_comments and line.lstrip().startswith("#"):
                        continue

                    if strip_empty and not line.strip():
                        continue

                    line = line.strip()

                    if lowercase:
                        line = line.lower()

                    lines.append(line)
        except Exception as e:
            C.fail(f"Error reading {filepath}: {e}")
            meta["error"] = str(e)

        meta["lines_read"] = len(lines)
        meta["read_errors"] = errors
        return lines, meta

    @staticmethod
    def read_directory(dirpath: str, extensions: List[str] = None, **kwargs) -> Tuple[List[str], List[Dict]]:
        """Read all wordlist files from a directory."""
        if not os.path.isdir(dirpath):
            C.fail(f"Directory not found: {dirpath}")
            return [], []

        valid_ext = extensions or [".txt", ".lst", ".wordlist", ".dict", ".csv", ".list"]
        all_lines = []
        all_meta = []

        for root, dirs, files in os.walk(dirpath):
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if ext in valid_ext or not extensions:
                    fpath = os.path.join(root, fname)
                    lines, meta = WordlistReader.read_file(fpath, **kwargs)
                    all_lines.extend(lines)
                    all_meta.append(meta)

        return all_lines, all_meta


# =============================================================================
#  DEDUPLICATOR
# =============================================================================

class Deduplicator:
    """Remove duplicates with various strategies."""

    @staticmethod
    def exact(lines: List[str]) -> List[str]:
        """Remove exact duplicates (preserving order)."""
        seen = set()
        result = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                result.append(line)
        return result

    @staticmethod
    def case_insensitive(lines: List[str]) -> List[str]:
        """Remove case-insensitive duplicates (keep first occurrence)."""
        seen = set()
        result = []
        for line in lines:
            lower = line.lower()
            if lower not in seen:
                seen.add(lower)
                result.append(line)
        return result

    @staticmethod
    def prefix(lines: List[str], min_prefix: int = 3) -> List[str]:
        """Remove entries that are prefixes of other entries."""
        sorted_lines = sorted(lines, key=len, reverse=True)
        keep = set()
        for line in sorted_lines:
            is_prefix = False
            for kept in keep:
                if kept.startswith(line) and len(kept) > len(line) >= min_prefix:
                    is_prefix = True
                    break
            if not is_prefix:
                keep.add(line)
        return [l for l in lines if l in keep]

    @staticmethod
    def length_filter(lines: List[str], min_len: int = 1, max_len: int = 0) -> List[str]:
        """Filter by line length."""
        result = [l for l in lines if len(l) >= min_len]
        if max_len > 0:
            result = [l for l in result if len(l) <= max_len]
        return result

    @staticmethod
    def regex_filter(lines: List[str], pattern: str, invert: bool = False) -> List[str]:
        """Filter lines matching a regex pattern."""
        compiled = re.compile(pattern)
        if invert:
            return [l for l in lines if not compiled.search(l)]
        return [l for l in lines if compiled.search(l)]


# =============================================================================
#  SORTER
# =============================================================================

class Sorter:
    """Sort wordlists with various strategies."""

    @staticmethod
    def alphabetical(lines: List[str], reverse: bool = False) -> List[str]:
        return sorted(lines, key=str.lower, reverse=reverse)

    @staticmethod
    def by_length(lines: List[str], reverse: bool = False) -> List[str]:
        return sorted(lines, key=len, reverse=reverse)

    @staticmethod
    def by_frequency(lines: List[str], reverse: bool = True) -> List[str]:
        """Sort by frequency (most common first by default)."""
        counter = Counter(lines)
        return sorted(set(lines), key=lambda x: counter[x], reverse=reverse)

    @staticmethod
    def natural(lines: List[str], reverse: bool = False) -> List[str]:
        """Natural sort (handles numbers correctly)."""
        def natural_key(s):
            return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", s)]
        return sorted(lines, key=natural_key, reverse=reverse)


# =============================================================================
#  ANALYZER
# =============================================================================

class WordlistAnalyzer:
    """Analyze wordlist statistics."""

    @staticmethod
    def analyze(lines: List[str]) -> Dict:
        if not lines:
            return {"total": 0}

        lengths = [len(l) for l in lines]
        unique = set(lines)
        counter = Counter(lines)

        char_freq = Counter()
        for l in lines:
            char_freq.update(l)

        return {
            "total_lines": len(lines),
            "unique_lines": len(unique),
            "duplicates": len(lines) - len(unique),
            "duplicate_pct": round((len(lines) - len(unique)) / max(len(lines), 1) * 100, 1),
            "min_length": min(lengths),
            "max_length": max(lengths),
            "avg_length": round(sum(lengths) / len(lengths), 1),
            "median_length": sorted(lengths)[len(lengths) // 2],
            "total_chars": sum(lengths),
            "top_duplicates": counter.most_common(10),
            "top_chars": char_freq.most_common(15),
            "has_numeric": sum(1 for l in lines if l.isdigit()),
            "has_alpha": sum(1 for l in lines if l.isalpha()),
            "has_mixed": sum(1 for l in lines if l.isalnum() and not l.isalpha() and not l.isdigit()),
        }


# =============================================================================
#  LIST CONSOLIDATOR ENGINE
# =============================================================================

class ListConsolidator:
    """Main engine for merging, deduplicating, and sorting wordlists."""

    def __init__(self, output_dir: str = "fu_wordlists"):
        self.output_dir = output_dir
        self.all_lines: List[str] = []
        self.source_meta: List[Dict] = []
        self.stats: Dict = {}

    def add_file(self, filepath: str, encoding: str = None, lowercase: bool = False):
        """Add a single file to the consolidation."""
        C.info(f"Reading: {filepath}")
        lines, meta = WordlistReader.read_file(filepath, encoding=encoding, lowercase=lowercase)
        self.all_lines.extend(lines)
        self.source_meta.append(meta)
        C.ok(f"Loaded {meta['lines_read']} lines ({meta.get('encoding', '?')}, {meta.get('size_mb', '?')} MB)")

    def add_directory(self, dirpath: str, extensions: List[str] = None, lowercase: bool = False):
        """Add all wordlists from a directory."""
        C.info(f"Scanning directory: {dirpath}")
        lines, metas = WordlistReader.read_directory(dirpath, extensions=extensions, lowercase=lowercase)
        self.all_lines.extend(lines)
        self.source_meta.extend(metas)
        C.ok(f"Loaded {len(lines)} lines from {len(metas)} files")

    def consolidate(self, dedup_mode: str = "exact", sort_mode: str = "alpha",
                    min_length: int = 1, max_length: int = 0,
                    filter_regex: str = None, invert_regex: bool = False,
                    reverse_sort: bool = False) -> List[str]:
        """Run the full consolidation pipeline."""

        total_before = len(self.all_lines)
        C.section("CONSOLIDATION PIPELINE")
        C.info(f"Input: {total_before} total lines from {len(self.source_meta)} sources")
        C.p("")

        result = list(self.all_lines)

        C.info(f"Step 1: Length filter (min={min_length}, max={max_length or 'unlimited'})")
        result = Deduplicator.length_filter(result, min_length=min_length, max_length=max_length)
        C.ok(f"After length filter: {len(result)} lines")

        if filter_regex:
            C.info(f"Step 2: Regex filter ({'invert' if invert_regex else 'match'}): {filter_regex}")
            result = Deduplicator.regex_filter(result, filter_regex, invert=invert_regex)
            C.ok(f"After regex filter: {len(result)} lines")

        dedup_name = {"exact": "Exact", "case": "Case-insensitive", "prefix": "Prefix"}.get(dedup_mode, "Exact")
        C.info(f"Step 3: Deduplication ({dedup_name})")
        before_dedup = len(result)
        if dedup_mode == "case":
            result = Deduplicator.case_insensitive(result)
        elif dedup_mode == "prefix":
            result = Deduplicator.exact(result)
            result = Deduplicator.prefix(result)
        else:
            result = Deduplicator.exact(result)
        removed = before_dedup - len(result)
        C.ok(f"Removed {removed} duplicates -> {len(result)} unique lines")

        sort_name = {"alpha": "Alphabetical", "length": "By length", "freq": "By frequency",
                     "natural": "Natural"}.get(sort_mode, "Alphabetical")
        C.info(f"Step 4: Sorting ({sort_name}, {'desc' if reverse_sort else 'asc'})")
        if sort_mode == "length":
            result = Sorter.by_length(result, reverse=reverse_sort)
        elif sort_mode == "freq":
            result = Sorter.by_frequency(self.all_lines, reverse=reverse_sort)
            seen = set()
            unique_result = []
            for line in result:
                if line not in seen and line in set(result):
                    seen.add(line)
                    unique_result.append(line)
            result = unique_result
        elif sort_mode == "natural":
            result = Sorter.natural(result, reverse=reverse_sort)
        else:
            result = Sorter.alphabetical(result, reverse=reverse_sort)

        C.ok(f"Final result: {len(result)} lines")

        self.stats = {
            "input_lines": total_before,
            "output_lines": len(result),
            "duplicates_removed": total_before - len(result),
            "reduction_pct": round((total_before - len(result)) / max(total_before, 1) * 100, 1),
            "source_files": len(self.source_meta),
            "dedup_mode": dedup_mode,
            "sort_mode": sort_mode,
        }

        return result

    def export(self, lines: List[str], output_name: str = "consolidated",
               output_encoding: str = "utf-8", analyze: bool = True):
        """Export the consolidated wordlist."""
        os.makedirs(self.output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        txt_path = os.path.join(self.output_dir, f"{output_name}_{ts}.txt")
        with open(txt_path, "w", encoding=output_encoding, errors="replace") as f:
            for line in lines:
                f.write(line + "\n")

        C.section("EXPORT")
        C.ok(f"Wordlist: {C.BLD}{txt_path}{C.R}")
        file_size = os.path.getsize(txt_path)
        C.ok(f"Size: {file_size / 1024:.1f} KB ({file_size / (1024*1024):.2f} MB)")
        C.ok(f"Lines: {len(lines)}")
        C.ok(f"Encoding: {output_encoding}")

        if analyze:
            C.section("ANALYSIS")
            analysis = WordlistAnalyzer.analyze(lines)

            stats_display = [
                ("Total lines", str(analysis["total_lines"])),
                ("Unique lines", str(analysis["unique_lines"])),
                ("Duplicates", f"{analysis['duplicates']} ({analysis['duplicate_pct']}%)"),
                ("Min length", str(analysis["min_length"])),
                ("Max length", str(analysis["max_length"])),
                ("Avg length", str(analysis["avg_length"])),
                ("Median length", str(analysis["median_length"])),
                ("Total chars", str(analysis["total_chars"])),
                ("Numeric only", str(analysis["has_numeric"])),
                ("Alpha only", str(analysis["has_alpha"])),
                ("Mixed", str(analysis["has_mixed"])),
            ]
            for label, val in stats_display:
                C.ok(f"{C.WHT}{label:<18}{C.R} {val}")

            if analysis.get("top_chars"):
                C.p(f"\n  {C.CYN}Top characters:{C.R}")
                for char, count in analysis["top_chars"][:10]:
                    display_char = repr(char) if not char.isprintable() or char == " " else char
                    C.p(f"    {display_char:<8} {count}")

            json_path = os.path.join(self.output_dir, f"{output_name}_{ts}_stats.json")
            export_analysis = dict(analysis)
            export_analysis["top_duplicates"] = [[k, v] for k, v in analysis.get("top_duplicates", [])]
            export_analysis["top_chars"] = [[k, v] for k, v in analysis.get("top_chars", [])]

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "tool": "FU PERSON :: List Consolidator v2.0",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "pipeline": self.stats,
                    "sources": self.source_meta,
                    "analysis": export_analysis,
                }, f, indent=2, ensure_ascii=False, default=str)
            C.ok(f"Stats: {C.BLD}{json_path}{C.R}")

        C.p(f"\n  {C.GRN}{C.BLD}{'=' * 50}")
        C.p(f"  {'':>2}CONSOLIDATION COMPLETE")
        C.p(f"  {'=' * 50}{C.R}")
        C.p(f"  {C.CYN}Sources:    {len(self.source_meta)} files{C.R}")
        C.p(f"  {C.CYN}Input:      {self.stats.get('input_lines', 0)} lines{C.R}")
        C.p(f"  {C.CYN}Output:     {len(lines)} lines{C.R}")
        C.p(f"  {C.CYN}Reduction:  {self.stats.get('reduction_pct', 0)}%{C.R}")
        C.p(f"  {C.GRN}{C.BLD}{'=' * 50}{C.R}\n")

        return txt_path


# =============================================================================
#  BUILT-IN WORDLIST GENERATORS
# =============================================================================

class BuiltinLists:
    """Generate common built-in wordlists."""

    @staticmethod
    def subdomains() -> List[str]:
        return [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "prod",
            "api", "api2", "api3", "v1", "v2", "portal", "vpn", "remote",
            "cloud", "app", "mobile", "m", "secure", "ssl", "webmail",
            "smtp", "pop", "imap", "ns1", "ns2", "dns", "cdn", "static",
            "assets", "media", "images", "blog", "news", "forum", "shop",
            "store", "login", "auth", "dashboard", "panel", "db", "mysql",
            "postgres", "mongo", "redis", "backup", "archive", "internal",
            "monitor", "status", "health", "metrics", "git", "jenkins",
            "ci", "grafana", "kibana", "elastic", "prometheus", "docker",
            "registry", "jira", "confluence", "gitlab", "vault", "config",
            "sso", "oauth", "ldap", "exchange", "owa", "autodiscover",
            "sharepoint", "sandbox", "demo", "beta", "web", "www2", "mx",
            "sftp", "ssh", "rdp", "ntp", "snmp", "syslog", "waf", "dmz",
            "mgmt", "data", "analytics", "billing", "crm", "erp", "hr",
            "docs", "wiki", "help", "support", "proxy", "gateway", "lb",
            "edge", "node", "worker", "qa", "uat", "preprod", "release",
        ]

    @staticmethod
    def directories() -> List[str]:
        return [
            "admin", "administrator", "api", "app", "assets", "auth",
            "backup", "bin", "blog", "cache", "cgi-bin", "config",
            "console", "css", "dashboard", "data", "db", "debug",
            "deploy", "dev", "docs", "download", "downloads", "editor",
            "email", "error", "export", "feed", "file", "files",
            "font", "fonts", "forum", "help", "home", "html", "image",
            "images", "img", "import", "include", "includes", "index",
            "install", "internal", "js", "json", "lib", "library",
            "log", "login", "logs", "mail", "media", "member", "members",
            "misc", "mobile", "module", "modules", "monitor", "new",
            "news", "old", "page", "pages", "panel", "password",
            "php", "phpmyadmin", "portal", "post", "posts", "private",
            "profile", "public", "register", "report", "reports",
            "resource", "resources", "rest", "root", "rss", "script",
            "scripts", "search", "secret", "secure", "security",
            "server", "service", "services", "session", "settings",
            "setup", "shop", "signin", "signup", "sitemap", "sql",
            "src", "staff", "staging", "static", "stats", "status",
            "storage", "store", "style", "styles", "support", "system",
            "temp", "template", "templates", "test", "testing", "tmp",
            "tools", "upload", "uploads", "user", "users", "util",
            "utils", "vendor", "version", "web", "webmail", "wp-admin",
            "wp-content", "wp-includes", "xml", "xmlrpc",
        ]


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def main():
    C.p(BANNER)
    C.p(DISCLAIMER)

    parser = argparse.ArgumentParser(
        prog="list_consolidator",
        description=f"{C.GRN}FU PERSON :: List Consolidator v2.0 -- Wordlist Engine{C.R}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        {C.CYN}Examples:{C.R}
          python list_consolidator.py -f wordlist1.txt wordlist2.txt
          python list_consolidator.py -d ./wordlists/ -o ./output
          python list_consolidator.py -f list.txt --dedup case --sort length
          python list_consolidator.py -f big.txt --min-length 3 --max-length 20
          python list_consolidator.py --builtin subdomains -o ./output
          python list_consolidator.py -f list.txt --encoding latin-1 --output-encoding utf-8
          python list_consolidator.py -f list.txt --filter "^[a-z]" --lowercase
          
        {C.CYN}Dedup modes:{C.R}  exact (default), case (case-insensitive), prefix
        {C.CYN}Sort modes:{C.R}   alpha (default), length, freq (frequency), natural
        {C.CYN}Built-in:{C.R}     subdomains, directories
        """),
    )

    input_group = parser.add_argument_group("Input")
    input_group.add_argument("-f", "--files", nargs="+", help="Input wordlist file(s)")
    input_group.add_argument("-d", "--dir", help="Directory containing wordlist files")
    input_group.add_argument("--builtin", choices=["subdomains", "directories"], help="Use a built-in wordlist")
    input_group.add_argument("--ext", nargs="+", default=[".txt", ".lst", ".wordlist", ".dict"],
                             help="File extensions to include from directory")

    proc_group = parser.add_argument_group("Processing")
    proc_group.add_argument("--dedup", choices=["exact", "case", "prefix"], default="exact",
                            help="Deduplication mode (default: exact)")
    proc_group.add_argument("--sort", choices=["alpha", "length", "freq", "natural"], default="alpha",
                            help="Sort mode (default: alpha)")
    proc_group.add_argument("--reverse", action="store_true", help="Reverse sort order")
    proc_group.add_argument("--lowercase", action="store_true", help="Convert all entries to lowercase")
    proc_group.add_argument("--min-length", type=int, default=1, help="Minimum line length (default: 1)")
    proc_group.add_argument("--max-length", type=int, default=0, help="Maximum line length (0=unlimited)")
    proc_group.add_argument("--filter", dest="filter_regex", help="Regex filter (keep matching lines)")
    proc_group.add_argument("--invert-filter", action="store_true", help="Invert regex filter (remove matching)")

    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", default="fu_wordlists", help="Output directory")
    output_group.add_argument("--name", default="consolidated", help="Output filename prefix")
    output_group.add_argument("--encoding", help="Input file encoding (auto-detect if not set)")
    output_group.add_argument("--output-encoding", default="utf-8", help="Output encoding (default: utf-8)")
    output_group.add_argument("--no-analyze", action="store_true", help="Skip analysis")

    args = parser.parse_args()

    if not args.files and not args.dir and not args.builtin:
        parser.print_help()
        C.p(f"\n  {C.YLW}[!] Provide --files, --dir, or --builtin.{C.R}\n")
        sys.exit(0)

    consolidator = ListConsolidator(output_dir=args.output)

    C.section("INPUT LOADING")

    if args.builtin:
        C.info(f"Loading built-in wordlist: {args.builtin}")
        if args.builtin == "subdomains":
            builtin_lines = BuiltinLists.subdomains()
        else:
            builtin_lines = BuiltinLists.directories()
        consolidator.all_lines.extend(builtin_lines)
        consolidator.source_meta.append({"filepath": f"<builtin:{args.builtin}>", "lines_read": len(builtin_lines)})
        C.ok(f"Loaded {len(builtin_lines)} built-in entries")

    if args.files:
        for fpath in args.files:
            consolidator.add_file(fpath, encoding=args.encoding, lowercase=args.lowercase)

    if args.dir:
        consolidator.add_directory(args.dir, extensions=args.ext, lowercase=args.lowercase)

    if not consolidator.all_lines:
        C.fail("No lines loaded. Check your input files/directory.")
        sys.exit(1)

    result = consolidator.consolidate(
        dedup_mode=args.dedup,
        sort_mode=args.sort,
        min_length=args.min_length,
        max_length=args.max_length,
        filter_regex=args.filter_regex,
        invert_regex=args.invert_filter,
        reverse_sort=args.reverse,
    )

    consolidator.export(
        result,
        output_name=args.name,
        output_encoding=args.output_encoding,
        analyze=not args.no_analyze,
    )


if __name__ == "__main__":
    main()
