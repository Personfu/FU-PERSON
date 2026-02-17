#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: REPO COLLECTOR v2.0
  GitHub Repository Scanner & Intelligence Extractor
  User Repos | Stars | Forks | Languages | Secret Pattern Detection
===============================================================================
"""

import os
import sys
import json
import time
import re
import base64
import argparse
import textwrap
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings("ignore")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
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
{C.BLU}{C.BLD}
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.R}{C.BLU}    ──────────────── REPO COLLECTOR v2.0 ─── GitHub OSINT ──────────────{C.R}
{C.DIM}    FLLC  |  Legal OSINT Only  |  Public Repository Analysis{C.R}
"""

DISCLAIMER = f"""{C.YLW}{C.BLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│  LEGAL DISCLAIMER                                                            │
│  This tool queries ONLY the public GitHub API and public repositories.       │
│  No unauthorized access is performed. Secret detection identifies PATTERNS   │
│  only -- it does NOT extract or use any discovered credentials.              │
│  For authorized OSINT research only. Comply with GitHub ToS.                │
└──────────────────────────────────────────────────────────────────────────────┘{C.R}
"""


# =============================================================================
#  SECRET PATTERN DEFINITIONS
# =============================================================================

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
    "GitHub Token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "GitHub OAuth": r"gho_[A-Za-z0-9_]{36,}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
    "Bearer Token": r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Private Key": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
    "Slack Token": r"xox[bpors]-[0-9]{10,}-[A-Za-z0-9]{10,}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Heroku API Key": r"(?i)heroku.*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Stripe Key": r"[sr]k_(live|test)_[A-Za-z0-9]{20,}",
    "Twilio SID": r"AC[a-f0-9]{32}",
    "SendGrid Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "SSH Password": r"(?i)sshpass\s+-p\s+['\"]?[^\s'\"]+",
    "Database URL": r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"]+",
    "IP Address (Private)": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
}

SENSITIVE_FILENAMES = [
    ".env", ".env.local", ".env.production", ".env.development",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "secrets.json", "secrets.yml", "secrets.yaml",
    ".htpasswd", ".htaccess", "wp-config.php",
    "id_rsa", "id_rsa.pub", "id_ed25519",
    "docker-compose.yml", "Dockerfile",
    ".npmrc", ".pypirc", ".netrc",
    "config.json", "config.yml", "settings.json",
    "firebase.json", "serviceAccountKey.json",
    "terraform.tfvars", "terraform.tfstate",
    ".travis.yml", ".circleci/config.yml",
    "Jenkinsfile", "Vagrantfile",
    "database.yml", "application.properties",
]


# =============================================================================
#  GITHUB API CLIENT
# =============================================================================

class GitHubClient:
    """Interact with GitHub's public API."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str = None):
        self.session = requests.Session() if HAS_REQUESTS else None
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        if self.session:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "FU-PERSON-RepoCollector/2.0",
            }
            if self.token:
                headers["Authorization"] = f"token {self.token}"
            self.session.headers.update(headers)
        self.rate_remaining = 60
        self.rate_reset = 0

    def _get(self, endpoint: str, params: dict = None) -> Optional[Dict]:
        if not self.session:
            C.fail("requests library required. pip install requests")
            return None
        url = f"{self.BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint
        try:
            resp = self.session.get(url, params=params, timeout=15)
            self.rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", 60))
            self.rate_reset = int(resp.headers.get("X-RateLimit-Reset", 0))

            if resp.status_code == 403 and self.rate_remaining == 0:
                reset_time = datetime.fromtimestamp(self.rate_reset)
                C.warn(f"Rate limited. Resets at {reset_time.strftime('%H:%M:%S')}")
                if not self.token:
                    C.warn("Set GITHUB_TOKEN env var for higher rate limits (5000/hr)")
                return None
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            C.fail(f"GitHub API error: {e}")
            return None

    def _get_paginated(self, endpoint: str, params: dict = None, max_pages: int = 10) -> List[Dict]:
        params = params or {}
        params["per_page"] = 100
        all_items = []
        for page in range(1, max_pages + 1):
            params["page"] = page
            data = self._get(endpoint, params)
            if not data or not isinstance(data, list) or len(data) == 0:
                break
            all_items.extend(data)
            if len(data) < 100:
                break
        return all_items

    def get_user(self, username: str) -> Optional[Dict]:
        return self._get(f"/users/{username}")

    def get_repos(self, username: str, max_pages: int = 10) -> List[Dict]:
        return self._get_paginated(f"/users/{username}/repos", {"sort": "updated"}, max_pages)

    def get_gists(self, username: str) -> List[Dict]:
        return self._get_paginated(f"/users/{username}/gists", max_pages=3)

    def get_orgs(self, username: str) -> List[Dict]:
        return self._get_paginated(f"/users/{username}/orgs", max_pages=2)

    def get_events(self, username: str) -> List[Dict]:
        return self._get_paginated(f"/users/{username}/events/public", max_pages=3)

    def get_repo_contents(self, owner: str, repo: str, path: str = "") -> Optional[List]:
        return self._get(f"/repos/{owner}/{repo}/contents/{path}")

    def search_code(self, query: str) -> Optional[Dict]:
        return self._get("/search/code", {"q": query})


# =============================================================================
#  REPO ANALYZER
# =============================================================================

class RepoAnalyzer:
    """Analyze repository metadata and content."""

    def __init__(self, client: GitHubClient):
        self.client = client

    def analyze_repo(self, repo: Dict) -> Dict:
        """Extract comprehensive metadata from a repository."""
        return {
            "name": repo.get("name", ""),
            "full_name": repo.get("full_name", ""),
            "description": repo.get("description", ""),
            "url": repo.get("html_url", ""),
            "clone_url": repo.get("clone_url", ""),
            "language": repo.get("language", ""),
            "stars": repo.get("stargazers_count", 0),
            "forks": repo.get("forks_count", 0),
            "watchers": repo.get("watchers_count", 0),
            "open_issues": repo.get("open_issues_count", 0),
            "size_kb": repo.get("size", 0),
            "default_branch": repo.get("default_branch", "main"),
            "created_at": repo.get("created_at", ""),
            "updated_at": repo.get("updated_at", ""),
            "pushed_at": repo.get("pushed_at", ""),
            "is_fork": repo.get("fork", False),
            "is_archived": repo.get("archived", False),
            "is_private": repo.get("private", False),
            "has_wiki": repo.get("has_wiki", False),
            "has_pages": repo.get("has_pages", False),
            "has_issues": repo.get("has_issues", False),
            "license": repo.get("license", {}).get("spdx_id", "None") if repo.get("license") else "None",
            "topics": repo.get("topics", []),
        }

    def scan_sensitive_files(self, owner: str, repo_name: str) -> List[Dict]:
        """Check root directory for sensitive filenames."""
        findings = []
        contents = self.client.get_repo_contents(owner, repo_name)
        if not contents or not isinstance(contents, list):
            return findings

        for item in contents:
            name = item.get("name", "")
            if name.lower() in [f.lower() for f in SENSITIVE_FILENAMES]:
                findings.append({
                    "type": "sensitive_file",
                    "filename": name,
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "size": item.get("size", 0),
                    "severity": "high" if name.startswith(".env") or "credential" in name.lower() or "secret" in name.lower() else "medium",
                })

        common_dirs = [".github", "config", "deploy", "scripts", "infra"]
        for item in contents:
            if item.get("type") == "dir" and item.get("name", "").lower() in common_dirs:
                sub_contents = self.client.get_repo_contents(owner, repo_name, item["name"])
                if sub_contents and isinstance(sub_contents, list):
                    for sub in sub_contents:
                        sname = sub.get("name", "")
                        if sname.lower() in [f.lower() for f in SENSITIVE_FILENAMES]:
                            findings.append({
                                "type": "sensitive_file",
                                "filename": sname,
                                "path": sub.get("path", ""),
                                "url": sub.get("html_url", ""),
                                "size": sub.get("size", 0),
                                "severity": "medium",
                            })

        return findings

    def scan_readme_for_patterns(self, owner: str, repo_name: str) -> List[Dict]:
        """Scan README for secret patterns (common mistake)."""
        findings = []
        for readme_name in ["README.md", "README.rst", "README.txt", "README"]:
            content_data = self.client.get_repo_contents(owner, repo_name, readme_name)
            if content_data and isinstance(content_data, dict) and "content" in content_data:
                try:
                    content = base64.b64decode(content_data["content"]).decode("utf-8", errors="replace")
                    for pattern_name, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            findings.append({
                                "type": "pattern_in_readme",
                                "pattern": pattern_name,
                                "file": readme_name,
                                "match_count": len(matches),
                                "severity": "high" if "key" in pattern_name.lower() or "token" in pattern_name.lower() else "medium",
                            })
                except Exception:
                    pass
                break
        return findings


# =============================================================================
#  REPO COLLECTOR ENGINE
# =============================================================================

class RepoCollector:
    """Main engine for GitHub user reconnaissance."""

    def __init__(self, token: str = None, output_dir: str = "fu_repo_output"):
        self.client = GitHubClient(token=token)
        self.analyzer = RepoAnalyzer(self.client)
        self.output_dir = output_dir
        self.results = {
            "tool": "FU PERSON :: Repo Collector v2.0",
            "timestamp": "",
            "user_profile": {},
            "organizations": [],
            "repositories": [],
            "gists": [],
            "secret_findings": [],
            "statistics": {},
            "activity_summary": {},
        }

    def scan_user(self, username: str, deep_scan: bool = False):
        """Run the full GitHub user scan."""
        self.results["timestamp"] = datetime.utcnow().isoformat() + "Z"

        if not HAS_REQUESTS:
            C.fail("requests library required. pip install requests")
            return

        C.section("USER PROFILE")
        C.info(f"Querying GitHub user: {C.BLD}{username}{C.R}")
        C.p("")

        user = self.client.get_user(username)
        if not user:
            C.fail(f"User '{username}' not found on GitHub")
            return

        profile = {
            "login": user.get("login", ""),
            "name": user.get("name", ""),
            "bio": user.get("bio", ""),
            "company": user.get("company", ""),
            "location": user.get("location", ""),
            "email": user.get("email", ""),
            "blog": user.get("blog", ""),
            "twitter": user.get("twitter_username", ""),
            "public_repos": user.get("public_repos", 0),
            "public_gists": user.get("public_gists", 0),
            "followers": user.get("followers", 0),
            "following": user.get("following", 0),
            "created_at": user.get("created_at", ""),
            "updated_at": user.get("updated_at", ""),
            "avatar_url": user.get("avatar_url", ""),
            "html_url": user.get("html_url", ""),
            "hireable": user.get("hireable"),
            "type": user.get("type", "User"),
        }
        self.results["user_profile"] = profile

        profile_lines = [
            ("Login", profile["login"]), ("Name", profile["name"]),
            ("Bio", profile["bio"]), ("Company", profile["company"]),
            ("Location", profile["location"]), ("Email", profile["email"]),
            ("Blog", profile["blog"]), ("Twitter", profile["twitter"]),
            ("Repos", str(profile["public_repos"])), ("Gists", str(profile["public_gists"])),
            ("Followers", str(profile["followers"])), ("Following", str(profile["following"])),
            ("Created", profile["created_at"]), ("URL", profile["html_url"]),
        ]
        for label, val in profile_lines:
            if val:
                C.ok(f"{C.WHT}{label:<12}{C.R} {val}")

        C.p(f"\n  {C.DIM}Rate limit remaining: {self.client.rate_remaining}{C.R}")

        C.section("ORGANIZATIONS")
        orgs = self.client.get_orgs(username)
        self.results["organizations"] = [
            {"login": o.get("login", ""), "url": f"https://github.com/{o.get('login', '')}",
             "description": o.get("description", "")}
            for o in orgs
        ]
        if orgs:
            for o in self.results["organizations"]:
                C.ok(f"{o['login']}: {o['description'] or 'No description'}")
        else:
            C.info("No public organizations found")

        C.section("REPOSITORIES")
        C.info(f"Fetching repositories for {username}...")
        repos = self.client.get_repos(username)
        C.ok(f"Found {len(repos)} public repositories")
        C.p("")

        lang_stats = {}
        total_stars = 0
        total_forks = 0
        all_topics = set()

        for i, repo in enumerate(repos):
            analyzed = self.analyzer.analyze_repo(repo)
            self.results["repositories"].append(analyzed)

            lang = analyzed["language"] or "Unknown"
            lang_stats[lang] = lang_stats.get(lang, 0) + 1
            total_stars += analyzed["stars"]
            total_forks += analyzed["forks"]
            all_topics.update(analyzed["topics"])

            star_icon = f"{C.YLW}*{analyzed['stars']}{C.R}" if analyzed["stars"] > 0 else ""
            fork_icon = f"{C.CYN}F{analyzed['forks']}{C.R}" if analyzed["forks"] > 0 else ""
            lang_tag = f"{C.MAG}{lang}{C.R}" if lang != "Unknown" else ""
            archived = f" {C.RED}[ARCHIVED]{C.R}" if analyzed["is_archived"] else ""
            forked = f" {C.DIM}[FORK]{C.R}" if analyzed["is_fork"] else ""

            desc = (analyzed["description"] or "")[:60]
            C.p(f"  {C.GRN}{analyzed['name']:<30}{C.R} {star_icon} {fork_icon} {lang_tag}{archived}{forked}")
            if desc:
                C.p(f"  {C.DIM}{'':>30} {desc}{C.R}")

            C.progress(i + 1, len(repos), "repos analyzed")

        C.section("GISTS")
        gists = self.client.get_gists(username)
        self.results["gists"] = [
            {
                "id": g.get("id", ""),
                "description": g.get("description", ""),
                "url": g.get("html_url", ""),
                "files": list(g.get("files", {}).keys()),
                "public": g.get("public", True),
                "created_at": g.get("created_at", ""),
            }
            for g in gists
        ]
        if gists:
            for g in self.results["gists"][:10]:
                desc = g["description"][:60] if g["description"] else "No description"
                C.ok(f"{g['id'][:8]}...  {desc}  ({len(g['files'])} files)")
        else:
            C.info("No public gists found")

        if deep_scan:
            C.section("SECRET PATTERN SCAN")
            C.info("Scanning repositories for potential secret patterns...")
            C.warn("This checks file listings and READMEs only (non-invasive)")
            C.p("")

            all_findings = []
            scan_repos = [r for r in self.results["repositories"] if not r["is_fork"]][:20]

            for i, repo in enumerate(scan_repos):
                repo_name = repo["name"]
                findings = self.analyzer.scan_sensitive_files(username, repo_name)
                findings.extend(self.analyzer.scan_readme_for_patterns(username, repo_name))

                for f in findings:
                    f["repository"] = repo_name
                    severity_color = C.RED if f.get("severity") == "high" else C.YLW
                    C.p(f"  {severity_color}[{f['severity'].upper()}]{C.R} {repo_name}: {f['type']} - {f.get('filename', f.get('pattern', ''))}")

                all_findings.extend(findings)
                C.progress(i + 1, len(scan_repos), "repos scanned")

                if self.client.rate_remaining < 10:
                    C.warn("Rate limit low, pausing secret scan")
                    break
                time.sleep(0.3)

            self.results["secret_findings"] = all_findings
            if not all_findings:
                C.ok("No obvious secret patterns detected in scanned repos")
            else:
                high = sum(1 for f in all_findings if f.get("severity") == "high")
                med = sum(1 for f in all_findings if f.get("severity") == "medium")
                C.p(f"\n  {C.RED}[!] Found {len(all_findings)} potential findings: {high} HIGH, {med} MEDIUM{C.R}")

        C.section("STATISTICS")
        stats = {
            "total_repos": len(self.results["repositories"]),
            "total_stars": total_stars,
            "total_forks": total_forks,
            "original_repos": sum(1 for r in self.results["repositories"] if not r["is_fork"]),
            "forked_repos": sum(1 for r in self.results["repositories"] if r["is_fork"]),
            "archived_repos": sum(1 for r in self.results["repositories"] if r["is_archived"]),
            "languages": lang_stats,
            "top_language": max(lang_stats, key=lang_stats.get) if lang_stats else "None",
            "topics": sorted(all_topics),
            "total_gists": len(self.results["gists"]),
            "total_orgs": len(self.results["organizations"]),
        }
        self.results["statistics"] = stats

        stat_lines = [
            ("Total Repos", str(stats["total_repos"])),
            ("Original", str(stats["original_repos"])),
            ("Forked", str(stats["forked_repos"])),
            ("Archived", str(stats["archived_repos"])),
            ("Total Stars", str(stats["total_stars"])),
            ("Total Forks", str(stats["total_forks"])),
            ("Top Language", stats["top_language"]),
            ("Gists", str(stats["total_gists"])),
            ("Organizations", str(stats["total_orgs"])),
        ]
        for label, val in stat_lines:
            C.ok(f"{C.WHT}{label:<18}{C.R} {val}")

        if lang_stats:
            C.p(f"\n  {C.CYN}Language breakdown:{C.R}")
            for lang, count in sorted(lang_stats.items(), key=lambda x: -x[1])[:10]:
                bar_len = int(20 * count / max(lang_stats.values()))
                C.p(f"    {lang:<15} {C.GRN}{'█' * bar_len}{C.R} {count}")

        if all_topics:
            C.p(f"\n  {C.CYN}Topics:{C.R} {', '.join(sorted(all_topics)[:20])}")

        events = self.client.get_events(username)
        if events:
            event_types = {}
            for ev in events:
                t = ev.get("type", "Unknown")
                event_types[t] = event_types.get(t, 0) + 1
            self.results["activity_summary"] = {
                "recent_events": len(events),
                "event_types": event_types,
                "last_event": events[0].get("created_at", "") if events else "",
            }
            C.p(f"\n  {C.CYN}Recent activity: {len(events)} events{C.R}")
            for etype, count in sorted(event_types.items(), key=lambda x: -x[1])[:5]:
                C.p(f"    {etype:<30} {count}")

        self._export(username)

    def _export(self, username: str):
        """Export results to JSON."""
        os.makedirs(self.output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"github_{username}_{ts}.json")

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)

        C.section("EXPORT")
        C.ok(f"Report saved: {C.BLD}{filepath}{C.R}")

        C.p(f"\n  {C.GRN}{C.BLD}[*] GitHub scan complete for @{username}{C.R}")
        C.p(f"  {C.DIM}    Rate limit remaining: {self.client.rate_remaining}{C.R}")
        C.p(f"  {C.DIM}    Timestamp: {datetime.utcnow().isoformat()}Z{C.R}\n")


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def main():
    C.p(BANNER)
    C.p(DISCLAIMER)

    parser = argparse.ArgumentParser(
        prog="repo_collector",
        description=f"{C.BLU}FU PERSON :: Repo Collector v2.0 -- GitHub OSINT Scanner{C.R}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        {C.CYN}Examples:{C.R}
          python repo_collector.py -u octocat
          python repo_collector.py -u torvalds --deep
          python repo_collector.py -u target-user --token ghp_xxxxx -o ./reports
          
        {C.YLW}Note:{C.R} Set GITHUB_TOKEN env var or use --token for higher rate limits.
        Without auth: 60 req/hr. With token: 5000 req/hr.
        """),
    )

    parser.add_argument("-u", "--user", required=True, help="GitHub username to scan")
    parser.add_argument("-o", "--output", default="fu_repo_output", help="Output directory")
    parser.add_argument("--token", help="GitHub personal access token (or set GITHUB_TOKEN)")
    parser.add_argument("--deep", action="store_true", help="Deep scan: check repos for secret patterns")

    args = parser.parse_args()

    if not HAS_REQUESTS:
        C.fail("requests library required. pip install requests")
        sys.exit(1)

    collector = RepoCollector(token=args.token, output_dir=args.output)
    collector.scan_user(args.user, deep_scan=args.deep)


if __name__ == "__main__":
    main()
