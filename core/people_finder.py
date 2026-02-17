#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: PEOPLE FINDER v2.0
  Comprehensive People Search & OSINT Intelligence Aggregator
  88+ Public Platforms | Legal OSINT Only
===============================================================================
"""

import os
import sys
import json
import time
import re
import urllib.parse
import socket
import csv
import argparse
import textwrap
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
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
    from requests.adapters import HTTPAdapter
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=False)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Blank:
        def __getattr__(self, _):
            return ""
    Fore = _Blank()
    Style = _Blank()

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


# =============================================================================
#  ANSI COLORS & DISPLAY HELPERS
# =============================================================================

class C:
    """Terminal color codes for the Kali aesthetic."""
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
    BGBLK = "\033[40m"

    @staticmethod
    def p(text: str):
        try:
            print(text)
        except UnicodeEncodeError:
            print(re.sub(r"\033\[[0-9;]*m", "", str(text)))

    @staticmethod
    def box(title: str, items: list, color: str = "\033[96m"):
        w = max(len(title) + 4, max((len(str(i)) for i in items), default=40) + 4, 60)
        C.p(f"{color}{'=' * w}")
        C.p(f"  {C.BLD}{title}{C.R}{color}")
        C.p(f"{'=' * w}{C.R}")
        for item in items:
            C.p(f"  {color}{item}{C.R}")
        C.p(f"{color}{'=' * w}{C.R}")

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
{C.R}{C.CYN}    ──────────────── PEOPLE FINDER v2.0 ─── 88+ Platforms ────────────────{C.R}
{C.DIM}    FLLC  |  Legal OSINT Only  |  Public Data Aggregation{C.R}
"""

DISCLAIMER = f"""{C.YLW}{C.BLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│  LEGAL DISCLAIMER                                                            │
│  This tool queries ONLY publicly available data sources. No unauthorized      │
│  access is performed. Users must comply with all applicable laws and the      │
│  terms of service of each platform. For authorized research only.            │
│  The developers assume NO liability for misuse.                              │
└──────────────────────────────────────────────────────────────────────────────┘{C.R}
"""


# =============================================================================
#  CONFIGURATION
# =============================================================================

class Config:
    OUTPUT_DIR = "fu_person_output"
    MAX_WORKERS = 10
    REQUEST_TIMEOUT = 10
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    VERIFY_URLS = False


# =============================================================================
#  DATA MODEL
# =============================================================================

@dataclass
class SearchQuery:
    full_name: str = ""
    first_name: str = ""
    last_name: str = ""
    middle_name: str = ""
    email: str = ""
    phone: str = ""
    username: str = ""
    city: str = ""
    state: str = ""
    country: str = "US"
    employer: str = ""
    school: str = ""
    aliases: List[str] = field(default_factory=list)

    def name_slug(self) -> str:
        parts = []
        if self.first_name:
            parts.append(self.first_name)
        if self.last_name:
            parts.append(self.last_name)
        if not parts and self.full_name:
            parts = self.full_name.strip().split()
        return "-".join(p.lower() for p in parts)

    def name_plus(self) -> str:
        if self.full_name:
            return self.full_name.replace(" ", "+")
        parts = []
        if self.first_name:
            parts.append(self.first_name)
        if self.last_name:
            parts.append(self.last_name)
        return "+".join(parts)

    def name_encoded(self) -> str:
        name = self.full_name or f"{self.first_name} {self.last_name}"
        return urllib.parse.quote(name.strip())

    def first(self) -> str:
        if self.first_name:
            return self.first_name
        if self.full_name:
            return self.full_name.strip().split()[0]
        return ""

    def last(self) -> str:
        if self.last_name:
            return self.last_name
        parts = self.full_name.strip().split()
        return parts[-1] if len(parts) > 1 else ""

    def phone_digits(self) -> str:
        return re.sub(r"\D", "", self.phone)


@dataclass
class PlatformResult:
    platform: str
    category: str
    url: str
    status: str = "generated"
    http_code: int = 0
    timestamp: str = ""
    notes: str = ""


# =============================================================================
#  PLATFORM URL GENERATORS  (88+ platforms)
# =============================================================================

class PlatformURLs:
    """Generates search/profile URLs for 88+ public platforms."""

    @staticmethod
    def people_search_engines(q: SearchQuery) -> List[PlatformResult]:
        """25 people-search engines."""
        name = q.name_plus()
        slug = q.name_slug()
        first = q.first().lower()
        last = q.last().lower()
        state = q.state.lower() if q.state else ""
        city = q.city.lower() if q.city else ""
        loc = f"{city}-{state}" if city and state else state

        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="People Search", url=url))

        add("Whitepages", f"https://www.whitepages.com/name/{first}-{last}" + (f"/{loc}" if loc else ""))
        add("Spokeo", f"https://www.spokeo.com/{first}-{last}" + (f"/{state.upper()}" if state else ""))
        add("BeenVerified", f"https://www.beenverified.com/people/{first}-{last}/" + (f"{state}/" if state else ""))
        add("TruePeopleSearch", f"https://www.truepeoplesearch.com/results?name={name}" + (f"&citystatezip={q.city}+{q.state}" if q.city else ""))
        add("FastPeopleSearch", f"https://www.fastpeoplesearch.com/name/{first}-{last}" + (f"_{city}-{state}" if city else ""))
        add("Pipl", f"https://pipl.com/search/?q={name}")
        add("ThatsThem", f"https://thatsthem.com/name/{first}-{last}" + (f"/{city}-{state}" if city and state else ""))
        add("USPhoneBook", f"https://www.usphonebook.com/{first}-{last}")
        add("Radaris", f"https://radaris.com/p/{first}/{last}/")
        add("Intelius", f"https://www.intelius.com/people-search/{first}-{last}/" + (f"{state}/" if state else ""))
        add("PeekYou", f"https://www.peekyou.com/{first}_{last}" + (f"/{state}" if state else ""))
        add("Zabasearch", f"https://www.zabasearch.com/people/{first}+{last}/" + (f"{state}/" if state else ""))
        add("AnyWho", f"https://www.anywho.com/people/{first}+{last}" + (f"/{city}+{state}" if city else ""))
        add("411.com", f"https://www.411.com/name/{first}-{last}/" + (f"{city}-{state}/" if city else ""))
        add("Addresses.com", f"https://www.addresses.com/people/{first}+{last}" + (f"/{state}/" if state else ""))
        add("FamilyTreeNow", f"https://www.familytreenow.com/search/people?first={first}&last={last}")
        add("NumLookup", f"https://www.numlookup.com/")
        add("SearchPeopleFree", f"https://www.searchpeoplefree.com/find/{first}-{last}" + (f"/{state}" if state else ""))
        add("TruthFinder", f"https://www.truthfinder.com/results/?firstName={first}&lastName={last}")
        add("Nuwber", f"https://nuwber.com/search?name={name}")
        add("CyberBackgroundChecks", f"https://www.cyberbackgroundchecks.com/people/{first}-{last}" + (f"/{state}" if state else ""))
        add("Instant Checkmate", f"https://www.instantcheckmate.com/people/{first}-{last}/")
        add("USSearch", f"https://www.ussearch.com/search/results?firstName={first}&lastName={last}")
        add("SpyDialer", f"https://www.spydialer.com/results/?q={name}")
        add("CocoFinder", f"https://www.cocofinder.com/people-search/result?name={name}")

        return platforms

    @staticmethod
    def social_media(q: SearchQuery) -> List[PlatformResult]:
        """20 social media platforms."""
        name = q.name_plus()
        uname = q.username or q.name_slug()
        first = q.first()
        last = q.last()
        encoded = q.name_encoded()
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="Social Media", url=url))

        add("LinkedIn", f"https://www.linkedin.com/search/results/people/?keywords={encoded}")
        add("Facebook", f"https://www.facebook.com/search/people/?q={encoded}")
        add("Twitter/X", f"https://x.com/search?q={encoded}&f=user")
        add("Twitter/X Profile", f"https://x.com/{uname}")
        add("Instagram", f"https://www.instagram.com/{uname}/")
        add("Instagram Search", f"https://www.instagram.com/explore/tags/{uname}/")
        add("Reddit", f"https://www.reddit.com/search/?q={encoded}&type=user")
        add("Reddit User", f"https://www.reddit.com/user/{uname}")
        add("GitHub", f"https://github.com/{uname}")
        add("GitHub Search", f"https://github.com/search?q={encoded}&type=users")
        add("TikTok", f"https://www.tiktok.com/@{uname}")
        add("TikTok Search", f"https://www.tiktok.com/search?q={encoded}")
        add("YouTube", f"https://www.youtube.com/results?search_query={encoded}")
        add("YouTube Channel", f"https://www.youtube.com/@{uname}")
        add("Pinterest", f"https://www.pinterest.com/{uname}/")
        add("Pinterest Search", f"https://www.pinterest.com/search/users/?q={encoded}")
        add("Snapchat", f"https://www.snapchat.com/add/{uname}")
        add("Twitch", f"https://www.twitch.tv/{uname}")
        add("Medium", f"https://medium.com/@{uname}")
        add("Mastodon", f"https://mastodon.social/@{uname}")

        return platforms

    @staticmethod
    def email_phone_lookup(q: SearchQuery) -> List[PlatformResult]:
        """13 email/phone lookup platforms."""
        platforms = []

        def add(p, url, cat="Email/Phone Lookup"):
            platforms.append(PlatformResult(platform=p, category=cat, url=url))

        if q.email:
            e = urllib.parse.quote(q.email)
            add("Hunter.io", f"https://hunter.io/email-verifier/{q.email}")
            add("EmailRep", f"https://emailrep.io/{q.email}")
            add("Have I Been Pwned", f"https://haveibeenpwned.com/account/{e}")
            add("Gravatar", f"https://en.gravatar.com/{q.email}")
            add("Epieos", f"https://epieos.com/?q={e}")
            add("Spokeo Email", f"https://www.spokeo.com/email-search/search?q={e}")
            add("ThatsThem Email", f"https://thatsthem.com/email/{q.email}")

        if q.phone:
            p = q.phone_digits()
            raw = q.phone
            add("Whitepages Phone", f"https://www.whitepages.com/phone/{p}")
            add("TrueCaller", f"https://www.truecaller.com/search/us/{p}")
            add("SpyDialer Phone", f"https://www.spydialer.com/results/?q={p}")
            add("USPhoneBook Phone", f"https://www.usphonebook.com/{p}")
            add("CallerID", f"https://www.calleridtest.com/look-up/{p}.html")
            add("WhoCalledMe", f"https://www.whocalledme.com/phone/{p}")

        return platforms

    @staticmethod
    def professional_business(q: SearchQuery) -> List[PlatformResult]:
        """10 professional/business platforms."""
        name = q.name_encoded()
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="Professional/Business", url=url))

        add("Crunchbase", f"https://www.crunchbase.com/textsearch?q={name}")
        add("Bloomberg", f"https://www.bloomberg.com/search?query={name}")
        add("SEC EDGAR", f"https://efts.sec.gov/LATEST/search-index?q={name}")
        add("OpenCorporates", f"https://opencorporates.com/officers?q={name}")
        add("Glassdoor", f"https://www.glassdoor.com/Search/results.htm?keyword={name}")
        add("Indeed", f"https://www.indeed.com/people/{q.name_slug()}")
        add("AngelList", f"https://angel.co/search?q={name}")
        add("Clutch", f"https://clutch.co/search?q={name}")
        add("ZoomInfo", f"https://www.zoominfo.com/s/#!search/profile/person?query={name}")
        add("RocketReach", f"https://rocketreach.co/search?query={name}")

        return platforms

    @staticmethod
    def court_legal_records(q: SearchQuery) -> List[PlatformResult]:
        """7 court/legal record platforms."""
        name = q.name_encoded()
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="Court/Legal Records", url=url))

        add("CourtListener", f"https://www.courtlistener.com/?q={name}&type=r")
        add("Justia", f"https://www.justia.com/search?q={name}")
        add("CaseText", f"https://casetext.com/search?q={name}")
        add("PACER", f"https://pcl.uscourts.gov/pcl/pages/search.jsf")
        add("UniCourt", f"https://unicourt.com/search?q={name}")
        add("Federal BOP Inmate", f"https://www.bop.gov/mobile/find_inmate/byname.jsp#inmate_name={name}")
        add("Sex Offender Registry", f"https://www.nsopw.gov/search-public")

        return platforms

    @staticmethod
    def property_address(q: SearchQuery) -> List[PlatformResult]:
        """5 property/address platforms."""
        name = q.name_encoded()
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="Property/Address", url=url))

        add("Zillow", f"https://www.zillow.com/people/{q.name_slug()}/")
        add("Redfin", f"https://www.redfin.com/search#{name}")
        add("Realtor.com", f"https://www.realtor.com/realestateagents/{q.name_slug()}")
        add("BlockShopper", f"https://blockshopper.com/search?q={name}")
        add("Voter Records", f"https://voterrecords.com/voters?name={name}")

        return platforms

    @staticmethod
    def forums_communities(q: SearchQuery) -> List[PlatformResult]:
        """8 forum/community platforms."""
        uname = q.username or q.name_slug()
        name = q.name_encoded()
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="Forums/Community", url=url))

        add("Stack Overflow", f"https://stackoverflow.com/users?tab=all&q={name}")
        add("Quora", f"https://www.quora.com/search?q={name}")
        add("Hacker News", f"https://hn.algolia.com/?q={name}")
        add("Keybase", f"https://keybase.io/{uname}")
        add("About.me", f"https://about.me/{uname}")
        add("BitcoinTalk", f"https://bitcointalk.org/index.php?action=findmember;search={uname}")
        add("Telegram (search)", f"https://t.me/{uname}")
        add("Discord (search)", f"https://discordservers.com/search/{uname}")

        return platforms

    @staticmethod
    def news_archives(q: SearchQuery) -> List[PlatformResult]:
        """8 news/archive platforms."""
        name = q.name_encoded()
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="News/Archives", url=url))

        add("Google News", f"https://news.google.com/search?q={name}")
        add("Bing News", f"https://www.bing.com/news/search?q={name}")
        add("DuckDuckGo News", f"https://duckduckgo.com/?q={name}&iar=news&ia=news")
        add("Archive.org", f"https://web.archive.org/web/*/{name}")
        add("Google Scholar", f"https://scholar.google.com/scholar?q={name}")
        add("Google Cache", f"https://www.google.com/search?q=cache:{name}")
        add("Yahoo News", f"https://news.yahoo.com/search?p={name}")
        add("Newspapers.com", f"https://www.newspapers.com/search/#query={name}")

        return platforms

    @staticmethod
    def username_enumeration(q: SearchQuery) -> List[PlatformResult]:
        """Additional username-based checks across misc platforms."""
        if not q.username:
            return []
        u = q.username
        platforms = []

        def add(p, url):
            platforms.append(PlatformResult(platform=p, category="Username OSINT", url=url))

        add("NameChk", f"https://namechk.com/{u}")
        add("KnowEm", f"https://knowem.com/checkusernames.php?u={u}")
        add("WhatsMyName", f"https://whatsmyname.app/?q={u}")
        add("Sherlock (query)", f"https://sherlock-project.github.io/#{u}")
        add("Gravatar Profile", f"https://en.gravatar.com/{u}")
        add("Linktree", f"https://linktr.ee/{u}")
        add("Cash App", f"https://cash.app/${u}")
        add("Venmo", f"https://venmo.com/{u}")
        add("Spotify", f"https://open.spotify.com/search/{u}")
        add("SoundCloud", f"https://soundcloud.com/{u}")
        add("DeviantArt", f"https://www.deviantart.com/{u}")
        add("Flickr", f"https://www.flickr.com/photos/{u}/")
        add("Vimeo", f"https://vimeo.com/{u}")
        add("Steam", f"https://steamcommunity.com/id/{u}")
        add("Xbox Gamertag", f"https://xboxgamertag.com/search/{u}")
        add("Patreon", f"https://www.patreon.com/{u}")
        add("Substack", f"https://{u}.substack.com/")
        add("GitLab", f"https://gitlab.com/{u}")
        add("Bitbucket", f"https://bitbucket.org/{u}/")
        add("NPM", f"https://www.npmjs.com/~{u}")
        add("PyPI", f"https://pypi.org/user/{u}/")
        add("Docker Hub", f"https://hub.docker.com/u/{u}")

        return platforms

    @classmethod
    def generate_all(cls, q: SearchQuery) -> List[PlatformResult]:
        """Aggregate URLs from all 88+ platform generators."""
        all_results = []
        generators = [
            cls.people_search_engines,
            cls.social_media,
            cls.email_phone_lookup,
            cls.professional_business,
            cls.court_legal_records,
            cls.property_address,
            cls.forums_communities,
            cls.news_archives,
            cls.username_enumeration,
        ]
        for gen in generators:
            all_results.extend(gen(q))
        for r in all_results:
            r.timestamp = datetime.utcnow().isoformat() + "Z"
        return all_results


# =============================================================================
#  URL VERIFIER  (optional HTTP HEAD checks)
# =============================================================================

class URLVerifier:
    """Optionally verify URLs via HTTP HEAD requests."""

    def __init__(self, timeout: int = Config.REQUEST_TIMEOUT, max_workers: int = Config.MAX_WORKERS):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": Config.USER_AGENT})
            adapter = HTTPAdapter(pool_maxsize=max_workers, max_retries=1)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def check_one(self, result: PlatformResult) -> PlatformResult:
        if not self.session:
            return result
        try:
            resp = self.session.head(result.url, timeout=self.timeout, allow_redirects=True)
            result.http_code = resp.status_code
            if resp.status_code == 200:
                result.status = "found"
            elif resp.status_code in (301, 302, 303, 307, 308):
                result.status = "redirect"
            elif resp.status_code == 404:
                result.status = "not_found"
            elif resp.status_code == 403:
                result.status = "blocked"
            else:
                result.status = f"http_{resp.status_code}"
        except requests.exceptions.Timeout:
            result.status = "timeout"
        except requests.exceptions.ConnectionError:
            result.status = "conn_error"
        except Exception as e:
            result.status = "error"
            result.notes = str(e)[:100]
        return result

    def check_batch(self, results: List[PlatformResult], callback=None) -> List[PlatformResult]:
        verified = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.check_one, r): r for r in results}
            for i, future in enumerate(as_completed(futures)):
                res = future.result()
                verified.append(res)
                if callback:
                    callback(i + 1, len(results), res.platform)
        return sorted(verified, key=lambda r: r.category)


# =============================================================================
#  REPORT EXPORTERS
# =============================================================================

class ReportExporter:
    """Export results to JSON, CSV, and PDF."""

    @staticmethod
    def ensure_dir(path: str):
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def to_json(results: List[PlatformResult], query: SearchQuery, filepath: str):
        data = {
            "tool": "FU PERSON :: People Finder v2.0",
            "generated": datetime.utcnow().isoformat() + "Z",
            "query": asdict(query),
            "total_platforms": len(results),
            "categories": {},
            "results": [asdict(r) for r in results],
        }
        cats = defaultdict(int)
        for r in results:
            cats[r.category] += 1
        data["categories"] = dict(cats)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    @staticmethod
    def to_csv(results: List[PlatformResult], filepath: str):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "Category", "URL", "Status", "HTTP Code", "Timestamp", "Notes"])
            for r in results:
                writer.writerow([r.platform, r.category, r.url, r.status, r.http_code, r.timestamp, r.notes])
        return filepath

    @staticmethod
    def to_pdf(results: List[PlatformResult], query: SearchQuery, filepath: str):
        if not HAS_FPDF:
            C.p(f"  {C.YLW}[!] PDF export requires fpdf2: pip install fpdf2{C.R}")
            return None

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Courier", "B", 16)
        pdf.cell(0, 10, "FU PERSON - People Finder Report", ln=True, align="C")
        pdf.set_font("Courier", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.utcnow().isoformat()}Z", ln=True, align="C")
        pdf.cell(0, 8, f"Query: {query.full_name or query.first_name + ' ' + query.last_name}", ln=True, align="C")
        pdf.ln(5)

        current_cat = ""
        for r in sorted(results, key=lambda x: x.category):
            if r.category != current_cat:
                current_cat = r.category
                pdf.set_font("Courier", "B", 12)
                pdf.cell(0, 10, f"--- {current_cat} ---", ln=True)
                pdf.set_font("Courier", "", 9)
            status_mark = "[+]" if r.status == "found" else "[ ]" if r.status == "generated" else "[x]"
            line = f"{status_mark} {r.platform}"
            pdf.cell(0, 6, line, ln=True)
            pdf.set_text_color(50, 50, 200)
            pdf.cell(0, 5, f"    {r.url[:100]}", ln=True)
            pdf.set_text_color(0, 0, 0)

        pdf.output(filepath)
        return filepath


# =============================================================================
#  PEOPLE FINDER ENGINE
# =============================================================================

class PeopleFinder:
    """Main orchestrator for the People Finder tool."""

    def __init__(self, verify_urls: bool = False, output_dir: str = None):
        self.verify = verify_urls
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.verifier = URLVerifier() if verify_urls else None
        self.results: List[PlatformResult] = []

    def print_banner(self):
        C.p(BANNER)
        C.p(DISCLAIMER)

    def find(self, query: SearchQuery) -> List[PlatformResult]:
        """Run the full search pipeline."""
        name_display = query.full_name or f"{query.first_name} {query.last_name}"
        C.p(f"\n  {C.GRN}{C.BLD}[*] TARGET: {name_display.upper()}{C.R}")
        if query.email:
            C.p(f"  {C.CYN}    Email:    {query.email}{C.R}")
        if query.phone:
            C.p(f"  {C.CYN}    Phone:    {query.phone}{C.R}")
        if query.username:
            C.p(f"  {C.CYN}    Username: {query.username}{C.R}")
        if query.city or query.state:
            C.p(f"  {C.CYN}    Location: {query.city}, {query.state}{C.R}")
        C.p("")

        C.p(f"  {C.GRN}[*] Generating search URLs across 88+ platforms...{C.R}")
        self.results = PlatformURLs.generate_all(query)
        C.p(f"  {C.GRN}[+] Generated {C.BLD}{len(self.results)}{C.R}{C.GRN} platform URLs{C.R}\n")

        if self.verify and self.verifier:
            C.p(f"  {C.CYN}[*] Verifying URLs (HTTP HEAD checks)...{C.R}")
            self.results = self.verifier.check_batch(
                self.results,
                callback=lambda cur, tot, name: C.progress(cur, tot, name)
            )
            found = sum(1 for r in self.results if r.status == "found")
            C.p(f"  {C.GRN}[+] Verification complete: {found}/{len(self.results)} responsive{C.R}\n")

        self._display_results()
        self._export(query)

        return self.results

    def _display_results(self):
        """Display categorized results in terminal."""
        by_cat = defaultdict(list)
        for r in self.results:
            by_cat[r.category].append(r)

        for cat, items in sorted(by_cat.items()):
            C.p(f"\n  {C.MAG}{C.BLD}┌─── {cat} ({len(items)} platforms) ───┐{C.R}")
            for r in items:
                if r.status == "found":
                    icon = f"{C.GRN}[+]{C.R}"
                elif r.status == "not_found":
                    icon = f"{C.RED}[-]{C.R}"
                elif r.status in ("timeout", "conn_error", "blocked"):
                    icon = f"{C.YLW}[?]{C.R}"
                else:
                    icon = f"{C.CYN}[>]{C.R}"
                C.p(f"  {icon} {C.WHT}{r.platform:<30}{C.R} {C.DIM}{r.url[:80]}{C.R}")
            C.p(f"  {C.MAG}└{'─' * 50}┘{C.R}")

    def _export(self, query: SearchQuery):
        """Export results to files."""
        ReportExporter.ensure_dir(self.output_dir)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name_part = query.name_slug() or "unknown"
        base = os.path.join(self.output_dir, f"pf_{name_part}_{ts}")

        json_path = ReportExporter.to_json(self.results, query, f"{base}.json")
        C.p(f"\n  {C.GRN}[+] JSON report: {json_path}{C.R}")

        csv_path = ReportExporter.to_csv(self.results, f"{base}.csv")
        C.p(f"  {C.GRN}[+] CSV report:  {csv_path}{C.R}")

        pdf_path = ReportExporter.to_pdf(self.results, query, f"{base}.pdf")
        if pdf_path:
            C.p(f"  {C.GRN}[+] PDF report:  {pdf_path}{C.R}")

        C.p(f"\n  {C.GRN}{C.BLD}[*] Scan complete. {len(self.results)} platforms queried.{C.R}")
        C.p(f"  {C.DIM}    Timestamp: {datetime.utcnow().isoformat()}Z{C.R}\n")


# =============================================================================
#  INTERACTIVE MODE
# =============================================================================

def interactive_mode() -> SearchQuery:
    """Guided interactive interview for building a search query."""
    C.p(f"\n  {C.CYN}{C.BLD}┌──────────────────────────────────────────────────┐{C.R}")
    C.p(f"  {C.CYN}{C.BLD}│        INTERACTIVE SEARCH WIZARD                 │{C.R}")
    C.p(f"  {C.CYN}{C.BLD}│   Press ENTER to skip any field                  │{C.R}")
    C.p(f"  {C.CYN}{C.BLD}└──────────────────────────────────────────────────┘{C.R}\n")

    def ask(prompt, default=""):
        try:
            val = input(f"  {C.GRN}>{C.R} {prompt}: ").strip()
            return val if val else default
        except (EOFError, KeyboardInterrupt):
            return default

    full = ask("Full name (e.g. John Michael Doe)")
    first, last, middle = "", "", ""
    if not full:
        first = ask("First name")
        middle = ask("Middle name")
        last = ask("Last name")
    else:
        parts = full.split()
        first = parts[0] if parts else ""
        last = parts[-1] if len(parts) > 1 else ""
        middle = " ".join(parts[1:-1]) if len(parts) > 2 else ""

    email = ask("Email address")
    phone = ask("Phone number")
    username = ask("Username / handle")
    city = ask("City")
    state = ask("State (2-letter code)")
    employer = ask("Employer / company")
    school = ask("School / university")

    return SearchQuery(
        full_name=full,
        first_name=first,
        last_name=last,
        middle_name=middle,
        email=email,
        phone=phone,
        username=username,
        city=city,
        state=state,
        employer=employer,
        school=school,
    )


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="people_finder",
        description=f"{C.GRN}FU PERSON :: People Finder v2.0 -- 88+ Platform OSINT Aggregator{C.R}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        {C.CYN}Examples:{C.R}
          python people_finder.py -n "John Doe"
          python people_finder.py --first John --last Doe --state CA --city "Los Angeles"
          python people_finder.py -e john@example.com -p 5551234567
          python people_finder.py -u johndoe42 --verify
          python people_finder.py --interactive
        """),
    )

    parser.add_argument("-n", "--name", help="Full name to search")
    parser.add_argument("--first", help="First name")
    parser.add_argument("--last", help="Last name")
    parser.add_argument("--middle", help="Middle name")
    parser.add_argument("-e", "--email", help="Email address")
    parser.add_argument("-p", "--phone", help="Phone number")
    parser.add_argument("-u", "--username", help="Username / handle")
    parser.add_argument("--city", help="City")
    parser.add_argument("--state", help="State (2-letter code)")
    parser.add_argument("--employer", help="Employer / company name")
    parser.add_argument("--school", help="School / university")
    parser.add_argument("-o", "--output", default=Config.OUTPUT_DIR, help="Output directory")
    parser.add_argument("--verify", action="store_true", help="Verify URLs with HTTP HEAD requests")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive guided mode")
    parser.add_argument("--json-only", action="store_true", help="Output JSON only (no terminal display)")

    args = parser.parse_args()

    finder = PeopleFinder(verify_urls=args.verify, output_dir=args.output)
    finder.print_banner()

    if args.interactive:
        query = interactive_mode()
    elif args.name or (args.first and args.last) or args.email or args.phone or args.username:
        query = SearchQuery(
            full_name=args.name or "",
            first_name=args.first or "",
            last_name=args.last or "",
            middle_name=args.middle or "",
            email=args.email or "",
            phone=args.phone or "",
            username=args.username or "",
            city=args.city or "",
            state=args.state or "",
            employer=args.employer or "",
            school=args.school or "",
        )
    else:
        parser.print_help()
        C.p(f"\n  {C.YLW}[!] Provide at least a name, email, phone, or username. Use -i for interactive mode.{C.R}\n")
        sys.exit(0)

    finder.find(query)


if __name__ == "__main__":
    main()
