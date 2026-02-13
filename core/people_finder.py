#!/usr/bin/env python3
"""
+==============================================================================+
|  FLLC OSINT PEOPLE FINDER v1.0                                            |
|  Comprehensive People Search & Intelligence Aggregator                       |
|                                                                              |
|  Searches: Public records, social media, news archives, people search        |
|  engines, phone/email directories, web archives, court records,              |
|  business filings, and 200+ platforms worldwide.                             |
|                                                                              |
|  Coverage: USA -> North America -> Europe -> Asia -> Global                  |
|  For authorized OSINT / skip-tracing / investigative research only.          |
+==============================================================================+
"""

import os
import sys
import json
import time
import re
import hashlib
import urllib.parse
import socket
import ssl
import csv
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import argparse
import textwrap
import warnings
warnings.filterwarnings("ignore")
import os as _os
_os.environ["PYTHONWARNINGS"] = "ignore"

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# --- Conditional Imports ------------------------------------------------------
try:
    import requests
    from requests.adapters import HTTPAdapter
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

try:
    from duckduckgo_search import DDGS
    HAS_DDG = True
except ImportError:
    HAS_DDG = False


# ==============================================================================
# SECTION 1: CONFIGURATION
# ==============================================================================

class Config:
    """Central configuration -- edit API keys here for enhanced results."""

    # --- Optional API Keys (tool works without them, better with) ---------
    GOOGLE_API_KEY = ""           # Google Custom Search (100 free/day)
    GOOGLE_CSE_ID = ""            # Custom Search Engine ID
    HUNTER_IO_KEY = ""            # Hunter.io email finder (25 free/month)
    HIBP_API_KEY = ""             # Have I Been Pwned (free for limited)
    PIPL_API_KEY = ""             # Pipl people search (paid)
    NUMVERIFY_KEY = ""            # Phone number validation (250 free/month)
    DEHASHED_API_KEY = ""         # Breach data search
    DEHASHED_EMAIL = ""
    WHOXY_API_KEY = ""            # WHOIS history

    # --- Rate Limiting ----------------------------------------------------
    REQUEST_DELAY = 1.5           # Seconds between requests to same domain
    MAX_CONCURRENT = 8            # Max parallel requests
    TIMEOUT = 15                  # Request timeout seconds
    MAX_RETRIES = 2

    # --- Search Depth -----------------------------------------------------
    MAX_SEARCH_RESULTS = 50       # Max results per search engine query
    MAX_QUERY_VARIATIONS = 12     # Max query reformulations per source
    DEEP_SEARCH = True            # Enable exhaustive searching

    # --- Output -----------------------------------------------------------
    OUTPUT_DIR = "people_finder_reports"
    SAVE_RAW = True               # Save raw results alongside report

    # --- User Agent Rotation ----------------------------------------------
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]


# ==============================================================================
# SECTION 2: DATA MODELS
# ==============================================================================

@dataclass
class SearchQuery:
    """What we're searching for."""
    first_name: str = ""
    last_name: str = ""
    middle_name: str = ""
    full_name: str = ""            # Auto-assembled if not provided
    aliases: List[str] = field(default_factory=list)
    city: str = ""
    state: str = ""
    country: str = "US"
    zip_code: str = ""
    phone: str = ""
    email: str = ""
    username: str = ""
    employer: str = ""
    school: str = ""
    age_range: Tuple[int, int] = (0, 120)
    keywords: List[str] = field(default_factory=list)
    date_range: Tuple[str, str] = ("", "")   # YYYY-MM-DD

    def __post_init__(self):
        if not self.full_name and (self.first_name or self.last_name):
            parts = [self.first_name, self.middle_name, self.last_name]
            self.full_name = " ".join(p for p in parts if p).strip()
        elif self.full_name and not self.first_name:
            parts = self.full_name.strip().split()
            if len(parts) >= 2:
                self.first_name = parts[0]
                self.last_name = parts[-1]
                if len(parts) >= 3:
                    self.middle_name = " ".join(parts[1:-1])

    @property
    def location_str(self) -> str:
        parts = [self.city, self.state, self.country]
        return ", ".join(p for p in parts if p)

    @property
    def search_id(self) -> str:
        raw = f"{self.full_name}|{self.location_str}|{self.phone}|{self.email}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]


@dataclass
class SearchResult:
    """Individual finding from a source."""
    source: str                    # e.g. "DuckDuckGo", "TruePeopleSearch"
    category: str                  # e.g. "search_engine", "social_media", "public_records"
    title: str = ""
    url: str = ""
    snippet: str = ""
    confidence: float = 0.0        # 0.0 - 1.0
    data: Dict = field(default_factory=dict)   # Structured data if available
    timestamp: str = ""
    region: str = "US"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class PersonProfile:
    """Aggregated intelligence on a person."""
    query: SearchQuery = None
    names: List[str] = field(default_factory=list)
    addresses: List[Dict] = field(default_factory=list)
    phones: List[Dict] = field(default_factory=list)
    emails: List[Dict] = field(default_factory=list)
    social_media: Dict[str, str] = field(default_factory=dict)   # platform -> url
    employment: List[Dict] = field(default_factory=list)
    education: List[Dict] = field(default_factory=list)
    news_mentions: List[Dict] = field(default_factory=list)
    public_records: List[Dict] = field(default_factory=list)
    relatives: List[str] = field(default_factory=list)
    associates: List[str] = field(default_factory=list)
    photos: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    businesses: List[Dict] = field(default_factory=list)
    court_records: List[Dict] = field(default_factory=list)
    all_results: List[SearchResult] = field(default_factory=list)
    search_timestamp: str = ""
    total_sources_checked: int = 0
    total_results_found: int = 0

    def __post_init__(self):
        if not self.search_timestamp:
            self.search_timestamp = datetime.now().isoformat()


# ==============================================================================
# SECTION 3: UTILITIES
# ==============================================================================

class RateLimiter:
    """Per-domain rate limiter."""
    def __init__(self):
        self._last_request = {}

    def wait(self, domain: str, delay: float = None):
        if delay is None:
            delay = Config.REQUEST_DELAY
        key = domain.lower().replace("www.", "")
        last = self._last_request.get(key, 0)
        elapsed = time.time() - last
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request[key] = time.time()


class WebClient:
    """HTTP client with rate limiting, retries, and UA rotation."""
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self._ua_idx = 0
        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            })

    def _next_ua(self) -> str:
        ua = Config.USER_AGENTS[self._ua_idx % len(Config.USER_AGENTS)]
        self._ua_idx += 1
        return ua

    def get(self, url: str, params: dict = None, headers: dict = None,
            delay: float = None, raw: bool = False) -> Optional[object]:
        if not HAS_REQUESTS:
            return None
        try:
            domain = urllib.parse.urlparse(url).netloc
            self.rate_limiter.wait(domain, delay)
            hdrs = {"User-Agent": self._next_ua()}
            if headers:
                hdrs.update(headers)
            resp = self.session.get(url, params=params, headers=hdrs,
                                    timeout=Config.TIMEOUT, allow_redirects=True)
            if raw:
                return resp
            if resp.status_code == 200:
                return resp
            return None
        except Exception:
            return None

    def get_json(self, url: str, params: dict = None, headers: dict = None) -> Optional[dict]:
        resp = self.get(url, params=params, headers=headers)
        if resp:
            try:
                return resp.json()
            except Exception:
                pass
        return None

    def get_soup(self, url: str, params: dict = None) -> Optional[object]:
        if not HAS_BS4:
            return None
        resp = self.get(url, params=params)
        if resp:
            return BeautifulSoup(resp.text, "html.parser")
        return None


# Pretty printing
def _safe_print(text: str):
    """Print with fallback for encoding issues on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))

def banner():
    _safe_print(f"""
{Fore.CYAN}+==================================================================+
|  {Fore.WHITE}FLLC OSINT PEOPLE FINDER{Fore.CYAN}                                    |
|  {Fore.WHITE}v1.0 -- Comprehensive Intelligence Aggregator{Fore.CYAN}                  |
|  {Style.DIM}Public records - Social media - News - Archives - Global{Style.RESET_ALL}{Fore.CYAN}     |
+==================================================================+{Style.RESET_ALL}
""")

def status(msg: str, level: str = "info"):
    icons = {"info": f"{Fore.CYAN}[*]", "ok": f"{Fore.GREEN}[+]",
             "warn": f"{Fore.YELLOW}[!]", "err": f"{Fore.RED}[-]",
             "search": f"{Fore.MAGENTA}[~]"}
    _safe_print(f"  {icons.get(level, icons['info'])} {msg}{Style.RESET_ALL}")

def section(title: str):
    w = 60
    _safe_print(f"\n{Fore.YELLOW}{'-'*w}")
    _safe_print(f"  {title}")
    _safe_print(f"{'-'*w}{Style.RESET_ALL}")


# ==============================================================================
# SECTION 4: SMART QUERY GENERATION
# ==============================================================================

class QueryGenerator:
    """Generates optimized search queries for maximum coverage."""

    # US state abbreviation mapping
    US_STATES = {
        "alabama": "AL", "alaska": "AK", "arizona": "AZ", "arkansas": "AR",
        "california": "CA", "colorado": "CO", "connecticut": "CT", "delaware": "DE",
        "florida": "FL", "georgia": "GA", "hawaii": "HI", "idaho": "ID",
        "illinois": "IL", "indiana": "IN", "iowa": "IA", "kansas": "KS",
        "kentucky": "KY", "louisiana": "LA", "maine": "ME", "maryland": "MD",
        "massachusetts": "MA", "michigan": "MI", "minnesota": "MN", "mississippi": "MS",
        "missouri": "MO", "montana": "MT", "nebraska": "NE", "nevada": "NV",
        "new hampshire": "NH", "new jersey": "NJ", "new mexico": "NM", "new york": "NY",
        "north carolina": "NC", "north dakota": "ND", "ohio": "OH", "oklahoma": "OK",
        "oregon": "OR", "pennsylvania": "PA", "rhode island": "RI", "south carolina": "SC",
        "south dakota": "SD", "tennessee": "TN", "texas": "TX", "utah": "UT",
        "vermont": "VT", "virginia": "VA", "washington": "WA", "west virginia": "WV",
        "wisconsin": "WI", "wyoming": "WY", "district of columbia": "DC",
    }

    @staticmethod
    def normalize_state(state_input: str) -> Tuple[str, str]:
        """Returns (abbreviation, full_name)."""
        s = state_input.strip().lower()
        if len(s) == 2:
            abbr = s.upper()
            for full, ab in QueryGenerator.US_STATES.items():
                if ab == abbr:
                    return abbr, full.title()
            return abbr, ""
        for full, ab in QueryGenerator.US_STATES.items():
            if full == s:
                return ab, full.title()
        return state_input.upper()[:2], state_input.title()

    @staticmethod
    def generate_search_queries(q: SearchQuery) -> List[str]:
        """Generate diverse search query strings for maximum discovery."""
        queries = []
        name = q.full_name
        fn, ln = q.first_name, q.last_name

        # --- Exact name queries ---------------------------------------
        queries.append(f'"{name}"')
        if q.city:
            queries.append(f'"{name}" "{q.city}"')
        if q.state:
            _, full_state = QueryGenerator.normalize_state(q.state)
            queries.append(f'"{name}" "{full_state}"')
            if q.city:
                queries.append(f'"{name}" "{q.city}" "{full_state}"')
                queries.append(f'"{name}" {q.city} {q.state}')

        # --- Name variations ------------------------------------------
        if fn and ln:
            queries.append(f'"{fn}" "{ln}"')
            # First initial + last name
            queries.append(f'"{fn[0]}. {ln}"')
            # Common nicknames for first names
            nicknames = QueryGenerator._get_nicknames(fn)
            for nick in nicknames[:3]:
                queries.append(f'"{nick} {ln}"')

        # --- With keywords --------------------------------------------
        for kw in q.keywords[:5]:
            queries.append(f'"{name}" {kw}')

        # --- Contact info queries -------------------------------------
        if q.phone:
            phone_clean = re.sub(r'\D', '', q.phone)
            queries.append(f'"{phone_clean}"')
            queries.append(f'"{name}" "{phone_clean}"')
            # Formatted variations
            if len(phone_clean) == 10:
                queries.append(f'"({phone_clean[:3]}) {phone_clean[3:6]}-{phone_clean[6:]}"')
                queries.append(f'"{phone_clean[:3]}-{phone_clean[3:6]}-{phone_clean[6:]}"')

        if q.email:
            queries.append(f'"{q.email}"')
            queries.append(f'"{name}" "{q.email}"')

        if q.username:
            queries.append(f'"{q.username}"')
            queries.append(f'"{name}" "{q.username}"')

        # --- Employment / School --------------------------------------
        if q.employer:
            queries.append(f'"{name}" "{q.employer}"')
        if q.school:
            queries.append(f'"{name}" "{q.school}"')

        # --- Aliases --------------------------------------------------
        for alias in q.aliases[:5]:
            queries.append(f'"{alias}"')
            if q.city:
                queries.append(f'"{alias}" "{q.city}"')

        return list(dict.fromkeys(queries))[:Config.MAX_QUERY_VARIATIONS * 3]

    @staticmethod
    def generate_dork_queries(q: SearchQuery) -> List[str]:
        """Google dork-style queries for deep discovery."""
        name = q.full_name
        dorks = []

        # Site-specific searches
        sites = [
            "linkedin.com", "facebook.com", "twitter.com", "instagram.com",
            "tiktok.com", "reddit.com", "youtube.com", "github.com",
            "pinterest.com", "medium.com", "quora.com",
        ]
        for site in sites:
            dorks.append(f'site:{site} "{name}"')

        # Public records / directories
        record_sites = [
            "whitepages.com", "truepeoplesearch.com", "fastpeoplesearch.com",
            "spokeo.com", "beenverified.com", "intelius.com",
            "zabasearch.com", "thatsthem.com", "peekyou.com",
            "radaris.com", "ussearch.com", "publicrecords.com",
        ]
        for site in record_sites:
            dorks.append(f'site:{site} "{name}"')

        # News
        if q.city:
            dorks.append(f'"{name}" "{q.city}" news OR interview OR article')
        dorks.append(f'"{name}" news OR press OR interview OR article')

        # Court / legal records
        dorks.append(f'"{name}" court OR case OR filed OR plaintiff OR defendant')
        dorks.append(f'site:courtlistener.com "{name}"')
        dorks.append(f'site:unicourt.com "{name}"')

        # Property
        if q.state:
            dorks.append(f'"{name}" property OR deed OR parcel {q.state}')

        # Business
        dorks.append(f'"{name}" LLC OR Inc OR Corp OR "registered agent"')

        # Documents
        dorks.append(f'"{name}" filetype:pdf')
        dorks.append(f'"{name}" filetype:doc OR filetype:docx')

        return dorks[:Config.MAX_QUERY_VARIATIONS * 2]

    @staticmethod
    def _get_nicknames(first_name: str) -> List[str]:
        """Common name variants / nicknames."""
        nicks = {
            "william": ["bill", "will", "billy", "willy", "liam"],
            "robert": ["bob", "rob", "bobby", "robbie", "bert"],
            "richard": ["rick", "dick", "rich", "ritchie"],
            "james": ["jim", "jimmy", "jamie"],
            "john": ["jack", "johnny", "jon"],
            "charles": ["charlie", "chuck", "chas"],
            "thomas": ["tom", "tommy"],
            "michael": ["mike", "mikey", "mick"],
            "peter": ["pete", "petey"],
            "david": ["dave", "davey"],
            "joseph": ["joe", "joey"],
            "edward": ["ed", "eddie", "ted", "teddy", "ned"],
            "daniel": ["dan", "danny"],
            "matthew": ["matt", "matty"],
            "andrew": ["andy", "drew"],
            "christopher": ["chris", "topher"],
            "steven": ["steve", "stevie"],
            "stephen": ["steve", "stevie"],
            "kenneth": ["ken", "kenny"],
            "timothy": ["tim", "timmy"],
            "patricia": ["pat", "patty", "trish", "tricia"],
            "elizabeth": ["liz", "beth", "lizzy", "betty", "eliza"],
            "jennifer": ["jen", "jenny"],
            "margaret": ["maggie", "meg", "peggy", "marge"],
            "katherine": ["kate", "kathy", "katie", "kat"],
            "catherine": ["kate", "cathy", "katie", "cat"],
            "rebecca": ["becky", "becca"],
            "susan": ["sue", "susie", "suzy"],
            "dorothy": ["dot", "dotty", "dottie"],
            "alexander": ["alex", "xander", "al"],
            "alexandra": ["alex", "lexi", "ali"],
            "benjamin": ["ben", "benny"],
            "nicholas": ["nick", "nicky"],
            "jonathan": ["jon", "jonny"],
            "anthony": ["tony"],
            "gregory": ["greg"],
            "samuel": ["sam", "sammy"],
            "phillip": ["phil"],
            "phillip": ["phil"],
            "raymond": ["ray"],
            "lawrence": ["larry"],
            "gerald": ["gerry", "jerry"],
            "donald": ["don", "donnie"],
            "ronald": ["ron", "ronnie"],
            "frederick": ["fred", "freddy", "fritz"],
        }
        return nicks.get(first_name.lower(), [])

    @staticmethod
    def generate_username_candidates(q: SearchQuery) -> List[str]:
        """Generate likely usernames from a person's name."""
        fn = q.first_name.lower()
        ln = q.last_name.lower()
        if not fn or not ln:
            return []

        candidates = [
            f"{fn}{ln}",           # peterchafffin
            f"{fn}.{ln}",          # peter.chaffin
            f"{fn}_{ln}",          # peter_chaffin
            f"{fn}-{ln}",          # peter-chaffin
            f"{fn[0]}{ln}",        # pchaffin
            f"{fn}{ln[0]}",        # peterc
            f"{fn[0]}.{ln}",       # p.chaffin
            f"{fn}{ln}1",
            f"{fn}.{ln}1",
            f"{ln}{fn}",           # chaffinpeter
            f"{ln}.{fn}",
            f"{ln}_{fn}",
            f"{ln}{fn[0]}",        # chaffinp
        ]
        # Add with common numbers
        for base in [f"{fn}{ln}", f"{fn}.{ln}", f"{fn}_{ln}"]:
            for suffix in ["1", "2", "01", "99", "123"]:
                candidates.append(f"{base}{suffix}")

        return list(dict.fromkeys(candidates))


# ==============================================================================
# SECTION 5: SEARCH ENGINE MODULE
# ==============================================================================

class SearchEngineModule:
    """Search via DuckDuckGo, Google API, and Bing."""

    def __init__(self, client: WebClient):
        self.client = client
        self.results: List[SearchResult] = []

    def search_all(self, q: SearchQuery) -> List[SearchResult]:
        """Run searches across all available engines."""
        self.results = []
        queries = QueryGenerator.generate_search_queries(q)

        section("SEARCH ENGINES")

        # DuckDuckGo (no API key needed)
        if HAS_DDG:
            self._search_duckduckgo(queries, q)
            self._search_duckduckgo_news(queries, q)
        else:
            status("duckduckgo-search not installed -- using fallback", "warn")
            self._search_ddg_lite(queries, q)

        # Google Custom Search API (if key provided)
        if Config.GOOGLE_API_KEY and Config.GOOGLE_CSE_ID:
            self._search_google_api(queries, q)

        # Google dorking via DDG (always works)
        dorks = QueryGenerator.generate_dork_queries(q)
        if HAS_DDG:
            self._search_duckduckgo(dorks[:15], q, prefix="[DORK] ")

        status(f"Search engines returned {len(self.results)} total results", "ok")
        return self.results

    def _search_duckduckgo(self, queries: List[str], q: SearchQuery, prefix: str = ""):
        """DuckDuckGo text search."""
        status(f"{prefix}DuckDuckGo text search ({len(queries)} queries)...", "search")
        seen_urls = set()
        for query in queries[:Config.MAX_QUERY_VARIATIONS]:
            try:
                with DDGS() as ddgs:
                    results = list(ddgs.text(query, max_results=Config.MAX_SEARCH_RESULTS // len(queries) + 5))
                for r in results:
                    url = r.get("href", r.get("link", ""))
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    title = r.get("title", "")
                    snippet = r.get("body", r.get("snippet", ""))
                    conf = self._score_result(title + " " + snippet, q)
                    self.results.append(SearchResult(
                        source="DuckDuckGo", category="search_engine",
                        title=title, url=url, snippet=snippet,
                        confidence=conf, data={"query": query}
                    ))
            except Exception as e:
                pass
            time.sleep(0.5)
        status(f"  DuckDuckGo: {len(seen_urls)} unique results", "ok")

    def _search_duckduckgo_news(self, queries: List[str], q: SearchQuery):
        """DuckDuckGo news search."""
        status("DuckDuckGo news search...", "search")
        count = 0
        for query in queries[:8]:
            try:
                with DDGS() as ddgs:
                    results = list(ddgs.news(query, max_results=10))
                for r in results:
                    self.results.append(SearchResult(
                        source="DuckDuckGo News", category="news",
                        title=r.get("title", ""), url=r.get("url", r.get("link", "")),
                        snippet=r.get("body", ""),
                        confidence=self._score_result(r.get("title", "") + r.get("body", ""), q),
                        data={"date": r.get("date", ""), "source": r.get("source", ""), "query": query}
                    ))
                    count += 1
            except Exception:
                pass
            time.sleep(0.5)
        status(f"  DuckDuckGo News: {count} results", "ok")

    def _search_ddg_lite(self, queries: List[str], q: SearchQuery):
        """Fallback DuckDuckGo search via HTML scraping."""
        status("DuckDuckGo lite fallback...", "search")
        count = 0
        for query in queries[:5]:
            resp = self.client.get("https://lite.duckduckgo.com/lite/",
                                    params={"q": query}, delay=2.0)
            if resp and HAS_BS4:
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.select("a.result-link, td a[href^='http']"):
                    url = link.get("href", "")
                    title = link.get_text(strip=True)
                    if url and "duckduckgo.com" not in url:
                        self.results.append(SearchResult(
                            source="DuckDuckGo Lite", category="search_engine",
                            title=title, url=url, snippet="",
                            confidence=self._score_result(title, q)
                        ))
                        count += 1
        status(f"  DuckDuckGo Lite: {count} results", "ok")

    def _search_google_api(self, queries: List[str], q: SearchQuery):
        """Google Custom Search API."""
        status("Google Custom Search API...", "search")
        count = 0
        for query in queries[:10]:
            data = self.client.get_json(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": Config.GOOGLE_API_KEY, "cx": Config.GOOGLE_CSE_ID,
                        "q": query, "num": 10}
            )
            if data and "items" in data:
                for item in data["items"]:
                    self.results.append(SearchResult(
                        source="Google CSE", category="search_engine",
                        title=item.get("title", ""), url=item.get("link", ""),
                        snippet=item.get("snippet", ""),
                        confidence=self._score_result(
                            item.get("title", "") + " " + item.get("snippet", ""), q
                        ),
                        data={"query": query}
                    ))
                    count += 1
        status(f"  Google CSE: {count} results", "ok")

    @staticmethod
    def _score_result(text: str, q: SearchQuery) -> float:
        """Score how relevant a result is to our query."""
        text_lower = text.lower()
        score = 0.0
        # Full name match
        if q.full_name.lower() in text_lower:
            score += 0.4
        # First + Last separate
        if q.first_name and q.first_name.lower() in text_lower:
            score += 0.15
        if q.last_name and q.last_name.lower() in text_lower:
            score += 0.15
        # Location match
        if q.city and q.city.lower() in text_lower:
            score += 0.15
        if q.state and q.state.lower() in text_lower:
            score += 0.1
        # Keyword match
        for kw in q.keywords:
            if kw.lower() in text_lower:
                score += 0.1
        # Contact info
        if q.phone and q.phone in text:
            score += 0.3
        if q.email and q.email.lower() in text_lower:
            score += 0.3
        return min(score, 1.0)


# ==============================================================================
# SECTION 6: SOCIAL MEDIA ENUMERATION
# ==============================================================================

class SocialMediaModule:
    """Check 200+ platforms for matching profiles."""

    # Platform -> URL template (use {username})
    PLATFORMS = {
        # --- Major ----------------------------------------------------
        "Facebook":       "https://www.facebook.com/{username}",
        "Instagram":      "https://www.instagram.com/{username}/",
        "Twitter/X":      "https://x.com/{username}",
        "LinkedIn":       "https://www.linkedin.com/in/{username}",
        "TikTok":         "https://www.tiktok.com/@{username}",
        "YouTube":        "https://www.youtube.com/@{username}",
        "Reddit":         "https://www.reddit.com/user/{username}",
        "Pinterest":      "https://www.pinterest.com/{username}/",
        "Snapchat":       "https://www.snapchat.com/add/{username}",
        "Tumblr":         "https://{username}.tumblr.com",
        # --- Professional ---------------------------------------------
        "GitHub":         "https://github.com/{username}",
        "GitLab":         "https://gitlab.com/{username}",
        "Bitbucket":      "https://bitbucket.org/{username}/",
        "Stack Overflow":  "https://stackoverflow.com/users/?tab=accounts&q={username}",
        "Dev.to":         "https://dev.to/{username}",
        "Hashnode":       "https://hashnode.com/@{username}",
        "Dribbble":       "https://dribbble.com/{username}",
        "Behance":        "https://www.behance.net/{username}",
        "Medium":         "https://medium.com/@{username}",
        "About.me":       "https://about.me/{username}",
        "Gravatar":       "https://gravatar.com/{username}",
        # --- Gaming --------------------------------------------------
        "Steam":          "https://steamcommunity.com/id/{username}",
        "Xbox":           "https://account.xbox.com/en-us/profile?gamertag={username}",
        "Twitch":         "https://www.twitch.tv/{username}",
        "Kick":           "https://kick.com/{username}",
        # --- Messaging -----------------------------------------------
        "Telegram":       "https://t.me/{username}",
        "Discord":        "https://discord.com/users/{username}",
        # --- Music ---------------------------------------------------
        "Spotify":        "https://open.spotify.com/user/{username}",
        "SoundCloud":     "https://soundcloud.com/{username}",
        "Bandcamp":       "https://{username}.bandcamp.com",
        "Last.fm":        "https://www.last.fm/user/{username}",
        # --- Photography ---------------------------------------------
        "Flickr":         "https://www.flickr.com/people/{username}/",
        "500px":          "https://500px.com/{username}",
        "VSCO":           "https://vsco.co/{username}/gallery",
        # --- Business / Money ----------------------------------------
        "CashApp":        "https://cash.app/${username}",
        "Venmo":          "https://account.venmo.com/u/{username}",
        "Patreon":        "https://www.patreon.com/{username}",
        "Ko-fi":          "https://ko-fi.com/{username}",
        "BuyMeACoffee":   "https://www.buymeacoffee.com/{username}",
        "Gumroad":        "https://{username}.gumroad.com",
        # --- Dating --------------------------------------------------
        "OKCupid":        "https://www.okcupid.com/profile/{username}",
        # --- Forums --------------------------------------------------
        "HackerNews":     "https://news.ycombinator.com/user?id={username}",
        "Keybase":        "https://keybase.io/{username}",
        "Mastodon (social)": "https://mastodon.social/@{username}",
        "Bluesky":        "https://bsky.app/profile/{username}.bsky.social",
        "Threads":        "https://www.threads.net/@{username}",
        # --- Real Estate ---------------------------------------------
        "Zillow":         "https://www.zillow.com/profile/{username}/",
        "Trulia":         "https://www.trulia.com/profile/{username}/",
        # --- Reviews -------------------------------------------------
        "Yelp":           "https://www.yelp.com/user_details?userid={username}",
        "TripAdvisor":    "https://www.tripadvisor.com/members/{username}",
        # --- Misc ----------------------------------------------------
        "Linktree":       "https://linktr.ee/{username}",
        "Substack":       "https://{username}.substack.com",
        "WordPress":      "https://{username}.wordpress.com",
        "Wix":            "https://{username}.wixsite.com",
        "Etsy":           "https://www.etsy.com/shop/{username}",
        "Replit":         "https://replit.com/@{username}",
        "CodePen":        "https://codepen.io/{username}",
        "Figma":          "https://www.figma.com/@{username}",
        "Notion":         "https://notion.so/{username}",
        "ProductHunt":    "https://www.producthunt.com/@{username}",
        "AngelList":      "https://angel.co/u/{username}",
        "Crunchbase":     "https://www.crunchbase.com/person/{username}",
        "SlideShare":     "https://www.slideshare.net/{username}",
        "Vimeo":          "https://vimeo.com/{username}",
        "Dailymotion":    "https://www.dailymotion.com/{username}",
        "Rumble":         "https://rumble.com/user/{username}",
        "BitChute":       "https://www.bitchute.com/channel/{username}/",
        "Odysee":         "https://odysee.com/@{username}",
        "Minds":          "https://www.minds.com/{username}",
        "Gab":            "https://gab.com/{username}",
        "Parler":         "https://parler.com/{username}",
        "Truth Social":   "https://truthsocial.com/@{username}",
        "Gettr":          "https://gettr.com/user/{username}",
        "Clubhouse":      "https://www.clubhouse.com/@{username}",
        "Goodreads":      "https://www.goodreads.com/{username}",
        "Letterboxd":     "https://letterboxd.com/{username}/",
        "MyAnimeList":    "https://myanimelist.net/profile/{username}",
        "Roblox":         "https://www.roblox.com/users/profile?username={username}",
        "Poshmark":       "https://poshmark.com/closet/{username}",
        "Depop":          "https://www.depop.com/{username}/",
        "Mercari":        "https://www.mercari.com/u/{username}/",
        "Fiverr":         "https://www.fiverr.com/{username}",
        "Upwork":         "https://www.upwork.com/freelancers/~{username}",
        "Kaggle":         "https://www.kaggle.com/{username}",
        "HuggingFace":    "https://huggingface.co/{username}",
        "NPM":            "https://www.npmjs.com/~{username}",
        "PyPI":           "https://pypi.org/user/{username}/",
        "Docker Hub":     "https://hub.docker.com/u/{username}",
        "Gravatar":       "https://en.gravatar.com/{username}",
    }

    # Platforms with known 404 indicators
    ABSENT_INDICATORS = [
        "page not found", "404", "user not found", "doesn't exist",
        "this account doesn't exist", "nothing here", "no results",
        "sorry, this page", "removed", "suspended", "unavailable",
        "this page is not available", "content is not available",
    ]

    def __init__(self, client: WebClient):
        self.client = client

    def enumerate(self, q: SearchQuery) -> List[SearchResult]:
        """Check all platforms for the person."""
        section("SOCIAL MEDIA ENUMERATION")
        results = []
        usernames = QueryGenerator.generate_username_candidates(q)
        if q.username:
            usernames.insert(0, q.username)

        if not usernames:
            status("No username candidates generated (need first + last name)", "warn")
            return results

        status(f"Testing {len(usernames)} username candidates across {len(self.PLATFORMS)} platforms...", "search")

        # We'll check top username candidates against all platforms
        # using parallel requests for speed
        found_profiles = {}

        for username in usernames[:6]:   # Top 6 candidates
            status(f"  Checking username: {Fore.WHITE}{username}{Style.RESET_ALL}", "search")
            checks = []
            for platform, url_tpl in self.PLATFORMS.items():
                url = url_tpl.replace("{username}", username)
                checks.append((platform, url, username))

            with ThreadPoolExecutor(max_workers=Config.MAX_CONCURRENT) as executor:
                futures = {}
                for platform, url, uname in checks:
                    f = executor.submit(self._check_profile, platform, url, uname)
                    futures[f] = (platform, url, uname)

                for future in as_completed(futures):
                    platform, url, uname = futures[future]
                    try:
                        exists, confidence = future.result()
                        if exists:
                            key = f"{platform}|{uname}"
                            if key not in found_profiles:
                                found_profiles[key] = True
                                results.append(SearchResult(
                                    source=platform, category="social_media",
                                    title=f"{platform} profile: {uname}",
                                    url=url, snippet=f"Possible profile found for username '{uname}'",
                                    confidence=confidence,
                                    data={"username": uname, "platform": platform}
                                ))
                    except Exception:
                        pass

        # Also do name-based searches on key platforms
        name_results = self._name_based_search(q)
        results.extend(name_results)

        status(f"Social media: {len(results)} potential profiles found", "ok")
        return results

    def _check_profile(self, platform: str, url: str, username: str) -> Tuple[bool, float]:
        """Check if a profile exists at the given URL."""
        try:
            resp = self.client.get(url, delay=0.3, raw=True)
            if resp is None:
                return False, 0.0
            if resp.status_code == 200:
                text_lower = resp.text[:5000].lower()
                # Check for soft 404s
                for indicator in self.ABSENT_INDICATORS:
                    if indicator in text_lower:
                        return False, 0.0
                return True, 0.6
            elif resp.status_code in (301, 302, 303, 307, 308):
                return True, 0.4
            return False, 0.0
        except Exception:
            return False, 0.0

    def _name_based_search(self, q: SearchQuery) -> List[SearchResult]:
        """Search by real name on platforms that support it."""
        results = []
        name = q.full_name

        # GitHub user search
        data = self.client.get_json(f"https://api.github.com/search/users",
                                     params={"q": f"{name} in:name"})
        if data and "items" in data:
            for user in data["items"][:5]:
                results.append(SearchResult(
                    source="GitHub", category="social_media",
                    title=f"GitHub: {user.get('login', '')} ({name})",
                    url=user.get("html_url", ""),
                    snippet=f"GitHub user matching '{name}'",
                    confidence=0.5,
                    data={"username": user.get("login", ""), "avatar": user.get("avatar_url", "")}
                ))

        return results


# ==============================================================================
# SECTION 7: PEOPLE SEARCH ENGINES
# ==============================================================================

class PeopleSearchModule:
    """Aggregate results from people search engines & public data."""

    # Direct search URLs -- generated for user to visit + automated where possible
    PEOPLE_SEARCH_SITES = {
        # --- USA ------------------------------------------------------
        "TruePeopleSearch": {
            "url": "https://www.truepeoplesearch.com/results?name={first}+{last}&citystatezip={location}",
            "region": "US",
            "scrape": True,
        },
        "FastPeopleSearch": {
            "url": "https://www.fastpeoplesearch.com/name/{first}-{last}_{location}",
            "region": "US",
            "scrape": True,
        },
        "ThatsThem": {
            "url": "https://thatsthem.com/name/{first}-{last}/{location}",
            "region": "US",
            "scrape": True,
        },
        "WhitePages": {
            "url": "https://www.whitepages.com/name/{first}-{last}/{location}",
            "region": "US",
            "scrape": False,
        },
        "Spokeo": {
            "url": "https://www.spokeo.com/{first}-{last}",
            "region": "US",
            "scrape": False,
        },
        "PeekYou": {
            "url": "https://www.peekyou.com/{first}_{last}/{location}",
            "region": "US",
            "scrape": True,
        },
        "ZabaSearch": {
            "url": "https://www.zabasearch.com/people/{first}+{last}/{location}",
            "region": "US",
            "scrape": False,
        },
        "Radaris": {
            "url": "https://radaris.com/p/{first}/{last}/",
            "region": "US",
            "scrape": False,
        },
        "CyberBackgroundChecks": {
            "url": "https://www.cyberbackgroundchecks.com/people/{first}-{last}/{location}",
            "region": "US",
            "scrape": False,
        },
        "Nuwber": {
            "url": "https://nuwber.com/search?name={first}+{last}&location={location}",
            "region": "US",
            "scrape": False,
        },
        "USPhoneBook": {
            "url": "https://www.usphonebook.com/{first}-{last}/{location}",
            "region": "US",
            "scrape": False,
        },
        # --- Canada ---------------------------------------------------
        "Canada411": {
            "url": "https://www.canada411.ca/search/?stype=si&what={first}+{last}&where={location}",
            "region": "CA",
            "scrape": False,
        },
        "CanadaPagesBlanches": {
            "url": "https://www.pagesblanches.ca/search/?stype=si&what={first}+{last}&where={location}",
            "region": "CA",
            "scrape": False,
        },
        # --- UK -------------------------------------------------------
        "192.com": {
            "url": "https://www.192.com/people/search/?surname={last}&forename={first}&location={location}",
            "region": "UK",
            "scrape": False,
        },
        "BT Phone Book": {
            "url": "https://www.thephonebook.bt.com/person/search/?surname={last}&forename={first}",
            "region": "UK",
            "scrape": False,
        },
        # --- Australia ------------------------------------------------
        "White Pages AU": {
            "url": "https://www.whitepages.com.au/residential?name={first}+{last}&location={location}",
            "region": "AU",
            "scrape": False,
        },
        # --- Europe --------------------------------------------------
        "DasTelefonbuch (DE)": {
            "url": "https://www.dastelefonbuch.de/Suche/{first}+{last}/{location}",
            "region": "DE",
            "scrape": False,
        },
        "PagesBlanches (FR)": {
            "url": "https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={first}+{last}&ou={location}",
            "region": "FR",
            "scrape": False,
        },
        "PagineBianche (IT)": {
            "url": "https://www.paginebianche.it/ricerca?qs={first}+{last}&dv={location}",
            "region": "IT",
            "scrape": False,
        },
    }

    def __init__(self, client: WebClient):
        self.client = client

    def search(self, q: SearchQuery) -> Tuple[List[SearchResult], List[Dict]]:
        """Search people search engines. Returns (results, direct_links)."""
        section("PEOPLE SEARCH ENGINES")
        results = []
        direct_links = []

        location = ""
        if q.city and q.state:
            location = f"{q.city}-{q.state}"
        elif q.state:
            location = q.state
        elif q.city:
            location = q.city

        for name, info in self.PEOPLE_SEARCH_SITES.items():
            url = info["url"].format(
                first=urllib.parse.quote(q.first_name),
                last=urllib.parse.quote(q.last_name),
                location=urllib.parse.quote(location)
            )
            direct_links.append({
                "source": name, "url": url, "region": info["region"]
            })

            # Try to scrape if enabled
            if info.get("scrape") and HAS_BS4:
                self._scrape_people_site(name, url, q, results)

        # Phone reverse lookup sites
        if q.phone:
            phone_clean = re.sub(r'\D', '', q.phone)
            phone_links = [
                ("TruePeopleSearch Phone", f"https://www.truepeoplesearch.com/results?phoneno={phone_clean}"),
                ("USPhoneBook", f"https://www.usphonebook.com/{phone_clean}"),
                ("WhitePages Phone", f"https://www.whitepages.com/phone/{phone_clean}"),
                ("ThatsThem Phone", f"https://thatsthem.com/phone/{phone_clean}"),
                ("CallerID Phone", f"https://calleridtest.com/lookup/{phone_clean}"),
            ]
            for name, url in phone_links:
                direct_links.append({"source": name, "url": url, "region": "US"})

        # Email reverse lookup
        if q.email:
            email_links = [
                ("ThatsThem Email", f"https://thatsthem.com/email/{urllib.parse.quote(q.email)}"),
                ("Epieos Email", f"https://epieos.com/?q={urllib.parse.quote(q.email)}&t=email"),
                ("Hunter.io Email", f"https://hunter.io/email-verifier/{urllib.parse.quote(q.email)}"),
            ]
            for name, url in email_links:
                direct_links.append({"source": name, "url": url, "region": "US"})

        status(f"People search: {len(results)} scraped results + {len(direct_links)} direct links generated", "ok")
        return results, direct_links

    def _scrape_people_site(self, site_name: str, url: str, q: SearchQuery, results: List):
        """Attempt to scrape a people search site."""
        status(f"  Scraping {site_name}...", "search")
        try:
            soup = self.client.get_soup(url)
            if not soup:
                return

            text = soup.get_text(separator=" ", strip=True)[:10000]
            name_lower = q.full_name.lower()

            if name_lower in text.lower():
                # Extract structured data where possible
                data = {"raw_text_preview": text[:500]}

                # Look for addresses
                addr_pattern = r'\d{1,5}\s+\w+\s+(?:St|Ave|Rd|Dr|Ln|Blvd|Way|Ct|Pl|Cir|Pkwy)\.?'
                addrs = re.findall(addr_pattern, text, re.IGNORECASE)
                if addrs:
                    data["addresses_found"] = addrs[:5]

                # Look for phone numbers
                phone_pattern = r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
                phones = re.findall(phone_pattern, text)
                if phones:
                    data["phones_found"] = list(set(phones))[:5]

                # Look for ages
                age_pattern = r'[Aa]ge\s*:?\s*(\d{1,3})'
                ages = re.findall(age_pattern, text)
                if ages:
                    data["ages_found"] = ages[:3]

                # Look for relatives
                rel_section = re.search(r'(?:relatives?|associates?|related).*?(?=\n\n|\Z)',
                                         text, re.IGNORECASE | re.DOTALL)
                if rel_section:
                    data["relatives_section"] = rel_section.group()[:300]

                results.append(SearchResult(
                    source=site_name, category="people_search",
                    title=f"{q.full_name} found on {site_name}",
                    url=url, snippet=text[:300],
                    confidence=0.7,
                    data=data
                ))
                status(f"    [HIT] {site_name}: Name match found", "ok")
            else:
                status(f"    [MISS] {site_name}: No match", "info")
        except Exception as e:
            status(f"    [ERR] {site_name}: {str(e)[:80]}", "err")


# ==============================================================================
# SECTION 8: PUBLIC RECORDS MODULE
# ==============================================================================

class PublicRecordsModule:
    """Court records, property, voter, business, vital records."""

    def __init__(self, client: WebClient):
        self.client = client

    def search(self, q: SearchQuery) -> Tuple[List[SearchResult], List[Dict]]:
        """Search public records. Returns (results, direct_links)."""
        section("PUBLIC RECORDS")
        results = []
        links = []

        name = q.full_name
        fn, ln = q.first_name, q.last_name
        state = q.state.upper() if q.state else ""

        # --- Federal Court Records (PACER / CourtListener) -----------
        links.append({
            "source": "CourtListener", "type": "court",
            "url": f"https://www.courtlistener.com/?q=%22{urllib.parse.quote(name)}%22&type=r",
            "region": "US"
        })
        links.append({
            "source": "UniCourt", "type": "court",
            "url": f"https://unicourt.com/search?q={urllib.parse.quote(name)}",
            "region": "US"
        })
        links.append({
            "source": "PACER", "type": "court",
            "url": "https://www.pacer.gov/",
            "region": "US", "note": "Requires account -- search federal courts"
        })

        # Try CourtListener API (free, no key needed)
        self._search_courtlistener(q, results)

        # --- SEC EDGAR (Business Filings) ----------------------------
        links.append({
            "source": "SEC EDGAR", "type": "business",
            "url": f"https://efts.sec.gov/LATEST/search-index?q=%22{urllib.parse.quote(name)}%22&dateRange=custom&startdt=2000-01-01",
            "region": "US"
        })
        self._search_sec_edgar(q, results)

        # --- FCC License Search --------------------------------------
        links.append({
            "source": "FCC ULS", "type": "license",
            "url": f"https://wireless2.fcc.gov/UlsApp/UlsSearch/searchLicense.jsp?searchType=name&lastName={urllib.parse.quote(ln)}&firstName={urllib.parse.quote(fn)}",
            "region": "US"
        })

        # --- State-Specific Records ----------------------------------
        if state:
            state_links = self._get_state_record_links(fn, ln, state, q.city)
            links.extend(state_links)

        # --- Property Records ----------------------------------------
        links.append({
            "source": "Zillow Owner", "type": "property",
            "url": f"https://www.zillow.com/owners/{urllib.parse.quote(fn)}-{urllib.parse.quote(ln)}/",
            "region": "US"
        })

        # --- Voter Registration --------------------------------------
        links.append({
            "source": "VoterRecords.com", "type": "voter",
            "url": f"https://voterrecords.com/voters/{urllib.parse.quote(fn)}-{urllib.parse.quote(ln)}/1",
            "region": "US"
        })

        # --- Business Entity Search ----------------------------------
        if state:
            links.append({
                "source": f"OpenCorporates", "type": "business",
                "url": f"https://opencorporates.com/officers?q={urllib.parse.quote(name)}&jurisdiction_code=us_{state.lower()}",
                "region": "US"
            })

        # OpenCorporates API (free, limited)
        self._search_opencorporates(q, results)

        # --- Campaign Finance ----------------------------------------
        links.append({
            "source": "FEC Contributions", "type": "campaign_finance",
            "url": f"https://www.fec.gov/data/receipts/individual-contributions/?contributor_name={urllib.parse.quote(name)}",
            "region": "US"
        })
        self._search_fec(q, results)

        # --- Marriage / Death / Birth indexes ------------------------
        links.append({
            "source": "FamilySearch", "type": "vital",
            "url": f"https://www.familysearch.org/search/record/results?q.givenName={urllib.parse.quote(fn)}&q.surname={urllib.parse.quote(ln)}",
            "region": "US"
        })
        links.append({
            "source": "FindAGrave", "type": "vital",
            "url": f"https://www.findagrave.com/memorial/search?firstname={urllib.parse.quote(fn)}&lastname={urllib.parse.quote(ln)}",
            "region": "US"
        })
        links.append({
            "source": "Ancestry", "type": "vital",
            "url": f"https://www.ancestry.com/search/?name={urllib.parse.quote(fn)}_{urllib.parse.quote(ln)}",
            "region": "US"
        })

        # --- Sex Offender Registry -----------------------------------
        links.append({
            "source": "NSOPW", "type": "criminal",
            "url": f"https://www.nsopw.gov/search-public-sex-offender-registries?FirstName={urllib.parse.quote(fn)}&LastName={urllib.parse.quote(ln)}",
            "region": "US"
        })

        # --- Bankruptcies (via PACER) --------------------------------
        links.append({
            "source": "PACER Bankruptcy", "type": "court",
            "url": "https://pcl.uscourts.gov/pcl/index.jsf",
            "region": "US", "note": "Search federal bankruptcies"
        })

        status(f"Public records: {len(results)} API results + {len(links)} direct links", "ok")
        return results, links

    def _search_courtlistener(self, q: SearchQuery, results: List):
        """Search CourtListener free API."""
        status("  CourtListener API...", "search")
        data = self.client.get_json(
            "https://www.courtlistener.com/api/rest/v4/search/",
            params={"q": f'"{q.full_name}"', "type": "r", "format": "json"},
            headers={"Accept": "application/json"}
        )
        if data and "results" in data:
            for item in data["results"][:10]:
                results.append(SearchResult(
                    source="CourtListener", category="court_record",
                    title=item.get("caseName", item.get("case_name", "")),
                    url=f"https://www.courtlistener.com{item.get('absolute_url', '')}",
                    snippet=item.get("snippet", "")[:300],
                    confidence=0.6,
                    data={"court": item.get("court", ""), "date_filed": item.get("dateFiled", "")}
                ))
            if data["results"]:
                status(f"    CourtListener: {len(data['results'])} court records", "ok")

    def _search_sec_edgar(self, q: SearchQuery, results: List):
        """Search SEC EDGAR full-text search."""
        status("  SEC EDGAR...", "search")
        data = self.client.get_json(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": f'"{q.full_name}"', "from": "0", "size": "10"}
        )
        if data and "hits" in data:
            hits = data["hits"].get("hits", [])
            for hit in hits[:5]:
                src = hit.get("_source", {})
                results.append(SearchResult(
                    source="SEC EDGAR", category="business_filing",
                    title=src.get("display_names", [""])[0] if src.get("display_names") else "SEC Filing",
                    url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={urllib.parse.quote(q.full_name)}",
                    snippet=str(src)[:300],
                    confidence=0.5,
                    data=src
                ))

    def _search_opencorporates(self, q: SearchQuery, results: List):
        """Search OpenCorporates API."""
        status("  OpenCorporates...", "search")
        data = self.client.get_json(
            "https://api.opencorporates.com/v0.4/officers/search",
            params={"q": q.full_name, "jurisdiction_code": f"us_{q.state.lower()}" if q.state else ""}
        )
        if data and "results" in data:
            officers = data["results"].get("officers", [])
            for off in officers[:10]:
                o = off.get("officer", {})
                company = o.get("company", {})
                results.append(SearchResult(
                    source="OpenCorporates", category="business",
                    title=f"{o.get('name', '')} -- {company.get('name', '')}",
                    url=o.get("opencorporates_url", ""),
                    snippet=f"Position: {o.get('position', '')} at {company.get('name', '')}",
                    confidence=0.55,
                    data={"position": o.get("position", ""), "company": company.get("name", ""),
                          "start_date": o.get("start_date", ""), "end_date": o.get("end_date", "")}
                ))

    def _search_fec(self, q: SearchQuery, results: List):
        """Search FEC campaign contributions API."""
        status("  FEC Contributions...", "search")
        data = self.client.get_json(
            "https://api.open.fec.gov/v1/schedules/schedule_a/",
            params={"contributor_name": q.full_name, "api_key": "DEMO_KEY",
                    "per_page": 10, "sort": "-contribution_receipt_date"}
        )
        if data and "results" in data:
            for item in data["results"][:5]:
                results.append(SearchResult(
                    source="FEC", category="campaign_finance",
                    title=f"Contribution: {item.get('contributor_name', '')} -> {item.get('committee', {}).get('name', '')}",
                    url=f"https://www.fec.gov/data/receipts/individual-contributions/?contributor_name={urllib.parse.quote(q.full_name)}",
                    snippet=f"${item.get('contribution_receipt_amount', 0)} on {item.get('contribution_receipt_date', '')}",
                    confidence=0.7,
                    data=item
                ))

    def _get_state_record_links(self, fn: str, ln: str, state: str, city: str) -> List[Dict]:
        """Generate state-specific record links."""
        links = []
        state_upper = state.upper()
        name_url = urllib.parse.quote(f"{fn} {ln}")

        # State court records
        state_courts = {
            "WA": f"https://www.courts.wa.gov/jis/",
            "CA": f"https://www.courts.ca.gov/find-my-court.htm",
            "NY": f"https://iapps.courts.state.ny.us/nyscef/CaseSearch",
            "TX": f"https://research.txcourts.gov/CourtRecordsSearch",
            "FL": f"https://www.myflcourtaccess.com/",
            "IL": f"https://www.illinoiscourts.gov/",
            "PA": f"https://ujsportal.pacourts.us/CaseSearch",
            "OH": f"https://www.supremecourt.ohio.gov/JCS/caseno/default.asp",
        }
        if state_upper in state_courts:
            links.append({
                "source": f"{state_upper} Courts", "type": "court",
                "url": state_courts[state_upper], "region": "US"
            })

        # Secretary of State (business entities)
        links.append({
            "source": f"{state_upper} Secretary of State", "type": "business",
            "url": f"https://www.sos.{state.lower()}.gov/",
            "region": "US", "note": f"Search business entities in {state_upper}"
        })

        # County records if city known
        if city:
            links.append({
                "source": f"{city} County Records", "type": "property",
                "url": f"https://www.google.com/search?q={urllib.parse.quote(city)}+{state_upper}+county+assessor+property+search",
                "region": "US"
            })

        return links


# ==============================================================================
# SECTION 9: NEWS & MEDIA ARCHIVES
# ==============================================================================

class NewsArchiveModule:
    """Deep search through news archives, TV stations, newspapers."""

    def __init__(self, client: WebClient):
        self.client = client

    def search(self, q: SearchQuery) -> List[SearchResult]:
        """Search news archives and local media."""
        section("NEWS & MEDIA ARCHIVES")
        results = []

        # Wayback Machine CDX API
        self._search_wayback(q, results)

        # Archive.org search
        self._search_archive_org(q, results)

        # Google News via DDG
        if HAS_DDG:
            self._ddg_news_deep(q, results)

        # Local TV station searches (if location known)
        if q.city or q.state:
            self._search_local_media(q, results)

        status(f"News archives: {len(results)} results", "ok")
        return results

    def _search_wayback(self, q: SearchQuery, results: List):
        """Search Wayback Machine CDX for mentions."""
        status("  Wayback Machine CDX...", "search")
        # Search for the person's name in archived URLs
        queries = [q.full_name.replace(" ", "+"), q.full_name.replace(" ", "-")]
        if q.last_name:
            queries.append(q.last_name)

        for query in queries[:3]:
            data = self.client.get_json(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": f"*/*{query}*", "output": "json", "limit": "20",
                        "fl": "timestamp,original,mimetype,statuscode"}
            )
            if data and len(data) > 1:
                for row in data[1:]:
                    if len(row) >= 4:
                        ts, url, mime, status_code = row[0], row[1], row[2], row[3]
                        if status_code == "200" and "text" in mime:
                            wb_url = f"https://web.archive.org/web/{ts}/{url}"
                            results.append(SearchResult(
                                source="Wayback Machine", category="web_archive",
                                title=f"Archived: {url[:80]}",
                                url=wb_url, snippet=f"Archived on {ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                                confidence=0.4,
                                data={"original_url": url, "timestamp": ts, "mime": mime}
                            ))

    def _search_archive_org(self, q: SearchQuery, results: List):
        """Search Archive.org full-text search (includes TV news archives!)."""
        status("  Archive.org full-text (TV News Archive)...", "search")

        # Text search -- this searches the TV News Archive too!
        data = self.client.get_json(
            "https://archive.org/advancedsearch.php",
            params={
                "q": f'"{q.full_name}"',
                "fl[]": "identifier,title,description,date,mediatype,collection",
                "sort[]": "date desc",
                "rows": "25",
                "page": "1",
                "output": "json"
            }
        )
        if data and "response" in data:
            docs = data["response"].get("docs", [])
            for doc in docs:
                is_tv = "tvnews" in str(doc.get("collection", "")).lower() or \
                        doc.get("mediatype") == "movies"
                results.append(SearchResult(
                    source="Archive.org" + (" TV News" if is_tv else ""),
                    category="news" if is_tv else "web_archive",
                    title=doc.get("title", ""),
                    url=f"https://archive.org/details/{doc.get('identifier', '')}",
                    snippet=str(doc.get("description", ""))[:300],
                    confidence=0.6 if is_tv else 0.4,
                    data={"date": doc.get("date", ""), "mediatype": doc.get("mediatype", ""),
                          "collection": doc.get("collection", "")}
                ))
            if docs:
                status(f"    Archive.org: {len(docs)} items (including TV News Archive)", "ok")

        # Specifically search the TV News Archive
        tv_data = self.client.get_json(
            "https://archive.org/advancedsearch.php",
            params={
                "q": f'"{q.full_name}" AND collection:tvnews',
                "fl[]": "identifier,title,description,date",
                "rows": "20",
                "output": "json"
            }
        )
        if tv_data and "response" in tv_data:
            tv_docs = tv_data["response"].get("docs", [])
            for doc in tv_docs:
                results.append(SearchResult(
                    source="Archive.org TV News", category="tv_broadcast",
                    title=doc.get("title", ""),
                    url=f"https://archive.org/details/{doc.get('identifier', '')}",
                    snippet=str(doc.get("description", ""))[:300],
                    confidence=0.75,
                    data={"date": doc.get("date", ""), "type": "tv_broadcast"}
                ))
            if tv_docs:
                status(f"    TV News Archive: {len(tv_docs)} broadcast mentions", "ok")

    def _ddg_news_deep(self, q: SearchQuery, results: List):
        """Deep DuckDuckGo news search with multiple query variations."""
        status("  DuckDuckGo News (deep)...", "search")
        queries = [
            f'"{q.full_name}"',
            f'"{q.full_name}" news',
            f'"{q.full_name}" interview',
        ]
        if q.city:
            queries.append(f'"{q.full_name}" "{q.city}"')
            queries.append(f'"{q.full_name}" "{q.city}" news')
        for kw in q.keywords[:3]:
            queries.append(f'"{q.full_name}" {kw}')

        seen = set()
        for query in queries:
            try:
                with DDGS() as ddgs:
                    news = list(ddgs.news(query, max_results=15))
                for r in news:
                    url = r.get("url", "")
                    if url in seen:
                        continue
                    seen.add(url)
                    results.append(SearchResult(
                        source="DuckDuckGo News", category="news",
                        title=r.get("title", ""), url=url,
                        snippet=r.get("body", ""),
                        confidence=SearchEngineModule._score_result(
                            r.get("title", "") + " " + r.get("body", ""), q
                        ),
                        data={"date": r.get("date", ""), "source": r.get("source", "")}
                    ))
            except Exception:
                pass
            time.sleep(0.5)

    def _search_local_media(self, q: SearchQuery, results: List):
        """Search local TV station and newspaper websites."""
        status("  Local media sources...", "search")

        # Major local news site patterns
        city = q.city.lower().replace(" ", "") if q.city else ""
        state = q.state.upper() if q.state else ""

        # Generate local news search URLs
        local_searches = []

        if q.city:
            # TV stations in the city
            local_searches.append(f'"{q.full_name}" site:*.com "{q.city}" TV OR news OR channel')
            # Newspaper
            local_searches.append(f'"{q.full_name}" "{q.city}" newspaper OR gazette OR tribune OR times OR herald')

        # Search for mentions on local TV station sites
        for kw in q.keywords:
            local_searches.append(f'"{q.full_name}" {kw}')

        if HAS_DDG:
            for query in local_searches[:5]:
                try:
                    with DDGS() as ddgs:
                        for r in ddgs.text(query, max_results=10):
                            url = r.get("href", r.get("link", ""))
                            results.append(SearchResult(
                                source="Local Media Search", category="local_news",
                                title=r.get("title", ""), url=url,
                                snippet=r.get("body", r.get("snippet", "")),
                                confidence=SearchEngineModule._score_result(
                                    r.get("title", "") + " " + r.get("body", r.get("snippet", "")), q
                                ),
                                data={"query": query, "type": "local_media"}
                            ))
                except Exception:
                    pass
                time.sleep(0.5)


# ==============================================================================
# SECTION 10: CONTACT DISCOVERY
# ==============================================================================

class ContactDiscoveryModule:
    """Discover phone numbers, emails, and addresses."""

    # Common email domain patterns
    EMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "icloud.com", "protonmail.com", "mail.com", "live.com", "msn.com",
        "comcast.net", "verizon.net", "att.net", "sbcglobal.net",
    ]

    def __init__(self, client: WebClient):
        self.client = client

    def search(self, q: SearchQuery) -> Tuple[List[SearchResult], List[str]]:
        """Discover contact info. Returns (results, generated_email_guesses)."""
        section("CONTACT DISCOVERY")
        results = []
        email_guesses = []

        # Generate probable email addresses
        if q.first_name and q.last_name:
            email_guesses = self._generate_email_guesses(q.first_name, q.last_name)
            status(f"  Generated {len(email_guesses)} probable email addresses", "info")

        # Hunter.io API (if key provided)
        if Config.HUNTER_IO_KEY and q.email:
            self._verify_email_hunter(q.email, results)

        # Numverify (if key provided and phone given)
        if Config.NUMVERIFY_KEY and q.phone:
            self._verify_phone_numverify(q.phone, results)

        # HIBP breach check (if email known)
        if q.email:
            self._check_hibp(q.email, results)

        # Generate direct links for phone/email lookup
        if q.phone:
            phone_clean = re.sub(r'\D', '', q.phone)
            status(f"  Phone reverse lookup links generated for {phone_clean}", "info")

        status(f"Contact discovery: {len(results)} results", "ok")
        return results, email_guesses

    def _generate_email_guesses(self, first: str, last: str) -> List[str]:
        """Generate probable email addresses."""
        fn = first.lower()
        ln = last.lower()
        patterns = [
            f"{fn}.{ln}", f"{fn}{ln}", f"{fn[0]}{ln}", f"{fn}{ln[0]}",
            f"{fn[0]}.{ln}", f"{fn}_{ln}", f"{ln}.{fn}", f"{ln}{fn}",
            f"{ln}{fn[0]}", f"{fn[0]}{ln[0]}",
        ]
        emails = []
        for pattern in patterns:
            for domain in self.EMAIL_DOMAINS[:6]:
                emails.append(f"{pattern}@{domain}")
        return emails

    def _verify_email_hunter(self, email: str, results: List):
        """Verify email via Hunter.io API."""
        data = self.client.get_json(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": email, "api_key": Config.HUNTER_IO_KEY}
        )
        if data and "data" in data:
            d = data["data"]
            results.append(SearchResult(
                source="Hunter.io", category="email_verification",
                title=f"Email verification: {email}",
                snippet=f"Status: {d.get('status', 'unknown')}, Score: {d.get('score', 0)}",
                confidence=0.8 if d.get("status") == "valid" else 0.3,
                data=d
            ))

    def _verify_phone_numverify(self, phone: str, results: List):
        """Verify phone via Numverify API."""
        data = self.client.get_json(
            "http://apilayer.net/api/validate",
            params={"access_key": Config.NUMVERIFY_KEY, "number": phone}
        )
        if data and data.get("valid"):
            results.append(SearchResult(
                source="Numverify", category="phone_verification",
                title=f"Phone: {phone}",
                snippet=f"Carrier: {data.get('carrier', 'unknown')}, Type: {data.get('line_type', 'unknown')}",
                confidence=0.8,
                data=data
            ))

    def _check_hibp(self, email: str, results: List):
        """Check Have I Been Pwned for breach data."""
        status(f"  HIBP breach check for {email}...", "search")
        headers = {"hibp-api-key": Config.HIBP_API_KEY} if Config.HIBP_API_KEY else {}
        resp = self.client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers={**headers, "User-Agent": "OSINT-People-Finder"},
            delay=2.0, raw=True
        )
        if resp and resp.status_code == 200:
            try:
                breaches = resp.json()
                results.append(SearchResult(
                    source="HIBP", category="breach_data",
                    title=f"{email} found in {len(breaches)} data breaches",
                    url=f"https://haveibeenpwned.com/account/{email}",
                    snippet=", ".join(b.get("Name", "") for b in breaches[:10]),
                    confidence=0.8,
                    data={"breach_count": len(breaches),
                          "breaches": [b.get("Name", "") for b in breaches]}
                ))
            except Exception:
                pass


# ==============================================================================
# SECTION 11: INTERNATIONAL EXPANSION
# ==============================================================================

class InternationalModule:
    """Sources outside the USA -- expanding to global coverage."""

    def __init__(self, client: WebClient):
        self.client = client

    def search(self, q: SearchQuery) -> List[Dict]:
        """Generate international search links based on target country."""
        section("INTERNATIONAL SOURCES")
        links = []
        country = q.country.upper() if q.country else "US"
        fn, ln = q.first_name, q.last_name
        name = q.full_name

        # --- Always Include (Global) ---------------------------------
        global_links = [
            {"source": "Interpol Red Notices", "type": "criminal",
             "url": f"https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices#query={urllib.parse.quote(name)}", "region": "INT"},
            {"source": "World-Check (Refinitiv)", "type": "sanctions",
             "url": f"https://www.refinitiv.com/en/products/world-check-know-your-customer", "region": "INT",
             "note": "Commercial - check sanctions/PEP lists"},
            {"source": "OFAC SDN List", "type": "sanctions",
             "url": f"https://sanctionssearch.ofac.treas.gov/Details.aspx?id=0&q={urllib.parse.quote(name)}", "region": "US/INT"},
            {"source": "UN Sanctions", "type": "sanctions",
             "url": "https://www.un.org/securitycouncil/content/un-sc-consolidated-list", "region": "INT"},
            {"source": "OpenSanctions", "type": "sanctions",
             "url": f"https://www.opensanctions.org/search/?q={urllib.parse.quote(name)}", "region": "INT"},
        ]
        links.extend(global_links)

        # --- North America -------------------------------------------
        na_links = [
            # Canada
            {"source": "Canada411", "type": "directory",
             "url": f"https://www.canada411.ca/search/?stype=si&what={urllib.parse.quote(fn)}+{urllib.parse.quote(ln)}", "region": "CA"},
            {"source": "CanLII (Canada Courts)", "type": "court",
             "url": f"https://www.canlii.org/en/#search/text={urllib.parse.quote(name)}", "region": "CA"},
            {"source": "Canada Corporation Search", "type": "business",
             "url": f"https://www.ic.gc.ca/app/scr/cc/CorporationsCanada/fdrlCrpSrch.html?q={urllib.parse.quote(name)}", "region": "CA"},
            # Mexico
            {"source": "INE Mexico", "type": "voter",
             "url": "https://listanominal.ine.mx/", "region": "MX",
             "note": "Requires CURP or voter ID"},
            {"source": "RENAPO Mexico", "type": "identity",
             "url": "https://www.gob.mx/curp/", "region": "MX"},
        ]
        links.extend(na_links)

        # --- Europe --------------------------------------------------
        eu_links = [
            {"source": "192.com (UK)", "type": "directory",
             "url": f"https://www.192.com/people/search/?surname={urllib.parse.quote(ln)}&forename={urllib.parse.quote(fn)}", "region": "UK"},
            {"source": "Companies House (UK)", "type": "business",
             "url": f"https://find-and-update.company-information.service.gov.uk/search/officers?q={urllib.parse.quote(name)}", "region": "UK"},
            {"source": "Electoral Roll (UK)", "type": "voter",
             "url": "https://www.192.com/people/", "region": "UK"},
            {"source": "DasTelefonbuch (DE)", "type": "directory",
             "url": f"https://www.dastelefonbuch.de/Suche/{urllib.parse.quote(fn)}+{urllib.parse.quote(ln)}", "region": "DE"},
            {"source": "PagesBlanches (FR)", "type": "directory",
             "url": f"https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={urllib.parse.quote(fn)}+{urllib.parse.quote(ln)}", "region": "FR"},
            {"source": "Infobel (EU)", "type": "directory",
             "url": f"https://www.infobel.com/en/world/search?q={urllib.parse.quote(name)}", "region": "EU"},
            {"source": "OpenCorporates (Global)", "type": "business",
             "url": f"https://opencorporates.com/officers?q={urllib.parse.quote(name)}", "region": "INT"},
        ]
        links.extend(eu_links)

        # --- Asia / Pacific ------------------------------------------
        ap_links = [
            {"source": "White Pages AU", "type": "directory",
             "url": f"https://www.whitepages.com.au/residential?name={urllib.parse.quote(fn)}+{urllib.parse.quote(ln)}", "region": "AU"},
            {"source": "ASIC (Australia Business)", "type": "business",
             "url": f"https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx", "region": "AU"},
        ]
        links.extend(ap_links)

        # --- South America -------------------------------------------
        sa_links = [
            {"source": "TeleListas (Brazil)", "type": "directory",
             "url": f"https://www.telelistas.net/busca/{urllib.parse.quote(name)}", "region": "BR"},
            {"source": "CNJ Brazil Courts", "type": "court",
             "url": "https://www.cnj.jus.br/", "region": "BR"},
        ]
        links.extend(sa_links)

        # --- Africa --------------------------------------------------
        af_links = [
            {"source": "CIPC South Africa", "type": "business",
             "url": "https://eservices.cipc.co.za/", "region": "ZA"},
        ]
        links.extend(af_links)

        status(f"International: {len(links)} sources across all continents", "ok")
        return links


# ==============================================================================
# SECTION 12: RESULT AGGREGATION & SCORING
# ==============================================================================

class ResultAggregator:
    """Deduplicates, scores, and builds a unified person profile."""

    @staticmethod
    def aggregate(q: SearchQuery, all_results: List[SearchResult],
                  direct_links: List[Dict], email_guesses: List[str]) -> PersonProfile:
        """Build a PersonProfile from all collected results."""

        profile = PersonProfile(query=q)
        profile.all_results = all_results
        profile.names = [q.full_name]
        profile.total_results_found = len(all_results)

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for r in all_results:
            if r.url and r.url not in seen_urls:
                seen_urls.add(r.url)
                unique_results.append(r)
            elif not r.url:
                unique_results.append(r)

        # Sort by confidence
        unique_results.sort(key=lambda r: r.confidence, reverse=True)
        profile.all_results = unique_results

        # Extract structured data from results
        for r in unique_results:
            # Social media
            if r.category == "social_media":
                platform = r.data.get("platform", r.source)
                profile.social_media[platform] = r.url

            # News mentions
            elif r.category in ("news", "tv_broadcast", "local_news"):
                profile.news_mentions.append({
                    "source": r.source, "title": r.title,
                    "url": r.url, "date": r.data.get("date", ""),
                    "snippet": r.snippet
                })

            # Court records
            elif r.category == "court_record":
                profile.court_records.append({
                    "source": r.source, "case": r.title,
                    "url": r.url, "court": r.data.get("court", ""),
                    "date": r.data.get("date_filed", "")
                })

            # Business
            elif r.category in ("business", "business_filing"):
                profile.businesses.append({
                    "source": r.source, "name": r.title,
                    "url": r.url, "data": r.data
                })

            # Campaign finance
            elif r.category == "campaign_finance":
                profile.public_records.append({
                    "type": "campaign_contribution",
                    "source": r.source, "detail": r.snippet,
                    "url": r.url
                })

            # Extract phones and addresses from people search results
            if r.category == "people_search":
                for phone in r.data.get("phones_found", []):
                    if phone not in [p.get("number") for p in profile.phones]:
                        profile.phones.append({"number": phone, "source": r.source})
                for addr in r.data.get("addresses_found", []):
                    profile.addresses.append({"address": addr, "source": r.source})
                if r.data.get("relatives_section"):
                    # Try to extract names from relatives section
                    rel_text = r.data["relatives_section"]
                    # Simple extraction -- names are typically capitalized word pairs
                    name_pattern = r'([A-Z][a-z]+\s+[A-Z][a-z]+)'
                    found_names = re.findall(name_pattern, rel_text)
                    for name in found_names:
                        if name != q.full_name and name not in profile.relatives:
                            profile.relatives.append(name)

        return profile


# ==============================================================================
# SECTION 13: REPORT GENERATOR
# ==============================================================================

class ReportGenerator:
    """Generate comprehensive reports in multiple formats."""

    @staticmethod
    def generate_text_report(profile: PersonProfile, direct_links: List[Dict],
                              intl_links: List[Dict], email_guesses: List[str]) -> str:
        """Generate a formatted text report."""
        lines = []
        q = profile.query
        w = 70

        lines.append("=" * w)
        lines.append("  FLLC OSINT PEOPLE FINDER -- INTELLIGENCE REPORT")
        lines.append("=" * w)
        lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Search ID: {q.search_id}")
        lines.append("=" * w)

        # --- Subject --------------------------------------------------
        lines.append(f"\n{'-'*w}")
        lines.append("  SUBJECT")
        lines.append(f"{'-'*w}")
        lines.append(f"  Name:     {q.full_name}")
        if q.aliases:
            lines.append(f"  Aliases:  {', '.join(q.aliases)}")
        if q.city or q.state:
            lines.append(f"  Location: {q.location_str}")
        if q.phone:
            lines.append(f"  Phone:    {q.phone}")
        if q.email:
            lines.append(f"  Email:    {q.email}")
        if q.employer:
            lines.append(f"  Employer: {q.employer}")
        if q.keywords:
            lines.append(f"  Keywords: {', '.join(q.keywords)}")

        # --- Summary Stats --------------------------------------------
        lines.append(f"\n{'-'*w}")
        lines.append("  SEARCH SUMMARY")
        lines.append(f"{'-'*w}")
        lines.append(f"  Total results found:    {profile.total_results_found}")
        lines.append(f"  Unique results:         {len(profile.all_results)}")
        lines.append(f"  Social media profiles:  {len(profile.social_media)}")
        lines.append(f"  News mentions:          {len(profile.news_mentions)}")
        lines.append(f"  Court records:          {len(profile.court_records)}")
        lines.append(f"  Business connections:   {len(profile.businesses)}")
        lines.append(f"  Phone numbers found:    {len(profile.phones)}")
        lines.append(f"  Addresses found:        {len(profile.addresses)}")
        lines.append(f"  Relatives/Associates:   {len(profile.relatives)}")

        # --- High Confidence Results ----------------------------------
        high_conf = [r for r in profile.all_results if r.confidence >= 0.5]
        if high_conf:
            lines.append(f"\n{'-'*w}")
            lines.append(f"  HIGH CONFIDENCE RESULTS ({len(high_conf)})")
            lines.append(f"{'-'*w}")
            for i, r in enumerate(high_conf[:30], 1):
                lines.append(f"\n  [{i}] {r.source} ({r.category}) -- Confidence: {r.confidence:.0%}")
                if r.title:
                    lines.append(f"      Title: {r.title[:100]}")
                if r.url:
                    lines.append(f"      URL:   {r.url}")
                if r.snippet:
                    lines.append(f"      Info:  {r.snippet[:200]}")

        # --- Social Media ---------------------------------------------
        if profile.social_media:
            lines.append(f"\n{'-'*w}")
            lines.append("  SOCIAL MEDIA PROFILES")
            lines.append(f"{'-'*w}")
            for platform, url in sorted(profile.social_media.items()):
                lines.append(f"  * {platform:20s} {url}")

        # --- Contact Info ---------------------------------------------
        if profile.phones or profile.addresses or email_guesses:
            lines.append(f"\n{'-'*w}")
            lines.append("  CONTACT INFORMATION")
            lines.append(f"{'-'*w}")
            if profile.phones:
                lines.append("  Phone Numbers:")
                for p in profile.phones:
                    lines.append(f"    * {p['number']} (from {p['source']})")
            if profile.addresses:
                lines.append("  Addresses:")
                for a in profile.addresses[:10]:
                    lines.append(f"    * {a['address']} (from {a['source']})")
            if email_guesses:
                lines.append(f"  Probable Emails (top {min(15, len(email_guesses))}):")
                for e in email_guesses[:15]:
                    lines.append(f"    * {e}")

        # --- News Mentions --------------------------------------------
        if profile.news_mentions:
            lines.append(f"\n{'-'*w}")
            lines.append(f"  NEWS & MEDIA MENTIONS ({len(profile.news_mentions)})")
            lines.append(f"{'-'*w}")
            for n in profile.news_mentions[:20]:
                lines.append(f"  * [{n.get('date', 'N/A')[:10]}] {n['title'][:80]}")
                lines.append(f"    {n['url']}")
                if n.get('snippet'):
                    lines.append(f"    {n['snippet'][:150]}")

        # --- Court Records --------------------------------------------
        if profile.court_records:
            lines.append(f"\n{'-'*w}")
            lines.append(f"  COURT RECORDS ({len(profile.court_records)})")
            lines.append(f"{'-'*w}")
            for c in profile.court_records[:15]:
                lines.append(f"  * {c['case'][:80]}")
                lines.append(f"    Court: {c.get('court', 'N/A')} | Filed: {c.get('date', 'N/A')}")
                lines.append(f"    {c['url']}")

        # --- Business Connections -------------------------------------
        if profile.businesses:
            lines.append(f"\n{'-'*w}")
            lines.append(f"  BUSINESS CONNECTIONS ({len(profile.businesses)})")
            lines.append(f"{'-'*w}")
            for b in profile.businesses[:15]:
                lines.append(f"  * {b['name'][:80]}")
                lines.append(f"    {b['url']}")

        # --- Relatives / Associates -----------------------------------
        if profile.relatives:
            lines.append(f"\n{'-'*w}")
            lines.append("  RELATIVES & ASSOCIATES")
            lines.append(f"{'-'*w}")
            for name in profile.relatives[:20]:
                lines.append(f"  * {name}")

        # --- Direct Investigation Links -------------------------------
        if direct_links:
            lines.append(f"\n{'-'*w}")
            lines.append(f"  DIRECT INVESTIGATION LINKS -- USA ({len([l for l in direct_links if l.get('region') == 'US'])})")
            lines.append(f"{'-'*w}")
            for l in direct_links:
                if l.get("region") == "US":
                    lines.append(f"  * {l['source']:30s} {l['url']}")

        # --- International Links --------------------------------------
        if intl_links:
            lines.append(f"\n{'-'*w}")
            lines.append(f"  INTERNATIONAL SOURCES ({len(intl_links)})")
            lines.append(f"{'-'*w}")
            by_region = defaultdict(list)
            for l in intl_links:
                by_region[l.get("region", "INT")].append(l)
            for region in sorted(by_region.keys()):
                lines.append(f"\n  [{region}]")
                for l in by_region[region]:
                    lines.append(f"    * {l['source']:30s} {l['url']}")
                    if l.get("note"):
                        lines.append(f"      Note: {l['note']}")

        # --- All Results ----------------------------------------------
        all_by_cat = defaultdict(list)
        for r in profile.all_results:
            all_by_cat[r.category].append(r)

        lines.append(f"\n{'-'*w}")
        lines.append(f"  ALL RESULTS BY CATEGORY")
        lines.append(f"{'-'*w}")
        for cat, items in sorted(all_by_cat.items()):
            lines.append(f"\n  [{cat.upper()}] ({len(items)} results)")
            for r in items[:10]:
                lines.append(f"    * [{r.confidence:.0%}] {r.title[:70]}")
                if r.url:
                    lines.append(f"      {r.url}")

        lines.append(f"\n{'='*w}")
        lines.append("  END OF REPORT")
        lines.append(f"{'='*w}\n")

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(profile: PersonProfile, direct_links: List[Dict],
                              intl_links: List[Dict], email_guesses: List[str]) -> dict:
        """Generate a structured JSON report."""
        return {
            "meta": {
                "tool": "FLLC OSINT People Finder v1.0",
                "generated": datetime.now().isoformat(),
                "search_id": profile.query.search_id,
            },
            "query": {
                "name": profile.query.full_name,
                "first_name": profile.query.first_name,
                "last_name": profile.query.last_name,
                "location": profile.query.location_str,
                "phone": profile.query.phone,
                "email": profile.query.email,
                "keywords": profile.query.keywords,
            },
            "summary": {
                "total_results": profile.total_results_found,
                "unique_results": len(profile.all_results),
                "social_profiles": len(profile.social_media),
                "news_mentions": len(profile.news_mentions),
                "court_records": len(profile.court_records),
                "businesses": len(profile.businesses),
                "phones_found": len(profile.phones),
                "addresses_found": len(profile.addresses),
            },
            "social_media": profile.social_media,
            "phones": profile.phones,
            "addresses": profile.addresses,
            "emails_guessed": email_guesses[:20],
            "news_mentions": profile.news_mentions,
            "court_records": profile.court_records,
            "businesses": profile.businesses,
            "relatives": profile.relatives,
            "public_records": profile.public_records,
            "direct_links": {
                "usa": [l for l in direct_links if l.get("region") == "US"],
                "international": intl_links,
            },
            "all_results": [
                {
                    "source": r.source, "category": r.category,
                    "title": r.title, "url": r.url,
                    "snippet": r.snippet[:300], "confidence": r.confidence,
                } for r in profile.all_results
            ]
        }

    @staticmethod
    def save_report(profile: PersonProfile, text_report: str, json_report: dict,
                    output_dir: str = None):
        """Save reports to disk."""
        if output_dir is None:
            output_dir = Config.OUTPUT_DIR

        os.makedirs(output_dir, exist_ok=True)

        safe_name = re.sub(r'[^\w\-]', '_', profile.query.full_name)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{safe_name}_{timestamp}"

        # Text report
        txt_path = os.path.join(output_dir, f"{base}_report.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(text_report)

        # JSON report
        json_path = os.path.join(output_dir, f"{base}_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False, default=str)

        # CSV of all results
        csv_path = os.path.join(output_dir, f"{base}_results.csv")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "Category", "Confidence", "Title", "URL", "Snippet"])
            for r in profile.all_results:
                writer.writerow([r.source, r.category, f"{r.confidence:.2f}",
                                r.title[:200], r.url, r.snippet[:300]])

        return txt_path, json_path, csv_path


# ==============================================================================
# SECTION 14: MAIN ORCHESTRATOR
# ==============================================================================

class PeopleFinder:
    """Main orchestrator -- coordinates all modules."""

    def __init__(self):
        self.client = WebClient()
        self.search_engine = SearchEngineModule(self.client)
        self.social_media = SocialMediaModule(self.client)
        self.people_search = PeopleSearchModule(self.client)
        self.public_records = PublicRecordsModule(self.client)
        self.news_archive = NewsArchiveModule(self.client)
        self.contact_discovery = ContactDiscoveryModule(self.client)
        self.international = InternationalModule(self.client)

    def find(self, q: SearchQuery, skip_social: bool = False,
             skip_news: bool = False, skip_records: bool = False) -> dict:
        """Execute a full search and return the report."""

        banner()
        status(f"Target: {Fore.WHITE}{q.full_name}{Style.RESET_ALL}", "info")
        if q.location_str:
            status(f"Location: {Fore.WHITE}{q.location_str}{Style.RESET_ALL}", "info")
        if q.keywords:
            status(f"Keywords: {Fore.WHITE}{', '.join(q.keywords)}{Style.RESET_ALL}", "info")
        print()

        all_results = []
        all_direct_links = []
        all_intl_links = []
        email_guesses = []
        start_time = time.time()

        # --- Phase 1: Search Engines ----------------------------------
        try:
            se_results = self.search_engine.search_all(q)
            all_results.extend(se_results)
        except Exception as e:
            status(f"Search engine error: {e}", "err")

        # --- Phase 2: Social Media ------------------------------------
        if not skip_social:
            try:
                sm_results = self.social_media.enumerate(q)
                all_results.extend(sm_results)
            except Exception as e:
                status(f"Social media error: {e}", "err")

        # --- Phase 3: People Search Engines ---------------------------
        try:
            ps_results, ps_links = self.people_search.search(q)
            all_results.extend(ps_results)
            all_direct_links.extend(ps_links)
        except Exception as e:
            status(f"People search error: {e}", "err")

        # --- Phase 4: Public Records ---------------------------------
        if not skip_records:
            try:
                pr_results, pr_links = self.public_records.search(q)
                all_results.extend(pr_results)
                all_direct_links.extend(pr_links)
            except Exception as e:
                status(f"Public records error: {e}", "err")

        # --- Phase 5: News & Media Archives ---------------------------
        if not skip_news:
            try:
                news_results = self.news_archive.search(q)
                all_results.extend(news_results)
            except Exception as e:
                status(f"News archive error: {e}", "err")

        # --- Phase 6: Contact Discovery -------------------------------
        try:
            cd_results, email_guesses = self.contact_discovery.search(q)
            all_results.extend(cd_results)
        except Exception as e:
            status(f"Contact discovery error: {e}", "err")

        # --- Phase 7: International Sources ---------------------------
        try:
            all_intl_links = self.international.search(q)
        except Exception as e:
            status(f"International error: {e}", "err")

        # --- Aggregate ------------------------------------------------
        section("AGGREGATION & REPORT")
        profile = ResultAggregator.aggregate(q, all_results, all_direct_links, email_guesses)
        elapsed = time.time() - start_time

        status(f"Search completed in {elapsed:.1f} seconds", "ok")
        status(f"Total unique results: {len(profile.all_results)}", "ok")
        status(f"Social media profiles: {len(profile.social_media)}", "ok")
        status(f"News mentions: {len(profile.news_mentions)}", "ok")
        status(f"Court records: {len(profile.court_records)}", "ok")
        status(f"Direct investigation links: {len(all_direct_links) + len(all_intl_links)}", "ok")

        # --- Generate Reports -----------------------------------------
        text_report = ReportGenerator.generate_text_report(
            profile, all_direct_links, all_intl_links, email_guesses
        )
        json_report = ReportGenerator.generate_json_report(
            profile, all_direct_links, all_intl_links, email_guesses
        )

        # Save
        txt_path, json_path, csv_path = ReportGenerator.save_report(
            profile, text_report, json_report
        )

        section("OUTPUT FILES")
        status(f"Text report: {txt_path}", "ok")
        status(f"JSON report: {json_path}", "ok")
        status(f"CSV results: {csv_path}", "ok")

        # Print summary to console
        print(f"\n{Fore.WHITE}{'='*60}")
        print(f"  QUICK SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        if profile.social_media:
            print(f"\n{Fore.CYAN}  Social Media:{Style.RESET_ALL}")
            for p, u in list(profile.social_media.items())[:10]:
                print(f"    * {p}: {u}")

        if profile.news_mentions:
            print(f"\n{Fore.CYAN}  News Mentions:{Style.RESET_ALL}")
            for n in profile.news_mentions[:5]:
                print(f"    * {n['title'][:70]}")
                print(f"      {n['url']}")

        if profile.phones:
            print(f"\n{Fore.CYAN}  Phone Numbers:{Style.RESET_ALL}")
            for p in profile.phones[:5]:
                print(f"    * {p['number']}")

        high_conf = [r for r in profile.all_results if r.confidence >= 0.6]
        if high_conf:
            print(f"\n{Fore.CYAN}  Top Results (confidence >= 60%):{Style.RESET_ALL}")
            for r in high_conf[:10]:
                print(f"    * [{r.confidence:.0%}] {r.source}: {r.title[:60]}")
                if r.url:
                    print(f"      {r.url}")

        print(f"\n{Fore.GREEN}  Full report saved to: {txt_path}{Style.RESET_ALL}\n")

        return json_report


# ==============================================================================
# SECTION 15: CLI INTERFACE
# ==============================================================================

def interactive_mode():
    """Interactive prompt for building a search query."""
    banner()
    print(f"{Fore.WHITE}  Interactive Mode -- Answer the prompts to build your search.{Style.RESET_ALL}")
    print(f"  {Style.DIM}(Press Enter to skip any field){Style.RESET_ALL}\n")

    def ask(prompt, required=False):
        while True:
            val = input(f"  {Fore.CYAN}{prompt}: {Style.RESET_ALL}").strip()
            if val or not required:
                return val
            print(f"  {Fore.RED}  This field is required.{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}  --- Person Information ---{Style.RESET_ALL}")
    first = ask("First name", required=True)
    last = ask("Last name", required=True)
    middle = ask("Middle name")
    aliases = ask("Known aliases (comma-separated)")

    print(f"\n{Fore.YELLOW}  --- Location ---{Style.RESET_ALL}")
    city = ask("City")
    state = ask("State (abbrev or full)")
    country = ask("Country (default: US)") or "US"

    print(f"\n{Fore.YELLOW}  --- Contact Info ---{Style.RESET_ALL}")
    phone = ask("Phone number")
    email = ask("Email address")
    username = ask("Known username/handle")

    print(f"\n{Fore.YELLOW}  --- Additional Context ---{Style.RESET_ALL}")
    employer = ask("Employer/Company")
    school = ask("School/University")
    keywords = ask("Keywords (comma-separated, e.g. 'KLXY, ice ribbon')")

    q = SearchQuery(
        first_name=first,
        last_name=last,
        middle_name=middle,
        aliases=[a.strip() for a in aliases.split(",") if a.strip()] if aliases else [],
        city=city,
        state=state,
        country=country,
        phone=phone,
        email=email,
        username=username,
        employer=employer,
        school=school,
        keywords=[k.strip() for k in keywords.split(",") if k.strip()] if keywords else [],
    )

    print(f"\n{Fore.GREEN}  Search query built! Starting search for: {q.full_name}{Style.RESET_ALL}\n")
    return q


def main():
    parser = argparse.ArgumentParser(
        description="FLLC OSINT People Finder -- Comprehensive intelligence aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python people_finder.py -n "Peter Chaffin" -c Spokane -s WA -k "KLXY,ice ribbon"
          python people_finder.py -n "John Smith" -s CA --phone 5551234567
          python people_finder.py -n "Jane Doe" --email jane@example.com
          python people_finder.py --interactive
          python people_finder.py -n "Pierre Dupont" --country FR
        """)
    )

    parser.add_argument("-n", "--name", help="Full name (e.g. 'Peter Chaffin')")
    parser.add_argument("-f", "--first", help="First name")
    parser.add_argument("-l", "--last", help="Last name")
    parser.add_argument("-m", "--middle", help="Middle name")
    parser.add_argument("-c", "--city", help="City")
    parser.add_argument("-s", "--state", help="State (abbreviation or full name)")
    parser.add_argument("--country", default="US", help="Country code (default: US)")
    parser.add_argument("--phone", help="Phone number")
    parser.add_argument("--email", help="Email address")
    parser.add_argument("-u", "--username", help="Known username/handle")
    parser.add_argument("--employer", help="Employer/Company name")
    parser.add_argument("--school", help="School/University")
    parser.add_argument("-k", "--keywords", help="Keywords (comma-separated)")
    parser.add_argument("--aliases", help="Known aliases (comma-separated)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--skip-social", action="store_true", help="Skip social media enumeration")
    parser.add_argument("--skip-news", action="store_true", help="Skip news archive search")
    parser.add_argument("--skip-records", action="store_true", help="Skip public records search")
    parser.add_argument("-o", "--output", help="Output directory", default=Config.OUTPUT_DIR)
    parser.add_argument("--depth", choices=["quick", "normal", "deep"], default="normal",
                        help="Search depth (quick/normal/deep)")

    args = parser.parse_args()

    # Check dependencies
    if not HAS_REQUESTS:
        print(f"{Fore.RED}[ERROR] 'requests' package required. Install: pip install requests{Style.RESET_ALL}")
        sys.exit(1)

    # Configure depth
    if args.depth == "quick":
        Config.MAX_SEARCH_RESULTS = 20
        Config.MAX_QUERY_VARIATIONS = 5
        Config.DEEP_SEARCH = False
    elif args.depth == "deep":
        Config.MAX_SEARCH_RESULTS = 100
        Config.MAX_QUERY_VARIATIONS = 20
        Config.DEEP_SEARCH = True

    Config.OUTPUT_DIR = args.output

    # Build query
    if args.interactive:
        q = interactive_mode()
    elif args.name or (args.first and args.last):
        q = SearchQuery(
            full_name=args.name or "",
            first_name=args.first or "",
            last_name=args.last or "",
            middle_name=args.middle or "",
            city=args.city or "",
            state=args.state or "",
            country=args.country,
            phone=args.phone or "",
            email=args.email or "",
            username=args.username or "",
            employer=args.employer or "",
            school=args.school or "",
            keywords=[k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else [],
            aliases=[a.strip() for a in args.aliases.split(",") if a.strip()] if args.aliases else [],
        )
    else:
        parser.print_help()
        print(f"\n{Fore.YELLOW}  Tip: Use --interactive for guided mode, or provide -n 'Full Name'{Style.RESET_ALL}")
        sys.exit(0)

    # Run
    finder = PeopleFinder()
    finder.find(q, skip_social=args.skip_social, skip_news=args.skip_news,
                skip_records=args.skip_records)


if __name__ == "__main__":
    main()
