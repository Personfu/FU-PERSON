#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: CMS SCANNER & WEB SHELL DETECTOR v1.0
  CMS Fingerprinting | Plugin Enumeration | Web Shell Detection
  WordPress / Joomla / Drupal / Technology Stack Analysis
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  Unauthorized scanning of web applications is ILLEGAL.
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
import re
import math
import json
import time
import argparse
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path
from urllib.parse import urljoin, urlparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnError
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


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
        C.p(f"  {C.BLU}[*]{C.R} {msg}")

    @staticmethod
    def warn(msg: str):
        C.p(f"  {C.YLW}[!]{C.R} {msg}")

    @staticmethod
    def fail(msg: str):
        C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def banner(title: str):
        w = 70
        C.p(f"\n  {C.CYN}{'=' * w}")
        C.p(f"  {C.BLD}{C.WHT}  {title}")
        C.p(f"  {C.CYN}{'=' * w}{C.R}\n")


# =============================================================================
#  DATA STRUCTURES
# =============================================================================

@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: str = ""
    category: str = "unknown"

@dataclass
class PluginInfo:
    slug: str
    name: str = ""
    version: Optional[str] = None
    exists: bool = False
    url: str = ""

@dataclass
class UserInfo:
    uid: int = 0
    username: str = ""
    display_name: str = ""
    source: str = ""

@dataclass
class WebShellMatch:
    filepath: str
    reason: str
    severity: str = "high"
    line_number: int = 0
    snippet: str = ""
    entropy: float = 0.0

@dataclass
class ScanResult:
    url: str = ""
    technologies: List[Technology] = field(default_factory=list)
    plugins: List[PluginInfo] = field(default_factory=list)
    themes: List[PluginInfo] = field(default_factory=list)
    users: List[UserInfo] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    webshells: List[WebShellMatch] = field(default_factory=list)


# =============================================================================
#  HTTP HELPERS
# =============================================================================

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_TIMEOUT = 10


def _get(url: str, **kwargs) -> Optional["requests.Response"]:
    if not HAS_REQUESTS:
        return None
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", _DEFAULT_UA)
    try:
        resp = requests.get(url, headers=headers, timeout=_TIMEOUT,
                            verify=False, allow_redirects=True, **kwargs)
        return resp
    except (RequestException, Timeout, ReqConnError):
        return None


def _head(url: str) -> Optional["requests.Response"]:
    if not HAS_REQUESTS:
        return None
    try:
        return requests.head(url, headers={"User-Agent": _DEFAULT_UA},
                             timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except (RequestException, Timeout, ReqConnError):
        return None


def _probe(url: str) -> Tuple[bool, int]:
    resp = _head(url)
    if resp is not None:
        return (resp.status_code == 200, resp.status_code)
    return (False, 0)


# =============================================================================
#  CMS FINGERPRINTER
# =============================================================================

class CMSFingerprinter:
    """Generic CMS and technology stack detection."""

    _HEADER_SIGNATURES: Dict[str, List[Tuple[str, str, str]]] = {
        "server": [
            ("Apache",      r"(?i)apache",      "web-server"),
            ("Nginx",       r"(?i)nginx",       "web-server"),
            ("IIS",         r"(?i)microsoft-iis","web-server"),
            ("LiteSpeed",   r"(?i)litespeed",   "web-server"),
        ],
        "x-powered-by": [
            ("PHP",         r"(?i)php/?(\S*)",  "language"),
            ("ASP.NET",     r"(?i)asp\.net",    "framework"),
            ("Express",     r"(?i)express",     "framework"),
        ],
        "x-generator": [
            ("WordPress",   r"(?i)wordpress",   "cms"),
            ("Drupal",      r"(?i)drupal",      "cms"),
            ("Joomla",      r"(?i)joomla",      "cms"),
        ],
    }

    _HTML_SIGNATURES: List[Tuple[str, str, str, str]] = [
        ("WordPress",   r'wp-content/',                         "cms",       "wp-content path in HTML"),
        ("WordPress",   r'<meta\s+name="generator"\s+content="WordPress\s*([\d.]*)"', "cms", "meta generator"),
        ("Joomla",      r'/media/system/js/',                   "cms",       "Joomla system JS path"),
        ("Joomla",      r'<meta\s+name="generator"\s+content="Joomla', "cms", "meta generator"),
        ("Drupal",      r'Drupal\.settings',                    "cms",       "Drupal.settings in JS"),
        ("Drupal",      r'sites/default/files',                 "cms",       "Drupal default files path"),
        ("Magento",     r'Mage\.Cookies',                       "cms",       "Mage.Cookies JS object"),
        ("Magento",     r'/static/version',                     "cms",       "Magento static versioning"),
        ("Shopify",     r'cdn\.shopify\.com',                   "cms",       "Shopify CDN reference"),
        ("Squarespace", r'squarespace\.com',                    "cms",       "Squarespace reference"),
        ("Wix",         r'wix\.com',                            "cms",       "Wix reference"),
        ("Ghost",       r'ghost-(?:url|api)',                   "cms",       "Ghost API reference"),
        ("Hugo",        r'hugo-[\d.]+',                         "ssg",       "Hugo version string"),
        ("Jekyll",      r'jekyll',                              "ssg",       "Jekyll reference"),
        ("Angular",     r'ng-(?:app|controller|version)',       "framework", "Angular directives"),
        ("React",       r'_react|react(?:DOM|\.createElement)', "framework", "React runtime"),
        ("Vue",         r'Vue\.(?:component|use)|__vue__',      "framework", "Vue runtime"),
        ("Next.js",     r'_next/(?:static|data)',               "framework", "Next.js paths"),
        ("Nuxt",        r'__NUXT__|_nuxt/',                     "framework", "Nuxt runtime"),
        ("Laravel",     r'laravel_session',                     "framework", "Laravel session cookie"),
        ("Django",      r'csrfmiddlewaretoken|__admin_media_prefix__', "framework", "Django CSRF token"),
    ]

    _COOKIE_SIGNATURES: List[Tuple[str, str, str]] = [
        ("WordPress",   r"wordpress_",      "cms"),
        ("Joomla",      r"joomla_",         "cms"),
        ("Drupal",      r"Drupal\.visitor",  "cms"),
        ("Laravel",     r"laravel_session", "framework"),
        ("Django",      r"csrftoken",       "framework"),
        ("Cloudflare",  r"__cf",            "cdn"),
        ("AWS",         r"AWSALB",          "cloud"),
    ]

    def fingerprint(self, url: str) -> List[Technology]:
        if not HAS_REQUESTS:
            C.fail("requests library required for CMS fingerprinting")
            return []

        C.info(f"Fingerprinting {C.CYN}{url}{C.R}")
        resp = _get(url)
        if resp is None:
            C.fail("Could not connect to target")
            return []

        found: Dict[str, Technology] = {}

        self._check_headers(resp, found)
        self._check_html(resp.text, found)
        self._check_cookies(resp, found)
        self._check_cdn_cloud(resp, found)

        techs = sorted(found.values(), key=lambda t: t.confidence, reverse=True)
        for t in techs:
            col = C.GRN if t.confidence >= 0.7 else C.YLW if t.confidence >= 0.4 else C.DIM
            C.ok(f"{col}{t.name}{C.R} v{t.version or '?'} "
                 f"({t.category}, {t.confidence:.0%}) - {t.evidence}")
        return techs

    def _check_headers(self, resp: "requests.Response",
                       found: Dict[str, Technology]) -> None:
        for hdr, sigs in self._HEADER_SIGNATURES.items():
            val = resp.headers.get(hdr, "")
            if not val:
                continue
            for name, pattern, cat in sigs:
                m = re.search(pattern, val)
                if m:
                    ver = m.group(1) if m.lastindex else None
                    self._add(found, name, ver, 0.8, f"Header {hdr}: {val}", cat)

    def _check_html(self, html: str, found: Dict[str, Technology]) -> None:
        for name, pattern, cat, evidence in self._HTML_SIGNATURES:
            m = re.search(pattern, html)
            if m:
                ver = m.group(1) if m.lastindex and m.group(1) else None
                self._add(found, name, ver, 0.7, evidence, cat)

    def _check_cookies(self, resp: "requests.Response",
                       found: Dict[str, Technology]) -> None:
        cookie_str = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
        for name, pattern, cat in self._COOKIE_SIGNATURES:
            if re.search(pattern, cookie_str):
                self._add(found, name, None, 0.5, f"Cookie matching {pattern}", cat)

    def _check_cdn_cloud(self, resp: "requests.Response",
                         found: Dict[str, Technology]) -> None:
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        if "cf-ray" in hdrs or "cf-cache-status" in hdrs:
            self._add(found, "Cloudflare", None, 0.9, "CF-Ray header", "cdn")
        if hdrs.get("server", "").lower().startswith("cloudflare"):
            self._add(found, "Cloudflare", None, 0.95, "Server: cloudflare", "cdn")
        if "x-amz-cf-id" in hdrs or "x-amz-request-id" in hdrs:
            self._add(found, "AWS", None, 0.8, "AWS headers", "cloud")
        if hdrs.get("server", "").lower().startswith("vercel"):
            self._add(found, "Vercel", None, 0.9, "Server: Vercel", "cloud")
        if "x-vercel-id" in hdrs:
            self._add(found, "Vercel", None, 0.9, "X-Vercel-Id header", "cloud")

    @staticmethod
    def _add(found: Dict[str, Technology], name: str, version: Optional[str],
             confidence: float, evidence: str, category: str) -> None:
        key = name.lower()
        if key in found:
            old = found[key]
            if confidence > old.confidence:
                old.confidence = confidence
                old.evidence = evidence
            if version and not old.version:
                old.version = version
        else:
            found[key] = Technology(name=name, version=version,
                                    confidence=confidence, evidence=evidence,
                                    category=category)


# =============================================================================
#  WORDPRESS SCANNER
# =============================================================================

_TOP_WP_PLUGINS: List[str] = [
    "contact-form-7", "woocommerce", "akismet", "jetpack", "elementor",
    "wordfence", "yoast-seo", "wordpress-seo", "classic-editor",
    "really-simple-ssl", "wpforms-lite", "litespeed-cache",
    "all-in-one-wp-migration", "updraftplus", "wp-super-cache",
    "duplicate-page", "google-analytics-for-wordpress",
    "advanced-custom-fields", "wp-mail-smtp", "redirection",
    "all-in-one-seo-pack", "tinymce-advanced", "wp-optimize",
    "limit-login-attempts-reloaded", "tablepress", "w3-total-cache",
    "broken-link-checker", "regenerate-thumbnails", "custom-post-type-ui",
    "better-wp-security", "sucuri-scanner", "wp-fastest-cache",
    "google-sitemap-generator", "hello-dolly", "wp-migrate-db",
    "insert-headers-and-footers", "coming-soon", "shortcodes-ultimate",
    "instagram-feed", "disable-comments", "simple-custom-css",
    "mailchimp-for-wp", "header-footer-elementor", "breadcrumb-navxt",
    "user-role-editor", "members", "svg-support", "safe-svg",
    "autoptimize", "async-javascript", "cookie-notice",
]


class WordPressScanner:
    """WordPress-specific vulnerability and enumeration scanner."""

    def detect_version(self, url: str) -> Optional[str]:
        C.info("Detecting WordPress version")
        base = url.rstrip("/")
        version: Optional[str] = None

        resp = _get(base + "/")
        if resp:
            m = re.search(r'<meta\s+name="generator"\s+content="WordPress\s+([\d.]+)"',
                          resp.text, re.I)
            if m:
                version = m.group(1)
                C.ok(f"Version from meta generator: {C.CYN}{version}{C.R}")
                return version

        for path in ["/readme.html", "/wp-links-opml.php"]:
            resp = _get(base + path)
            if resp and resp.status_code == 200:
                m = re.search(r"(?:version|WordPress)\s+([\d.]+)", resp.text, re.I)
                if m:
                    version = m.group(1)
                    C.ok(f"Version from {path}: {C.CYN}{version}{C.R}")
                    return version

        resp = _get(base + "/feed/")
        if resp and resp.status_code == 200:
            m = re.search(r'<generator>.*?v=([\d.]+)</generator>', resp.text)
            if m:
                version = m.group(1)
                C.ok(f"Version from RSS feed: {C.CYN}{version}{C.R}")
                return version

        if version is None:
            C.warn("Could not determine WordPress version")
        return version

    def enumerate_plugins(self, url: str, aggressive: bool = False) -> List[PluginInfo]:
        C.info(f"Enumerating plugins ({'aggressive' if aggressive else 'passive'})")
        base = url.rstrip("/")
        plugins: List[PluginInfo] = []

        resp = _get(base + "/")
        if resp:
            found_slugs: Set[str] = set()
            for m in re.finditer(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', resp.text):
                found_slugs.add(m.group(1))
            for slug in sorted(found_slugs):
                pi = PluginInfo(slug=slug, exists=True,
                                url=f"{base}/wp-content/plugins/{slug}/")
                readme_resp = _get(pi.url + "readme.txt")
                if readme_resp and readme_resp.status_code == 200:
                    vm = re.search(r"Stable tag:\s*([\d.]+)", readme_resp.text, re.I)
                    if vm:
                        pi.version = vm.group(1)
                plugins.append(pi)
                C.ok(f"Plugin: {C.CYN}{slug}{C.R} v{pi.version or '?'}")

        if aggressive:
            slugs_to_probe = [s for s in _TOP_WP_PLUGINS
                              if s not in {p.slug for p in plugins}]

            def _probe_plugin(slug: str) -> Optional[PluginInfo]:
                probe_url = f"{base}/wp-content/plugins/{slug}/"
                r = _head(probe_url)
                if r and r.status_code in (200, 403):
                    return PluginInfo(slug=slug, exists=True, url=probe_url)
                return None

            with ThreadPoolExecutor(max_workers=10) as pool:
                futs = {pool.submit(_probe_plugin, s): s for s in slugs_to_probe}
                for fut in as_completed(futs):
                    result = fut.result()
                    if result:
                        plugins.append(result)
                        C.ok(f"Plugin (probed): {C.CYN}{result.slug}{C.R}")

        C.info(f"Found {C.CYN}{len(plugins)}{C.R} plugins total")
        return plugins

    def enumerate_themes(self, url: str) -> List[PluginInfo]:
        C.info("Enumerating themes")
        base = url.rstrip("/")
        themes: List[PluginInfo] = []

        resp = _get(base + "/")
        if resp:
            found: Set[str] = set()
            for m in re.finditer(r'/wp-content/themes/([a-zA-Z0-9_-]+)/', resp.text):
                found.add(m.group(1))
            for slug in sorted(found):
                theme_url = f"{base}/wp-content/themes/{slug}/"
                ti = PluginInfo(slug=slug, exists=True, url=theme_url)
                style = _get(theme_url + "style.css")
                if style and style.status_code == 200:
                    vm = re.search(r"Version:\s*([\d.]+)", style.text)
                    if vm:
                        ti.version = vm.group(1)
                    nm = re.search(r"Theme Name:\s*(.+)", style.text)
                    if nm:
                        ti.name = nm.group(1).strip()
                themes.append(ti)
                C.ok(f"Theme: {C.CYN}{ti.name or slug}{C.R} v{ti.version or '?'}")

        C.info(f"Found {C.CYN}{len(themes)}{C.R} themes")
        return themes

    def enumerate_users(self, url: str) -> List[UserInfo]:
        C.info("Enumerating users")
        base = url.rstrip("/")
        users: List[UserInfo] = []
        seen: Set[str] = set()

        resp = _get(base + "/wp-json/wp/v2/users?per_page=50")
        if resp and resp.status_code == 200:
            try:
                for u in resp.json():
                    uname = u.get("slug", "")
                    if uname and uname not in seen:
                        seen.add(uname)
                        users.append(UserInfo(uid=u.get("id", 0), username=uname,
                                              display_name=u.get("name", ""),
                                              source="wp-json"))
                        C.ok(f"User: {C.CYN}{uname}{C.R} (id={u.get('id')})")
            except (ValueError, KeyError):
                pass

        for n in range(1, 21):
            resp = _get(base + f"/?author={n}", allow_redirects=False)
            if resp is None:
                continue
            loc = resp.headers.get("Location", "")
            m = re.search(r'/author/([^/]+)', loc)
            if m:
                uname = m.group(1)
                if uname not in seen:
                    seen.add(uname)
                    users.append(UserInfo(uid=n, username=uname,
                                          source="author-enum"))
                    C.ok(f"User: {C.CYN}{uname}{C.R} (author={n})")

        resp = _get(base + "/wp-json/oembed/1.0/embed?url=" + base + "/")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                author = data.get("author_name", "")
                if author and author not in seen:
                    seen.add(author)
                    users.append(UserInfo(username=author, source="oembed"))
                    C.ok(f"User: {C.CYN}{author}{C.R} (oembed)")
            except (ValueError, KeyError):
                pass

        C.info(f"Found {C.CYN}{len(users)}{C.R} users")
        return users

    def check_xmlrpc(self, url: str) -> bool:
        C.info("Checking XML-RPC")
        base = url.rstrip("/")
        resp = _get(base + "/xmlrpc.php")
        if resp and resp.status_code == 200 and "XML-RPC" in resp.text:
            C.warn(f"{C.RED}xmlrpc.php is ENABLED{C.R}")
            if HAS_REQUESTS:
                payload = ('<?xml version="1.0"?>'
                           '<methodCall><methodName>system.listMethods</methodName>'
                           '<params></params></methodCall>')
                try:
                    r = requests.post(base + "/xmlrpc.php", data=payload,
                                      headers={"Content-Type": "text/xml",
                                                "User-Agent": _DEFAULT_UA},
                                      timeout=_TIMEOUT, verify=False)
                    if "pingback.ping" in r.text:
                        C.warn(f"{C.RED}Pingback abuse possible{C.R}")
                except RequestException:
                    pass
            return True
        C.ok("xmlrpc.php not exposed")
        return False

    def check_wp_cron(self, url: str) -> bool:
        C.info("Checking wp-cron.php")
        exists, code = _probe(url.rstrip("/") + "/wp-cron.php")
        if exists:
            C.warn(f"{C.YLW}wp-cron.php accessible (DoS risk){C.R}")
            return True
        C.ok("wp-cron.php not directly accessible")
        return False

    def check_debug_log(self, url: str) -> bool:
        C.info("Checking debug.log exposure")
        resp = _get(url.rstrip("/") + "/wp-content/debug.log")
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            C.warn(f"{C.RED}debug.log EXPOSED ({len(resp.text)} bytes){C.R}")
            return True
        C.ok("debug.log not exposed")
        return False

    def check_config_backup(self, url: str) -> List[str]:
        C.info("Probing for wp-config backups")
        base = url.rstrip("/")
        exposed: List[str] = []
        candidates = [
            "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php.orig",
            "/wp-config.php.save", "/wp-config.php.swp", "/wp-config.php~",
            "/wp-config.bak", "/wp-config.old", "/wp-config.txt",
            "/.wp-config.php.swp",
        ]
        for path in candidates:
            resp = _get(base + path)
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                if "DB_NAME" in resp.text or "DB_PASSWORD" in resp.text:
                    C.warn(f"{C.RED}Config backup FOUND: {path}{C.R}")
                    exposed.append(path)
        if not exposed:
            C.ok("No wp-config backups found")
        return exposed


# =============================================================================
#  JOOMLA SCANNER
# =============================================================================

class JoomlaScanner:
    """Joomla-specific vulnerability and enumeration scanner."""

    _COMMON_COMPONENTS: List[str] = [
        "com_content", "com_users", "com_contact", "com_banners",
        "com_finder", "com_search", "com_newsfeeds", "com_tags",
        "com_fields", "com_redirect", "com_media", "com_modules",
        "com_plugins", "com_templates", "com_languages",
        "com_akeeba", "com_k2", "com_virtuemart", "com_hikashop",
        "com_phocagallery", "com_fabrik", "com_jce", "com_zoo",
        "com_kunena", "com_easyblog", "com_rsform",
    ]

    def detect_version(self, url: str) -> Optional[str]:
        C.info("Detecting Joomla version")
        base = url.rstrip("/")

        for xml_path in ["/administrator/manifests/files/joomla.xml",
                         "/language/en-GB/en-GB.xml"]:
            resp = _get(base + xml_path)
            if resp and resp.status_code == 200:
                m = re.search(r"<version>([\d.]+)</version>", resp.text)
                if m:
                    C.ok(f"Version from XML: {C.CYN}{m.group(1)}{C.R}")
                    return m.group(1)

        resp = _get(base + "/README.txt")
        if resp and resp.status_code == 200:
            m = re.search(r"Joomla!\s+([\d.]+)", resp.text)
            if m:
                C.ok(f"Version from README: {C.CYN}{m.group(1)}{C.R}")
                return m.group(1)

        resp = _get(base + "/")
        if resp:
            m = re.search(r'<meta\s+name="generator"\s+content="Joomla!\s*([\d.]*)"',
                          resp.text, re.I)
            if m and m.group(1):
                C.ok(f"Version from meta: {C.CYN}{m.group(1)}{C.R}")
                return m.group(1)

        C.warn("Could not determine Joomla version")
        return None

    def enumerate_components(self, url: str) -> List[PluginInfo]:
        C.info("Enumerating Joomla components")
        base = url.rstrip("/")
        components: List[PluginInfo] = []

        def _probe_component(comp: str) -> Optional[PluginInfo]:
            for prefix in ["/administrator/components/", "/components/"]:
                probe_url = base + prefix + comp + "/"
                r = _head(probe_url)
                if r and r.status_code in (200, 403):
                    return PluginInfo(slug=comp, exists=True, url=probe_url)
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(_probe_component, c): c for c in self._COMMON_COMPONENTS}
            for fut in as_completed(futs):
                result = fut.result()
                if result:
                    components.append(result)
                    C.ok(f"Component: {C.CYN}{result.slug}{C.R}")

        C.info(f"Found {C.CYN}{len(components)}{C.R} components")
        return components

    def check_admin(self, url: str) -> Optional[str]:
        C.info("Locating admin panel")
        base = url.rstrip("/")
        for path in ["/administrator/", "/administrator/index.php"]:
            resp = _get(base + path)
            if resp and resp.status_code == 200:
                if "login" in resp.text.lower() or "joomla" in resp.text.lower():
                    full_url = base + path
                    C.ok(f"Admin panel: {C.CYN}{full_url}{C.R}")
                    return full_url
        C.info("Admin panel not found at default location")
        return None

    def check_registration(self, url: str) -> bool:
        C.info("Checking if registration is open")
        base = url.rstrip("/")
        resp = _get(base + "/index.php?option=com_users&view=registration")
        if resp and resp.status_code == 200:
            if re.search(r'(?:registration|register)', resp.text, re.I):
                C.warn(f"{C.YLW}User registration appears OPEN{C.R}")
                return True
        C.ok("Registration not openly accessible")
        return False

    def check_debug(self, url: str) -> bool:
        C.info("Checking for debug mode indicators")
        resp = _get(url.rstrip("/") + "/")
        if resp and resp.status_code == 200:
            indicators = [r"joomla-debug", r"system-debug",
                          r"Debug\s+mode\s+is\s+on", r"profiler\s+information"]
            for pat in indicators:
                if re.search(pat, resp.text, re.I):
                    C.warn(f"{C.RED}Debug mode appears ENABLED{C.R}")
                    return True
        C.ok("No debug mode indicators found")
        return False


# =============================================================================
#  DRUPAL SCANNER
# =============================================================================

_COMMON_DRUPAL_MODULES: List[str] = [
    "views", "token", "ctools", "pathauto", "entity", "libraries",
    "admin_menu", "date", "link", "webform", "metatag", "redirect",
    "field_group", "module_filter", "devel", "backup_migrate",
    "google_analytics", "imce", "rules", "jquery_update", "features",
    "media", "xmlsitemap", "captcha", "smtp", "colorbox",
]


class DrupalScanner:
    """Drupal-specific vulnerability and enumeration scanner."""

    def detect_version(self, url: str) -> Optional[str]:
        C.info("Detecting Drupal version")
        base = url.rstrip("/")

        resp = _get(base + "/CHANGELOG.txt")
        if resp and resp.status_code == 200:
            m = re.search(r"Drupal\s+([\d.]+)", resp.text)
            if m:
                C.ok(f"Version from CHANGELOG: {C.CYN}{m.group(1)}{C.R}")
                return m.group(1)

        resp = _get(base + "/")
        if resp:
            m = re.search(r'<meta\s+name="generator"\s+content="Drupal\s+([\d.]+)"',
                          resp.text, re.I)
            if m:
                C.ok(f"Version from meta: {C.CYN}{m.group(1)}{C.R}")
                return m.group(1)
            x_gen = resp.headers.get("X-Generator", "")
            m = re.search(r"Drupal\s+([\d.]+)", x_gen, re.I)
            if m:
                C.ok(f"Version from X-Generator: {C.CYN}{m.group(1)}{C.R}")
                return m.group(1)

        for path in ["/core/install.php", "/install.php"]:
            resp = _get(base + path)
            if resp and resp.status_code == 200:
                m = re.search(r"Drupal\s+([\d.]+)", resp.text)
                if m:
                    C.ok(f"Version from install.php: {C.CYN}{m.group(1)}{C.R}")
                    return m.group(1)

        C.warn("Could not determine Drupal version")
        return None

    def enumerate_modules(self, url: str) -> List[PluginInfo]:
        C.info("Enumerating Drupal modules")
        base = url.rstrip("/")
        modules: List[PluginInfo] = []

        def _probe_module(mod: str) -> Optional[PluginInfo]:
            for prefix in ["/modules/", "/sites/all/modules/",
                           "/modules/contrib/"]:
                probe_url = base + prefix + mod + "/"
                r = _head(probe_url)
                if r and r.status_code in (200, 403):
                    pi = PluginInfo(slug=mod, exists=True, url=probe_url)
                    info_resp = _get(probe_url + mod + ".info.yml")
                    if info_resp and info_resp.status_code == 200:
                        vm = re.search(r"version:\s*['\"]?([\d.]+)", info_resp.text)
                        if vm:
                            pi.version = vm.group(1)
                    return pi
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(_probe_module, m): m for m in _COMMON_DRUPAL_MODULES}
            for fut in as_completed(futs):
                result = fut.result()
                if result:
                    modules.append(result)
                    C.ok(f"Module: {C.CYN}{result.slug}{C.R} v{result.version or '?'}")

        C.info(f"Found {C.CYN}{len(modules)}{C.R} modules")
        return modules

    def check_user_enum(self, url: str) -> List[UserInfo]:
        C.info("Testing user enumeration")
        base = url.rstrip("/")
        users: List[UserInfo] = []

        for uid in range(0, 11):
            resp = _get(base + f"/user/{uid}")
            if resp and resp.status_code == 200:
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    title = soup.find("title")
                    if title:
                        name = title.get_text().split("|")[0].strip()
                        if name and name.lower() not in ("access denied", "page not found"):
                            users.append(UserInfo(uid=uid, username=name,
                                                  source="user-path"))
                            C.ok(f"User {uid}: {C.CYN}{name}{C.R}")
                            continue
                m = re.search(r"<title>([^|<]+)", resp.text)
                if m:
                    name = m.group(1).strip()
                    if name.lower() not in ("access denied", "page not found", ""):
                        users.append(UserInfo(uid=uid, username=name,
                                              source="user-path"))
                        C.ok(f"User {uid}: {C.CYN}{name}{C.R}")

        resp = _get(base + "/jsonapi/user/user")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    name = attrs.get("display_name") or attrs.get("name", "")
                    if name:
                        users.append(UserInfo(username=name, source="jsonapi"))
                        C.ok(f"User (JSON API): {C.CYN}{name}{C.R}")
            except (ValueError, KeyError):
                pass

        C.info(f"Found {C.CYN}{len(users)}{C.R} users")
        return users

    def check_updates(self, url: str) -> bool:
        C.info("Checking update status endpoint")
        base = url.rstrip("/")
        resp = _get(base + "/admin/reports/updates")
        if resp and resp.status_code == 200 and "update" in resp.text.lower():
            C.warn(f"{C.YLW}Update status page accessible without auth{C.R}")
            return True
        resp = _get(base + "/xmlrpc.php")
        if resp and resp.status_code == 200:
            C.warn(f"{C.YLW}XMLRPC endpoint accessible{C.R}")
            return True
        C.ok("Update endpoints properly secured")
        return False


# =============================================================================
#  WEB SHELL DETECTOR
# =============================================================================

class WebShellDetector:
    """Detect web shells by signature, entropy, and obfuscation analysis."""

    _SHELL_EXTENSIONS: Set[str] = {".php", ".asp", ".aspx", ".jsp", ".jspx",
                                    ".cgi", ".pl", ".py", ".cfm"}

    _SIGNATURE_PATTERNS: List[Tuple[str, str, str]] = [
        (r"eval\s*\(\s*base64_decode\s*\(",          "eval(base64_decode())",      "critical"),
        (r"eval\s*\(\s*gzinflate\s*\(",              "eval(gzinflate())",          "critical"),
        (r"eval\s*\(\s*str_rot13\s*\(",              "eval(str_rot13())",          "critical"),
        (r"eval\s*\(\s*\$_(GET|POST|REQUEST)",       "eval($_INPUT)",              "critical"),
        (r"assert\s*\(\s*\$_(GET|POST|REQUEST)",     "assert($_INPUT)",            "critical"),
        (r"preg_replace\s*\(.*/e['\"]",              "preg_replace /e modifier",   "critical"),
        (r"\bsystem\s*\(\s*\$_(GET|POST|REQUEST)",   "system($_INPUT)",            "critical"),
        (r"\bexec\s*\(\s*\$_(GET|POST|REQUEST)",     "exec($_INPUT)",              "critical"),
        (r"\bpassthru\s*\(",                         "passthru()",                 "high"),
        (r"\bshell_exec\s*\(",                       "shell_exec()",               "high"),
        (r"\bpopen\s*\(",                            "popen()",                    "medium"),
        (r"\bproc_open\s*\(",                        "proc_open()",                "high"),
        (r"\bpcntl_exec\s*\(",                       "pcntl_exec()",               "high"),
        (r"(?:FilesMan|WSO\s+\d|c99shell|r57shell)", "known shell identifier",     "critical"),
        (r"(?:b374k|weevely|china\s*chopper)",       "known shell family",         "critical"),
        (r"edoced_46teledasb",                       "reversed base64_decode",     "critical"),
        (r"\bchr\s*\(\s*\d+\s*\)\s*\.\s*chr",       "chr() chain obfuscation",    "high"),
        (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}", "hex string encoding",   "high"),
        (r"create_function\s*\(",                    "create_function()",          "high"),
        (r"call_user_func\s*\(\s*\$",               "call_user_func($var)",       "high"),
        (r"move_uploaded_file\s*\(",                 "file upload handler",        "medium"),
        (r"fsockopen\s*\(",                          "fsockopen()",                "medium"),
        (r"\$\w+\s*\(\s*\$_(GET|POST|REQUEST)",     "variable function call",     "high"),
    ]

    _ENTROPY_THRESHOLD: float = 5.7
    _RECENT_DAYS: int = 7

    def scan_directory(self, path: str, recent_only: bool = False) -> List[WebShellMatch]:
        C.info(f"Scanning directory: {C.CYN}{path}{C.R}")
        root = Path(path)
        if not root.is_dir():
            C.fail(f"Directory not found: {path}")
            return []

        matches: List[WebShellMatch] = []
        scanned = 0
        now = time.time()
        recent_threshold = now - (self._RECENT_DAYS * 86400)

        for fpath in root.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in self._SHELL_EXTENSIONS:
                continue

            scanned += 1

            if recent_only:
                try:
                    mtime = fpath.stat().st_mtime
                    if mtime < recent_threshold:
                        continue
                except OSError:
                    continue

            file_matches = self._scan_file(fpath)
            matches.extend(file_matches)

            if self._check_recently_modified(fpath, recent_threshold):
                matches.append(WebShellMatch(
                    filepath=str(fpath),
                    reason="Recently modified web script",
                    severity="info",
                ))

        C.info(f"Scanned {C.CYN}{scanned}{C.R} files, "
               f"found {C.CYN}{len(matches)}{C.R} indicators")

        for m in matches:
            sev_color = {
                "critical": C.RED, "high": C.RED,
                "medium": C.YLW, "info": C.BLU,
            }.get(m.severity, C.DIM)
            C.warn(f"{sev_color}[{m.severity.upper()}]{C.R} {m.filepath} - {m.reason}"
                   + (f" (line {m.line_number})" if m.line_number else "")
                   + (f" [entropy={m.entropy:.2f}]" if m.entropy > 0 else ""))

        return matches

    def _scan_file(self, fpath: Path) -> List[WebShellMatch]:
        results: List[WebShellMatch] = []
        try:
            raw = fpath.read_bytes()
        except (OSError, PermissionError):
            return results

        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            return results

        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            for pattern, reason, severity in self._SIGNATURE_PATTERNS:
                if re.search(pattern, line, re.I):
                    snippet = line.strip()[:120]
                    results.append(WebShellMatch(
                        filepath=str(fpath), reason=reason,
                        severity=severity, line_number=line_num,
                        snippet=snippet,
                    ))
                    break

        entropy = self._shannon_entropy(raw)
        if entropy >= self._ENTROPY_THRESHOLD:
            results.append(WebShellMatch(
                filepath=str(fpath),
                reason=f"High entropy ({entropy:.2f}) suggests obfuscation",
                severity="high", entropy=entropy,
            ))

        obfusc = self._detect_obfuscation(content)
        for reason in obfusc:
            results.append(WebShellMatch(
                filepath=str(fpath), reason=reason, severity="high",
            ))

        return results

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _detect_obfuscation(content: str) -> List[str]:
        findings: List[str] = []
        if content.count("str_rot13") >= 2:
            findings.append("Multiple str_rot13 calls (layered obfuscation)")
        if content.count("gzinflate") >= 2:
            findings.append("Multiple gzinflate calls (layered compression)")
        long_b64 = re.findall(r'[A-Za-z0-9+/=]{200,}', content)
        if long_b64:
            findings.append(f"Long base64 blob(s) detected ({len(long_b64)} occurrence(s))")
        hex_chains = re.findall(r'(?:\\x[0-9a-fA-F]{2}){10,}', content)
        if hex_chains:
            findings.append(f"Long hex-encoded string(s) ({len(hex_chains)} occurrence(s))")
        chr_chain = re.findall(r'chr\s*\(\s*\d+\s*\)', content)
        if len(chr_chain) >= 10:
            findings.append(f"Extensive chr() usage ({len(chr_chain)} calls)")
        if re.search(r'\$\w+\s*=\s*str_replace\(.+?\$\w+\s*=\s*str_replace', content, re.S):
            findings.append("Chained str_replace obfuscation")
        return findings

    @staticmethod
    def _check_recently_modified(fpath: Path, threshold: float) -> bool:
        try:
            return fpath.stat().st_mtime >= threshold
        except OSError:
            return False


# =============================================================================
#  CLI
# =============================================================================

def _cli_scan(args: argparse.Namespace) -> None:
    if not HAS_REQUESTS:
        C.fail("Install requests: pip install requests")
        return
    url = args.url.rstrip("/")
    result = ScanResult(url=url)

    fp = CMSFingerprinter()
    result.technologies = fp.fingerprint(url)

    cms_names = {t.name.lower() for t in result.technologies if t.category == "cms"}
    if "wordpress" in cms_names:
        _run_wordpress(url, result, aggressive=args.aggressive)
    if "joomla" in cms_names:
        _run_joomla(url, result)
    if "drupal" in cms_names:
        _run_drupal(url, result)

    if not cms_names & {"wordpress", "joomla", "drupal"}:
        C.info("No specific CMS detected; trying WordPress heuristic")
        probe = _get(url + "/wp-login.php")
        if probe and probe.status_code == 200:
            _run_wordpress(url, result, aggressive=args.aggressive)

    _print_summary(result)


def _cli_wordpress(args: argparse.Namespace) -> None:
    if not HAS_REQUESTS:
        C.fail("Install requests: pip install requests")
        return
    url = args.url.rstrip("/")
    result = ScanResult(url=url)
    _run_wordpress(url, result, aggressive=args.aggressive)
    _print_summary(result)


def _cli_joomla(args: argparse.Namespace) -> None:
    if not HAS_REQUESTS:
        C.fail("Install requests: pip install requests")
        return
    url = args.url.rstrip("/")
    result = ScanResult(url=url)
    _run_joomla(url, result)
    _print_summary(result)


def _cli_drupal(args: argparse.Namespace) -> None:
    if not HAS_REQUESTS:
        C.fail("Install requests: pip install requests")
        return
    url = args.url.rstrip("/")
    result = ScanResult(url=url)
    _run_drupal(url, result)
    _print_summary(result)


def _cli_webshell(args: argparse.Namespace) -> None:
    detector = WebShellDetector()
    result = ScanResult()
    result.webshells = detector.scan_directory(args.path, recent_only=args.recent)


def _run_wordpress(url: str, result: ScanResult,
                   aggressive: bool = False) -> None:
    C.p(f"\n  {C.MAG}--- WordPress Deep Scan ---{C.R}")
    wp = WordPressScanner()
    ver = wp.detect_version(url)
    if ver:
        result.technologies.append(Technology("WordPress", ver, 1.0,
                                              "version confirmed", "cms"))
    result.plugins = wp.enumerate_plugins(url, aggressive=aggressive)
    result.themes = wp.enumerate_themes(url)
    result.users = wp.enumerate_users(url)
    if wp.check_xmlrpc(url):
        result.vulnerabilities.append("XML-RPC enabled (brute-force / DDoS risk)")
    if wp.check_wp_cron(url):
        result.vulnerabilities.append("wp-cron.php accessible (DoS risk)")
    if wp.check_debug_log(url):
        result.vulnerabilities.append("debug.log exposed (information leak)")
    exposed_cfgs = wp.check_config_backup(url)
    for cfg in exposed_cfgs:
        result.vulnerabilities.append(f"Config backup exposed: {cfg}")


def _run_joomla(url: str, result: ScanResult) -> None:
    C.p(f"\n  {C.MAG}--- Joomla Deep Scan ---{C.R}")
    jm = JoomlaScanner()
    ver = jm.detect_version(url)
    if ver:
        result.technologies.append(Technology("Joomla", ver, 1.0,
                                              "version confirmed", "cms"))
    result.plugins = jm.enumerate_components(url)
    admin = jm.check_admin(url)
    if admin:
        result.vulnerabilities.append(f"Admin panel found: {admin}")
    if jm.check_registration(url):
        result.vulnerabilities.append("User registration is open")
    if jm.check_debug(url):
        result.vulnerabilities.append("Debug mode enabled")


def _run_drupal(url: str, result: ScanResult) -> None:
    C.p(f"\n  {C.MAG}--- Drupal Deep Scan ---{C.R}")
    dp = DrupalScanner()
    ver = dp.detect_version(url)
    if ver:
        result.technologies.append(Technology("Drupal", ver, 1.0,
                                              "version confirmed", "cms"))
    result.plugins = dp.enumerate_modules(url)
    result.users = dp.check_user_enum(url)
    if dp.check_updates(url):
        result.vulnerabilities.append("Update/XMLRPC endpoint accessible")


def _print_summary(result: ScanResult) -> None:
    C.p(f"\n  {C.CYN}{'=' * 60}")
    C.p(f"  {C.BLD}{C.WHT}  SCAN SUMMARY")
    C.p(f"  {C.CYN}{'=' * 60}{C.R}")
    if result.url:
        C.p(f"  Target: {C.CYN}{result.url}{C.R}")
    if result.technologies:
        C.p(f"\n  {C.BLD}Technologies ({len(result.technologies)}):{C.R}")
        for t in result.technologies:
            C.p(f"    {C.GRN}{t.name}{C.R} v{t.version or '?'} "
                f"[{t.confidence:.0%}] ({t.category})")
    if result.plugins:
        C.p(f"\n  {C.BLD}Plugins/Components ({len(result.plugins)}):{C.R}")
        for p in result.plugins:
            C.p(f"    {C.CYN}{p.slug}{C.R} v{p.version or '?'}")
    if result.themes:
        C.p(f"\n  {C.BLD}Themes ({len(result.themes)}):{C.R}")
        for t in result.themes:
            C.p(f"    {C.CYN}{t.name or t.slug}{C.R} v{t.version or '?'}")
    if result.users:
        C.p(f"\n  {C.BLD}Users ({len(result.users)}):{C.R}")
        for u in result.users:
            C.p(f"    {C.CYN}{u.username}{C.R} (source: {u.source})")
    if result.vulnerabilities:
        C.p(f"\n  {C.BLD}{C.RED}Findings ({len(result.vulnerabilities)}):{C.R}")
        for v in result.vulnerabilities:
            C.p(f"    {C.RED}[!]{C.R} {v}")
    if result.webshells:
        C.p(f"\n  {C.BLD}{C.RED}Web Shells ({len(result.webshells)}):{C.R}")
        for w in result.webshells:
            C.p(f"    {C.RED}[{w.severity}]{C.R} {w.filepath} - {w.reason}")
    C.p(f"\n  {C.CYN}{'=' * 60}{C.R}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cms_scanner",
        description="FU PERSON :: CMS Scanner & Web Shell Detector",
    )
    sub = parser.add_subparsers(dest="command", help="Scan mode")

    p_scan = sub.add_parser("scan", help="Full CMS auto-detect scan")
    p_scan.add_argument("url", help="Target URL (e.g. https://example.com)")
    p_scan.add_argument("--aggressive", action="store_true",
                        help="Enable aggressive plugin probing")

    p_wp = sub.add_parser("wordpress", help="WordPress-specific scan")
    p_wp.add_argument("url", help="Target URL")
    p_wp.add_argument("--aggressive", action="store_true",
                      help="Enable aggressive plugin probing")

    p_jm = sub.add_parser("joomla", help="Joomla-specific scan")
    p_jm.add_argument("url", help="Target URL")

    p_dp = sub.add_parser("drupal", help="Drupal-specific scan")
    p_dp.add_argument("url", help="Target URL")

    p_ws = sub.add_parser("webshell", help="Web shell detector")
    p_ws.add_argument("path", help="Directory to scan")
    p_ws.add_argument("--recent", action="store_true",
                      help="Only check recently modified files")

    return parser


def main() -> None:
    C.banner("FU PERSON :: CMS SCANNER & WEB SHELL DETECTOR v1.0")
    C.p(f"  {C.DIM}requests: {'available' if HAS_REQUESTS else 'NOT INSTALLED'} | "
        f"beautifulsoup4: {'available' if HAS_BS4 else 'NOT INSTALLED'}{C.R}\n")

    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "scan":      _cli_scan,
        "wordpress": _cli_wordpress,
        "joomla":    _cli_joomla,
        "drupal":    _cli_drupal,
        "webshell":  _cli_webshell,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
