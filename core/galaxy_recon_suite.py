#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: GALAXY RECON SUITE v2.0
  Deep Intelligence Aggregator  |  People + Network + Cross-Reference
  Comprehensive PDF Dossier Generator
===============================================================================
"""

import os
import sys
import json
import time
import re
import socket
import argparse
import textwrap
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
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
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=False)
except ImportError:
    pass

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

# Import sibling modules
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

try:
    from people_finder import (
        PeopleFinder, SearchQuery, PlatformURLs, PlatformResult,
        ReportExporter, C as _C, Config as PFConfig
    )
    HAS_PF = True
except ImportError:
    HAS_PF = False

try:
    from osint_recon_suite import (
        OSINTReconEngine, DNSEnumerator, SubdomainBruteForcer,
        WHOISLookup, GeoIPLookup, PortScanner, ThreatIntelLinks,
    )
    HAS_RECON = True
except ImportError:
    HAS_RECON = False


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
        C.p(f"\n  {C.MAG}{C.BLD}{'=' * w}")
        C.p(f"  {'':>2}{title}")
        C.p(f"  {'=' * w}{C.R}")

    @staticmethod
    def phase(num: int, title: str):
        C.p(f"\n  {C.CYN}{C.BLD}{'*' * 60}")
        C.p(f"  {'':>2}PHASE {num}: {title}")
        C.p(f"  {'*' * 60}{C.R}\n")

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


BANNER = rf"""
{C.MAG}{C.BLD}
    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.R}{C.MAG}    ──────── GALAXY RECON SUITE v2.0 ─── Deep Intelligence ──────────{C.R}
{C.DIM}    FLLC  |  People + Network + Cross-Reference  |  Full Dossier{C.R}
"""

DISCLAIMER = f"""{C.YLW}{C.BLD}
┌──────────────────────────────────────────────────────────────────────────────┐
│  LEGAL DISCLAIMER                                                            │
│  Galaxy Recon aggregates ONLY publicly available data. No unauthorized        │
│  access, no hacking. For legal OSINT, skip-tracing, and authorized           │
│  investigative research only. Comply with all applicable laws.               │
│  The developers assume NO liability for misuse.                              │
└──────────────────────────────────────────────────────────────────────────────┘{C.R}
"""


# =============================================================================
#  GALAXY RECON DATA MODEL
# =============================================================================

@dataclass
class GalaxyTarget:
    full_name: str = ""
    first_name: str = ""
    last_name: str = ""
    email: str = ""
    phone: str = ""
    username: str = ""
    city: str = ""
    state: str = ""
    domain: str = ""
    employer: str = ""
    school: str = ""
    notes: str = ""


@dataclass
class GalaxyDossier:
    target: Dict = field(default_factory=dict)
    timestamp: str = ""
    people_results: List[Dict] = field(default_factory=list)
    people_count: int = 0
    dns_records: Dict = field(default_factory=dict)
    subdomains: List[Dict] = field(default_factory=list)
    whois: Dict = field(default_factory=dict)
    geoip: Dict = field(default_factory=dict)
    open_ports: List[Dict] = field(default_factory=list)
    threat_links: Dict = field(default_factory=dict)
    cross_references: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)


# =============================================================================
#  CROSS-REFERENCE ENGINE
# =============================================================================

class CrossReferenceEngine:
    """Cross-reference results from people finder and network recon."""

    @staticmethod
    def analyze(dossier: GalaxyDossier, target: GalaxyTarget) -> GalaxyDossier:
        """Find connections between people results and network data."""
        C.section("CROSS-REFERENCE ANALYSIS")
        C.info("Correlating people data with network intelligence...")
        C.p("")

        xrefs = []

        if target.domain and target.email:
            email_domain = target.email.split("@")[-1] if "@" in target.email else ""
            if email_domain and email_domain.lower() == target.domain.lower():
                xrefs.append({
                    "type": "email_domain_match",
                    "description": f"Email domain matches target domain: {email_domain}",
                    "confidence": "high",
                    "entities": [target.email, target.domain],
                })
                C.ok(f"{C.GRN}Email domain matches target: {email_domain}{C.R}")

        if target.domain and target.employer:
            xrefs.append({
                "type": "employer_domain_link",
                "description": f"Domain {target.domain} potentially linked to employer {target.employer}",
                "confidence": "medium",
                "entities": [target.domain, target.employer],
            })
            C.ok(f"Employer-domain link: {target.employer} <-> {target.domain}")

        whois_org = dossier.whois.get("Registrant Org", "")
        if whois_org and target.employer:
            if target.employer.lower() in whois_org.lower() or whois_org.lower() in target.employer.lower():
                xrefs.append({
                    "type": "whois_employer_match",
                    "description": f"WHOIS registrant org matches employer: {whois_org}",
                    "confidence": "high",
                    "entities": [whois_org, target.employer],
                })
                C.ok(f"{C.GRN}WHOIS registrant matches employer: {whois_org}{C.R}")

        if target.full_name and whois_org:
            xrefs.append({
                "type": "name_whois_association",
                "description": f"Subject {target.full_name} associated with WHOIS org {whois_org}",
                "confidence": "medium",
                "entities": [target.full_name, whois_org],
            })

        social_platforms = set()
        professional_platforms = set()
        for pr in dossier.people_results:
            cat = pr.get("category", "")
            if "Social" in cat:
                social_platforms.add(pr.get("platform", ""))
            if "Professional" in cat:
                professional_platforms.add(pr.get("platform", ""))

        if social_platforms:
            xrefs.append({
                "type": "social_footprint",
                "description": f"Social media presence across {len(social_platforms)} platforms",
                "confidence": "info",
                "entities": list(social_platforms),
            })
            C.ok(f"Social footprint: {len(social_platforms)} platforms identified")

        if professional_platforms:
            xrefs.append({
                "type": "professional_footprint",
                "description": f"Professional presence across {len(professional_platforms)} platforms",
                "confidence": "info",
                "entities": list(professional_platforms),
            })

        if dossier.open_ports:
            web_ports = [p for p in dossier.open_ports if p.get("port") in (80, 443, 8080, 8443)]
            if web_ports:
                xrefs.append({
                    "type": "web_infrastructure",
                    "description": f"Web services detected on {len(web_ports)} ports",
                    "confidence": "high",
                    "entities": [f"port:{p['port']}" for p in web_ports],
                })
                C.ok(f"Web infrastructure detected on {len(web_ports)} ports")

            mail_ports = [p for p in dossier.open_ports if p.get("port") in (25, 110, 143, 465, 587, 993, 995)]
            if mail_ports and target.email:
                xrefs.append({
                    "type": "mail_infrastructure_email",
                    "description": f"Mail services running; target has email on this domain",
                    "confidence": "high",
                    "entities": [target.email] + [f"port:{p['port']}" for p in mail_ports],
                })
                C.ok(f"{C.GRN}Mail infrastructure confirmed with email on domain{C.R}")

        if not xrefs:
            C.warn("No cross-references found with available data")
        else:
            C.p(f"\n  {C.GRN}[+] Found {C.BLD}{len(xrefs)}{C.R}{C.GRN} cross-references{C.R}")

        dossier.cross_references = xrefs
        return dossier


# =============================================================================
#  TIMELINE BUILDER
# =============================================================================

class TimelineBuilder:
    """Build a chronological timeline from gathered intelligence."""

    @staticmethod
    def build(dossier: GalaxyDossier, target: GalaxyTarget) -> GalaxyDossier:
        C.section("TIMELINE CONSTRUCTION")
        C.info("Building intelligence timeline...")
        C.p("")

        events = []

        events.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "Galaxy Recon initiated",
            "source": "system",
            "details": f"Target: {target.full_name or target.domain or 'unknown'}",
        })

        creation = dossier.whois.get("Creation Date", "")
        if creation:
            events.append({
                "timestamp": creation.strip(),
                "event": f"Domain {target.domain} registered",
                "source": "WHOIS",
                "details": f"Registrar: {dossier.whois.get('Registrar', 'unknown')}",
            })
            C.ok(f"Domain registration: {creation.strip()}")

        expiry = dossier.whois.get("Expiration Date", "")
        if expiry:
            events.append({
                "timestamp": expiry.strip(),
                "event": f"Domain {target.domain} expires",
                "source": "WHOIS",
                "details": "Expiration date from WHOIS",
            })
            C.ok(f"Domain expiration: {expiry.strip()}")

        updated = dossier.whois.get("Updated Date", "")
        if updated:
            events.append({
                "timestamp": updated.strip(),
                "event": f"Domain {target.domain} last updated",
                "source": "WHOIS",
                "details": "Last update from WHOIS",
            })

        if dossier.people_count > 0:
            events.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": f"People search completed: {dossier.people_count} platforms queried",
                "source": "People Finder",
                "details": f"Subject: {target.full_name}",
            })

        if dossier.subdomains:
            events.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": f"Subdomain enumeration: {len(dossier.subdomains)} found",
                "source": "Subdomain Scanner",
                "details": ", ".join(s.get("subdomain", "") for s in dossier.subdomains[:5]),
            })

        if dossier.open_ports:
            events.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event": f"Port scan: {len(dossier.open_ports)} open ports",
                "source": "Port Scanner",
                "details": ", ".join(f"{p['port']}/{p['service']}" for p in dossier.open_ports[:10]),
            })

        events.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "Galaxy Recon completed",
            "source": "system",
            "details": f"Cross-references: {len(dossier.cross_references)}",
        })

        for ev in events:
            C.p(f"  {C.DIM}{ev['timestamp'][:19]:<22}{C.R} {C.CYN}{ev['event']}{C.R}")

        C.p(f"\n  {C.GRN}[+] Timeline: {len(events)} events recorded{C.R}")
        dossier.timeline = events
        return dossier


# =============================================================================
#  RELATIONSHIP MAPPER
# =============================================================================

class RelationshipMapper:
    """Map relationships between discovered entities."""

    @staticmethod
    def map_relationships(dossier: GalaxyDossier, target: GalaxyTarget) -> GalaxyDossier:
        C.section("RELATIONSHIP MAPPING")
        C.info("Mapping entity relationships...")
        C.p("")

        rels = []

        if target.full_name and target.domain:
            rels.append({
                "entity_a": target.full_name,
                "entity_b": target.domain,
                "relationship": "associated_domain",
                "confidence": "user_provided",
            })
            C.ok(f"{target.full_name} <--associated_domain--> {target.domain}")

        if target.full_name and target.email:
            rels.append({
                "entity_a": target.full_name,
                "entity_b": target.email,
                "relationship": "uses_email",
                "confidence": "user_provided",
            })
            C.ok(f"{target.full_name} <--uses_email--> {target.email}")

        if target.full_name and target.employer:
            rels.append({
                "entity_a": target.full_name,
                "entity_b": target.employer,
                "relationship": "employed_by",
                "confidence": "user_provided",
            })
            C.ok(f"{target.full_name} <--employed_by--> {target.employer}")

        if target.full_name and target.username:
            rels.append({
                "entity_a": target.full_name,
                "entity_b": target.username,
                "relationship": "uses_handle",
                "confidence": "user_provided",
            })
            C.ok(f"{target.full_name} <--uses_handle--> @{target.username}")

        if target.domain and target.email and "@" in target.email:
            email_domain = target.email.split("@")[1]
            rels.append({
                "entity_a": target.domain,
                "entity_b": email_domain,
                "relationship": "email_hosted_on" if email_domain == target.domain else "email_external",
                "confidence": "derived",
            })

        whois_org = dossier.whois.get("Registrant Org", "")
        if whois_org and target.domain:
            rels.append({
                "entity_a": target.domain,
                "entity_b": whois_org,
                "relationship": "registered_by",
                "confidence": "whois",
            })
            C.ok(f"{target.domain} <--registered_by--> {whois_org}")

        ns_list = dossier.whois.get("Name Servers", "")
        if ns_list and target.domain:
            for ns in ns_list.split(",")[:2]:
                ns = ns.strip()
                if ns:
                    rels.append({
                        "entity_a": target.domain,
                        "entity_b": ns,
                        "relationship": "dns_served_by",
                        "confidence": "dns",
                    })

        for sub in dossier.subdomains[:10]:
            sd = sub.get("subdomain", "")
            if sd:
                rels.append({
                    "entity_a": target.domain,
                    "entity_b": sd,
                    "relationship": "has_subdomain",
                    "confidence": "dns",
                })

        C.p(f"\n  {C.GRN}[+] Mapped {C.BLD}{len(rels)}{C.R}{C.GRN} relationships{C.R}")
        dossier.relationships = rels
        return dossier


# =============================================================================
#  PDF DOSSIER GENERATOR
# =============================================================================

class DossierPDF:
    """Generate a comprehensive PDF report."""

    @staticmethod
    def generate(dossier: GalaxyDossier, target: GalaxyTarget, filepath: str) -> Optional[str]:
        if not HAS_FPDF:
            C.warn("PDF generation requires fpdf2: pip install fpdf2")
            return None

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        pdf.add_page()
        pdf.set_font("Courier", "B", 20)
        pdf.cell(0, 15, "FU PERSON - GALAXY RECON DOSSIER", ln=True, align="C")
        pdf.set_font("Courier", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.utcnow().isoformat()}Z", ln=True, align="C")
        pdf.cell(0, 8, "CONFIDENTIAL - AUTHORIZED USE ONLY", ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("Courier", "B", 14)
        pdf.cell(0, 10, "TARGET SUMMARY", ln=True)
        pdf.set_font("Courier", "", 10)
        fields = [
            ("Name", target.full_name or f"{target.first_name} {target.last_name}"),
            ("Email", target.email), ("Phone", target.phone),
            ("Username", target.username), ("Domain", target.domain),
            ("Location", f"{target.city}, {target.state}" if target.city else target.state),
            ("Employer", target.employer), ("School", target.school),
        ]
        for label, val in fields:
            if val and val.strip():
                pdf.cell(0, 6, f"  {label}: {val}", ln=True)
        pdf.ln(5)

        if dossier.people_results:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, f"PEOPLE SEARCH ({dossier.people_count} platforms)", ln=True)
            pdf.set_font("Courier", "", 8)
            cats = defaultdict(list)
            for pr in dossier.people_results:
                cats[pr.get("category", "Other")].append(pr)
            for cat, items in sorted(cats.items()):
                pdf.set_font("Courier", "B", 10)
                pdf.cell(0, 7, f"  {cat} ({len(items)})", ln=True)
                pdf.set_font("Courier", "", 8)
                for item in items[:15]:
                    platform = item.get("platform", "")
                    url = item.get("url", "")[:90]
                    pdf.cell(0, 5, f"    [{item.get('status', '?')}] {platform}: {url}", ln=True)
            pdf.ln(3)

        if dossier.dns_records:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, "DNS RECORDS", ln=True)
            pdf.set_font("Courier", "", 9)
            for rtype, records in dossier.dns_records.items():
                for rec in records:
                    pdf.cell(0, 5, f"  {rtype:>6}  {rec}", ln=True)
            pdf.ln(3)

        if dossier.subdomains:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, f"SUBDOMAINS ({len(dossier.subdomains)})", ln=True)
            pdf.set_font("Courier", "", 9)
            for sub in dossier.subdomains[:30]:
                pdf.cell(0, 5, f"  {sub.get('subdomain', ''):<40} -> {sub.get('ip', '')}", ln=True)
            pdf.ln(3)

        if dossier.whois:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, "WHOIS", ln=True)
            pdf.set_font("Courier", "", 9)
            for k, v in dossier.whois.items():
                if k != "_raw" and v:
                    pdf.cell(0, 5, f"  {k}: {str(v)[:80]}", ln=True)
            pdf.ln(3)

        if dossier.geoip:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, "GEOIP", ln=True)
            pdf.set_font("Courier", "", 9)
            for k in ["query", "country", "regionName", "city", "isp", "org", "as"]:
                val = dossier.geoip.get(k, "")
                if val:
                    pdf.cell(0, 5, f"  {k}: {val}", ln=True)
            pdf.ln(3)

        if dossier.open_ports:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, f"OPEN PORTS ({len(dossier.open_ports)})", ln=True)
            pdf.set_font("Courier", "", 9)
            for p in dossier.open_ports:
                pdf.cell(0, 5, f"  {p['port']:<8} {p.get('service', 'unknown')}", ln=True)
            pdf.ln(3)

        if dossier.cross_references:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, f"CROSS-REFERENCES ({len(dossier.cross_references)})", ln=True)
            pdf.set_font("Courier", "", 9)
            for xr in dossier.cross_references:
                pdf.cell(0, 5, f"  [{xr['confidence']}] {xr['description']}", ln=True)
            pdf.ln(3)

        if dossier.timeline:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, "TIMELINE", ln=True)
            pdf.set_font("Courier", "", 9)
            for ev in dossier.timeline:
                ts = ev["timestamp"][:19] if ev["timestamp"] else "N/A"
                pdf.cell(0, 5, f"  {ts}  {ev['event']}", ln=True)
            pdf.ln(3)

        if dossier.relationships:
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, f"RELATIONSHIP MAP ({len(dossier.relationships)})", ln=True)
            pdf.set_font("Courier", "", 9)
            for rel in dossier.relationships:
                pdf.cell(0, 5, f"  {rel['entity_a']} --[{rel['relationship']}]--> {rel['entity_b']}", ln=True)

        pdf.output(filepath)
        return filepath


# =============================================================================
#  GALAXY RECON ENGINE
# =============================================================================

class GalaxyReconEngine:
    """Master orchestrator combining all modules."""

    def __init__(self, output_dir: str = "fu_galaxy_output"):
        self.output_dir = output_dir
        self.dossier = GalaxyDossier()

    def run(self, target: GalaxyTarget, skip_ports: bool = False,
            skip_subdomains: bool = False, skip_people: bool = False,
            skip_network: bool = False, verify_urls: bool = False):
        """Execute the full Galaxy Recon pipeline."""

        os.makedirs(self.output_dir, exist_ok=True)
        self.dossier.target = {
            "full_name": target.full_name, "email": target.email,
            "phone": target.phone, "username": target.username,
            "domain": target.domain, "employer": target.employer,
        }
        self.dossier.timestamp = datetime.utcnow().isoformat() + "Z"

        phase_num = 0

        # --- PHASE 1: People Search ---
        if not skip_people and (target.full_name or target.first_name or target.email or target.phone or target.username):
            phase_num += 1
            C.phase(phase_num, "PEOPLE INTELLIGENCE")

            if not HAS_PF:
                C.fail("people_finder module not available. Skipping people search.")
            else:
                query = SearchQuery(
                    full_name=target.full_name,
                    first_name=target.first_name,
                    last_name=target.last_name,
                    email=target.email,
                    phone=target.phone,
                    username=target.username,
                    city=target.city,
                    state=target.state,
                    employer=target.employer,
                    school=target.school,
                )
                C.info("Generating search URLs across 88+ platforms...")
                results = PlatformURLs.generate_all(query)
                self.dossier.people_results = [asdict(r) for r in results]
                self.dossier.people_count = len(results)
                C.ok(f"People search: {len(results)} platform URLs generated")

                by_cat = defaultdict(int)
                for r in results:
                    by_cat[r.category] += 1
                for cat, count in sorted(by_cat.items()):
                    C.p(f"    {C.DIM}{cat}: {count}{C.R}")

        # --- PHASE 2: Network Recon ---
        if not skip_network and target.domain:
            phase_num += 1
            C.phase(phase_num, "NETWORK RECONNAISSANCE")

            if not HAS_RECON:
                C.fail("osint_recon_suite module not available. Skipping network recon.")
            else:
                engine = OSINTReconEngine(target=target.domain, output_dir=self.output_dir)
                engine.run_all(
                    skip_ports=skip_ports,
                    skip_subdomains=skip_subdomains,
                )
                self.dossier.dns_records = engine.results.get("dns", {})
                self.dossier.subdomains = engine.results.get("subdomains", [])
                whois_data = engine.results.get("whois", {})
                self.dossier.whois = {k: v for k, v in whois_data.items() if k != "_raw"}
                self.dossier.geoip = engine.results.get("geoip", {})
                self.dossier.open_ports = engine.results.get("ports", [])
                self.dossier.threat_links = engine.results.get("threat_intel_links", {})
                C.ok("Network reconnaissance complete")

        # --- PHASE 3: Cross-Reference ---
        phase_num += 1
        C.phase(phase_num, "CROSS-REFERENCE ANALYSIS")
        self.dossier = CrossReferenceEngine.analyze(self.dossier, target)

        # --- PHASE 4: Timeline ---
        phase_num += 1
        C.phase(phase_num, "TIMELINE CONSTRUCTION")
        self.dossier = TimelineBuilder.build(self.dossier, target)

        # --- PHASE 5: Relationship Mapping ---
        phase_num += 1
        C.phase(phase_num, "RELATIONSHIP MAPPING")
        self.dossier = RelationshipMapper.map_relationships(self.dossier, target)

        # --- PHASE 6: Export ---
        phase_num += 1
        C.phase(phase_num, "REPORT GENERATION")
        self._export(target)

        C.p(f"\n  {C.GRN}{C.BLD}{'=' * 60}")
        C.p(f"  {'':>2}GALAXY RECON COMPLETE")
        C.p(f"  {'=' * 60}{C.R}")
        name_disp = target.full_name or target.domain or "unknown"
        C.p(f"  {C.CYN}Target:          {name_disp}{C.R}")
        C.p(f"  {C.CYN}People URLs:     {self.dossier.people_count}{C.R}")
        C.p(f"  {C.CYN}DNS Records:     {sum(len(v) for v in self.dossier.dns_records.values()) if self.dossier.dns_records else 0}{C.R}")
        C.p(f"  {C.CYN}Subdomains:      {len(self.dossier.subdomains)}{C.R}")
        C.p(f"  {C.CYN}Open Ports:      {len(self.dossier.open_ports)}{C.R}")
        C.p(f"  {C.CYN}Cross-Refs:      {len(self.dossier.cross_references)}{C.R}")
        C.p(f"  {C.CYN}Relationships:   {len(self.dossier.relationships)}{C.R}")
        C.p(f"  {C.CYN}Timeline Events: {len(self.dossier.timeline)}{C.R}")
        C.p(f"  {C.GRN}{C.BLD}{'=' * 60}{C.R}\n")

    def _export(self, target: GalaxyTarget):
        """Export full dossier to JSON and PDF."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name_part = (target.full_name or target.domain or "unknown").replace(" ", "_").lower()
        name_part = re.sub(r"[^a-zA-Z0-9_.-]", "", name_part)
        base = os.path.join(self.output_dir, f"galaxy_{name_part}_{ts}")

        json_path = f"{base}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self.dossier), f, indent=2, ensure_ascii=False, default=str)
        C.ok(f"JSON dossier: {C.BLD}{json_path}{C.R}")

        pdf_path = f"{base}.pdf"
        result = DossierPDF.generate(self.dossier, target, pdf_path)
        if result:
            C.ok(f"PDF dossier:  {C.BLD}{pdf_path}{C.R}")


# =============================================================================
#  INTERACTIVE MODE
# =============================================================================

def interactive_mode() -> GalaxyTarget:
    """Guided interview to build a target profile."""
    C.p(f"\n  {C.MAG}{C.BLD}┌──────────────────────────────────────────────────┐{C.R}")
    C.p(f"  {C.MAG}{C.BLD}│     GALAXY RECON - INTERACTIVE WIZARD            │{C.R}")
    C.p(f"  {C.MAG}{C.BLD}│     Press ENTER to skip any field                │{C.R}")
    C.p(f"  {C.MAG}{C.BLD}└──────────────────────────────────────────────────┘{C.R}\n")

    def ask(prompt, default=""):
        try:
            val = input(f"  {C.GRN}>{C.R} {prompt}: ").strip()
            return val if val else default
        except (EOFError, KeyboardInterrupt):
            return default

    full = ask("Full name")
    first, last = "", ""
    if not full:
        first = ask("First name")
        last = ask("Last name")
    else:
        parts = full.split()
        first = parts[0] if parts else ""
        last = parts[-1] if len(parts) > 1 else ""

    return GalaxyTarget(
        full_name=full,
        first_name=first,
        last_name=last,
        email=ask("Email"),
        phone=ask("Phone"),
        username=ask("Username / handle"),
        city=ask("City"),
        state=ask("State (2-letter)"),
        domain=ask("Domain (e.g. company.com)"),
        employer=ask("Employer"),
        school=ask("School"),
    )


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def main():
    C.p(BANNER)
    C.p(DISCLAIMER)

    parser = argparse.ArgumentParser(
        prog="galaxy_recon_suite",
        description=f"{C.MAG}FU PERSON :: Galaxy Recon Suite v2.0 -- Deep Intelligence Aggregator{C.R}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        {C.CYN}Examples:{C.R}
          python galaxy_recon_suite.py -i
          python galaxy_recon_suite.py -n "John Doe" -d example.com
          python galaxy_recon_suite.py -n "Jane Smith" -e jane@co.com -d co.com --skip-ports
          python galaxy_recon_suite.py -d example.com --skip-people
        """),
    )

    parser.add_argument("-n", "--name", help="Full name of target")
    parser.add_argument("--first", help="First name")
    parser.add_argument("--last", help="Last name")
    parser.add_argument("-e", "--email", help="Email address")
    parser.add_argument("-p", "--phone", help="Phone number")
    parser.add_argument("-u", "--username", help="Username / handle")
    parser.add_argument("-d", "--domain", help="Domain to investigate")
    parser.add_argument("--city", help="City")
    parser.add_argument("--state", help="State (2-letter code)")
    parser.add_argument("--employer", help="Employer / company")
    parser.add_argument("--school", help="School")
    parser.add_argument("-o", "--output", default="fu_galaxy_output", help="Output directory")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive guided mode")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain brute-force")
    parser.add_argument("--skip-people", action="store_true", help="Skip people search")
    parser.add_argument("--skip-network", action="store_true", help="Skip network recon")
    parser.add_argument("--verify", action="store_true", help="Verify URLs with HTTP HEAD")

    args = parser.parse_args()

    if args.interactive:
        target = interactive_mode()
    elif args.name or args.domain or args.email or args.username:
        first, last = "", ""
        if args.name:
            parts = args.name.split()
            first = parts[0] if parts else ""
            last = parts[-1] if len(parts) > 1 else ""
        target = GalaxyTarget(
            full_name=args.name or "",
            first_name=args.first or first,
            last_name=args.last or last,
            email=args.email or "",
            phone=args.phone or "",
            username=args.username or "",
            city=args.city or "",
            state=args.state or "",
            domain=args.domain or "",
            employer=args.employer or "",
            school=args.school or "",
        )
    else:
        parser.print_help()
        C.p(f"\n  {C.YLW}[!] Provide target info or use -i for interactive mode.{C.R}\n")
        sys.exit(0)

    engine = GalaxyReconEngine(output_dir=args.output)
    engine.run(
        target,
        skip_ports=args.skip_ports,
        skip_subdomains=args.skip_subdomains,
        skip_people=args.skip_people,
        skip_network=args.skip_network,
        verify_urls=args.verify,
    )


if __name__ == "__main__":
    main()
