#!/usr/bin/env python3
"""
FLLC - GALAXY RECONNAISSANCE SUITE v4.1
===============================================

FULL-AUTO DEEP SPACE INTELLIGENCE GATHERING PLATFORM
Just provide a NAME -- every single category is searched automatically.
If you don't know it, we find it.

Vehicles, Property, Employment, Education, Relatives, Court, Voter,
Social Media, Breach Data, Forum Posts, News -- ALL auto-discovered.

LEGAL WARNING - AUTHORIZED USE ONLY
All data gathered is from publicly accessible sources.
"""

import requests
import socket
import json
import sys
import os
import re
import time
import threading
from datetime import datetime, date
from urllib.parse import urljoin, urlparse, quote, urlencode
from bs4 import BeautifulSoup
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import base64
import random
import traceback

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
#  COLORS
# ============================================================================

class C:
    CYAN   = '\033[96m';  GREEN  = '\033[92m';  PURPLE = '\033[95m'
    PINK   = '\033[91m';  YELLOW = '\033[93m';  BLUE   = '\033[94m'
    WHITE  = '\033[97m';  NEBULA = '\033[35m';  COMET  = '\033[36m'
    BOLD   = '\033[1m';   UNDER  = '\033[4m';   DIM    = '\033[2m'
    R      = '\033[0m'

    @staticmethod
    def s(text):
        try:
            print(text)
        except UnicodeEncodeError:
            print(re.sub(r'\033\[[0-9;]*m', '', str(text)))


# ============================================================================
#  PERSON PROFILE
# ============================================================================

class PersonProfile:
    def __init__(self):
        # ---- interview data ----
        self.full_name = ''
        self.first_name = ''
        self.middle_name = ''
        self.last_name = ''
        self.dob = ''
        self.age_approx = ''
        self.current_state = ''
        self.current_city = ''
        self.current_zip = ''
        self.previous_states = []
        self.previous_cities = []
        self.known_email = ''
        self.known_phone = ''
        self.employer = ''
        self.job_title = ''
        self.school = ''
        self.known_relatives = []
        self.known_usernames = []
        self.known_domain = ''
        self.vehicle_info = ''
        self.ssn_last4 = ''
        self.gender = ''
        self.ethnicity = ''
        self.nickname = ''
        self.maiden_name = ''
        self.military = ''
        self.known_address = ''
        self.interests = ''
        self.extra_notes = ''

        # ---- discovered data ----
        self.discovered_emails = []
        self.discovered_phones = []
        self.discovered_addresses = []
        self.discovered_relatives = []
        self.discovered_social = {}
        self.discovered_usernames = []
        self.discovered_employers = []
        self.discovered_schools = []
        self.discovered_age = ''
        self.discovered_dob = ''
        self.discovered_gender = ''
        self.discovered_properties = []
        self.discovered_court = []
        self.discovered_news = []
        self.discovered_vehicles = []
        self.discovered_photos = []
        self.discovered_domains = []
        self.discovered_ips = []
        self.discovered_forum_posts = []
        self.discovered_blog_mentions = []
        self.discovered_public_records = []
        self.discovered_voter_info = {}
        self.discovered_business_records = []
        self.discovered_amazon_wishlists = []
        self.discovered_registries = []
        self.discovered_licenses = []
        self.discovered_marriages = []
        self.discovered_obituary_mentions = []

        # ---- breach / credential data ----
        self.breaches = []
        self.partial_passwords = []
        self.hackcheck_list = []
        self.paste_dumps = []

        # ---- domain recon data ----
        self.domain_dns = {}
        self.domain_subdomains = []
        self.domain_ports = []
        self.domain_tech = []
        self.domain_certs = []
        self.domain_whois = {}
        self.domain_historical = []
        self.domain_directories = []

        # ---- raw log ----
        self.findings = []

    def all_emails(self):
        s = set()
        if self.known_email:
            s.add(self.known_email.lower().strip())
        for e in self.discovered_emails:
            s.add(e.lower().strip())
        return sorted(s)

    def all_usernames(self):
        s = set()
        for u in self.known_usernames + self.discovered_usernames:
            s.add(u.strip())
        return sorted(s)

    def all_phones(self):
        s = set()
        if self.known_phone:
            s.add(self.known_phone.strip())
        for p in self.discovered_phones:
            s.add(p.strip())
        return sorted(s)

    def all_relatives(self):
        return sorted(set(self.known_relatives + self.discovered_relatives))

    def to_dict(self):
        return {
            'subject': {
                'full_name': self.full_name,
                'first_name': self.first_name,
                'middle_name': self.middle_name,
                'last_name': self.last_name,
                'nickname': self.nickname,
                'maiden_name': self.maiden_name,
                'gender': self.discovered_gender or self.gender,
                'date_of_birth': self.discovered_dob or self.dob,
                'age': self.discovered_age or self.age_approx,
                'ssn_last_4': self.ssn_last4,
                'military_service': self.military,
            },
            'contact': {
                'emails': self.all_emails(),
                'phones': self.all_phones(),
                'current_address': self.known_address or (
                    f"{self.current_city}, {self.current_state} {self.current_zip}".strip(', ')
                ),
                'all_addresses': self.discovered_addresses,
            },
            'location_history': {
                'current_city': self.current_city,
                'current_state': self.current_state,
                'current_zip': self.current_zip,
                'previous_states': self.previous_states,
                'previous_cities': self.previous_cities,
            },
            'employment': {
                'current_employer': self.employer,
                'job_title': self.job_title,
                'all_employers': sorted(set(
                    ([self.employer] if self.employer else []) + self.discovered_employers
                )),
            },
            'education': {
                'known_school': self.school,
                'all_schools': sorted(set(
                    ([self.school] if self.school else []) + self.discovered_schools
                )),
            },
            'family': {
                'relatives': self.all_relatives(),
                'marriages': self.discovered_marriages,
                'obituary_mentions': self.discovered_obituary_mentions,
            },
            'social_media': self.discovered_social,
            'usernames': self.all_usernames(),
            'vehicles': self.discovered_vehicles or ([self.vehicle_info] if self.vehicle_info else []),
            'licenses': self.discovered_licenses,
            'properties': self.discovered_properties,
            'court_records': self.discovered_court,
            'business_records': self.discovered_business_records,
            'voter_registration': self.discovered_voter_info,
            'news_mentions': self.discovered_news,
            'forum_posts': self.discovered_forum_posts,
            'blog_mentions': self.discovered_blog_mentions,
            'public_records': self.discovered_public_records,
            'photo_urls': self.discovered_photos,
            'associated_domains': self.discovered_domains,
            'associated_ips': self.discovered_ips,
            'breach_exposure': {
                'breaches': self.breaches,
                'partial_passwords': self.partial_passwords,
                'paste_dumps': self.paste_dumps,
                'hackcheck_lookup_list': self.hackcheck_list,
            },
            'domain_recon': {
                'dns_records': self.domain_dns,
                'subdomains': self.domain_subdomains,
                'open_ports': self.domain_ports,
                'technologies': self.domain_tech,
                'ssl_certificates': self.domain_certs,
                'whois': self.domain_whois,
                'historical_snapshots': self.domain_historical,
                'exposed_directories': self.domain_directories,
            },
            'interests': self.interests,
            'extra_notes': self.extra_notes,
            'raw_findings_count': len(self.findings),
        }


# ============================================================================
#  MAIN SUITE
# ============================================================================

class GalaxyReconSuite:

    HACKCHECK_API_KEY = ''   # drop your key here if you have one

    def __init__(self):
        self.p = PersonProfile()
        self.s = requests.Session()
        self.s.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/122.0.0.0 Safari/537.36'),
            'Accept': 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.s.verify = False

    # ------------------------------------------------------------------ #
    #  BANNER                                                             #
    # ------------------------------------------------------------------ #

    def print_banner(self):
        C.s(f"""
{C.NEBULA}{C.BOLD}
    ================================================================
    =                                                              =
    =   *** GALAXY RECONNAISSANCE SUITE v4.1 ***                   =
    =                                                              =
    =   FULL-AUTO DEEP SPACE INTELLIGENCE                          =
    =   Just give a NAME -- we find EVERYTHING else.               =
    =                                                              =
    =   * 10 People-Search Engines     * Vehicle/VIN Lookup        =
    =   * 24 Social Media Platforms    * Property & Deed Records   =
    =   * Employment Auto-Discovery    * Education Auto-Discovery  =
    =   * Court Records & Arrests      * Voter Registration        =
    =   * Obituary & Marriage Records  * Breach/Password Check     =
    =   * Reddit/Forum Scan            * Reverse Phone/Email       =
    =                                                              =
    ================================================================{C.R}

{C.PINK}{C.BOLD}[!] LEGAL WARNING [!]{C.R}
{C.YELLOW}All data is gathered from publicly accessible sources.
Only use on targets you are authorized to investigate.{C.R}
""")

    # ------------------------------------------------------------------ #
    #  LOGGING                                                            #
    # ------------------------------------------------------------------ #

    def _log(self, cat, sev, msg, data=None):
        ico = {'CRITICAL': f'{C.PINK}[!!!]', 'HIGH': f'{C.YELLOW}[!!]',
               'MEDIUM': f'{C.CYAN}[+]', 'LOW': f'{C.GREEN}[-]', 'INFO': f'{C.BLUE}[*]'}
        col = {'CRITICAL': C.PINK, 'HIGH': C.YELLOW, 'MEDIUM': C.CYAN,
               'LOW': C.GREEN, 'INFO': C.BLUE}
        C.s(f"  {col.get(sev, C.BLUE)}{ico.get(sev, '[*]')} {sev} | {cat}: {msg}{C.R}")
        if data:
            if isinstance(data, dict):
                for k, v in list(data.items())[:6]:
                    C.s(f"       {C.NEBULA}->{C.R} {k}: {str(v)[:150]}")
            elif isinstance(data, list):
                for item in data[:5]:
                    C.s(f"       {C.NEBULA}->{C.R} {str(item)[:150]}")
            else:
                C.s(f"       {C.NEBULA}->{C.R} {str(data)[:250]}")
        self.p.findings.append({
            'category': cat, 'severity': sev, 'message': msg,
            'data': str(data)[:500] if data else None,
            'time': datetime.now().isoformat()
        })

    def _phase(self, title):
        C.s(f"\n{C.NEBULA}{C.BOLD}{'='*64}")
        C.s(f"  *** {title} ***")
        C.s(f"{'='*64}{C.R}\n")

    # ================================================================== #
    #  INTERVIEW  (25 questions)                                          #
    # ================================================================== #

    def _ask(self, num, total, q, required=False, multi=False):
        C.s(f"\n{C.COMET}--- Question {num}/{total} ---{C.R}")
        C.s(f"{C.CYAN}{C.BOLD}  {q}{C.R}")
        if multi:
            C.s(f"{C.DIM}  (Comma-separated, or ENTER = IDK){C.R}")
        elif required:
            C.s(f"{C.DIM}  (Required){C.R}")
        else:
            C.s(f"{C.DIM}  (ENTER = IDK -- we will try to find it automatically){C.R}")
        while True:
            try:
                a = input(f"{C.GREEN}  >>> {C.R}").strip()
            except (EOFError, KeyboardInterrupt):
                a = ''
            if required and not a:
                C.s(f"{C.PINK}  Required -- please enter a value.{C.R}")
                continue
            break
        if multi and a:
            return [x.strip() for x in a.split(',') if x.strip()]
        return a

    def interactive_interview(self):
        total = 25
        p = self.p

        C.s(f"""
{C.PURPLE}{C.BOLD}================================================================
=          DEEP SPACE INTELLIGENCE INTERVIEW                   =
=                                                              =
=   Just press ENTER on anything you don't know.               =
=   We will AUTO-DISCOVER everything from the name alone.      =
=   The more you give, the faster and more accurate we are.    =
================================================================{C.R}""")

        # 1
        name = self._ask(1, total, "FULL NAME of the person?", required=True)
        p.full_name = name
        pts = name.split()
        p.first_name = pts[0] if pts else ''
        p.last_name = pts[-1] if len(pts) > 1 else ''

        # 2
        p.middle_name = self._ask(2, total, "MIDDLE NAME? (helps narrow down)")
        if p.middle_name and len(pts) <= 2:
            p.full_name = f"{p.first_name} {p.middle_name} {p.last_name}" if p.last_name else f"{p.first_name} {p.middle_name}"

        # 3
        p.nickname = self._ask(3, total, "Any NICKNAME or ALIAS?")

        # 4
        p.maiden_name = self._ask(4, total, "MAIDEN NAME (if applicable)?")

        # 5
        dob = self._ask(5, total, "DATE OF BIRTH or approximate AGE? (e.g. 03/15/1990 or '34')")
        if dob:
            if any(c in dob for c in ['/', '-']):
                p.dob = dob
            else:
                p.age_approx = dob

        # 6
        p.gender = self._ask(6, total, "GENDER? (male/female/other)")

        # 7
        p.current_state = self._ask(7, total, "Current STATE? (e.g. Montana, WA)")

        # 8
        p.current_city = self._ask(8, total, "Current CITY?")

        # 9
        p.current_zip = self._ask(9, total, "Current ZIP CODE?")

        # 10
        p.known_address = self._ask(10, total, "Full current ADDRESS if you know it?")

        # 11
        prev_st = self._ask(11, total, "PREVIOUS STATES they lived in?", multi=True)
        p.previous_states = prev_st if isinstance(prev_st, list) else ([prev_st] if prev_st else [])

        # 12
        prev_ci = self._ask(12, total, "PREVIOUS CITIES?", multi=True)
        p.previous_cities = prev_ci if isinstance(prev_ci, list) else ([prev_ci] if prev_ci else [])

        # 13
        p.known_email = self._ask(13, total, "Known EMAIL ADDRESS?")

        # 14
        p.known_phone = self._ask(14, total, "Known PHONE NUMBER?")

        # 15
        p.employer = self._ask(15, total, "Current or past EMPLOYER?")

        # 16
        p.job_title = self._ask(16, total, "JOB TITLE or occupation?")

        # 17
        p.school = self._ask(17, total, "SCHOOL or UNIVERSITY?")

        # 18
        rels = self._ask(18, total, "Names of RELATIVES?", multi=True)
        p.known_relatives = rels if isinstance(rels, list) else ([rels] if rels else [])

        # 19
        unames = self._ask(19, total, "Known SOCIAL MEDIA USERNAMES? (e.g. pear.stone)")
        if unames:
            p.known_usernames = [u.strip() for u in unames.replace(',', ' ').split() if u.strip()]

        # 20
        p.known_domain = self._ask(20, total, "Any WEBSITE or DOMAIN associated with them?")

        # 21
        p.vehicle_info = self._ask(21, total, "VEHICLE info? (make, model, plate, color)")

        # 22
        p.ssn_last4 = self._ask(22, total, "Last 4 digits of SSN? (for record matching)")

        # 23
        p.military = self._ask(23, total, "MILITARY service info?")

        # 24
        p.interests = self._ask(24, total, "Known INTERESTS or HOBBIES?")

        # 25
        p.extra_notes = self._ask(25, total, "ANYTHING ELSE that could help?")

        # Confirm
        self._print_briefing()
        C.s(f"\n{C.CYAN}  Does this look correct? (ENTER = yes, 'n' = redo){C.R}")
        try:
            c = input(f"{C.GREEN}  >>> {C.R}").strip()
        except:
            c = ''
        if c.lower() in ('n', 'no'):
            self.p = PersonProfile()
            self.interactive_interview()
            return

        C.s(f"\n{C.GREEN}{C.BOLD}  INTEL LOCKED -- Full auto-discovery engaged across ALL categories...{C.R}\n")

    def _print_briefing(self):
        p = self.p
        C.s(f"""
{C.PURPLE}{C.BOLD}================================================================
=               KNOWN INTEL BRIEFING                           =
================================================================{C.R}""")
        fields = [
            ('Name', p.full_name), ('Middle', p.middle_name), ('Nickname', p.nickname),
            ('Maiden Name', p.maiden_name), ('DOB / Age', p.dob or p.age_approx),
            ('Gender', p.gender), ('State', p.current_state), ('City', p.current_city),
            ('ZIP', p.current_zip), ('Address', p.known_address),
            ('Prev States', ', '.join(p.previous_states) if p.previous_states else ''),
            ('Prev Cities', ', '.join(p.previous_cities) if p.previous_cities else ''),
            ('Email', p.known_email), ('Phone', p.known_phone),
            ('Employer', p.employer), ('Job Title', p.job_title), ('School', p.school),
            ('Relatives', ', '.join(p.known_relatives) if p.known_relatives else ''),
            ('Usernames', ', '.join(p.known_usernames) if p.known_usernames else ''),
            ('Domain', p.known_domain), ('Vehicle', p.vehicle_info),
            ('SSN Last 4', p.ssn_last4), ('Military', p.military),
            ('Interests', p.interests), ('Extra', p.extra_notes),
        ]
        known = 0
        for label, val in fields:
            status = f'{C.GREEN}{val}' if val else f'{C.DIM}[AUTO-DISCOVER]'
            if val:
                known += 1
            C.s(f"{C.CYAN}  {label:<15}: {status}{C.R}")
        auto = len(fields) - known
        C.s(f"\n{C.YELLOW}  {known} fields provided | {auto} fields will be AUTO-DISCOVERED{C.R}")
        C.s(f"{C.PURPLE}================================================================{C.R}")

    # ================================================================== #
    #  HELPERS                                                             #
    # ================================================================== #

    def _get_page(self, url, label):
        try:
            r = self.s.get(url, timeout=15)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup, soup.get_text(separator=' ', strip=True)
            else:
                self._log('HTTP', 'LOW', f'{label}: HTTP {r.status_code}')
        except Exception as e:
            self._log('HTTP', 'LOW', f'{label}: {str(e)[:60]}')
        return None, None

    def _google_dork(self, query, label='DORK', max_results=5):
        """Run a Google search, return list of (title, url_hint) tuples."""
        results = []
        try:
            r = self.s.get(f"https://www.google.com/search?q={quote(query)}&num={max_results}", timeout=12)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for h3 in soup.find_all('h3')[:max_results]:
                    title = h3.get_text(strip=True)
                    if title:
                        results.append(title)
            elif r.status_code == 429:
                self._log(label, 'LOW', 'Google rate-limited, pausing...')
                time.sleep(5)
        except:
            pass
        return results

    def _extract_data_from_html(self, soup, source, raw_text=None):
        """Universal extractor -- pulls phones, addresses, emails, age, DOB, relatives,
        employers, schools, vehicles from any page."""
        p = self.p
        text = raw_text or soup.get_text(separator=' ', strip=True)

        # PHONES
        for m in re.finditer(r'(?<!\d)(?:\+?1[-.\s]?)?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})(?!\d)', text):
            phone = f"({m.group(1)}) {m.group(2)}-{m.group(3)}"
            raw = m.group(1) + m.group(2) + m.group(3)
            if raw not in ''.join(p.discovered_phones) and len(raw) == 10:
                p.discovered_phones.append(phone)
                self._log('PHONE', 'HIGH', f'Phone ({source}): {phone}')

        # EMAILS
        for em in re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', text):
            if em.lower() not in [e.lower() for e in p.discovered_emails + [p.known_email or '']]:
                p.discovered_emails.append(em)
                self._log('EMAIL', 'HIGH', f'Email ({source}): {em}')

        # ADDRESSES
        addr_re = (
            r'(\d{1,6}\s+[\w\s]{2,40}'
            r'(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Rd|Road|Ln|Lane|Way|Ct|Court'
            r'|Pl|Place|Cir|Circle|Pkwy|Parkway|Ter|Terrace|Loop|Hwy|Highway|Trl|Trail)'
            r'[.,]?\s*(?:#\s?\w+|Apt\.?\s?\w+|Suite\s?\w+|Unit\s?\w+)?'
            r'[,\s]+[A-Z][a-z]+(?:\s[A-Z][a-z]+)?'
            r'[,\s]+[A-Z]{2}\s+\d{5}(?:-\d{4})?)'
        )
        for m in re.finditer(addr_re, text, re.IGNORECASE):
            addr = ' '.join(m.group(1).split())
            if addr not in p.discovered_addresses:
                p.discovered_addresses.append(addr)
                self._log('ADDRESS', 'HIGH', f'Address ({source}): {addr}')

        # AGE
        for m in re.finditer(r'(?:age|aged?)[:\s]+(\d{1,3})', text, re.IGNORECASE):
            if not p.discovered_age:
                p.discovered_age = m.group(1)
                self._log('AGE', 'MEDIUM', f'Age ({source}): {m.group(1)}')

        # DOB
        for m in re.finditer(r'(?:born|birth|dob|date of birth)[:\s]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text, re.IGNORECASE):
            if not p.discovered_dob:
                p.discovered_dob = m.group(1)
                self._log('DOB', 'HIGH', f'DOB ({source}): {m.group(1)}')

        # RELATIVES
        for m in re.finditer(r'(?:relat(?:ive|ed)|associat(?:e|ed)|family|also known|spouse|husband|wife|parent|child|sibling|brother|sister|son|daughter)[:\s]+((?:[A-Z][a-z]+\s+[A-Z][a-z]+[,\s]*)+)', text):
            for name in re.findall(r'([A-Z][a-z]+\s+[A-Z][a-z]+)', m.group(1)):
                if name.lower() != p.full_name.lower() and name not in p.discovered_relatives:
                    p.discovered_relatives.append(name)
                    self._log('RELATIVE', 'MEDIUM', f'Relative ({source}): {name}')

        # EMPLOYMENT (extract from context)
        emp_patterns = [
            r'(?:works?\s+(?:at|for)|employed\s+(?:at|by)|employer)[:\s]+([A-Z][\w\s&,.-]{2,40}?)(?:\s*[,.]|\s+(?:as|in|since))',
            r'(?:company|organization|firm)[:\s]+([A-Z][\w\s&,.-]{2,40}?)(?:\s*[,.])',
        ]
        for pat in emp_patterns:
            for m in re.finditer(pat, text):
                emp = m.group(1).strip().rstrip(',.')
                if emp and len(emp) > 2 and emp not in p.discovered_employers:
                    p.discovered_employers.append(emp)
                    self._log('EMPLOYER', 'MEDIUM', f'Employer ({source}): {emp}')

        # JOB TITLE
        title_patterns = [
            r'(?:title|position|role|occupation)[:\s]+([A-Z][\w\s]{2,30}?)(?:\s*[,.])',
        ]
        for pat in title_patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                title = m.group(1).strip()
                if not p.job_title and title:
                    p.job_title = title
                    self._log('JOB', 'MEDIUM', f'Job ({source}): {title}')

        # EDUCATION
        edu_patterns = [
            r'(?:school|university|college|attended|graduated|alumni)[:\s]+([A-Z][\w\s&,.-]{3,50}?)(?:\s*[,.]|\s+(?:in|class))',
        ]
        for pat in edu_patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                sch = m.group(1).strip().rstrip(',.')
                if sch and len(sch) > 3 and sch not in p.discovered_schools:
                    p.discovered_schools.append(sch)
                    self._log('SCHOOL', 'MEDIUM', f'School ({source}): {sch}')

        # GENDER
        if not p.discovered_gender and not p.gender:
            if re.search(r'\b(?:his|he|him|mr\.?)\b', text[:2000], re.IGNORECASE):
                p.discovered_gender = 'male'
            elif re.search(r'\b(?:her|she|ms\.?|mrs\.?)\b', text[:2000], re.IGNORECASE):
                p.discovered_gender = 'female'

    # ================================================================== #
    #  SMART SEARCH -- FULLY AUTOMATIC                                     #
    # ================================================================== #

    def smart_search(self):
        p = self.p

        self._phase("PHASE 1: PEOPLE SEARCH ENGINES (10 sites)")
        self._search_truepeoplesearch()
        self._search_fastpeoplesearch()
        self._search_thatsthem()
        self._search_whitepages()
        self._search_spokeo()
        self._search_beenverified()
        self._search_nuwber()
        self._search_radaris()
        self._search_usphonebook()
        self._search_cyberbackground()

        self._phase("PHASE 2: REVERSE LOOKUPS (use found data to find more)")
        self._reverse_phone_lookups()
        self._reverse_email_lookups()
        self._reverse_address_lookups()

        self._phase("PHASE 3: SOCIAL MEDIA DEEP SCAN (24+ platforms)")
        self._social_media_scan()
        self._username_enumeration()
        self._gravatar_lookup()

        self._phase("PHASE 4: EMAIL DISCOVERY & VERIFICATION")
        self._generate_emails()
        self._verify_emails()

        self._phase("PHASE 5: AUTO-DISCOVER VEHICLES & PROPERTY")
        self._auto_vehicle_search()
        self._auto_property_search()

        self._phase("PHASE 6: AUTO-DISCOVER EMPLOYMENT & EDUCATION")
        self._auto_employment_search()
        self._auto_education_search()

        self._phase("PHASE 7: RELATIVES, MARRIAGES, OBITUARIES")
        self._auto_relatives_search()
        self._auto_marriage_search()
        self._auto_obituary_search()

        self._phase("PHASE 8: COURT, VOTER, BUSINESS, SEC")
        self._court_listener_search()
        self._auto_arrest_search()
        self._voter_search()
        self._business_search()
        self._sec_edgar_search()
        self._auto_license_search()

        self._phase("PHASE 9: FORUM, REDDIT & ARCHIVE SCAN")
        self._reddit_search()
        self._archive_org_search()
        self._google_cache_search()
        self._paste_search()

        self._phase("PHASE 10: GOOGLE DORKING & NEWS")
        self._google_dork_deep()
        self._news_search()
        self._image_search()

        # Domain recon -- auto-discover from found domains too
        domains_to_check = []
        if p.known_domain:
            domains_to_check.append(p.known_domain)
        for d in p.discovered_domains[:2]:
            if '.' in d and d not in domains_to_check:
                domains_to_check.append(d)
        if domains_to_check:
            self._phase("PHASE 11: DOMAIN RECONNAISSANCE")
            for dom in domains_to_check[:2]:
                self._domain_recon(dom)

        self._phase("PHASE 12: CREDENTIAL EXPOSURE & BREACH CHECK")
        self._credential_exposure_check()

        self._phase("PHASE 13: FINAL CROSS-REFERENCE PASS")
        self._cross_reference_pass()

    # ================================================================== #
    #  PEOPLE SEARCH SITES                                                 #
    # ================================================================== #

    def _search_truepeoplesearch(self):
        self._log('RECORDS', 'INFO', 'TruePeopleSearch...')
        p = self.p
        url = f"https://www.truepeoplesearch.com/results?name={quote(p.full_name)}"
        if p.current_city and p.current_state:
            url += f"&citystatezip={quote(f'{p.current_city}, {p.current_state}')}"
        elif p.current_state:
            url += f"&citystatezip={quote(p.current_state)}"
        soup, text = self._get_page(url, 'TruePeopleSearch')
        if soup:
            self._extract_data_from_html(soup, 'TruePeopleSearch', text)

    def _search_fastpeoplesearch(self):
        self._log('RECORDS', 'INFO', 'FastPeopleSearch...')
        p = self.p
        slug = p.full_name.lower().replace(' ', '-')
        url = f"https://www.fastpeoplesearch.com/name/{slug}"
        if p.current_state:
            url += f"_{p.current_state.strip().lower().replace(' ', '-')}"
        soup, text = self._get_page(url, 'FastPeopleSearch')
        if soup:
            self._extract_data_from_html(soup, 'FastPeopleSearch', text)

    def _search_thatsthem(self):
        self._log('RECORDS', 'INFO', 'ThatsThem...')
        p = self.p
        url = f"https://thatsthem.com/name/{quote(p.first_name)}-{quote(p.last_name)}"
        if p.current_city and p.current_state:
            url += f"/{quote(p.current_city.replace(' ', '-'))}-{quote(p.current_state)}"
        soup, text = self._get_page(url, 'ThatsThem')
        if soup:
            self._extract_data_from_html(soup, 'ThatsThem', text)

    def _search_whitepages(self):
        self._log('RECORDS', 'INFO', 'Whitepages...')
        p = self.p
        url = f"https://www.whitepages.com/name/{quote(p.first_name)}-{quote(p.last_name)}"
        if p.current_state:
            url += f"/{quote(p.current_state.strip())}"
        soup, text = self._get_page(url, 'Whitepages')
        if soup:
            self._extract_data_from_html(soup, 'Whitepages', text)

    def _search_spokeo(self):
        self._log('RECORDS', 'INFO', 'Spokeo...')
        p = self.p
        slug = f"{p.first_name}-{p.last_name}".lower()
        url = f"https://www.spokeo.com/{slug}"
        if p.current_state:
            url += f"/{p.current_state.strip().title().replace(' ', '-')}"
        soup, text = self._get_page(url, 'Spokeo')
        if soup:
            self._extract_data_from_html(soup, 'Spokeo', text)

    def _search_beenverified(self):
        self._log('RECORDS', 'INFO', 'BeenVerified...')
        p = self.p
        url = f"https://www.beenverified.com/people/{p.first_name.lower()}-{p.last_name.lower()}/"
        if p.current_state:
            url += f"?state={quote(p.current_state.strip())}"
        soup, text = self._get_page(url, 'BeenVerified')
        if soup:
            self._extract_data_from_html(soup, 'BeenVerified', text)

    def _search_nuwber(self):
        self._log('RECORDS', 'INFO', 'Nuwber...')
        p = self.p
        url = f"https://nuwber.com/search?name={quote(p.full_name)}"
        if p.current_state:
            url += f"&state={quote(p.current_state)}"
        soup, text = self._get_page(url, 'Nuwber')
        if soup:
            self._extract_data_from_html(soup, 'Nuwber', text)

    def _search_radaris(self):
        self._log('RECORDS', 'INFO', 'Radaris...')
        p = self.p
        url = f"https://radaris.com/p/{quote(p.first_name)}/{quote(p.last_name)}/"
        soup, text = self._get_page(url, 'Radaris')
        if soup:
            self._extract_data_from_html(soup, 'Radaris', text)

    def _search_usphonebook(self):
        """Search USPhonebook by name (always) AND by phone (if known)."""
        self._log('RECORDS', 'INFO', 'USPhonebook...')
        p = self.p
        # By name
        slug = p.full_name.lower().replace(' ', '-')
        soup, text = self._get_page(f"https://www.usphonebook.com/name/{slug}", 'USPhonebook-Name')
        if soup:
            self._extract_data_from_html(soup, 'USPhonebook', text)
        # By phone if known
        if p.known_phone:
            digits = re.sub(r'\D', '', p.known_phone)
            soup2, text2 = self._get_page(f"https://www.usphonebook.com/{digits}", 'USPhonebook-Phone')
            if soup2:
                self._extract_data_from_html(soup2, 'USPhonebook', text2)

    def _search_cyberbackground(self):
        self._log('RECORDS', 'INFO', 'CyberBackgroundChecks...')
        p = self.p
        url = f"https://www.cyberbackgroundchecks.com/people/{p.first_name.lower()}-{p.last_name.lower()}"
        if p.current_state:
            url += f"/{p.current_state.strip().lower().replace(' ', '-')}"
        soup, text = self._get_page(url, 'CyberBackgroundChecks')
        if soup:
            self._extract_data_from_html(soup, 'CyberBackgroundChecks', text)

    # ================================================================== #
    #  REVERSE LOOKUPS (use discovered data to find MORE)                  #
    # ================================================================== #

    def _reverse_phone_lookups(self):
        """Take every discovered phone and reverse-search it for more data."""
        p = self.p
        phones = p.all_phones()
        if not phones:
            self._log('REVERSE', 'INFO', 'No phones yet -- skipping reverse phone')
            return
        self._log('REVERSE', 'INFO', f'Reverse-looking up {len(phones)} phone(s)...')
        for phone in phones[:5]:
            digits = re.sub(r'\D', '', phone)
            if len(digits) < 10:
                continue
            # ThatsThem reverse phone
            soup, text = self._get_page(f"https://thatsthem.com/phone/{digits}", f'RevPhone-{digits[:6]}')
            if soup:
                self._extract_data_from_html(soup, f'ReversePhone({digits[-4:]})', text)
            time.sleep(0.3)

    def _reverse_email_lookups(self):
        """Reverse-search discovered emails."""
        p = self.p
        emails = p.all_emails()
        if not emails:
            self._log('REVERSE', 'INFO', 'No emails yet -- skipping reverse email')
            return
        self._log('REVERSE', 'INFO', f'Reverse-looking up {len(emails[:3])} email(s)...')
        for email in emails[:3]:
            soup, text = self._get_page(
                f"https://thatsthem.com/email/{quote(email)}", f'RevEmail-{email[:15]}')
            if soup:
                self._extract_data_from_html(soup, f'ReverseEmail({email})', text)
            time.sleep(0.3)

    def _reverse_address_lookups(self):
        """Reverse-search discovered addresses to find neighbors/co-residents."""
        p = self.p
        addrs = p.discovered_addresses
        if not addrs:
            return
        self._log('REVERSE', 'INFO', f'Reverse-looking up {len(addrs[:2])} address(es)...')
        for addr in addrs[:2]:
            slug = addr.lower().replace(' ', '-').replace(',', '').replace('.', '')[:60]
            soup, text = self._get_page(
                f"https://thatsthem.com/address/{slug}", f'RevAddr-{slug[:20]}')
            if soup:
                self._extract_data_from_html(soup, f'ReverseAddress', text)
            time.sleep(0.3)

    # ================================================================== #
    #  SOCIAL MEDIA (24+ platforms)                                       #
    # ================================================================== #

    def _build_usernames(self):
        p = self.p
        names = set()
        fn, ln = p.first_name.lower(), p.last_name.lower()
        nick = p.nickname.lower() if p.nickname else ''
        mid = p.middle_name.lower() if p.middle_name else ''
        if fn and ln:
            names.update([
                f"{fn}{ln}", f"{fn}.{ln}", f"{fn}_{ln}", f"{fn}-{ln}",
                f"{fn[0]}{ln}", f"{fn}{ln[0]}", f"{ln}{fn}", f"{ln}.{fn}",
                f"{fn}{ln}1", f"{fn}.{ln}1", f"{fn}_{ln}1",
            ])
            if mid:
                names.update([f"{fn}{mid[0]}{ln}", f"{fn}.{mid[0]}.{ln}"])
        if nick:
            names.update([nick, f"{nick}{ln}" if ln else nick, f"{nick}1"])
        for u in p.known_usernames:
            names.add(u.lower())
        return list(names)

    def _social_media_scan(self):
        self._log('SOCIAL', 'INFO', 'Scanning 24+ social platforms...')
        p = self.p
        usernames = self._build_usernames()

        platforms = {
            'Instagram': 'https://www.instagram.com/{}/',
            'Twitter/X': 'https://x.com/{}',
            'GitHub': 'https://github.com/{}',
            'TikTok': 'https://www.tiktok.com/@{}',
            'Reddit': 'https://www.reddit.com/user/{}',
            'Pinterest': 'https://www.pinterest.com/{}/',
            'YouTube': 'https://www.youtube.com/@{}',
            'Medium': 'https://medium.com/@{}',
            'Twitch': 'https://www.twitch.tv/{}',
            'LinkedIn': 'https://www.linkedin.com/in/{}',
            'Facebook': 'https://www.facebook.com/{}',
            'Snapchat': 'https://www.snapchat.com/add/{}',
            'Tumblr': 'https://{}.tumblr.com',
            'SoundCloud': 'https://soundcloud.com/{}',
            'Spotify': 'https://open.spotify.com/user/{}',
            'Flickr': 'https://www.flickr.com/people/{}/',
            'Vimeo': 'https://vimeo.com/{}',
            'DeviantArt': 'https://www.deviantart.com/{}',
            'Steam': 'https://steamcommunity.com/id/{}',
            'Patreon': 'https://www.patreon.com/{}',
            'Keybase': 'https://keybase.io/{}',
            'About.me': 'https://about.me/{}',
            'BitBucket': 'https://bitbucket.org/{}/',
            'HackerNews': 'https://news.ycombinator.com/user?id={}',
        }

        def check(platform, url_t, uname):
            url = url_t.format(uname)
            try:
                r = self.s.get(url, timeout=8, allow_redirects=False)
                if r.status_code == 200:
                    if platform == 'GitHub':
                        if uname.lower() in r.text.lower():
                            return (platform, uname, url)
                    elif platform == 'HackerNews':
                        if 'user:' in r.text.lower():
                            return (platform, uname, url)
                    else:
                        return (platform, uname, url)
                if r.status_code in (301, 302):
                    loc = r.headers.get('Location', '')
                    if uname.lower() in loc.lower():
                        return (platform, uname, url)
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=25) as ex:
            futs = []
            for plat, url_t in platforms.items():
                for u in usernames[:8]:
                    futs.append(ex.submit(check, plat, url_t, u))
            for f in as_completed(futs):
                r = f.result()
                if r:
                    plat, uname, url = r
                    if plat not in p.discovered_social:
                        p.discovered_social[plat] = {'username': uname, 'url': url}
                        if uname not in p.discovered_usernames:
                            p.discovered_usernames.append(uname)
                        self._log('SOCIAL', 'HIGH', f'{plat}: @{uname}', url)

    def _username_enumeration(self):
        p = self.p
        all_u = list(set(self._build_usernames() + p.known_usernames + p.discovered_usernames))
        extra = {
            'Gravatar': 'https://en.gravatar.com/{}',
            'Cash.app': 'https://cash.app/${}',
            'Venmo': 'https://account.venmo.com/u/{}',
            'Linktree': 'https://linktr.ee/{}',
            'Ko-fi': 'https://ko-fi.com/{}',
            'Redbubble': 'https://www.redbubble.com/people/{}',
            'Etsy': 'https://www.etsy.com/shop/{}',
            'Fiverr': 'https://www.fiverr.com/{}',
        }
        for u in all_u[:6]:
            for site, url_t in extra.items():
                try:
                    url = url_t.format(u)
                    r = self.s.get(url, timeout=5, allow_redirects=False)
                    if r.status_code == 200:
                        if site not in p.discovered_social:
                            p.discovered_social[site] = {'username': u, 'url': url}
                            self._log('USERNAME', 'MEDIUM', f'{site}: @{u}', url)
                except:
                    pass

    def _gravatar_lookup(self):
        p = self.p
        for email in p.all_emails()[:5]:
            try:
                h = hashlib.md5(email.lower().strip().encode()).hexdigest()
                url = f"https://en.gravatar.com/{h}.json"
                r = self.s.get(url, timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    entry = data.get('entry', [{}])[0]
                    name = entry.get('displayName', '')
                    loc = entry.get('currentLocation', '')
                    about = entry.get('aboutMe', '')
                    photos = [ph.get('value') for ph in entry.get('photos', [])]
                    accounts = {a.get('shortname'): a.get('url') for a in entry.get('accounts', [])}
                    if name:
                        self._log('GRAVATAR', 'HIGH', f'Gravatar profile for {email}', {
                            'name': name, 'location': loc, 'about': about[:100],
                            'accounts': accounts
                        })
                    for url_a in accounts.values():
                        if url_a:
                            p.discovered_domains.append(url_a)
                    p.discovered_photos.extend(photos)
            except:
                pass

    # ================================================================== #
    #  EMAIL DISCOVERY & VERIFICATION                                     #
    # ================================================================== #

    def _generate_emails(self):
        p = self.p
        fn, ln = p.first_name.lower(), p.last_name.lower()
        if not fn:
            return
        patterns = []
        if ln:
            patterns = [
                f"{fn}.{ln}", f"{fn}{ln}", f"{fn}_{ln}", f"{fn[0]}{ln}",
                f"{fn}{ln[0]}", f"{fn[0]}.{ln}", f"{ln}.{fn}", f"{ln}{fn}",
                f"{ln}{fn[0]}", f"{fn}{ln}1", f"{fn}.{ln}1",
            ]
        else:
            patterns = [fn]
        for u in p.known_usernames + p.discovered_usernames:
            if u.lower() not in patterns:
                patterns.append(u.lower())

        domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                    'icloud.com', 'protonmail.com', 'aol.com', 'live.com', 'me.com']
        if p.known_domain:
            domains.insert(0, p.known_domain)

        for pat in patterns[:15]:
            for dom in domains[:6]:
                e = f"{pat}@{dom}"
                if e.lower() not in [x.lower() for x in p.all_emails()]:
                    p.discovered_emails.append(e)

        self._log('EMAIL', 'INFO', f'Generated {len(p.discovered_emails)} email candidates')

    def _verify_emails(self):
        p = self.p
        verified = 0
        good = []
        for email in p.all_emails()[:25]:
            try:
                r = self.s.get(f"https://emailrep.io/{quote(email)}", timeout=8,
                               headers={'User-Agent': 'Galaxy-Recon/4.1'})
                if r.status_code == 200:
                    d = r.json()
                    refs = d.get('references', 0)
                    det = d.get('details', {})
                    profiles = det.get('profiles', [])
                    breached = det.get('data_breach', False)
                    deliverable = det.get('deliverable', False)
                    if refs > 0 or profiles or deliverable:
                        verified += 1
                        good.append(email)
                        self._log('EMAIL', 'HIGH', f'Verified: {email}', {
                            'reputation': d.get('reputation'), 'references': refs,
                            'profiles': profiles, 'breached': breached
                        })
                elif r.status_code == 429:
                    self._log('EMAIL', 'LOW', 'EmailRep rate-limited, pausing...')
                    time.sleep(3)
            except:
                pass
            time.sleep(0.4)
        if verified:
            self._log('EMAIL', 'HIGH', f'{verified} emails verified total')
        if good:
            p.discovered_emails = good

    # ================================================================== #
    #  AUTO-DISCOVER: VEHICLES                                             #
    # ================================================================== #

    def _auto_vehicle_search(self):
        """Auto-discover vehicles registered to this person via multiple public sources."""
        p = self.p
        self._log('VEHICLE', 'INFO', 'Auto-discovering vehicles (name-based)...')

        # Google dorks for vehicle registrations, VINs, titles
        dorks = [
            f'"{p.full_name}" vehicle registration',
            f'"{p.full_name}" VIN OR "vehicle identification"',
            f'"{p.full_name}" car title OR "motor vehicle"',
            f'"{p.full_name}" site:vehiclehistory.com',
            f'"{p.full_name}" site:carfax.com',
            f'"{p.full_name}" "license plate"',
            f'"{p.full_name}" DMV OR "department of motor vehicles"',
            f'"{p.full_name}" auto insurance',
        ]
        # Add state-specific if we know state
        if p.current_state:
            dorks.append(f'"{p.full_name}" "{p.current_state}" vehicle OR car OR truck')
        for addr in p.discovered_addresses[:2]:
            # Sometimes vehicle records are tied to addresses
            short_addr = addr.split(',')[0].strip()[:30]
            dorks.append(f'"{short_addr}" vehicle registration')

        for dork in dorks[:8]:
            results = self._google_dork(dork, 'VEHICLE', 3)
            for title in results:
                # Extract vehicle makes/models from results
                veh_makes = ['Toyota', 'Honda', 'Ford', 'Chevrolet', 'Chevy', 'Nissan',
                             'BMW', 'Mercedes', 'Audi', 'Hyundai', 'Kia', 'Subaru',
                             'Jeep', 'Dodge', 'Ram', 'GMC', 'Buick', 'Cadillac',
                             'Lexus', 'Acura', 'Infiniti', 'Mazda', 'Volkswagen', 'VW',
                             'Tesla', 'Volvo', 'Porsche', 'Chrysler', 'Lincoln', 'Pontiac']
                for make in veh_makes:
                    if make.lower() in title.lower():
                        # Try to extract year + model
                        year_match = re.search(r'((?:19|20)\d{2})', title)
                        year = year_match.group(1) if year_match else ''
                        entry = f"{year} {make} (from: {title[:50]})"
                        if entry not in p.discovered_vehicles:
                            p.discovered_vehicles.append(entry)
                            self._log('VEHICLE', 'HIGH', f'Vehicle: {entry}')
                # Also extract VINs
                for vin in re.findall(r'\b[A-HJ-NPR-Z0-9]{17}\b', title):
                    entry = f"VIN: {vin}"
                    if entry not in p.discovered_vehicles:
                        p.discovered_vehicles.append(entry)
                        self._log('VEHICLE', 'CRITICAL', f'VIN found: {vin}')
                if title and not any(make.lower() in title.lower() for make in veh_makes):
                    p.discovered_vehicles.append(f"Record: {title[:80]}")
                    self._log('VEHICLE', 'MEDIUM', f'Vehicle record: {title[:60]}')
            time.sleep(0.5)

        # People-search sites often list vehicles -- check ThatsThem
        slug = f"{p.first_name}-{p.last_name}".lower()
        soup, text = self._get_page(f"https://thatsthem.com/name/{slug}", 'ThatsThem-Vehicles')
        if text:
            # Look for vehicle mentions
            for m in re.finditer(r'((?:19|20)\d{2})\s+(\w+)\s+(\w+)', text):
                year, make, model = m.groups()
                for known_make in ['Toyota', 'Honda', 'Ford', 'Chevrolet', 'Nissan', 'BMW',
                                   'Hyundai', 'Kia', 'Subaru', 'Jeep', 'Dodge', 'GMC',
                                   'Tesla', 'Mazda', 'Volkswagen']:
                    if make.lower() == known_make.lower():
                        veh = f"{year} {make} {model}"
                        if veh not in p.discovered_vehicles:
                            p.discovered_vehicles.append(veh)
                            self._log('VEHICLE', 'HIGH', f'Vehicle: {veh}')
                        break

        if not p.discovered_vehicles:
            self._log('VEHICLE', 'INFO', 'No vehicles found in public records')

    # ================================================================== #
    #  AUTO-DISCOVER: PROPERTY & DEED                                      #
    # ================================================================== #

    def _auto_property_search(self):
        """Auto-discover property records, deeds, tax assessor data."""
        p = self.p
        self._log('PROPERTY', 'INFO', 'Auto-discovering property records...')

        dorks = [
            f'"{p.full_name}" property records',
            f'"{p.full_name}" site:zillow.com',
            f'"{p.full_name}" deed OR "property owner"',
            f'"{p.full_name}" "tax assessor" OR "property tax"',
            f'"{p.full_name}" "real estate" owner',
            f'"{p.full_name}" site:realtor.com',
            f'"{p.full_name}" site:trulia.com',
            f'"{p.full_name}" "county records" property',
        ]
        if p.current_state:
            dorks.append(f'"{p.full_name}" "{p.current_state}" property deed')
        for city in ([p.current_city] + p.previous_cities[:2]):
            if city:
                dorks.append(f'"{p.full_name}" "{city}" property')

        for dork in dorks[:10]:
            results = self._google_dork(dork, 'PROPERTY', 3)
            for title in results:
                entry = {'source': 'Google', 'title': title, 'dork': dork[:40]}
                if entry not in p.discovered_properties:
                    p.discovered_properties.append(entry)
                    self._log('PROPERTY', 'MEDIUM', f'Property: {title[:60]}')
            time.sleep(0.5)

        # Check discovered addresses on Zillow
        for addr in p.discovered_addresses[:3]:
            slug = addr.lower().replace(' ', '-').replace(',', '').replace('.', '')[:50]
            results = self._google_dork(f'site:zillow.com "{addr[:30]}"', 'PROPERTY', 2)
            for title in results:
                entry = {'source': 'Zillow', 'title': title, 'address': addr}
                if entry not in p.discovered_properties:
                    p.discovered_properties.append(entry)
                    self._log('PROPERTY', 'HIGH', f'Zillow: {title[:60]}')
            time.sleep(0.3)

    # ================================================================== #
    #  AUTO-DISCOVER: EMPLOYMENT                                           #
    # ================================================================== #

    def _auto_employment_search(self):
        """Auto-discover employment via LinkedIn dorks, company directories, etc."""
        p = self.p
        self._log('EMPLOY', 'INFO', 'Auto-discovering employment...')

        dorks = [
            f'"{p.full_name}" site:linkedin.com',
            f'"{p.full_name}" resume OR CV',
            f'"{p.full_name}" employee OR staff OR team',
            f'"{p.full_name}" "works at" OR "employed by"',
            f'"{p.full_name}" site:indeed.com',
            f'"{p.full_name}" site:glassdoor.com',
            f'"{p.full_name}" site:zoominfo.com',
            f'"{p.full_name}" director OR manager OR engineer OR analyst',
        ]
        if p.current_state:
            dorks.append(f'"{p.full_name}" "{p.current_state}" employer OR company OR business')
        if p.current_city:
            dorks.append(f'"{p.full_name}" "{p.current_city}" works OR employed')

        for dork in dorks[:8]:
            results = self._google_dork(dork, 'EMPLOY', 3)
            for title in results:
                # Try to extract company names and titles
                # LinkedIn format: "Name - Title - Company | LinkedIn"
                linkedin_match = re.match(r'(.+?)\s*[-|]\s*(.+?)\s*[-|]\s*(.+?)(?:\s*\||\s*-)', title)
                if linkedin_match:
                    name_part = linkedin_match.group(1).strip()
                    possible_title = linkedin_match.group(2).strip()
                    possible_company = linkedin_match.group(3).strip()
                    if p.last_name.lower() in name_part.lower():
                        if possible_company and possible_company not in p.discovered_employers:
                            p.discovered_employers.append(possible_company)
                            self._log('EMPLOY', 'HIGH', f'Employer: {possible_company}')
                        if possible_title and not p.job_title:
                            p.job_title = possible_title
                            self._log('EMPLOY', 'HIGH', f'Title: {possible_title}')

                # Generic company extraction
                for pattern in [r'"works?\s+at\s+([^"]{3,40})"', r'(?:at|for)\s+([A-Z][\w\s&]{2,30}?)(?:\s*[,|]|$)']:
                    for m in re.finditer(pattern, title, re.IGNORECASE):
                        emp = m.group(1).strip().rstrip(',.|')
                        if emp and len(emp) > 2 and emp not in p.discovered_employers:
                            p.discovered_employers.append(emp)
                            self._log('EMPLOY', 'HIGH', f'Employer: {emp}')

                # Store raw for reference
                p.discovered_blog_mentions.append({'dork': dork[:40], 'title': title, 'category': 'employment'})
            time.sleep(0.6)

    # ================================================================== #
    #  AUTO-DISCOVER: EDUCATION                                            #
    # ================================================================== #

    def _auto_education_search(self):
        """Auto-discover schools, universities, yearbooks."""
        p = self.p
        self._log('SCHOOL', 'INFO', 'Auto-discovering education...')

        dorks = [
            f'"{p.full_name}" school OR university OR college OR "class of"',
            f'"{p.full_name}" graduated OR alumni OR yearbook',
            f'"{p.full_name}" site:classmates.com',
            f'"{p.full_name}" "high school" OR "middle school"',
            f'"{p.full_name}" site:linkedin.com education',
        ]
        if p.current_state:
            dorks.append(f'"{p.full_name}" "{p.current_state}" school')
        for city in ([p.current_city] + p.previous_cities[:3]):
            if city:
                dorks.append(f'"{p.full_name}" "{city}" school OR university')

        for dork in dorks[:8]:
            results = self._google_dork(dork, 'SCHOOL', 3)
            for title in results:
                # Extract school names
                school_keywords = ['School', 'University', 'College', 'Institute', 'Academy',
                                   'High', 'Elementary', 'Middle', 'Prep', 'Tech']
                for kw in school_keywords:
                    pattern = rf'([\w\s]{{2,30}}{kw}[\w\s]{{0,20}})'
                    for m in re.finditer(pattern, title, re.IGNORECASE):
                        sch = m.group(1).strip()
                        if sch and len(sch) > 4 and sch not in p.discovered_schools:
                            p.discovered_schools.append(sch)
                            self._log('SCHOOL', 'HIGH', f'School: {sch}')

                # Class of XXXX
                year_match = re.search(r'[Cc]lass\s+of\s+((?:19|20)\d{2})', title)
                if year_match:
                    yr = year_match.group(1)
                    note = f"Class of {yr}"
                    if note not in p.discovered_schools:
                        p.discovered_schools.append(note)
                        self._log('SCHOOL', 'MEDIUM', f'Graduation: {note}')
            time.sleep(0.5)

    # ================================================================== #
    #  AUTO-DISCOVER: RELATIVES, MARRIAGE, OBITUARY                        #
    # ================================================================== #

    def _auto_relatives_search(self):
        """Cross-reference relatives from people-search plus Google dorks."""
        p = self.p
        self._log('RELATIVE', 'INFO', 'Deep relative search...')

        dorks = [
            f'"{p.full_name}" family OR relatives OR "related to"',
            f'"{p.full_name}" brother OR sister OR parent OR child OR spouse',
            f'"{p.last_name}" family "{p.current_state or ""}"'.strip(),
        ]
        if p.maiden_name:
            dorks.append(f'"{p.maiden_name}" "{p.last_name}" family')
        for rel in p.known_relatives[:3]:
            dorks.append(f'"{rel}" "{p.last_name}"')

        for dork in dorks[:6]:
            results = self._google_dork(dork, 'RELATIVE', 3)
            for title in results:
                # Extract name patterns
                for m in re.findall(r'([A-Z][a-z]+\s+' + re.escape(p.last_name) + r')', title):
                    if m.lower() != p.full_name.lower() and m not in p.discovered_relatives:
                        p.discovered_relatives.append(m)
                        self._log('RELATIVE', 'HIGH', f'Possible relative: {m}')
            time.sleep(0.5)

    def _auto_marriage_search(self):
        """Search for marriage records."""
        p = self.p
        self._log('MARRIAGE', 'INFO', 'Searching marriage records...')

        dorks = [
            f'"{p.full_name}" marriage OR wedding OR married',
            f'"{p.full_name}" "marriage license" OR "marriage record"',
        ]
        if p.maiden_name:
            dorks.append(f'"{p.maiden_name}" marriage "{p.last_name}"')

        for dork in dorks[:3]:
            results = self._google_dork(dork, 'MARRIAGE', 3)
            for title in results:
                if title:
                    p.discovered_marriages.append(title)
                    self._log('MARRIAGE', 'MEDIUM', f'Marriage: {title[:60]}')
            time.sleep(0.5)

    def _auto_obituary_search(self):
        """Search obituaries -- reveals family trees, addresses, employment."""
        p = self.p
        self._log('OBITUARY', 'INFO', 'Searching obituaries (family tree mining)...')

        dorks = [
            f'"{p.full_name}" obituary',
            f'"{p.last_name}" obituary "{p.current_state or ""}"'.strip(),
            f'"{p.full_name}" site:legacy.com',
            f'"{p.full_name}" site:obituaries.com',
            f'"{p.full_name}" "survived by"',
        ]

        for dork in dorks[:4]:
            results = self._google_dork(dork, 'OBITUARY', 3)
            for title in results:
                if title:
                    p.discovered_obituary_mentions.append(title)
                    self._log('OBITUARY', 'MEDIUM', f'Obituary: {title[:60]}')
                    # Mine names from obituaries
                    for name in re.findall(r'([A-Z][a-z]+\s+[A-Z][a-z]+)', title):
                        if name.lower() != p.full_name.lower() and name not in p.discovered_relatives:
                            p.discovered_relatives.append(name)
            time.sleep(0.5)

    # ================================================================== #
    #  COURT, ARREST, VOTER, BUSINESS, LICENSE                             #
    # ================================================================== #

    def _court_listener_search(self):
        p = self.p
        self._log('COURT', 'INFO', 'Searching CourtListener...')
        try:
            url = f"https://www.courtlistener.com/api/rest/v3/search/?q={quote(p.full_name)}&type=r"
            r = self.s.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for case in data.get('results', [])[:10]:
                    c = {
                        'case_name': case.get('caseName', ''),
                        'court': case.get('court', ''),
                        'date_filed': case.get('dateFiled', ''),
                        'docket_number': case.get('docketNumber', ''),
                        'url': f"https://www.courtlistener.com{case.get('absolute_url', '')}"
                    }
                    p.discovered_court.append(c)
                    self._log('COURT', 'HIGH', f'{c["case_name"][:50]}',
                              {'court': c['court'], 'date': c['date_filed']})
        except:
            pass

    def _auto_arrest_search(self):
        """Auto-search arrest records, mugshots, criminal history."""
        p = self.p
        self._log('ARREST', 'INFO', 'Searching arrest/criminal records...')

        dorks = [
            f'"{p.full_name}" arrest OR arrested OR mugshot',
            f'"{p.full_name}" criminal record OR charges OR court',
            f'"{p.full_name}" site:arrests.org',
            f'"{p.full_name}" site:mugshots.com',
            f'"{p.full_name}" inmate OR booking OR jail',
        ]
        if p.current_state:
            dorks.append(f'"{p.full_name}" "{p.current_state}" arrest OR court')

        for dork in dorks[:5]:
            results = self._google_dork(dork, 'ARREST', 3)
            for title in results:
                p.discovered_court.append({
                    'case_name': title[:80], 'court': 'Google (arrest/criminal)',
                    'date_filed': '', 'docket_number': '', 'url': ''
                })
                self._log('ARREST', 'HIGH', f'Arrest/Criminal: {title[:60]}')
            time.sleep(0.5)

    def _voter_search(self):
        p = self.p
        self._log('VOTER', 'INFO', 'Searching voter registration...')
        dorks = [
            f'"{p.full_name}" voter registration',
            f'"{p.full_name}" "registered voter"',
        ]
        if p.current_state:
            dorks[0] += f' "{p.current_state}"'

        for dork in dorks[:2]:
            results = self._google_dork(dork, 'VOTER', 3)
            for title in results:
                if title and ('voter' in title.lower() or 'registr' in title.lower() or p.last_name.lower() in title.lower()):
                    p.discovered_voter_info = {'source': 'Google', 'result': title}
                    self._log('VOTER', 'MEDIUM', f'Voter: {title[:60]}')
            time.sleep(0.3)

    def _business_search(self):
        p = self.p
        self._log('BUSINESS', 'INFO', 'Searching business registrations...')
        try:
            url = f"https://opencorporates.com/companies?q={quote(p.full_name)}&utf8=1"
            r = self.s.get(url, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for link in soup.find_all('a', class_='company_search_result')[:5]:
                    name = link.get_text(strip=True)
                    href = link.get('href', '')
                    if name:
                        p.discovered_business_records.append({
                            'name': name, 'url': f"https://opencorporates.com{href}"
                        })
                        self._log('BUSINESS', 'HIGH', f'Business: {name[:50]}')
        except:
            pass

        # Also dork for LLCs, corporations
        dorks = [
            f'"{p.full_name}" LLC OR Inc OR Corp OR "registered agent"',
            f'"{p.full_name}" "secretary of state" business',
        ]
        for dork in dorks:
            results = self._google_dork(dork, 'BUSINESS', 3)
            for title in results:
                p.discovered_business_records.append({'name': title[:80], 'source': 'Google'})
                self._log('BUSINESS', 'MEDIUM', f'Business: {title[:60]}')
            time.sleep(0.3)

    def _sec_edgar_search(self):
        p = self.p
        self._log('SEC', 'INFO', 'Searching SEC EDGAR...')
        try:
            url = f"https://efts.sec.gov/LATEST/search-index?q={quote(p.full_name)}&dateRange=custom&startdt=2000-01-01"
            r = self.s.get(url, timeout=10,
                           headers={'User-Agent': 'Galaxy-Recon/4.1 research@example.com'})
            if r.status_code == 200:
                data = r.json()
                hits = data.get('hits', {}).get('hits', [])
                for hit in hits[:5]:
                    src = hit.get('_source', {})
                    filing = src.get('display_names', [''])[0] if src.get('display_names') else ''
                    if filing:
                        p.discovered_business_records.append({
                            'name': filing, 'source': 'SEC EDGAR'
                        })
                        self._log('SEC', 'MEDIUM', f'SEC filing: {filing[:60]}')
        except:
            pass

    def _auto_license_search(self):
        """Search for professional licenses, certifications."""
        p = self.p
        self._log('LICENSE', 'INFO', 'Searching professional licenses...')

        dorks = [
            f'"{p.full_name}" license OR licensed OR certification',
            f'"{p.full_name}" "professional license" OR "medical license" OR "real estate license"',
        ]
        if p.current_state:
            dorks.append(f'"{p.full_name}" "{p.current_state}" license board')

        for dork in dorks[:3]:
            results = self._google_dork(dork, 'LICENSE', 3)
            for title in results:
                if title:
                    p.discovered_licenses.append(title[:80])
                    self._log('LICENSE', 'MEDIUM', f'License: {title[:60]}')
            time.sleep(0.3)

    # ================================================================== #
    #  FORUMS / REDDIT / ARCHIVES                                         #
    # ================================================================== #

    def _reddit_search(self):
        p = self.p
        self._log('FORUM', 'INFO', 'Searching Reddit...')
        queries = [f'"{p.full_name}"']
        if p.known_email:
            queries.append(f'"{p.known_email}"')
        for u in (p.known_usernames + p.discovered_usernames)[:3]:
            queries.append(f'author:{u}')
            queries.append(f'"{u}"')

        for q in queries:
            try:
                url = f"https://www.reddit.com/search.json?q={quote(q)}&sort=relevance&limit=10"
                r = self.s.get(url, timeout=10, headers={'User-Agent': 'Galaxy-Recon/4.1'})
                if r.status_code == 200:
                    data = r.json()
                    posts = data.get('data', {}).get('children', [])
                    for post in posts[:5]:
                        pd = post.get('data', {})
                        title = pd.get('title', '')
                        sub = pd.get('subreddit', '')
                        author = pd.get('author', '')
                        url_p = pd.get('url', '')
                        selftext = pd.get('selftext', '')[:200]
                        if title:
                            p.discovered_forum_posts.append({
                                'source': 'Reddit', 'subreddit': sub,
                                'title': title, 'author': author,
                                'url': url_p, 'snippet': selftext
                            })
                            self._log('REDDIT', 'MEDIUM', f'r/{sub}: {title[:60]}',
                                      {'author': author, 'url': url_p})
            except:
                pass
            time.sleep(0.5)

    def _archive_org_search(self):
        p = self.p
        self._log('ARCHIVE', 'INFO', 'Searching Archive.org...')
        queries = [p.full_name]
        if p.known_email:
            queries.append(p.known_email)

        for q in queries[:3]:
            try:
                url = f"https://archive.org/advancedsearch.php?q={quote(q)}&output=json&rows=10"
                r = self.s.get(url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    docs = data.get('response', {}).get('docs', [])
                    for doc in docs[:5]:
                        title = doc.get('title', '')
                        identifier = doc.get('identifier', '')
                        desc = doc.get('description', '')
                        if isinstance(desc, list):
                            desc = ' '.join(desc)
                        if title:
                            p.discovered_blog_mentions.append({
                                'source': 'Archive.org', 'title': title,
                                'url': f"https://archive.org/details/{identifier}",
                                'description': str(desc)[:200]
                            })
                            self._log('ARCHIVE', 'MEDIUM', f'Archive: {title[:60]}')
            except:
                pass

    def _google_cache_search(self):
        p = self.p
        self._log('CACHE', 'INFO', 'Google cache & forum search...')
        dorks = [
            f'"{p.full_name}" site:reddit.com',
            f'"{p.full_name}" site:forum',
            f'"{p.full_name}" site:boards',
            f'"{p.full_name}" site:community',
        ]
        if p.known_email:
            dorks.append(f'"{p.known_email}"')
        for u in (p.known_usernames + p.discovered_usernames)[:2]:
            dorks.append(f'"{u}" site:reddit.com OR site:forum')

        for dork in dorks[:6]:
            results = self._google_dork(dork, 'CACHE', 3)
            for title in results:
                p.discovered_forum_posts.append({
                    'source': 'Google', 'title': title, 'dork': dork[:50]
                })
                self._log('GOOGLE', 'MEDIUM', f'Result: {title[:70]}')
            time.sleep(0.5)

    def _paste_search(self):
        p = self.p
        self._log('PASTE', 'INFO', 'Searching paste sites...')
        targets = list(set(
            ([p.known_email] if p.known_email else []) +
            p.discovered_emails[:3] +
            p.known_usernames[:2] +
            p.discovered_usernames[:2] +
            [p.full_name]
        ))

        for target in targets[:6]:
            try:
                url = f"https://www.google.com/search?q=site:pastebin.com+{quote(target)}"
                r = self.s.get(url, timeout=10)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    results = soup.find_all('h3')
                    if results:
                        for h3 in results[:3]:
                            p.paste_dumps.append({
                                'query': target, 'title': h3.get_text(strip=True),
                                'source': 'Pastebin (via Google)'
                            })
                            self._log('PASTE', 'HIGH', f'Paste found for {target}',
                                      h3.get_text(strip=True)[:80])
            except:
                pass
            time.sleep(0.5)

    # ================================================================== #
    #  GOOGLE DORKING, NEWS, IMAGES                                       #
    # ================================================================== #

    def _google_dork_deep(self):
        p = self.p
        self._log('GOOGLE', 'INFO', 'Deep Google dorking...')
        dorks = [
            f'"{p.full_name}"',
            f'"{p.full_name}" resume OR CV',
            f'"{p.full_name}" filetype:pdf',
            f'"{p.full_name}" inurl:profile',
            f'"{p.full_name}" birthday OR born',
            f'"{p.full_name}" site:amazon.com wishlist',
            f'"{p.full_name}" site:mylife.com',
            f'"{p.full_name}" "phone number" OR "email address"',
            f'"{p.full_name}" volunteer OR nonprofit OR charity',
        ]
        # Always add location-based dorks using discovered data too
        cities = [p.current_city] + p.previous_cities[:3]
        states = [p.current_state] + p.previous_states[:3]
        for loc in cities + states:
            if loc:
                dorks.append(f'"{p.full_name}" "{loc}"')
        if p.employer:
            dorks.append(f'"{p.full_name}" "{p.employer}"')
        if p.school:
            dorks.append(f'"{p.full_name}" "{p.school}"')
        if p.known_email:
            dorks.append(f'"{p.known_email}"')
        # Use discovered employers/schools too
        for emp in p.discovered_employers[:2]:
            dorks.append(f'"{p.full_name}" "{emp}"')
        for sch in p.discovered_schools[:2]:
            dorks.append(f'"{p.full_name}" "{sch}"')

        seen = set()
        for dork in dorks[:15]:
            if not dork or dork in seen:
                continue
            seen.add(dork)
            results = self._google_dork(dork, 'DORK', 3)
            for title in results:
                p.discovered_blog_mentions.append({'dork': dork[:50], 'title': title})
                self._log('DORK', 'MEDIUM', f'{title[:70]}')
            time.sleep(0.8)

    def _news_search(self):
        p = self.p
        self._log('NEWS', 'INFO', 'Searching news...')
        try:
            url = f"https://www.google.com/search?q={quote(p.full_name)}&tbm=nws&num=10"
            r = self.s.get(url, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for h3 in soup.find_all('h3')[:8]:
                    title = h3.get_text(strip=True)
                    if title:
                        p.discovered_news.append(title)
                        self._log('NEWS', 'MEDIUM', f'News: {title[:70]}')
        except:
            pass

    def _image_search(self):
        p = self.p
        self._log('IMAGE', 'INFO', 'Searching for photos...')
        try:
            url = f"https://www.google.com/search?q={quote(p.full_name)}&tbm=isch&num=5"
            r = self.s.get(url, timeout=10)
            if r.status_code == 200:
                img_urls = re.findall(r'https?://[^\s"<>]+\.(?:jpg|jpeg|png|webp)', r.text)
                for img in img_urls[:10]:
                    if 'google' not in img and 'gstatic' not in img:
                        p.discovered_photos.append(img)
                if p.discovered_photos:
                    self._log('IMAGE', 'MEDIUM',
                              f'{len(p.discovered_photos)} possible photos found')
        except:
            pass

    # ================================================================== #
    #  DOMAIN RECON                                                       #
    # ================================================================== #

    def _domain_recon(self, domain):
        self._log('DOMAIN', 'INFO', f'Full recon on {domain}...')
        tasks = [
            ('DNS', lambda: self._dns_enum(domain)),
            ('Subdomains', lambda: self._subdomain_scan(domain)),
            ('Ports', lambda: self._port_scan(domain)),
            ('Tech', lambda: self._tech_detect(domain)),
            ('Certs', lambda: self._cert_transparency(domain)),
            ('Wayback', lambda: self._wayback(domain)),
            ('Directories', lambda: self._directory_scan(domain)),
            ('SSL', lambda: self._ssl_analysis(domain)),
            ('WHOIS', lambda: self._whois_lookup(domain)),
        ]
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(fn): nm for nm, fn in tasks}
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as e:
                    self._log('DOMAIN', 'LOW', f'{futs[f]} failed: {str(e)[:60]}')

    def _dns_enum(self, domain):
        p = self.p
        for rt in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA']:
            try:
                ans = dns.resolver.resolve(domain, rt)
                recs = [str(r) for r in ans]
                p.domain_dns[rt] = recs
                for r in recs:
                    self._log('DNS', 'MEDIUM', f'{rt}: {r}')
                    if rt == 'A':
                        p.discovered_ips.append(r)
            except:
                pass

    def _subdomain_scan(self, domain):
        p = self.p
        words = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                 'portal', 'vpn', 'remote', 'cloud', 'app', 'mobile', 'secure',
                 'webmail', 'email', 'smtp', 'blog', 'shop', 'store', 'account',
                 'dashboard', 'panel', 'cdn', 'static', 'assets', 'media', 'img',
                 'db', 'backup', 'old', 'login', 'auth', 'docs', 'wiki', 'support',
                 'ns1', 'ns2', 'dns', 'mx', 'pop', 'imap', 'git', 'svn', 'pay',
                 'checkout', 'order', 'orders', 'tracking', 'customer', 'members']
        def ck(sub):
            try:
                dns.resolver.resolve(f"{sub}.{domain}", 'A', lifetime=2)
                return f"{sub}.{domain}"
            except:
                return None
        with ThreadPoolExecutor(max_workers=50) as ex:
            for f in as_completed({ex.submit(ck, w): w for w in words}):
                r = f.result()
                if r:
                    p.domain_subdomains.append(r)
                    self._log('SUBDOMAIN', 'HIGH', f'{r}')

    def _port_scan(self, domain):
        p = self.p
        try:
            ip = socket.gethostbyname(domain)
        except:
            return
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]
        def sc(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    s.close(); return port
                s.close()
            except:
                pass
        with ThreadPoolExecutor(max_workers=50) as ex:
            for f in as_completed({ex.submit(sc, pt): pt for pt in ports}):
                r = f.result()
                if r:
                    p.domain_ports.append(r)
                    self._log('PORT', 'MEDIUM', f'Port {r} OPEN on {ip}')

    def _tech_detect(self, domain):
        p = self.p
        for scheme in ['https', 'http']:
            try:
                r = self.s.get(f"{scheme}://{domain}", timeout=10)
                for h in ['Server', 'X-Powered-By', 'X-Generator']:
                    if h in r.headers:
                        p.domain_tech.append(f"{h}: {r.headers[h]}")
                        self._log('TECH', 'MEDIUM', f'{h}: {r.headers[h]}')
                html = r.text.lower()
                fws = {'WordPress': ['wp-content'], 'Shopify': ['shopify'],
                       'React': ['react-dom'], 'Vue': ['vue.js'],
                       'Angular': ['ng-app'], 'Laravel': ['laravel_session'],
                       'Django': ['csrfmiddlewaretoken'], 'Drupal': ['drupal'],
                       'Joomla': ['joomla'], 'Next.js': ['_next/'],
                       'Wix': ['wix.com'], 'Squarespace': ['squarespace']}
                for fw, inds in fws.items():
                    if any(i in html for i in inds):
                        p.domain_tech.append(fw)
                        self._log('TECH', 'HIGH', f'Framework: {fw}')
                break
            except:
                pass

    def _cert_transparency(self, domain):
        p = self.p
        try:
            r = self.s.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
            if r.status_code == 200:
                doms = set()
                for e in r.json()[:150]:
                    n = e.get('name_value', '')
                    if domain in n:
                        for d in n.split('\n'):
                            doms.add(d.strip())
                for d in sorted(doms)[:20]:
                    p.domain_certs.append(d)
                    self._log('CERT', 'MEDIUM', f'Cert: {d}')
        except:
            pass

    def _wayback(self, domain):
        p = self.p
        try:
            r = self.s.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=30", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if len(data) > 1:
                    p.domain_historical = [{'count': len(data) - 1}]
                    self._log('HISTORY', 'MEDIUM', f'{len(data)-1} Wayback snapshots')
        except:
            pass

    def _directory_scan(self, domain):
        p = self.p
        paths = [
            '/.env', '/.git', '/.git/HEAD', '/.htaccess', '/.htpasswd',
            '/admin', '/wp-admin', '/wp-login.php', '/administrator',
            '/phpinfo.php', '/info.php', '/server-status', '/server-info',
            '/backup', '/backup.sql', '/backup.zip', '/db.sql',
            '/api', '/api/v1', '/api/v2', '/graphql', '/swagger.json',
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/config', '/config.php', '/wp-config.php.bak', '/web.config',
            '/uploads', '/files', '/data', '/tmp', '/temp',
            '/.DS_Store', '/crossdomain.xml', '/clientaccesspolicy.xml',
        ]
        for scheme in ['https', 'http']:
            for path in paths:
                try:
                    r = self.s.get(f"{scheme}://{domain}{path}", timeout=5, allow_redirects=False)
                    if r.status_code in [200, 301, 302, 403]:
                        sev = 'CRITICAL' if path in ['/.env', '/.git', '/.git/HEAD', '/backup.sql', '/db.sql', '/wp-config.php.bak'] else 'MEDIUM'
                        p.domain_directories.append({'path': path, 'status': r.status_code})
                        self._log('DIR', sev, f'{path} -> {r.status_code}')
                except:
                    pass
            break

    def _ssl_analysis(self, domain):
        try:
            import ssl
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as conn:
                with ctx.wrap_socket(conn, server_hostname=domain) as ss:
                    cert = ss.getpeercert()
                    subj = dict(x[0] for x in cert.get('subject', ()))
                    iss = dict(x[0] for x in cert.get('issuer', ()))
                    self.p.domain_certs.append({
                        'cn': subj.get('commonName', ''),
                        'issuer': iss.get('organizationName', ''),
                        'expires': cert.get('notAfter', '')
                    })
                    self._log('SSL', 'MEDIUM', f'CN: {subj.get("commonName","")}',
                              {'issuer': iss.get('organizationName',''), 'expires': cert.get('notAfter','')})
        except:
            pass

    def _whois_lookup(self, domain):
        try:
            r = self.s.get(f"https://whois.domaintools.com/{domain}", timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                text = soup.get_text(separator=' ', strip=True)[:2000]
                for pattern in [r'Registrant[:\s]+(.*?)(?:Admin|Tech|Name Server)',
                                r'Organization[:\s]+([^\n]+)']:
                    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                    if m:
                        self.p.domain_whois['registrant'] = m.group(1).strip()[:200]
                        self._log('WHOIS', 'MEDIUM', f'Registrant info found')
                        break
        except:
            pass

    # ================================================================== #
    #  CREDENTIAL EXPOSURE                                                #
    # ================================================================== #

    def _credential_exposure_check(self):
        p = self.p
        self._log('CRED', 'INFO', 'Full credential exposure check...')

        derived = []
        for u in p.all_usernames():
            for dom in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']:
                e = f"{u}@{dom}"
                if e.lower() not in [x.lower() for x in p.all_emails() + derived]:
                    derived.append(e)
        if derived:
            self._log('CRED', 'INFO', f'Derived {len(derived)} emails from usernames')

        all_check = list(set(p.all_emails() + derived))

        for email in all_check[:30]:
            self._check_hibp(email)
            self._check_breach_directory(email)
            self._check_xposedornot(email)
            time.sleep(0.5)

        if self.HACKCHECK_API_KEY:
            self._check_hackcheck(all_check)

        p.hackcheck_list = all_check[:50]

    def _check_hibp(self, email):
        try:
            r = self.s.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                           timeout=10, headers={'User-Agent': 'Galaxy-Recon/4.1'})
            if r.status_code == 200:
                for b in r.json():
                    self.p.breaches.append({
                        'email': email, 'name': b.get('Name',''),
                        'domain': b.get('Domain',''), 'date': b.get('BreachDate',''),
                        'count': b.get('PwnCount',0),
                        'data_types': b.get('DataClasses',[]), 'source': 'HIBP'
                    })
                    self._log('BREACH', 'CRITICAL', f'BREACH: {b.get("Name")} ({b.get("BreachDate","")})',
                              {'email': email, 'data': ', '.join(b.get('DataClasses',[])[:5])})
            elif r.status_code == 401:
                self._log('BREACH', 'LOW', f'HIBP v3 requires API key for {email}')
        except:
            pass

    def _check_breach_directory(self, email):
        try:
            r = self.s.get(f"https://breachdirectory.org/api/search?email={quote(email)}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                results = data.get('result', [])
                if isinstance(results, list):
                    for entry in results[:10]:
                        pwd = entry.get('password', '')
                        src = entry.get('source', 'unknown')
                        if pwd:
                            self.p.partial_passwords.append({
                                'email': email, 'password': pwd, 'source': src
                            })
                            self._log('CRED', 'CRITICAL', f'Password found!',
                                      {'email': email, 'password': pwd, 'source': src})
        except:
            pass

    def _check_xposedornot(self, email):
        try:
            r = self.s.get(f"https://api.xposedornot.com/v1/check-email/{quote(email)}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                breaches = data.get('breaches', [])
                if isinstance(breaches, list) and breaches:
                    for name in breaches[:10]:
                        self.p.breaches.append({
                            'email': email, 'name': name, 'source': 'XposedOrNot'
                        })
                        self._log('BREACH', 'HIGH', f'XposedOrNot: {name}', {'email': email})
        except:
            pass

    def _check_hackcheck(self, emails):
        self._log('HACKCHECK', 'INFO', 'Querying HackCheck API...')
        for email in emails[:20]:
            try:
                r = self.s.get('https://hackcheck.io/api/v2/search',
                               params={'email': email},
                               headers={'Authorization': f'Bearer {self.HACKCHECK_API_KEY}'},
                               timeout=10)
                if r.status_code == 200:
                    for res in r.json().get('results', []):
                        pwd = res.get('password', '')
                        if pwd:
                            self.p.partial_passwords.append({
                                'email': email, 'password': pwd, 'source': 'HackCheck'
                            })
                            self._log('HACKCHECK', 'CRITICAL', f'Password!',
                                      {'email': email, 'password': pwd})
            except:
                pass
            time.sleep(0.3)

    # ================================================================== #
    #  CROSS-REFERENCE PASS                                                #
    # ================================================================== #

    def _cross_reference_pass(self):
        """Final pass: use everything discovered so far to fill remaining gaps."""
        p = self.p
        self._log('XREF', 'INFO', 'Cross-referencing all discovered data...')

        # If we found addresses but no state/city, extract from addresses
        if not p.current_state and p.discovered_addresses:
            for addr in p.discovered_addresses:
                state_match = re.search(r',\s*([A-Z]{2})\s+\d{5}', addr)
                if state_match:
                    p.current_state = state_match.group(1)
                    self._log('XREF', 'MEDIUM', f'Derived state from address: {p.current_state}')
                    break

        if not p.current_city and p.discovered_addresses:
            for addr in p.discovered_addresses:
                city_match = re.search(r',\s*([A-Za-z\s]+),\s*[A-Z]{2}', addr)
                if city_match:
                    p.current_city = city_match.group(1).strip()
                    self._log('XREF', 'MEDIUM', f'Derived city from address: {p.current_city}')
                    break

        # If we found employers in dork results but not in employer list, extract
        all_text = ' '.join([bm.get('title', '') for bm in p.discovered_blog_mentions])
        if not p.discovered_employers:
            for m in re.finditer(r'(?:at|for|with)\s+([A-Z][\w\s&]{2,25}?)(?:\s*[-|,]|$)', all_text):
                emp = m.group(1).strip()
                if emp and len(emp) > 3 and emp not in p.discovered_employers:
                    p.discovered_employers.append(emp)

        # Deduplicate
        p.discovered_addresses = list(dict.fromkeys(p.discovered_addresses))
        p.discovered_relatives = list(dict.fromkeys(p.discovered_relatives))
        p.discovered_phones = list(dict.fromkeys(p.discovered_phones))
        p.discovered_emails = list(dict.fromkeys(p.discovered_emails))
        p.discovered_employers = list(dict.fromkeys(p.discovered_employers))
        p.discovered_schools = list(dict.fromkeys(p.discovered_schools))
        p.discovered_vehicles = list(dict.fromkeys(p.discovered_vehicles))

        total_disc = (len(p.discovered_phones) + len(p.discovered_emails) +
                      len(p.discovered_addresses) + len(p.discovered_social) +
                      len(p.discovered_relatives) + len(p.discovered_employers) +
                      len(p.discovered_schools) + len(p.discovered_vehicles) +
                      len(p.discovered_properties) + len(p.discovered_court) +
                      len(p.discovered_news) + len(p.breaches))
        self._log('XREF', 'HIGH', f'Total data points discovered: {total_disc}')

    # ================================================================== #
    #  DOSSIER DISPLAY                                                    #
    # ================================================================== #

    def display_dossier(self):
        p = self.p
        C.s(f"""
{C.NEBULA}{C.BOLD}
================================================================
=                                                              =
=         *** CLASSIFIED INTELLIGENCE DOSSIER ***              =
=         GALAXY OPERATIONS - TOP SECRET                       =
=         Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                     =
=                                                              =
================================================================{C.R}""")

        def section(title):
            C.s(f"\n{C.CYAN}{C.BOLD}{'='*64}")
            C.s(f"  {title}")
            C.s(f"{'='*64}{C.R}")

        def kv(key, val, color=C.GREEN):
            if val and val != '-':
                C.s(f"  {C.WHITE}{key:<20}: {color}{val}{C.R}")

        # SUBJECT ID
        section("SUBJECT IDENTIFICATION")
        kv('Full Name', p.full_name)
        kv('Middle Name', p.middle_name)
        kv('Nickname', p.nickname)
        kv('Maiden Name', p.maiden_name)
        kv('Gender', p.discovered_gender or p.gender or '(not determined)')
        kv('Age', p.discovered_age or p.age_approx or '(not found)')
        kv('Date of Birth', p.discovered_dob or p.dob or '(not found)')
        kv('Military', p.military)

        # CONTACT
        section("CONTACT INFORMATION")
        all_emails = p.all_emails()
        all_phones = p.all_phones()
        if all_emails:
            for i, e in enumerate(all_emails[:20], 1):
                mark = ' (KNOWN)' if e == (p.known_email or '').lower() else ' (DISCOVERED)'
                C.s(f"  {C.WHITE}Email {i:>2}          : {C.GREEN}{e}{C.YELLOW}{mark}{C.R}")
        else:
            C.s(f"  {C.DIM}  No emails found{C.R}")
        if all_phones:
            for i, ph in enumerate(all_phones[:10], 1):
                mark = ' (KNOWN)' if ph == p.known_phone else ' (DISCOVERED)'
                C.s(f"  {C.WHITE}Phone {i:>2}          : {C.GREEN}{ph}{C.YELLOW}{mark}{C.R}")
        else:
            C.s(f"  {C.DIM}  No phones found{C.R}")

        # ADDRESSES
        section("ADDRESS HISTORY")
        if p.known_address:
            C.s(f"  {C.WHITE}Known Address    : {C.GREEN}{p.known_address} (provided){C.R}")
        if p.discovered_addresses:
            for i, a in enumerate(p.discovered_addresses[:20], 1):
                C.s(f"  {C.WHITE}Address {i:>2}       : {C.GREEN}{a}{C.R}")
        elif not p.known_address:
            C.s(f"  {C.DIM}  No addresses found{C.R}")

        # LOCATION
        section("LOCATION HISTORY")
        kv('Current', f"{p.current_city or '?'}, {p.current_state or '?'} {p.current_zip or ''}".strip())
        if p.previous_states:
            kv('Prev States', ', '.join(p.previous_states))
        if p.previous_cities:
            kv('Prev Cities', ', '.join(p.previous_cities))

        # SOCIAL MEDIA
        section("SOCIAL MEDIA PROFILES")
        if p.discovered_social:
            for plat, info in p.discovered_social.items():
                if isinstance(info, dict):
                    C.s(f"  {C.WHITE}{plat:<20}: {C.GREEN}@{info.get('username','')}  {C.BLUE}{info.get('url','')}{C.R}")
                else:
                    C.s(f"  {C.WHITE}{plat:<20}: {C.GREEN}{info}{C.R}")
        else:
            C.s(f"  {C.DIM}  No social media profiles found{C.R}")

        # RELATIVES
        section("RELATIVES & ASSOCIATES")
        all_rels = p.all_relatives()
        if all_rels:
            for name in all_rels[:25]:
                C.s(f"  {C.WHITE}* {C.GREEN}{name}{C.R}")
        else:
            C.s(f"  {C.DIM}  No relatives found{C.R}")

        # EMPLOYMENT / EDUCATION
        section("EMPLOYMENT & EDUCATION")
        employers = sorted(set(([p.employer] if p.employer else []) + p.discovered_employers))
        schools = sorted(set(([p.school] if p.school else []) + p.discovered_schools))
        if employers:
            for e in employers:
                kv('Employer', e)
        else:
            C.s(f"  {C.DIM}  No employers found{C.R}")
        kv('Job Title', p.job_title)
        if schools:
            for s in schools:
                kv('School', s)
        else:
            C.s(f"  {C.DIM}  No schools found{C.R}")

        # VEHICLES
        section("VEHICLES")
        vehicles = p.discovered_vehicles or ([p.vehicle_info] if p.vehicle_info else [])
        if vehicles:
            for v in vehicles:
                if isinstance(v, dict):
                    C.s(f"  {C.WHITE}* {C.GREEN}{v}{C.R}")
                else:
                    C.s(f"  {C.WHITE}* {C.GREEN}{v}{C.R}")
        else:
            C.s(f"  {C.DIM}  No vehicles found in public records{C.R}")

        # LICENSES
        if p.discovered_licenses:
            section("PROFESSIONAL LICENSES")
            for lic in p.discovered_licenses[:10]:
                C.s(f"  {C.WHITE}* {C.GREEN}{lic}{C.R}")

        # PROPERTIES
        section("PROPERTY RECORDS")
        if p.discovered_properties:
            for pr in p.discovered_properties[:10]:
                C.s(f"  {C.WHITE}* {C.GREEN}{pr.get('title','')}{C.R}")
        else:
            C.s(f"  {C.DIM}  No property records found{C.R}")

        # BUSINESS
        if p.discovered_business_records:
            section("BUSINESS RECORDS")
            for br in p.discovered_business_records[:10]:
                C.s(f"  {C.WHITE}* {C.GREEN}{br.get('name','')}{C.R}")
                if br.get('url'):
                    C.s(f"    {C.BLUE}{br['url']}{C.R}")

        # COURT RECORDS
        section("COURT / ARREST RECORDS")
        if p.discovered_court:
            for c in p.discovered_court[:10]:
                C.s(f"  {C.WHITE}Case  : {C.GREEN}{c.get('case_name','')}{C.R}")
                if c.get('court'):
                    C.s(f"  {C.WHITE}Court : {C.BLUE}{c.get('court','')}{C.R}")
                if c.get('date_filed'):
                    C.s(f"  {C.WHITE}Date  : {C.BLUE}{c.get('date_filed','')}{C.R}")
                C.s(f"  {C.DIM}{'- '*30}{C.R}")
        else:
            C.s(f"  {C.DIM}  No court/arrest records found{C.R}")

        # VOTER
        if p.discovered_voter_info:
            section("VOTER REGISTRATION")
            C.s(f"  {C.GREEN}{p.discovered_voter_info}{C.R}")

        # MARRIAGES
        if p.discovered_marriages:
            section("MARRIAGE RECORDS")
            for m in p.discovered_marriages[:5]:
                C.s(f"  {C.WHITE}* {C.GREEN}{m[:80]}{C.R}")

        # OBITUARIES
        if p.discovered_obituary_mentions:
            section("OBITUARY MENTIONS (family tree)")
            for ob in p.discovered_obituary_mentions[:5]:
                C.s(f"  {C.WHITE}* {C.GREEN}{ob[:80]}{C.R}")

        # NEWS
        if p.discovered_news:
            section("NEWS MENTIONS")
            for n in p.discovered_news[:10]:
                C.s(f"  {C.WHITE}* {C.GREEN}{n[:80]}{C.R}")

        # FORUM POSTS
        if p.discovered_forum_posts:
            section("FORUM & REDDIT POSTS")
            for fp in p.discovered_forum_posts[:15]:
                src = fp.get('source', '')
                sub = fp.get('subreddit', '')
                title = fp.get('title', '')
                prefix = f"r/{sub}" if sub else src
                C.s(f"  {C.WHITE}[{prefix}] {C.GREEN}{title[:70]}{C.R}")
                if fp.get('url'):
                    C.s(f"    {C.BLUE}{fp['url'][:100]}{C.R}")

        # BLOG / WEB MENTIONS
        if p.discovered_blog_mentions:
            section("WEB MENTIONS & DORK RESULTS")
            seen = set()
            for bm in p.discovered_blog_mentions[:15]:
                title = bm.get('title', '')
                if title and title not in seen:
                    seen.add(title)
                    C.s(f"  {C.WHITE}* {C.GREEN}{title[:80]}{C.R}")

        # PHOTOS
        if p.discovered_photos:
            section("DISCOVERED PHOTOS")
            for ph in p.discovered_photos[:10]:
                C.s(f"  {C.BLUE}{ph[:120]}{C.R}")

        # PASTE DUMPS
        if p.paste_dumps:
            section("PASTE SITE DUMPS")
            for pd_item in p.paste_dumps[:10]:
                C.s(f"  {C.PINK}[!] {C.WHITE}{pd_item.get('query','')}: {C.YELLOW}{pd_item.get('title','')}{C.R}")

        # ---- BREACH / CREDENTIALS ----
        section("CREDENTIAL EXPOSURE REPORT")
        if p.breaches:
            seen = set()
            for b in p.breaches:
                key = f"{b.get('email','')}-{b.get('name','')}"
                if key in seen:
                    continue
                seen.add(key)
                C.s(f"  {C.PINK}[!] {C.WHITE}{b.get('email','')}{C.R}")
                C.s(f"      {C.YELLOW}Breach: {b.get('name','')} ({b.get('date','')}) via {b.get('source','')}{C.R}")
                if b.get('data_types'):
                    C.s(f"      {C.CYAN}Data: {', '.join(b['data_types'][:6])}{C.R}")
        else:
            C.s(f"  {C.GREEN}No breaches found in checked databases.{C.R}")

        if p.partial_passwords:
            C.s(f"\n  {C.PINK}{C.BOLD}--- Exposed Passwords ---{C.R}")
            for pp in p.partial_passwords:
                C.s(f"  {C.PINK}[!] {C.WHITE}{pp.get('email','')}: "
                    f"{C.YELLOW}{pp.get('password','***')}{C.R} "
                    f"{C.DIM}(from {pp.get('source','')}){C.R}")

        # HACKCHECK LIST
        if p.hackcheck_list:
            C.s(f"\n{C.PURPLE}{C.BOLD}{'='*64}")
            C.s(f"  HACKCHECK QUICK-LOOKUP LIST")
            C.s(f"  Copy these into hackcheck.io for full password details:")
            C.s(f"{'='*64}{C.R}")
            for i, e in enumerate(p.hackcheck_list[:30], 1):
                C.s(f"  {C.WHITE}{i:>3}. {C.GREEN}{e}{C.R}")

        # DOMAIN RECON SUMMARY
        if p.domain_dns or p.domain_subdomains or p.domain_ports:
            section(f"DOMAIN RECON: {p.known_domain or 'discovered'}")
            if p.domain_subdomains:
                C.s(f"  {C.WHITE}Subdomains ({len(p.domain_subdomains)}):{C.R}")
                for sd in p.domain_subdomains[:15]:
                    C.s(f"    {C.GREEN}{sd}{C.R}")
            if p.domain_ports:
                C.s(f"  {C.WHITE}Open Ports: {C.GREEN}{', '.join(str(x) for x in sorted(p.domain_ports))}{C.R}")
            if p.domain_tech:
                C.s(f"  {C.WHITE}Technologies: {C.GREEN}{', '.join(p.domain_tech)}{C.R}")
            if p.domain_directories:
                C.s(f"  {C.WHITE}Exposed Directories:{C.R}")
                for d in p.domain_directories[:15]:
                    C.s(f"    {C.YELLOW}{d['path']} -> {d['status']}{C.R}")

        # SUMMARY
        C.s(f"\n{C.NEBULA}{C.BOLD}{'='*64}")
        C.s(f"  MISSION SUMMARY")
        C.s(f"{'='*64}{C.R}")
        stats = [
            ('Emails', len(all_emails)),
            ('Phones', len(all_phones)),
            ('Addresses', len(p.discovered_addresses)),
            ('Social Profiles', len(p.discovered_social)),
            ('Relatives', len(all_rels)),
            ('Employers', len(employers)),
            ('Schools', len(schools)),
            ('Vehicles', len(vehicles)),
            ('Properties', len(p.discovered_properties)),
            ('Court/Arrest Records', len(p.discovered_court)),
            ('Business Records', len(p.discovered_business_records)),
            ('Licenses', len(p.discovered_licenses)),
            ('Forum/Reddit Posts', len(p.discovered_forum_posts)),
            ('Web Mentions', len(p.discovered_blog_mentions)),
            ('News Articles', len(p.discovered_news)),
            ('Photos', len(p.discovered_photos)),
            ('Paste Dumps', len(p.paste_dumps)),
            ('Breaches', len(p.breaches)),
            ('Passwords Found', len(p.partial_passwords)),
            ('Total Findings', len(p.findings)),
        ]
        for label, count in stats:
            color = C.GREEN if count > 0 else C.DIM
            C.s(f"  {C.WHITE}{label:<22}: {color}{count}{C.R}")
        C.s(f"{C.NEBULA}{C.BOLD}{'='*64}{C.R}\n")

    # ================================================================== #
    #  SAVE REPORT                                                        #
    # ================================================================== #

    def save_report(self):
        p = self.p
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe = re.sub(r'[^\w]', '_', p.full_name or 'target')[:30]
        fn = f"galaxy_report_{safe}_{ts}.json"

        report = {
            'report_version': '4.1',
            'tool': 'FLLC - Galaxy Reconnaissance Suite',
            'generated': datetime.now().isoformat(),
            'subject': p.to_dict()
        }

        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        C.s(f"\n{C.GREEN}{C.BOLD}Full JSON dossier saved to: {fn}{C.R}")
        C.s(f"{C.DIM}Open in any text editor or JSON viewer for the complete data.{C.R}")
        return fn


# ============================================================================
#  MAIN
# ============================================================================

def main():
    suite = GalaxyReconSuite()
    suite.print_banner()

    if '--help' in sys.argv or '-h' in sys.argv:
        C.s(f"""
{C.CYAN}Galaxy Reconnaissance Suite v4.1 -- FULL AUTO{C.R}

Usage:
  python galaxy_recon_suite.py                  Interactive mode (recommended)
  python galaxy_recon_suite.py --interactive     Same
  python galaxy_recon_suite.py --domain <dom>   Domain-only recon

{C.YELLOW}Just provide a NAME and hit ENTER through everything else.
The tool will auto-discover vehicles, property, employment,
education, relatives, court records, and everything else.{C.R}

{C.GREEN}Double-click LAUNCH.bat for the easiest experience.{C.R}
""")
        sys.exit(0)

    if '--domain' in sys.argv:
        idx = sys.argv.index('--domain')
        if idx + 1 < len(sys.argv):
            domain = sys.argv[idx + 1]
            C.s(f"\n{C.GREEN}Domain-only recon: {domain}{C.R}\n")
            suite._phase("DOMAIN RECONNAISSANCE")
            suite._domain_recon(domain)
            suite.display_dossier()
            suite.save_report()
            return

    # Interactive (default)
    suite.interactive_interview()
    suite.smart_search()
    suite.display_dossier()
    suite.save_report()
    C.s(f"\n{C.GREEN}{C.BOLD}*** MISSION COMPLETE - RETURNING TO BASE ***{C.R}\n")


if __name__ == '__main__':
    main()
