"""
FLLC | FU PERSON - Core Security & OSINT Modules
Copyright (c) 2025-2026 FLLC. All rights reserved.

v4.0 | 2026 | Full-Spectrum Security Operations Platform

Modules:
  pentest_suite       - Full-spectrum web application penetration testing
  osint_recon_suite   - DNS/WHOIS/GeoIP/Port/Subdomain reconnaissance
  galaxy_recon_suite  - Deep intelligence aggregator (people + network + timeline)
  people_finder       - 88+ platform people search aggregator
  repo_collector      - GitHub repository scanner & secret pattern detector
  list_consolidator   - Wordlist merge/dedup/sort/analyze engine
  consolidated_lists  - Pre-built subdomain, directory, and domain wordlists
  network_sniffer     - Packet capture, ARP scanning, DNS intercept, OS fingerprinting
  tunnel_proxy        - SOCKS5 proxy, SSH tunnels, encrypted tunnels, pivot chains
  reverse_engineer    - PE/ELF analysis, string extraction, entropy, disassembly, YARA
  exploit_dev         - Shellcode, cyclic patterns, ROP gadgets, payload encoders
  cms_scanner         - WordPress/Joomla/Drupal scanning, CMS fingerprint, web shells
  voip_scanner        - SIP discovery, user enumeration, RTP analysis, SIP fuzzing
  stress_tester       - HTTP/TCP/UDP stress testing with authorization controls
  ids_evasion         - WAF detection, IDS evasion, payload mutation, fragmentation
  cve_engine          - NVD/CISA/EPSS/Exploit-DB intelligence with SQLite cache
  cve_monitor         - Live CVE monitoring daemon with alerting and digests
  quantum_crypto      - Post-quantum cryptography (Kyber/Dilithium/SPHINCS+)
  crypto_audit        - TLS scanning, weak crypto detection, quantum vulnerability assessment

Licensed under the FU PERSON Source-Available License v1.0.
Unauthorized redistribution is prohibited. See LICENSE.
"""

__version__ = "4.0"
__author__ = "FLLC | PrestonFurulie"
__license__ = "FU PERSON Source-Available License v1.0"

__all__ = [
    "pentest_suite",
    "osint_recon_suite",
    "galaxy_recon_suite",
    "people_finder",
    "repo_collector",
    "list_consolidator",
    "consolidated_lists",
    "network_sniffer",
    "tunnel_proxy",
    "reverse_engineer",
    "exploit_dev",
    "cms_scanner",
    "voip_scanner",
    "stress_tester",
    "ids_evasion",
    "cve_engine",
    "cve_monitor",
    "quantum_crypto",
    "crypto_audit",
]
