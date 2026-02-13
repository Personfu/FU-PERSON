#!/usr/bin/env python3
"""
FLLC - Repository Collector
===================================
Downloads and extracts relevant data from 13 GitHub repositories
for the USB Tri-Drive Pentest Toolkit.

Clones repos with --depth 1 (shallow) and extracts only the useful
files: website lists, service databases, tool scripts, etc.
"""

import os
import sys
import shutil
import subprocess
import json
import re
from pathlib import Path
from datetime import datetime


# ============================================================================
#  CONFIGURATION
# ============================================================================

REPOS = [
    {
        'name': 'website-lists',
        'url': 'https://github.com/Ringmast4r/website-lists.git',
        'description': 'Domain/website lists',
        'extract': 'all',  # take everything
    },
    {
        'name': 'flock-you',
        'url': 'https://github.com/colonelpanichacks/flock-you.git',
        'description': 'WiFi/device attack tools',
        'extract': 'all',
    },
    {
        'name': 'waymore',
        'url': 'https://github.com/xnl-h4ck3r/waymore.git',
        'description': 'Wayback Machine URL discovery',
        'extract': 'all',
    },
    {
        'name': 'public-apis',
        'url': 'https://github.com/public-apis/public-apis.git',
        'description': 'Public API database (1400+)',
        'extract': 'all',
    },
    {
        'name': 'nmap',
        'url': 'https://github.com/nmap/nmap.git',
        'description': 'Network scanner - extracting service/protocol data + NSE scripts',
        'extract': 'selective',
        'patterns': [
            'nmap-services',
            'nmap-protocols',
            'nmap-payloads',
            'nmap-mac-prefixes',
            'nmap-os-db',
            'nmap-service-probes',
            'nmap-rpc',
            'scripts/',
        ],
    },
    {
        'name': 'wireshark',
        'url': 'https://github.com/wireshark/wireshark.git',
        'description': 'Network analyzer - extracting OUI/manuf database',
        'extract': 'selective',
        'patterns': [
            'manuf',
            'enterprises.tsv',
            'services',
            'cfilters',
            'colorfilters',
            'dfilters',
            'smi_modules',
        ],
    },
    {
        'name': 'hydra',
        'url': 'https://github.com/hydralauncher/hydra.git',
        'description': 'Hydra launcher',
        'extract': 'all',
    },
    {
        'name': 'netcat',
        'url': 'https://github.com/diegocr/netcat.git',
        'description': 'Netcat networking utility',
        'extract': 'all',
    },
    {
        'name': 'dwarfs',
        'url': 'https://github.com/mhx/dwarfs.git',
        'description': 'DwarFS compressed filesystem',
        'extract': 'selective',
        'patterns': [
            'README.md',
            'doc/',
            'src/',
            'CMakeLists.txt',
            'include/',
        ],
    },
    {
        'name': 'erigon',
        'url': 'https://github.com/erigontech/erigon.git',
        'description': 'Ethereum execution client',
        'extract': 'selective',
        'patterns': [
            'README.md',
            'cmd/',
            'core/',
            'Makefile',
            'go.mod',
            'go.sum',
        ],
    },
    {
        'name': 'Tower-Hunter',
        'url': 'https://github.com/Ringmast4r/Tower-Hunter.git',
        'description': 'Cell tower hunting scripts',
        'extract': 'all',
    },
    {
        'name': 'GNSS',
        'url': 'https://github.com/Ringmast4r/GNSS.git',
        'description': 'GNSS/GPS tools',
        'extract': 'all',
    },
    {
        'name': 'shannon',
        'url': 'https://github.com/KeygraphHQ/shannon.git',
        'description': 'Shannon entropy analysis tool',
        'extract': 'all',
    },
]

# ============================================================================
#  COLORS
# ============================================================================

class C:
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    BOLD   = '\033[1m'
    R      = '\033[0m'


# ============================================================================
#  COLLECTOR
# ============================================================================

class RepoCollector:
    def __init__(self, output_dir=None):
        self.base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.output_dir = Path(output_dir) if output_dir else self.base_dir / 'repo_downloads'
        self.clone_dir = self.output_dir / '_clones'
        self.extracted_dir = self.output_dir / 'extracted'
        self.stats = {
            'cloned': 0,
            'failed': 0,
            'extracted_files': 0,
            'total_size_mb': 0,
        }

    def banner(self):
        print(f"""
{C.CYAN}{C.BOLD}========================================================
  FLLC - REPOSITORY COLLECTOR
  Downloading 13 GitHub Repos for USB Tri-Drive Toolkit
========================================================{C.R}
""")

    def ensure_dirs(self):
        """Create output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.clone_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_dir.mkdir(parents=True, exist_ok=True)

    def clone_repo(self, repo):
        """Shallow clone a single repository."""
        name = repo['name']
        url = repo['url']
        dest = self.clone_dir / name

        if dest.exists():
            print(f"  {C.YELLOW}[SKIP]{C.R} {name} already cloned")
            return True

        print(f"  {C.CYAN}[CLONE]{C.R} {name} <- {url}")
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', url, str(dest)],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print(f"  {C.GREEN}[OK]{C.R} {name} cloned successfully")
                self.stats['cloned'] += 1
                return True
            else:
                print(f"  {C.RED}[FAIL]{C.R} {name}: {result.stderr.strip()}")
                self.stats['failed'] += 1
                return False
        except subprocess.TimeoutExpired:
            print(f"  {C.RED}[TIMEOUT]{C.R} {name}: clone took too long (>300s)")
            self.stats['failed'] += 1
            return False
        except FileNotFoundError:
            print(f"  {C.RED}[ERROR]{C.R} git not found. Install git and try again.")
            sys.exit(1)

    def extract_repo(self, repo):
        """Extract relevant files from a cloned repo."""
        name = repo['name']
        src = self.clone_dir / name
        dst = self.extracted_dir / name

        if not src.exists():
            print(f"  {C.RED}[SKIP]{C.R} {name} not cloned, cannot extract")
            return

        dst.mkdir(parents=True, exist_ok=True)

        if repo['extract'] == 'all':
            # Copy everything except .git
            print(f"  {C.CYAN}[EXTRACT]{C.R} {name} -> copying all files")
            count = self._copy_tree(src, dst, exclude=['.git'])
            print(f"  {C.GREEN}[OK]{C.R} {name}: {count} files extracted")
        elif repo['extract'] == 'selective':
            print(f"  {C.CYAN}[EXTRACT]{C.R} {name} -> selective extraction")
            count = 0
            for pattern in repo.get('patterns', []):
                src_path = src / pattern
                if src_path.is_file():
                    dst_file = dst / pattern
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src_path), str(dst_file))
                    count += 1
                elif src_path.is_dir():
                    dst_sub = dst / pattern
                    count += self._copy_tree(src_path, dst_sub, exclude=['.git'])
                else:
                    # Try glob
                    for match in src.rglob(pattern):
                        if '.git' not in str(match):
                            rel = match.relative_to(src)
                            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
                            if match.is_file():
                                shutil.copy2(str(match), str(dst / rel))
                                count += 1
            print(f"  {C.GREEN}[OK]{C.R} {name}: {count} files extracted")

        self.stats['extracted_files'] += self._count_files(dst)

    def _copy_tree(self, src, dst, exclude=None):
        """Copy directory tree, excluding specified dirs."""
        exclude = exclude or []
        count = 0
        for item in src.rglob('*'):
            # Skip excluded directories
            skip = False
            for ex in exclude:
                if ex in item.parts:
                    skip = True
                    break
            if skip:
                continue

            if item.is_file():
                rel = item.relative_to(src)
                dest_file = dst / rel
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(str(item), str(dest_file))
                    count += 1
                except (PermissionError, OSError):
                    pass
        return count

    def _count_files(self, path):
        """Count files in directory."""
        if not path.exists():
            return 0
        return sum(1 for _ in path.rglob('*') if _.is_file())

    def _dir_size_mb(self, path):
        """Get directory size in MB."""
        if not path.exists():
            return 0
        total = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
        return total / (1024 * 1024)

    def extract_website_lists(self):
        """
        Scan all extracted repos for files that look like website/domain lists
        and collect them into a unified location.
        """
        print(f"\n{C.CYAN}{C.BOLD}--- Scanning for website/domain lists ---{C.R}")
        lists_dir = self.extracted_dir / '_website_lists'
        lists_dir.mkdir(parents=True, exist_ok=True)

        list_extensions = {'.txt', '.csv', '.lst', '.list', '.conf', '.cfg'}
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}', re.MULTILINE
        )

        found_lists = []

        for repo_dir in self.extracted_dir.iterdir():
            if repo_dir.name.startswith('_') or not repo_dir.is_dir():
                continue
            for f in repo_dir.rglob('*'):
                if not f.is_file():
                    continue
                if f.suffix.lower() in list_extensions or 'list' in f.name.lower() or 'domain' in f.name.lower() or 'url' in f.name.lower() or 'site' in f.name.lower():
                    try:
                        content = f.read_text(encoding='utf-8', errors='ignore')
                        # Check if file actually contains domains/URLs
                        if domain_pattern.search(content) or 'http' in content.lower():
                            dest = lists_dir / f'{repo_dir.name}_{f.name}'
                            shutil.copy2(str(f), str(dest))
                            found_lists.append(str(dest))
                    except Exception:
                        pass

        print(f"  {C.GREEN}[OK]{C.R} Found {len(found_lists)} website/domain list files")
        return found_lists

    def extract_api_list(self):
        """
        Extract the public-apis README into a structured list.
        """
        print(f"\n{C.CYAN}{C.BOLD}--- Extracting public API list ---{C.R}")
        readme = self.extracted_dir / 'public-apis' / 'README.md'
        if not readme.exists():
            print(f"  {C.YELLOW}[SKIP]{C.R} public-apis README not found")
            return []

        content = readme.read_text(encoding='utf-8', errors='ignore')

        # Extract API entries from the markdown table
        # Format: | API Name | Description | Auth | HTTPS | CORS | Link |
        apis = []
        url_pattern = re.compile(r'https?://[^\s\)|\]]+')
        for line in content.split('\n'):
            if '|' in line and 'http' in line.lower():
                urls = url_pattern.findall(line)
                cols = [c.strip() for c in line.split('|')]
                if len(cols) >= 3:
                    api_entry = {
                        'name': cols[1] if len(cols) > 1 else '',
                        'description': cols[2] if len(cols) > 2 else '',
                        'urls': urls,
                    }
                    apis.append(api_entry)

        # Save extracted APIs
        api_dir = self.extracted_dir / '_api_endpoints'
        api_dir.mkdir(parents=True, exist_ok=True)

        # Save as JSON
        with open(api_dir / 'public_apis.json', 'w', encoding='utf-8') as f:
            json.dump(apis, f, indent=2)

        # Save URLs only
        all_urls = []
        for api in apis:
            all_urls.extend(api['urls'])
        with open(api_dir / 'api_urls.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(set(all_urls))))

        print(f"  {C.GREEN}[OK]{C.R} Extracted {len(apis)} API entries, {len(set(all_urls))} unique URLs")
        return apis

    def extract_nmap_services(self):
        """Extract nmap service/port database."""
        print(f"\n{C.CYAN}{C.BOLD}--- Extracting nmap service database ---{C.R}")
        services_file = self.extracted_dir / 'nmap' / 'nmap-services'
        if not services_file.exists():
            print(f"  {C.YELLOW}[SKIP]{C.R} nmap-services not found")
            return []

        services = []
        content = services_file.read_text(encoding='utf-8', errors='ignore')
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    services.append({
                        'name': parts[0],
                        'port_proto': parts[1],
                    })

        svc_dir = self.extracted_dir / '_services'
        svc_dir.mkdir(parents=True, exist_ok=True)
        with open(svc_dir / 'nmap_services.json', 'w', encoding='utf-8') as f:
            json.dump(services, f, indent=2)

        print(f"  {C.GREEN}[OK]{C.R} Extracted {len(services)} service definitions")
        return services

    def cleanup_clones(self):
        """Remove raw clone directories to save space."""
        print(f"\n{C.CYAN}[CLEANUP]{C.R} Removing raw clone directories...")
        if self.clone_dir.exists():
            shutil.rmtree(str(self.clone_dir), ignore_errors=True)
        print(f"  {C.GREEN}[OK]{C.R} Clones removed")

    def generate_manifest(self):
        """Generate a manifest of all extracted content."""
        manifest = {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'repos': [],
        }

        for repo_dir in sorted(self.extracted_dir.iterdir()):
            if not repo_dir.is_dir():
                continue
            files = list(repo_dir.rglob('*'))
            file_list = [str(f.relative_to(self.extracted_dir)) for f in files if f.is_file()]
            size_mb = self._dir_size_mb(repo_dir)
            manifest['repos'].append({
                'name': repo_dir.name,
                'files': len(file_list),
                'size_mb': round(size_mb, 2),
            })
            self.stats['total_size_mb'] += size_mb

        self.stats['total_size_mb'] = round(self.stats['total_size_mb'], 2)

        manifest_path = self.output_dir / 'manifest.json'
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

        print(f"\n{C.GREEN}{C.BOLD}Manifest saved to {manifest_path}{C.R}")
        return manifest

    def run(self, cleanup_clones=True):
        """Run the full collection pipeline."""
        self.banner()
        self.ensure_dirs()

        # Phase 1: Clone all repos
        print(f"{C.BOLD}PHASE 1: Cloning {len(REPOS)} repositories...{C.R}\n")
        for repo in REPOS:
            self.clone_repo(repo)

        # Phase 2: Extract relevant files
        print(f"\n{C.BOLD}PHASE 2: Extracting relevant files...{C.R}\n")
        for repo in REPOS:
            self.extract_repo(repo)

        # Phase 3: Build specialized extracts
        print(f"\n{C.BOLD}PHASE 3: Building specialized extracts...{C.R}")
        self.extract_website_lists()
        self.extract_api_list()
        self.extract_nmap_services()

        # Phase 4: Cleanup
        if cleanup_clones:
            self.cleanup_clones()

        # Phase 5: Generate manifest
        print(f"\n{C.BOLD}PHASE 4: Generating manifest...{C.R}")
        manifest = self.generate_manifest()

        # Summary
        print(f"""
{C.GREEN}{C.BOLD}========================================================
  COLLECTION COMPLETE
========================================================{C.R}
  Repos cloned:      {self.stats['cloned']}
  Repos failed:      {self.stats['failed']}
  Files extracted:    {self.stats['extracted_files']}
  Total size:         {self.stats['total_size_mb']} MB
  Output directory:   {self.output_dir}
""")
        return manifest


# ============================================================================
#  MAIN
# ============================================================================

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='FLLC - Repository Collector')
    parser.add_argument('--output', '-o', default=None,
                        help='Output directory (default: ./repo_downloads)')
    parser.add_argument('--keep-clones', action='store_true',
                        help='Keep raw git clones (don\'t cleanup)')
    args = parser.parse_args()

    collector = RepoCollector(output_dir=args.output)
    collector.run(cleanup_clones=not args.keep_clones)
