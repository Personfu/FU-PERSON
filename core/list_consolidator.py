#!/usr/bin/env python3
"""
FLLC - List Consolidator
================================
Merges all extracted website lists, domain lists, API endpoints,
service databases, and directory wordlists into unified master files.

Reads from repo_downloads/extracted/ and produces master list files.
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse


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
#  BUILT-IN WORDLISTS (baseline that gets merged with extracted data)
# ============================================================================

BUILTIN_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod', 'production',
    'api', 'api2', 'api3', 'v1', 'v2', 'v3', 'portal', 'vpn', 'remote', 'cloud',
    'app', 'mobile', 'm', 'secure', 'ssl', 'webmail', 'email', 'smtp', 'pop',
    'ns1', 'ns2', 'dns', 'cdn', 'static', 'assets', 'media', 'images', 'img',
    'blog', 'news', 'forum', 'shop', 'store', 'cart', 'checkout', 'payment',
    'account', 'accounts', 'user', 'users', 'login', 'signin', 'auth', 'authz',
    'dashboard', 'panel', 'admin', 'administrator', 'root', 'sysadmin',
    'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
    'backup', 'backups', 'archive', 'old', 'legacy', 'temp', 'tmp',
    'test', 'testing', 'qa', 'staging', 'stage', 'dev', 'development',
    'internal', 'intranet', 'private', 'secure', 'vpn', 'remote',
    'monitor', 'monitoring', 'status', 'health', 'metrics', 'stats',
    'git', 'svn', 'svc', 'service', 'services', 'api-gateway',
    'order', 'orders', 'tracking', 'track', 'shipment', 'shipping',
    'customer', 'customers', 'client', 'clients',
    'support', 'help', 'docs', 'documentation', 'wiki', 'knowledge',
    'cms', 'content', 'upload', 'uploads', 'download', 'downloads',
    'files', 'file', 'storage', 's3', 'bucket', 'buckets',
    'proxy', 'gateway', 'lb', 'loadbalancer', 'edge', 'node',
    'jenkins', 'ci', 'cd', 'build', 'deploy', 'release',
    'grafana', 'kibana', 'elastic', 'logstash', 'prometheus',
    'docker', 'k8s', 'kubernetes', 'container', 'registry',
    'nexus', 'sonar', 'jira', 'confluence', 'bitbucket',
    'gitlab', 'github', 'repo', 'repos', 'code',
    'vault', 'secrets', 'config', 'configuration', 'settings',
    'sso', 'idp', 'identity', 'oauth', 'saml', 'ldap', 'ad',
    'exchange', 'owa', 'autodiscover', 'mapi', 'ews',
    'sharepoint', 'onedrive', 'teams', 'office',
    'crm', 'erp', 'sap', 'salesforce', 'hubspot',
    'aws', 'azure', 'gcp', 'heroku', 'digitalocean',
    'sandbox', 'demo', 'preview', 'beta', 'alpha', 'canary',
    'web', 'www2', 'www3', 'site', 'sites', 'home',
    'mx', 'mx1', 'mx2', 'pop3', 'imap',
    'sftp', 'ssh', 'rdp', 'vnc', 'telnet',
    'ntp', 'time', 'clock', 'snmp',
    'radius', 'tacacs', 'syslog', 'log', 'logs',
    'waf', 'firewall', 'ids', 'ips', 'siem',
    'dmz', 'nat', 'lan', 'wan', 'mgmt', 'management',
    'pki', 'ca', 'cert', 'certs', 'certificates',
    'sql', 'nosql', 'graphql', 'rest', 'soap', 'grpc',
    'ws', 'websocket', 'socket', 'stream', 'streaming',
    'data', 'datalake', 'datawarehouse', 'etl', 'pipeline',
    'ml', 'ai', 'model', 'predict', 'analytics',
    'pay', 'billing', 'invoice', 'subscription',
    'chat', 'messaging', 'notify', 'notification', 'push',
    'search', 'index', 'solr', 'elasticsearch',
    'cache', 'memcached', 'varnish', 'cloudflare',
    'wordpress', 'wp', 'drupal', 'joomla', 'magento',
    'cpanel', 'plesk', 'whm', 'webmin',
    'phpmyadmin', 'pma', 'adminer', 'pgadmin',
]

BUILTIN_DIRECTORIES = [
    '/.env', '/.git', '/.git/config', '/.git/HEAD', '/.gitignore',
    '/admin', '/login', '/dashboard', '/api', '/api/v1', '/api/v2',
    '/config', '/backup', '/backups', '/test', '/dev', '/phpinfo.php',
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
    '/.htaccess', '/web.config', '/crossdomain.xml',
    '/swagger', '/swagger-ui', '/swagger-ui.html', '/api-docs',
    '/api/docs', '/graphql', '/graphiql',
    '/.aws', '/.aws/credentials', '/.docker', '/docker-compose.yml',
    '/orders', '/tracking', '/users', '/customers', '/account',
    '/server-status', '/server-info', '/status', '/health', '/healthcheck',
    '/console', '/debug', '/trace', '/actuator', '/actuator/health',
    '/actuator/env', '/actuator/beans', '/actuator/configprops',
    '/metrics', '/prometheus', '/grafana',
    '/phpmyadmin', '/pma', '/adminer', '/mysql', '/pgadmin',
    '/cgi-bin', '/cgi-bin/test', '/scripts',
    '/includes', '/include', '/inc', '/common', '/shared',
    '/uploads', '/upload', '/files', '/documents', '/docs',
    '/images', '/img', '/assets', '/static', '/media', '/css', '/js',
    '/temp', '/tmp', '/cache', '/logs', '/log',
    '/private', '/internal', '/secret', '/hidden',
    '/node_modules', '/vendor', '/packages', '/lib',
    '/xmlrpc.php', '/wp-json', '/wp-cron.php',
    '/feed', '/rss', '/atom', '/sitemap_index.xml',
    '/.svn', '/.svn/entries', '/.hg', '/.bzr',
    '/.DS_Store', '/Thumbs.db', '/desktop.ini',
    '/composer.json', '/package.json', '/Gemfile', '/requirements.txt',
    '/Dockerfile', '/Vagrantfile', '/Makefile', '/Gruntfile.js',
    '/.travis.yml', '/.circleci', '/.github',
    '/readme.md', '/README.md', '/CHANGELOG.md', '/LICENSE',
    '/info.php', '/phpinfo', '/info', '/about',
    '/register', '/signup', '/forgot-password', '/reset-password',
    '/logout', '/signout', '/profile', '/settings',
    '/search', '/help', '/faq', '/terms', '/privacy',
    '/contact', '/about', '/pricing', '/features',
    '/blog', '/news', '/press', '/careers', '/jobs',
    '/download', '/downloads', '/install',
    '/cPanel', '/webmail', '/cpanel',
    '/elmah.axd', '/trace.axd', '/errors',
    '/.well-known/openid-configuration', '/.well-known/jwks.json',
    '/oauth/token', '/oauth/authorize', '/token', '/auth/login',
    '/api/login', '/api/register', '/api/users', '/api/admin',
    '/wp-content/uploads', '/wp-content/plugins', '/wp-content/themes',
    '/administrator', '/admin/login', '/manager', '/manager/html',
    '/jenkins', '/hudson', '/bamboo', '/teamcity',
    '/sonar', '/nexus', '/artifactory',
    '/jira', '/confluence', '/bitbucket',
    '/kibana', '/elasticsearch', '/_cat/indices',
    '/_cluster/health', '/_nodes', '/_search',
    '/solr', '/solr/admin', '/solr/select',
    '/redis', '/memcached', '/mongo',
    '/socket.io', '/sockjs', '/ws',
    '/cdn-cgi', '/cf-workers',
]

# ============================================================================
#  CONSOLIDATOR
# ============================================================================

class ListConsolidator:
    def __init__(self, extracted_dir=None, output_dir=None):
        self.base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.extracted_dir = Path(extracted_dir) if extracted_dir else self.base_dir / 'repo_downloads' / 'extracted'
        self.output_dir = Path(output_dir) if output_dir else self.base_dir / 'consolidated_lists'
        self.stats = {}

    def banner(self):
        print(f"""
{C.CYAN}{C.BOLD}========================================================
  FLLC - LIST CONSOLIDATOR
  Merging all extracted data into master lists
========================================================{C.R}
""")

    def ensure_dirs(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _extract_domains_from_file(self, filepath):
        """Extract domain names from a file."""
        domains = set()
        domain_re = re.compile(
            r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
            r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})'
        )
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            for match in domain_re.finditer(content):
                domain = match.group(1).lower().strip('.')
                if len(domain) > 3 and '.' in domain:
                    domains.add(domain)
        except Exception:
            pass
        return domains

    def _extract_urls_from_file(self, filepath):
        """Extract full URLs from a file."""
        urls = set()
        url_re = re.compile(r'https?://[^\s<>"\'\)\]]+')
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            for match in url_re.finditer(content):
                url = match.group(0).rstrip('.,;:')
                urls.add(url)
        except Exception:
            pass
        return urls

    def _extract_subdomains_from_file(self, filepath):
        """Extract potential subdomain prefixes from a file."""
        subs = set()
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    # If line looks like a bare word (subdomain prefix)
                    if re.match(r'^[a-z][a-z0-9-]{0,62}$', line, re.IGNORECASE):
                        subs.add(line.lower())
                    # If line is a full domain, extract subdomain part
                    elif '.' in line:
                        parts = line.split('.')
                        if len(parts) >= 3:
                            subs.add(parts[0].lower())
        except Exception:
            pass
        return subs

    def build_master_domains(self):
        """Build master_domains.txt from all sources."""
        print(f"\n{C.CYAN}[BUILD]{C.R} master_domains.txt")
        all_domains = set()

        # Scan all extracted repos
        if self.extracted_dir.exists():
            for f in self.extracted_dir.rglob('*'):
                if f.is_file() and f.suffix in ('.txt', '.csv', '.lst', '.list', '.md', '.conf'):
                    all_domains.update(self._extract_domains_from_file(f))

        # Filter out garbage
        valid = set()
        for d in all_domains:
            parts = d.split('.')
            tld = parts[-1]
            if len(tld) >= 2 and len(tld) <= 12 and tld.isalpha():
                if not any(c in d for c in ['..', '--', ' ']):
                    valid.add(d)

        domains_sorted = sorted(valid)
        outfile = self.output_dir / 'master_domains.txt'
        outfile.write_text('\n'.join(domains_sorted), encoding='utf-8')
        self.stats['domains'] = len(domains_sorted)
        print(f"  {C.GREEN}[OK]{C.R} {len(domains_sorted)} unique domains -> {outfile}")

    def build_master_subdomains(self):
        """Build master_subdomains.txt from all sources."""
        print(f"\n{C.CYAN}[BUILD]{C.R} master_subdomains.txt")
        all_subs = set(BUILTIN_SUBDOMAINS)

        # Scan extracted repos for subdomain-like content
        if self.extracted_dir.exists():
            for f in self.extracted_dir.rglob('*'):
                if f.is_file() and ('subdomain' in f.name.lower() or
                                     'sub' in f.name.lower() or
                                     'wordlist' in f.name.lower() or
                                     'prefix' in f.name.lower()):
                    all_subs.update(self._extract_subdomains_from_file(f))

            # Also pull subdomains from domain lists
            for f in self.extracted_dir.rglob('*'):
                if f.is_file() and f.suffix in ('.txt', '.lst', '.list'):
                    try:
                        content = f.read_text(encoding='utf-8', errors='ignore')
                        for line in content.split('\n'):
                            line = line.strip()
                            parts = line.split('.')
                            if len(parts) >= 3:
                                sub = parts[0].lower()
                                if re.match(r'^[a-z][a-z0-9-]{0,62}$', sub):
                                    all_subs.add(sub)
                    except Exception:
                        pass

        subs_sorted = sorted(all_subs)
        outfile = self.output_dir / 'master_subdomains.txt'
        outfile.write_text('\n'.join(subs_sorted), encoding='utf-8')
        self.stats['subdomains'] = len(subs_sorted)
        print(f"  {C.GREEN}[OK]{C.R} {len(subs_sorted)} unique subdomains -> {outfile}")

    def build_master_api_endpoints(self):
        """Build master_api_endpoints.txt from public-apis and other sources."""
        print(f"\n{C.CYAN}[BUILD]{C.R} master_api_endpoints.txt")
        all_urls = set()

        # From extracted API data
        api_json = self.extracted_dir / '_api_endpoints' / 'public_apis.json'
        if api_json.exists():
            try:
                apis = json.loads(api_json.read_text(encoding='utf-8'))
                for api in apis:
                    all_urls.update(api.get('urls', []))
            except Exception:
                pass

        api_urls = self.extracted_dir / '_api_endpoints' / 'api_urls.txt'
        if api_urls.exists():
            try:
                content = api_urls.read_text(encoding='utf-8', errors='ignore')
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('http'):
                        all_urls.add(line)
            except Exception:
                pass

        # Scan all repos for API-like URLs
        if self.extracted_dir.exists():
            for f in self.extracted_dir.rglob('*'):
                if f.is_file() and ('api' in f.name.lower() or
                                     'endpoint' in f.name.lower()):
                    all_urls.update(self._extract_urls_from_file(f))

        urls_sorted = sorted(all_urls)
        outfile = self.output_dir / 'master_api_endpoints.txt'
        outfile.write_text('\n'.join(urls_sorted), encoding='utf-8')
        self.stats['api_endpoints'] = len(urls_sorted)
        print(f"  {C.GREEN}[OK]{C.R} {len(urls_sorted)} API endpoints -> {outfile}")

    def build_master_services(self):
        """Build master_services.txt from nmap data."""
        print(f"\n{C.CYAN}[BUILD]{C.R} master_services.txt")
        services = []

        svc_json = self.extracted_dir / '_services' / 'nmap_services.json'
        if svc_json.exists():
            try:
                data = json.loads(svc_json.read_text(encoding='utf-8'))
                services = data
            except Exception:
                pass

        # Also try raw nmap-services file
        nmap_svc = self.extracted_dir / 'nmap' / 'nmap-services'
        if nmap_svc.exists():
            try:
                content = nmap_svc.read_text(encoding='utf-8', errors='ignore')
                outfile = self.output_dir / 'master_services.txt'
                outfile.write_text(content, encoding='utf-8')
                line_count = len([l for l in content.split('\n') if l.strip() and not l.startswith('#')])
                self.stats['services'] = line_count
                print(f"  {C.GREEN}[OK]{C.R} {line_count} service definitions -> {outfile}")
                return
            except Exception:
                pass

        # Fallback: write from JSON
        lines = []
        for svc in services:
            lines.append(f"{svc['name']}\t{svc['port_proto']}")

        outfile = self.output_dir / 'master_services.txt'
        outfile.write_text('\n'.join(lines), encoding='utf-8')
        self.stats['services'] = len(lines)
        print(f"  {C.GREEN}[OK]{C.R} {len(lines)} service definitions -> {outfile}")

    def build_master_directories(self):
        """Build master_directories.txt - expanded directory bruteforce wordlist."""
        print(f"\n{C.CYAN}[BUILD]{C.R} master_directories.txt")
        all_dirs = set(BUILTIN_DIRECTORIES)

        # Scan repos for directory/path wordlists
        if self.extracted_dir.exists():
            for f in self.extracted_dir.rglob('*'):
                if f.is_file() and ('dir' in f.name.lower() or
                                     'path' in f.name.lower() or
                                     'wordlist' in f.name.lower() or
                                     'brute' in f.name.lower() or
                                     'fuzz' in f.name.lower()):
                    try:
                        content = f.read_text(encoding='utf-8', errors='ignore')
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if line.startswith('/'):
                                    all_dirs.add(line)
                                elif re.match(r'^[a-zA-Z0-9_./-]+$', line) and len(line) < 200:
                                    all_dirs.add('/' + line)
                    except Exception:
                        pass

        dirs_sorted = sorted(all_dirs)
        outfile = self.output_dir / 'master_directories.txt'
        outfile.write_text('\n'.join(dirs_sorted), encoding='utf-8')
        self.stats['directories'] = len(dirs_sorted)
        print(f"  {C.GREEN}[OK]{C.R} {len(dirs_sorted)} directory paths -> {outfile}")

    def build_python_lists_module(self):
        """
        Generate a Python module with the consolidated lists
        that can be imported by pentest_suite.py and osint_recon_suite.py.
        """
        print(f"\n{C.CYAN}[BUILD]{C.R} consolidated_lists.py (importable module)")

        # Read the generated lists
        domains_file = self.output_dir / 'master_domains.txt'
        subs_file = self.output_dir / 'master_subdomains.txt'
        dirs_file = self.output_dir / 'master_directories.txt'

        domains = []
        subs = []
        dirs = []

        if domains_file.exists():
            domains = [l.strip() for l in domains_file.read_text(encoding='utf-8').split('\n') if l.strip()]
        if subs_file.exists():
            subs = [l.strip() for l in subs_file.read_text(encoding='utf-8').split('\n') if l.strip()]
        if dirs_file.exists():
            dirs = [l.strip() for l in dirs_file.read_text(encoding='utf-8').split('\n') if l.strip()]

        module_path = self.base_dir / 'consolidated_lists.py'
        with open(module_path, 'w', encoding='utf-8') as f:
            f.write('#!/usr/bin/env python3\n')
            f.write('"""\n')
            f.write('FLLC - Consolidated Lists Module\n')
            f.write(f'Auto-generated on {datetime.now().isoformat()}\n')
            f.write(f'Domains: {len(domains)} | Subdomains: {len(subs)} | Directories: {len(dirs)}\n')
            f.write('"""\n\n')

            # Subdomains list (most important for integration)
            f.write(f'# {len(subs)} subdomain prefixes\n')
            f.write('SUBDOMAINS = [\n')
            for s in subs:
                f.write(f'    {repr(s)},\n')
            f.write(']\n\n')

            # Directory paths
            f.write(f'# {len(dirs)} directory/path entries\n')
            f.write('DIRECTORIES = [\n')
            for d in dirs:
                f.write(f'    {repr(d)},\n')
            f.write(']\n\n')

            # Domains (truncate if huge)
            if len(domains) > 10000:
                f.write(f'# {len(domains)} domains (first 10000 included, full list in master_domains.txt)\n')
                domains = domains[:10000]
            else:
                f.write(f'# {len(domains)} domains\n')
            f.write('DOMAINS = [\n')
            for d in domains:
                f.write(f'    {repr(d)},\n')
            f.write(']\n')

        print(f"  {C.GREEN}[OK]{C.R} Module written to {module_path}")

    def run(self):
        """Run the full consolidation pipeline."""
        self.banner()
        self.ensure_dirs()

        self.build_master_domains()
        self.build_master_subdomains()
        self.build_master_api_endpoints()
        self.build_master_services()
        self.build_master_directories()
        self.build_python_lists_module()

        # Summary
        print(f"""
{C.GREEN}{C.BOLD}========================================================
  CONSOLIDATION COMPLETE
========================================================{C.R}
  Domains:          {self.stats.get('domains', 0)}
  Subdomains:       {self.stats.get('subdomains', 0)}
  API Endpoints:    {self.stats.get('api_endpoints', 0)}
  Services:         {self.stats.get('services', 0)}
  Directories:      {self.stats.get('directories', 0)}
  Output:           {self.output_dir}
""")


# ============================================================================
#  MAIN
# ============================================================================

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='FLLC - List Consolidator')
    parser.add_argument('--extracted', '-e', default=None,
                        help='Extracted repos directory (default: ./repo_downloads/extracted)')
    parser.add_argument('--output', '-o', default=None,
                        help='Output directory for master lists (default: ./consolidated_lists)')
    args = parser.parse_args()

    consolidator = ListConsolidator(extracted_dir=args.extracted, output_dir=args.output)
    consolidator.run()
