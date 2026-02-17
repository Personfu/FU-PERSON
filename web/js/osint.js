/**
 * FU PERSON OSINT Finder — Real OSINT Search Engine
 * All searches use real public APIs. No mocks. No placeholders.
 */

class OSINTSearch {
    constructor() {
        this.resultsEl = document.getElementById('results-content');
        this.isSearching = false;
        this.lastResults = null;
        this.lastType = null;
        this.lastQuery = null;
    }

    // ── LOADING ANIMATION ──────────────────────────────────
    showLoading(type, query) {
        if (!this.resultsEl) return;
        const frames = ['|', '/', '-', '\\'];
        let i = 0;
        this.resultsEl.innerHTML =
            `<span class="term-prompt">root@fllc:~$</span> osint search ${type} "${this._esc(query)}"\n\n` +
            `<span class="term-info">[*] Initializing OSINT modules...</span>\n` +
            `<span class="term-info">[*] Querying public databases...</span>\n\n` +
            `<span id="loading-spinner" class="term-success">[${frames[0]}] Searching...</span>`;
        this._spinnerInterval = setInterval(() => {
            i = (i + 1) % frames.length;
            const spinner = document.getElementById('loading-spinner');
            if (spinner) spinner.textContent = `[${frames[i]}] Searching...`;
        }, 120);
    }

    stopLoading() {
        if (this._spinnerInterval) {
            clearInterval(this._spinnerInterval);
            this._spinnerInterval = null;
        }
    }

    _esc(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    _link(url, text) {
        return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="term-link">${this._esc(text || url)}</a>`;
    }

    // ── DOMAIN SEARCH (real DNS + RDAP) ────────────────────
    async searchDomain(domain) {
        domain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

        const result = {
            type: 'domain',
            query: domain,
            dns: { A: [], AAAA: [], MX: [], NS: [], TXT: [], CNAME: [] },
            whois: null,
            subdomains: [],
            techStack: [],
            robotsTxt: null,
            headers: null
        };

        const dnsTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'];
        const dnsPromises = dnsTypes.map(async (type) => {
            try {
                const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
                const json = await resp.json();
                if (json.Answer) {
                    result.dns[type] = json.Answer.map(a => {
                        let val = a.data;
                        if (type === 'MX') {
                            const parts = val.split(' ');
                            val = parts.length > 1 ? `${parts[1]} (priority: ${parts[0]})` : val;
                        }
                        return val;
                    });
                }
            } catch (e) {
                result.dns[type] = [`Error: ${e.message}`];
            }
        });

        const whoisPromise = (async () => {
            try {
                const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
                if (resp.ok) {
                    const json = await resp.json();
                    result.whois = {
                        name: json.ldhName || domain,
                        status: (json.status || []).join(', ') || 'N/A',
                        events: (json.events || []).map(e => `${e.eventAction}: ${e.eventDate}`),
                        nameservers: (json.nameservers || []).map(ns => ns.ldhName || ns.unicodeName || 'N/A'),
                        registrar: 'N/A',
                        entities: []
                    };
                    if (json.entities && json.entities.length > 0) {
                        json.entities.forEach(ent => {
                            const roles = (ent.roles || []).join(', ');
                            let name = 'N/A';
                            if (ent.vcardArray && ent.vcardArray[1]) {
                                const fnEntry = ent.vcardArray[1].find(v => v[0] === 'fn');
                                if (fnEntry) name = fnEntry[3];
                            }
                            if (ent.handle) {
                                result.whois.entities.push({ handle: ent.handle, roles, name });
                            }
                            if (roles.includes('registrar') && name !== 'N/A') {
                                result.whois.registrar = name;
                            }
                        });
                    }
                }
            } catch (e) {
                result.whois = { error: e.message };
            }
        })();

        const subdomainPrefixes = ['www', 'mail', 'api', 'ftp', 'dev', 'staging', 'admin', 'vpn', 'cdn', 'blog', 'app', 'portal', 'shop', 'store', 'test', 'ns1', 'ns2', 'mx', 'smtp', 'imap', 'pop'];
        const subdomainPromise = Promise.allSettled(
            subdomainPrefixes.map(async (sub) => {
                try {
                    const resp = await fetch(`https://dns.google/resolve?name=${sub}.${domain}&type=A`);
                    const json = await resp.json();
                    if (json.Answer && json.Answer.length > 0) {
                        result.subdomains.push({
                            name: `${sub}.${domain}`,
                            ip: json.Answer[0].data
                        });
                    }
                } catch (_) { /* skip */ }
            })
        );

        const techPromise = (async () => {
            try {
                const resp = await fetch(`https://${domain}`, { mode: 'no-cors', redirect: 'follow' });
                const serverHeader = resp.headers.get('server');
                const poweredBy = resp.headers.get('x-powered-by');
                const via = resp.headers.get('via');
                const contentType = resp.headers.get('content-type');
                if (serverHeader) result.techStack.push(`Server: ${serverHeader}`);
                if (poweredBy) result.techStack.push(`X-Powered-By: ${poweredBy}`);
                if (via) result.techStack.push(`Via: ${via}`);
                if (contentType) result.techStack.push(`Content-Type: ${contentType}`);
                result.headers = {
                    server: serverHeader,
                    poweredBy: poweredBy,
                    via: via
                };
            } catch (_) {
                result.techStack.push('Could not fetch headers (CORS restricted)');
            }
        })();

        const robotsPromise = (async () => {
            try {
                const resp = await fetch(`https://${domain}/robots.txt`, { mode: 'no-cors' });
                if (resp.type === 'opaque' || resp.ok) {
                    result.robotsTxt = 'Exists (check manually)';
                }
            } catch (_) {
                result.robotsTxt = 'Not accessible';
            }
        })();

        await Promise.allSettled([...dnsPromises, whoisPromise, subdomainPromise, techPromise, robotsPromise]);

        this.lastResults = result;
        this.lastType = 'domain';
        this.lastQuery = domain;
        return result;
    }

    // ── IP SEARCH (real geolocation) ───────────────────────
    async searchIP(ip) {
        ip = ip.trim();
        const result = {
            type: 'ip',
            query: ip,
            geo: null,
            links: {}
        };

        try {
            const resp = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
            const json = await resp.json();
            if (json.success !== false) {
                result.geo = {
                    status: 'success',
                    country: json.country,
                    countryCode: json.country_code,
                    region: json.region_code,
                    regionName: json.region,
                    city: json.city,
                    zip: json.postal,
                    lat: json.latitude,
                    lon: json.longitude,
                    timezone: json.timezone?.id || json.timezone,
                    isp: json.connection?.isp || json.isp || '',
                    org: json.connection?.org || json.org || '',
                    as: json.connection?.asn ? `AS${json.connection.asn}` : '',
                    asname: json.connection?.domain || '',
                    reverse: json.reverse || '',
                    query: json.ip || ip
                };
            } else {
                result.geo = { error: json.message || 'Lookup failed' };
            }
        } catch (e) {
            result.geo = { error: e.message };
        }

        result.links = {
            shodan: `https://www.shodan.io/host/${ip}`,
            censys: `https://search.censys.io/hosts/${ip}`,
            abuseIPDB: `https://www.abuseipdb.com/check/${ip}`,
            virusTotal: `https://www.virustotal.com/gui/ip-address/${ip}`,
            ipInfo: `https://ipinfo.io/${ip}`,
            greynoise: `https://viz.greynoise.io/ip/${ip}`,
            threatCrowd: `https://www.threatcrowd.org/ip.php?ip=${ip}`
        };

        let dnsReverse = null;
        try {
            const parts = ip.split('.').reverse().join('.');
            const resp = await fetch(`https://dns.google/resolve?name=${parts}.in-addr.arpa&type=PTR`);
            const json = await resp.json();
            if (json.Answer) {
                dnsReverse = json.Answer.map(a => a.data);
            }
        } catch (_) { /* skip */ }
        result.reverseDNS = dnsReverse;

        this.lastResults = result;
        this.lastType = 'ip';
        this.lastQuery = ip;
        return result;
    }

    // ── EMAIL SEARCH (real MX + validation) ────────────────
    async searchEmail(email) {
        email = email.trim().toLowerCase();
        const parts = email.split('@');
        const localPart = parts[0] || '';
        const domain = parts[1] || '';

        const result = {
            type: 'email',
            query: email,
            localPart,
            domain,
            mxRecords: [],
            domainResolvable: false,
            domainA: [],
            links: {},
            patterns: []
        };

        try {
            const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
            const json = await resp.json();
            if (json.Answer) {
                result.mxRecords = json.Answer.map(a => {
                    const p = a.data.split(' ');
                    return p.length > 1 ? `${p[1]} (priority: ${p[0]})` : a.data;
                });
            }
        } catch (e) {
            result.mxRecords = [`Error: ${e.message}`];
        }

        try {
            const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
            const json = await resp.json();
            if (json.Answer) {
                result.domainResolvable = true;
                result.domainA = json.Answer.map(a => a.data);
            }
        } catch (_) { /* skip */ }

        try {
            const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
            const json = await resp.json();
            if (json.Answer) {
                result.txtRecords = json.Answer.map(a => a.data);
            }
        } catch (_) { /* skip */ }

        const nameParts = localPart.replace(/[._\-+]/g, ' ').split(/\s+/);
        if (nameParts.length >= 1) {
            const fn = nameParts[0];
            const ln = nameParts.length > 1 ? nameParts[nameParts.length - 1] : '';
            if (ln) {
                result.patterns = [
                    `${fn}.${ln}@${domain}`,
                    `${fn}${ln}@${domain}`,
                    `${fn[0]}${ln}@${domain}`,
                    `${fn}_${ln}@${domain}`,
                    `${fn}-${ln}@${domain}`,
                    `${ln}.${fn}@${domain}`,
                    `${ln}${fn[0]}@${domain}`
                ];
            }
        }

        result.links = {
            haveibeenpwned: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
            dehashed: `https://dehashed.com/search?query=${encodeURIComponent(email)}`,
            intelx: `https://intelx.io/?s=${encodeURIComponent(email)}`,
            epieos: `https://epieos.com/?q=${encodeURIComponent(email)}`,
            holehe: `https://github.com/megadose/holehe`,
            hunter: `https://hunter.io/email-verifier/${encodeURIComponent(email)}`,
            emailrep: `https://emailrep.io/${encodeURIComponent(email)}`,
            google: `https://www.google.com/search?q="${encodeURIComponent(email)}"`,
            gravatar: `https://en.gravatar.com/${encodeURIComponent(localPart)}`
        };

        this.lastResults = result;
        this.lastType = 'email';
        this.lastQuery = email;
        return result;
    }

    // ── PERSON SEARCH (real search engine links) ───────────
    async searchPerson(name) {
        name = name.trim();
        const encodedName = encodeURIComponent(name);
        const nameParts = name.split(/\s+/);
        const firstName = nameParts[0] || '';
        const lastName = nameParts[nameParts.length - 1] || '';
        const firstLast = `${firstName}-${lastName}`.toLowerCase();

        const guessedUsernames = [];
        if (firstName && lastName) {
            guessedUsernames.push(
                `${firstName.toLowerCase()}${lastName.toLowerCase()}`,
                `${firstName.toLowerCase()}.${lastName.toLowerCase()}`,
                `${firstName.toLowerCase()}_${lastName.toLowerCase()}`,
                `${firstName[0].toLowerCase()}${lastName.toLowerCase()}`,
                `${firstName.toLowerCase()}${lastName[0].toLowerCase()}`
            );
        } else {
            guessedUsernames.push(name.toLowerCase().replace(/\s+/g, ''));
        }

        const result = {
            type: 'person',
            query: name,
            firstName,
            lastName,
            guessedUsernames,
            peopleSearchEngines: [
                { name: 'ThatsThem', url: `https://thatsthem.com/name/${firstLast}` },
                { name: 'TruePeopleSearch', url: `https://www.truepeoplesearch.com/results?name=${encodedName}` },
                { name: 'FastPeopleSearch', url: `https://www.fastpeoplesearch.com/name/${firstLast}` },
                { name: 'WhitePages', url: `https://www.whitepages.com/name/${firstLast}` },
                { name: 'Spokeo', url: `https://www.spokeo.com/${firstLast}` },
                { name: 'PeopleFinder', url: `https://www.peoplefinder.com/people/${firstLast}` },
                { name: 'BeenVerified', url: `https://www.beenverified.com/people/${firstLast}` },
                { name: 'Pipl', url: `https://pipl.com/search/?q=${encodedName}` },
                { name: 'Radaris', url: `https://radaris.com/p/${firstName}/${lastName}/` },
                { name: 'ZabaSearch', url: `https://www.zabasearch.com/people/${firstLast}/` },
                { name: 'Intelius', url: `https://www.intelius.com/people-search/${firstLast}/` },
                { name: 'USSearch', url: `https://www.ussearch.com/search/results/?fn=${encodeURIComponent(firstName)}&ln=${encodeURIComponent(lastName)}` }
            ],
            socialMedia: [
                { name: 'LinkedIn', url: `https://www.linkedin.com/search/results/people/?keywords=${encodedName}` },
                { name: 'Facebook', url: `https://www.facebook.com/search/people/?q=${encodedName}` },
                { name: 'Twitter/X', url: `https://x.com/search?q=${encodedName}&f=user` },
                { name: 'Instagram', url: `https://www.instagram.com/${guessedUsernames[0]}/` },
                { name: 'GitHub', url: `https://github.com/search?q=${encodedName}&type=users` },
                { name: 'Reddit', url: `https://www.reddit.com/search/?q=${encodedName}&type=user` },
                { name: 'TikTok', url: `https://www.tiktok.com/search/user?q=${encodedName}` },
                { name: 'YouTube', url: `https://www.youtube.com/results?search_query=${encodedName}&sp=EgIQAg%253D%253D` },
                { name: 'Pinterest', url: `https://www.pinterest.com/search/users/?q=${encodedName}` }
            ],
            publicRecords: [
                { name: 'PACER (Court Records)', url: `https://www.pacer.gov/` },
                { name: 'SEC EDGAR', url: `https://efts.sec.gov/LATEST/search-index?q=%22${encodedName}%22` },
                { name: 'FEC Contributions', url: `https://www.fec.gov/data/receipts/individual-contributions/?contributor_name=${encodedName}` },
                { name: 'RECAP (CourtListener)', url: `https://www.courtlistener.com/?q=${encodedName}&type=r` },
                { name: 'OpenCorporates', url: `https://opencorporates.com/officers?q=${encodedName}` },
                { name: 'Google Scholar', url: `https://scholar.google.com/scholar?q=author:%22${encodedName}%22` },
                { name: 'US Voter Records', url: `https://voterrecords.com/voters/${firstLast}/1` }
            ],
            googleDorks: [
                { name: 'Google (exact name)', url: `https://www.google.com/search?q=%22${encodedName}%22` },
                { name: 'Google (name + resume)', url: `https://www.google.com/search?q=%22${encodedName}%22+resume+OR+cv` },
                { name: 'Google (name + email)', url: `https://www.google.com/search?q=%22${encodedName}%22+%40gmail.com+OR+%40yahoo.com+OR+%40hotmail.com` },
                { name: 'Google (name + phone)', url: `https://www.google.com/search?q=%22${encodedName}%22+phone+OR+contact` },
                { name: 'Google (name + address)', url: `https://www.google.com/search?q=%22${encodedName}%22+address+OR+residence` }
            ]
        };

        this.lastResults = result;
        this.lastType = 'person';
        this.lastQuery = name;
        return result;
    }

    // ── PHONE SEARCH (real reverse lookup links) ───────────
    async searchPhone(phone) {
        const cleaned = phone.replace(/[^\d+]/g, '');
        const digitsOnly = cleaned.replace(/\D/g, '');
        const formatted = phone.trim();

        const areaCodeMap = {
            '201': 'New Jersey', '202': 'Washington, D.C.', '203': 'Connecticut', '205': 'Alabama', '206': 'Washington',
            '207': 'Maine', '208': 'Idaho', '209': 'California', '210': 'Texas', '212': 'New York',
            '213': 'California', '214': 'Texas', '215': 'Pennsylvania', '216': 'Ohio', '217': 'Illinois',
            '218': 'Minnesota', '219': 'Indiana', '224': 'Illinois', '225': 'Louisiana', '228': 'Mississippi',
            '229': 'Georgia', '231': 'Michigan', '234': 'Ohio', '239': 'Florida', '240': 'Maryland',
            '248': 'Michigan', '251': 'Alabama', '252': 'North Carolina', '253': 'Washington', '254': 'Texas',
            '256': 'Alabama', '260': 'Indiana', '262': 'Wisconsin', '267': 'Pennsylvania', '269': 'Michigan',
            '270': 'Kentucky', '276': 'Virginia', '281': 'Texas', '301': 'Maryland', '302': 'Delaware',
            '303': 'Colorado', '304': 'West Virginia', '305': 'Florida', '307': 'Wyoming', '308': 'Nebraska',
            '309': 'Illinois', '310': 'California', '312': 'Illinois', '313': 'Michigan', '314': 'Missouri',
            '315': 'New York', '316': 'Kansas', '317': 'Indiana', '318': 'Louisiana', '319': 'Iowa',
            '320': 'Minnesota', '321': 'Florida', '323': 'California', '325': 'Texas', '330': 'Ohio',
            '331': 'Illinois', '334': 'Alabama', '336': 'North Carolina', '337': 'Louisiana', '339': 'Massachusetts',
            '340': 'U.S. Virgin Islands', '346': 'Texas', '347': 'New York', '351': 'Massachusetts',
            '352': 'Florida', '360': 'Washington', '361': 'Texas', '385': 'Utah', '386': 'Florida',
            '401': 'Rhode Island', '402': 'Nebraska', '404': 'Georgia', '405': 'Oklahoma', '406': 'Montana',
            '407': 'Florida', '408': 'California', '409': 'Texas', '410': 'Maryland', '412': 'Pennsylvania',
            '413': 'Massachusetts', '414': 'Wisconsin', '415': 'California', '417': 'Missouri', '419': 'Ohio',
            '423': 'Tennessee', '424': 'California', '425': 'Washington', '430': 'Texas', '432': 'Texas',
            '434': 'Virginia', '435': 'Utah', '440': 'Ohio', '442': 'California', '443': 'Maryland',
            '469': 'Texas', '470': 'Georgia', '475': 'Connecticut', '478': 'Georgia', '479': 'Arkansas',
            '480': 'Arizona', '484': 'Pennsylvania', '501': 'Arkansas', '502': 'Kentucky', '503': 'Oregon',
            '504': 'Louisiana', '505': 'New Mexico', '507': 'Minnesota', '508': 'Massachusetts', '509': 'Washington',
            '510': 'California', '512': 'Texas', '513': 'Ohio', '515': 'Iowa', '516': 'New York',
            '517': 'Michigan', '518': 'New York', '520': 'Arizona', '530': 'California', '531': 'Nebraska',
            '534': 'Wisconsin', '539': 'Oklahoma', '540': 'Virginia', '541': 'Oregon', '551': 'New Jersey',
            '559': 'California', '561': 'Florida', '562': 'California', '563': 'Iowa', '567': 'Ohio',
            '570': 'Pennsylvania', '571': 'Virginia', '573': 'Missouri', '574': 'Indiana', '575': 'New Mexico',
            '580': 'Oklahoma', '585': 'New York', '586': 'Michigan', '601': 'Mississippi', '602': 'Arizona',
            '603': 'New Hampshire', '605': 'South Dakota', '606': 'Kentucky', '607': 'New York', '608': 'Wisconsin',
            '609': 'New Jersey', '610': 'Pennsylvania', '612': 'Minnesota', '614': 'Ohio', '615': 'Tennessee',
            '616': 'Michigan', '617': 'Massachusetts', '618': 'Illinois', '619': 'California', '620': 'Kansas',
            '623': 'Arizona', '626': 'California', '630': 'Illinois', '631': 'New York', '636': 'Missouri',
            '641': 'Iowa', '646': 'New York', '650': 'California', '651': 'Minnesota', '657': 'California',
            '660': 'Missouri', '661': 'California', '662': 'Mississippi', '667': 'Maryland', '669': 'California',
            '678': 'Georgia', '681': 'West Virginia', '682': 'Texas', '701': 'North Dakota', '702': 'Nevada',
            '703': 'Virginia', '704': 'North Carolina', '706': 'Georgia', '707': 'California', '708': 'Illinois',
            '712': 'Iowa', '713': 'Texas', '714': 'California', '715': 'Wisconsin', '716': 'New York',
            '717': 'Pennsylvania', '718': 'New York', '719': 'Colorado', '720': 'Colorado', '724': 'Pennsylvania',
            '725': 'Nevada', '727': 'Florida', '731': 'Tennessee', '732': 'New Jersey', '734': 'Michigan',
            '737': 'Texas', '740': 'Ohio', '743': 'North Carolina', '747': 'California', '754': 'Florida',
            '757': 'Virginia', '760': 'California', '762': 'Georgia', '763': 'Minnesota', '765': 'Indiana',
            '769': 'Mississippi', '770': 'Georgia', '772': 'Florida', '773': 'Illinois', '774': 'Massachusetts',
            '775': 'Nevada', '779': 'Illinois', '781': 'Massachusetts', '785': 'Kansas', '786': 'Florida',
            '801': 'Utah', '802': 'Vermont', '803': 'South Carolina', '804': 'Virginia', '805': 'California',
            '806': 'Texas', '808': 'Hawaii', '810': 'Michigan', '812': 'Indiana', '813': 'Florida',
            '814': 'Pennsylvania', '815': 'Illinois', '816': 'Missouri', '817': 'Texas', '818': 'California',
            '828': 'North Carolina', '830': 'Texas', '831': 'California', '832': 'Texas', '843': 'South Carolina',
            '845': 'New York', '847': 'Illinois', '848': 'New Jersey', '850': 'Florida', '854': 'South Carolina',
            '856': 'New Jersey', '857': 'Massachusetts', '858': 'California', '859': 'Kentucky', '860': 'Connecticut',
            '862': 'New Jersey', '863': 'Florida', '864': 'South Carolina', '865': 'Tennessee', '870': 'Arkansas',
            '878': 'Pennsylvania', '901': 'Tennessee', '903': 'Texas', '904': 'Florida', '906': 'Michigan',
            '907': 'Alaska', '908': 'New Jersey', '909': 'California', '910': 'North Carolina', '912': 'Georgia',
            '913': 'Kansas', '914': 'New York', '915': 'Texas', '916': 'California', '917': 'New York',
            '918': 'Oklahoma', '919': 'North Carolina', '920': 'Wisconsin', '925': 'California', '928': 'Arizona',
            '929': 'New York', '930': 'Indiana', '931': 'Tennessee', '936': 'Texas', '937': 'Ohio',
            '938': 'Alabama', '940': 'Texas', '941': 'Florida', '947': 'Michigan', '949': 'California',
            '951': 'California', '952': 'Minnesota', '954': 'Florida', '956': 'Texas', '959': 'Connecticut',
            '970': 'Colorado', '971': 'Oregon', '972': 'Texas', '973': 'New Jersey', '978': 'Massachusetts',
            '979': 'Texas', '980': 'North Carolina', '984': 'North Carolina', '985': 'Louisiana'
        };

        let areaCode = '';
        let areaLocation = '';
        if (digitsOnly.length >= 10) {
            const ac = digitsOnly.length === 11 && digitsOnly[0] === '1' ? digitsOnly.substring(1, 4) : digitsOnly.substring(0, 3);
            areaCode = ac;
            areaLocation = areaCodeMap[ac] || 'Unknown';
        }

        const result = {
            type: 'phone',
            query: formatted,
            cleaned,
            digitsOnly,
            areaCode,
            areaLocation,
            links: [
                { name: 'SpyDialer', url: `https://www.spydialer.com/` },
                { name: 'TrueCaller', url: `https://www.truecaller.com/search/us/${digitsOnly}` },
                { name: 'WhitePages', url: `https://www.whitepages.com/phone/${digitsOnly}` },
                { name: 'ThatsThem', url: `https://thatsthem.com/phone/${digitsOnly}` },
                { name: 'NumLookup', url: `https://www.numlookup.com/` },
                { name: 'CallerID Test', url: `https://www.calleridtest.com/` },
                { name: 'USPhoneBook', url: `https://www.usphonebook.com/${digitsOnly}` },
                { name: 'Sync.me', url: `https://sync.me/search/?number=%2B1${digitsOnly}` },
                { name: 'Spokeo', url: `https://www.spokeo.com/phone-lookup/${digitsOnly}` },
                { name: 'FastPeopleSearch', url: `https://www.fastpeoplesearch.com/${digitsOnly}` },
                { name: 'Google', url: `https://www.google.com/search?q=%22${digitsOnly}%22` },
                { name: 'WhoCalledMe', url: `https://whocalledme.com/lookup/${digitsOnly}` }
            ],
            carrierLookup: [
                { name: 'FreeCarrierLookup', url: `https://freecarrierlookup.com/` },
                { name: 'CarrierLookup', url: `https://www.carrierlookup.com/` }
            ]
        };

        this.lastResults = result;
        this.lastType = 'phone';
        this.lastQuery = formatted;
        return result;
    }

    // ── USERNAME SEARCH (real platform checks) ─────────────
    async searchUsername(username) {
        username = username.trim().replace(/^@/, '');

        const platforms = [
            { name: 'GitHub', url: `https://github.com/${username}`, icon: 'code' },
            { name: 'Twitter/X', url: `https://x.com/${username}`, icon: 'social' },
            { name: 'Instagram', url: `https://www.instagram.com/${username}/`, icon: 'social' },
            { name: 'Reddit', url: `https://www.reddit.com/user/${username}`, icon: 'social' },
            { name: 'TikTok', url: `https://www.tiktok.com/@${username}`, icon: 'social' },
            { name: 'YouTube', url: `https://www.youtube.com/@${username}`, icon: 'social' },
            { name: 'Twitch', url: `https://www.twitch.tv/${username}`, icon: 'social' },
            { name: 'Pinterest', url: `https://www.pinterest.com/${username}/`, icon: 'social' },
            { name: 'Tumblr', url: `https://${username}.tumblr.com`, icon: 'social' },
            { name: 'Medium', url: `https://medium.com/@${username}`, icon: 'blog' },
            { name: 'DeviantArt', url: `https://www.deviantart.com/${username}`, icon: 'art' },
            { name: 'SoundCloud', url: `https://soundcloud.com/${username}`, icon: 'music' },
            { name: 'Spotify', url: `https://open.spotify.com/user/${username}`, icon: 'music' },
            { name: 'Steam', url: `https://steamcommunity.com/id/${username}`, icon: 'gaming' },
            { name: 'Xbox', url: `https://www.xbox.com/en-US/play/user/${username}`, icon: 'gaming' },
            { name: 'Keybase', url: `https://keybase.io/${username}`, icon: 'security' },
            { name: 'HackerOne', url: `https://hackerone.com/${username}`, icon: 'security' },
            { name: 'BugCrowd', url: `https://bugcrowd.com/${username}`, icon: 'security' },
            { name: 'Replit', url: `https://replit.com/@${username}`, icon: 'code' },
            { name: 'CodePen', url: `https://codepen.io/${username}`, icon: 'code' },
            { name: 'Dribbble', url: `https://dribbble.com/${username}`, icon: 'art' },
            { name: 'Behance', url: `https://www.behance.net/${username}`, icon: 'art' },
            { name: 'Flickr', url: `https://www.flickr.com/people/${username}/`, icon: 'social' },
            { name: 'Vimeo', url: `https://vimeo.com/${username}`, icon: 'social' },
            { name: 'GitLab', url: `https://gitlab.com/${username}`, icon: 'code' },
            { name: 'npm', url: `https://www.npmjs.com/~${username}`, icon: 'code' },
            { name: 'PyPI', url: `https://pypi.org/user/${username}/`, icon: 'code' },
            { name: 'Docker Hub', url: `https://hub.docker.com/u/${username}`, icon: 'code' },
            { name: 'Pastebin', url: `https://pastebin.com/u/${username}`, icon: 'code' },
            { name: 'About.me', url: `https://about.me/${username}`, icon: 'social' },
            { name: 'Gravatar', url: `https://en.gravatar.com/${username}`, icon: 'social' },
            { name: 'Mastodon (mstdn.social)', url: `https://mstdn.social/@${username}`, icon: 'social' },
            { name: 'Letterboxd', url: `https://letterboxd.com/${username}/`, icon: 'social' },
            { name: 'Kaggle', url: `https://www.kaggle.com/${username}`, icon: 'code' },
            { name: 'Hugging Face', url: `https://huggingface.co/${username}`, icon: 'code' },
            { name: 'Linktree', url: `https://linktr.ee/${username}`, icon: 'social' },
            { name: 'Cash App', url: `https://cash.app/$${username}`, icon: 'finance' },
            { name: 'Venmo', url: `https://venmo.com/${username}`, icon: 'finance' },
            { name: 'StackOverflow', url: `https://stackoverflow.com/users/?tab=accounts&SearchOn=displayname&q=${username}`, icon: 'code' },
            { name: 'Telegram', url: `https://t.me/${username}`, icon: 'social' }
        ];

        const apiChecks = [];

        try {
            const resp = await fetch(`https://api.github.com/users/${encodeURIComponent(username)}`, {
                headers: { 'Accept': 'application/vnd.github.v3+json' }
            });
            if (resp.ok) {
                const data = await resp.json();
                apiChecks.push({
                    platform: 'GitHub',
                    found: true,
                    profile: {
                        name: data.name,
                        bio: data.bio,
                        location: data.location,
                        repos: data.public_repos,
                        followers: data.followers,
                        following: data.following,
                        created: data.created_at,
                        avatar: data.avatar_url,
                        url: data.html_url
                    }
                });
            } else if (resp.status === 404) {
                apiChecks.push({ platform: 'GitHub', found: false });
            }
        } catch (_) { /* skip */ }

        try {
            const resp = await fetch(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`);
            if (resp.ok) {
                const data = await resp.json();
                if (data.length > 0) {
                    apiChecks.push({
                        platform: 'GitLab',
                        found: true,
                        profile: {
                            name: data[0].name,
                            username: data[0].username,
                            url: data[0].web_url,
                            avatar: data[0].avatar_url
                        }
                    });
                } else {
                    apiChecks.push({ platform: 'GitLab', found: false });
                }
            }
        } catch (_) { /* skip */ }

        const result = {
            type: 'username',
            query: username,
            platforms,
            apiChecks,
            metaSearchLinks: [
                { name: 'Namechk', url: `https://namechk.com/` },
                { name: 'KnowEm', url: `https://knowem.com/checkusernames.php?u=${encodeURIComponent(username)}` },
                { name: 'WhatsMyName', url: `https://whatsmyname.app/` },
                { name: 'Sherlock (GitHub)', url: `https://github.com/sherlock-project/sherlock` },
                { name: 'Maigret (GitHub)', url: `https://github.com/soxoj/maigret` },
                { name: 'Google', url: `https://www.google.com/search?q=%22${encodeURIComponent(username)}%22+profile+OR+account` }
            ]
        };

        this.lastResults = result;
        this.lastType = 'username';
        this.lastQuery = username;
        return result;
    }

    // ── RENDER RESULTS ─────────────────────────────────────
    renderResults(type, data) {
        if (!this.resultsEl) return;
        const lines = [];

        const addHeader = (title) => {
            lines.push(`<span class="term-accent">══════════════════════════════════════════════════════════</span>`);
            lines.push(`<span class="term-accent"> ${this._esc(title)}</span>`);
            lines.push(`<span class="term-accent">══════════════════════════════════════════════════════════</span>`);
            lines.push('');
        };

        const addSection = (title) => {
            lines.push(`<span class="term-info">── ${this._esc(title)} ${'─'.repeat(Math.max(0, 50 - title.length))}</span>`);
        };

        const addSuccess = (text) => {
            lines.push(`<span class="term-success">[+] ${text}</span>`);
        };

        const addInfo = (text) => {
            lines.push(`<span class="term-info">[*] ${text}</span>`);
        };

        const addWarning = (text) => {
            lines.push(`<span class="term-warning">[!] ${text}</span>`);
        };

        const addError = (text) => {
            lines.push(`<span class="term-error">[-] ${text}</span>`);
        };

        const addLink = (name, url) => {
            lines.push(`    ${this._link(url, name)}`);
        };

        const addItem = (text) => {
            lines.push(`    <span class="term-dim">•</span> ${text}`);
        };

        if (type === 'domain') {
            addHeader(`DOMAIN INTELLIGENCE: ${data.query}`);

            addSection('DNS A Records');
            if (data.dns.A.length > 0) {
                data.dns.A.forEach(r => addSuccess(r));
            } else {
                addWarning('No A records found');
            }
            lines.push('');

            if (data.dns.AAAA.length > 0) {
                addSection('DNS AAAA Records');
                data.dns.AAAA.forEach(r => addSuccess(r));
                lines.push('');
            }

            addSection('MX Records (Mail)');
            if (data.dns.MX.length > 0) {
                data.dns.MX.forEach(r => addSuccess(r));
            } else {
                addWarning('No MX records found');
            }
            lines.push('');

            addSection('NS Records (Nameservers)');
            if (data.dns.NS.length > 0) {
                data.dns.NS.forEach(r => addSuccess(r));
            } else {
                addWarning('No NS records found');
            }
            lines.push('');

            if (data.dns.TXT.length > 0) {
                addSection('TXT Records');
                data.dns.TXT.forEach(r => addInfo(r.length > 100 ? r.substring(0, 100) + '...' : r));
                lines.push('');
            }

            if (data.dns.CNAME.length > 0) {
                addSection('CNAME Records');
                data.dns.CNAME.forEach(r => addSuccess(r));
                lines.push('');
            }

            if (data.whois && !data.whois.error) {
                addSection('WHOIS / RDAP Data');
                addSuccess(`Domain: ${data.whois.name}`);
                addInfo(`Status: ${data.whois.status}`);
                addInfo(`Registrar: ${data.whois.registrar}`);
                if (data.whois.events.length > 0) {
                    data.whois.events.forEach(e => addInfo(e));
                }
                if (data.whois.nameservers.length > 0) {
                    addInfo('Nameservers:');
                    data.whois.nameservers.forEach(ns => addItem(ns));
                }
                if (data.whois.entities.length > 0) {
                    addInfo('Entities:');
                    data.whois.entities.forEach(ent => addItem(`${ent.name} [${ent.roles}] (${ent.handle})`));
                }
                lines.push('');
            } else if (data.whois && data.whois.error) {
                addSection('WHOIS / RDAP Data');
                addWarning(`RDAP lookup failed: ${data.whois.error}`);
                lines.push('');
            }

            if (data.subdomains.length > 0) {
                addSection(`Subdomains Found (${data.subdomains.length})`);
                data.subdomains.forEach(s => addSuccess(`${s.name} → ${s.ip}`));
                lines.push('');
            }

            if (data.techStack.length > 0) {
                addSection('Technology Detection');
                data.techStack.forEach(t => addInfo(t));
                lines.push('');
            }

            if (data.robotsTxt) {
                addSection('robots.txt');
                addInfo(data.robotsTxt);
                addLink('View robots.txt', `https://${data.query}/robots.txt`);
                lines.push('');
            }

            addSection('External Tools');
            addLink('SecurityTrails', `https://securitytrails.com/domain/${data.query}/dns`);
            addLink('crt.sh (Certificates)', `https://crt.sh/?q=%25.${data.query}`);
            addLink('DNSDumpster', `https://dnsdumpster.com/`);
            addLink('BuiltWith', `https://builtwith.com/${data.query}`);
            addLink('Wappalyzer', `https://www.wappalyzer.com/lookup/${data.query}/`);
            addLink('Wayback Machine', `https://web.archive.org/web/*/${data.query}`);
            addLink('VirusTotal', `https://www.virustotal.com/gui/domain/${data.query}`);
            addLink('Shodan', `https://www.shodan.io/search?query=hostname:${data.query}`);

        } else if (type === 'ip') {
            addHeader(`IP INTELLIGENCE: ${data.query}`);

            if (data.geo && !data.geo.error) {
                addSection('Geolocation');
                addSuccess(`Country: ${data.geo.country} (${data.geo.countryCode})`);
                addSuccess(`Region: ${data.geo.regionName} (${data.geo.region})`);
                addSuccess(`City: ${data.geo.city}`);
                addInfo(`ZIP: ${data.geo.zip || 'N/A'}`);
                addInfo(`Coordinates: ${data.geo.lat}, ${data.geo.lon}`);
                addInfo(`Timezone: ${data.geo.timezone}`);
                lines.push('');

                addSection('Network');
                addSuccess(`ISP: ${data.geo.isp}`);
                addSuccess(`Organization: ${data.geo.org}`);
                addInfo(`ASN: ${data.geo.as}`);
                addInfo(`AS Name: ${data.geo.asname}`);
                if (data.geo.reverse) addInfo(`Reverse DNS: ${data.geo.reverse}`);
                lines.push('');
            } else {
                addSection('Geolocation');
                addError(`Lookup failed: ${(data.geo && data.geo.error) || 'Unknown error'}`);
                lines.push('');
            }

            if (data.reverseDNS && data.reverseDNS.length > 0) {
                addSection('Reverse DNS (PTR)');
                data.reverseDNS.forEach(r => addSuccess(r));
                lines.push('');
            }

            addSection('Threat Intelligence Links');
            Object.entries(data.links).forEach(([key, url]) => {
                addLink(key.charAt(0).toUpperCase() + key.slice(1), url);
            });

            if (data.geo && data.geo.lat && data.geo.lon) {
                lines.push('');
                addSection('Map');
                addLink('Google Maps', `https://www.google.com/maps/@${data.geo.lat},${data.geo.lon},12z`);
                addLink('OpenStreetMap', `https://www.openstreetmap.org/?mlat=${data.geo.lat}&mlon=${data.geo.lon}#map=12/${data.geo.lat}/${data.geo.lon}`);
            }

        } else if (type === 'email') {
            addHeader(`EMAIL INTELLIGENCE: ${data.query}`);

            addSection('Email Parsing');
            addInfo(`Local Part: ${this._esc(data.localPart)}`);
            addInfo(`Domain: ${this._esc(data.domain)}`);
            lines.push('');

            addSection('MX Records (Mail Server Validation)');
            if (data.mxRecords.length > 0) {
                addSuccess('Domain has mail servers configured — email likely valid');
                data.mxRecords.forEach(r => addItem(r));
            } else {
                addError('No MX records found — domain may not accept email');
            }
            lines.push('');

            addSection('Domain Resolution');
            if (data.domainResolvable) {
                addSuccess(`Domain resolves: ${data.domainA.join(', ')}`);
            } else {
                addError('Domain does not resolve — likely invalid');
            }
            lines.push('');

            if (data.txtRecords && data.txtRecords.length > 0) {
                addSection('TXT Records (SPF, DMARC, etc.)');
                data.txtRecords.forEach(r => addInfo(r.length > 100 ? r.substring(0, 100) + '...' : r));
                lines.push('');
            }

            if (data.patterns.length > 0) {
                addSection('Common Email Patterns');
                data.patterns.forEach(p => addItem(this._esc(p)));
                lines.push('');
            }

            addSection('Breach & Reputation Checks');
            addLink('HaveIBeenPwned', data.links.haveibeenpwned);
            addLink('DeHashed', data.links.dehashed);
            addLink('IntelX', data.links.intelx);
            addLink('Epieos', data.links.epieos);
            addLink('Hunter.io Verify', data.links.hunter);
            addLink('EmailRep', data.links.emailrep);
            addLink('Gravatar', data.links.gravatar);
            lines.push('');

            addSection('Google Dork');
            addLink('Search for this email', data.links.google);

        } else if (type === 'person') {
            addHeader(`PERSON INTELLIGENCE: ${data.query}`);

            addSection('People Search Engines');
            addInfo('Click each link to search public databases:');
            data.peopleSearchEngines.forEach(s => addLink(s.name, s.url));
            lines.push('');

            addSection('Social Media Search');
            data.socialMedia.forEach(s => addLink(s.name, s.url));
            lines.push('');

            if (data.guessedUsernames.length > 0) {
                addSection('Possible Usernames');
                data.guessedUsernames.forEach(u => addItem(this._esc(u)));
                lines.push('');
            }

            addSection('Public Records');
            data.publicRecords.forEach(r => addLink(r.name, r.url));
            lines.push('');

            addSection('Google Dorks');
            data.googleDorks.forEach(d => addLink(d.name, d.url));

        } else if (type === 'phone') {
            addHeader(`PHONE INTELLIGENCE: ${data.query}`);

            addSection('Phone Number Analysis');
            addInfo(`Cleaned: ${this._esc(data.cleaned)}`);
            addInfo(`Digits: ${this._esc(data.digitsOnly)}`);
            if (data.areaCode) {
                addSuccess(`Area Code: ${data.areaCode}`);
                addSuccess(`Estimated Location: ${this._esc(data.areaLocation)}`);
            } else {
                addWarning('Could not determine area code');
            }
            lines.push('');

            addSection('Reverse Lookup Services');
            addInfo('Click each link to search:');
            data.links.forEach(l => addLink(l.name, l.url));
            lines.push('');

            addSection('Carrier Lookup Services');
            data.carrierLookup.forEach(l => addLink(l.name, l.url));

        } else if (type === 'username') {
            addHeader(`USERNAME INTELLIGENCE: ${data.query}`);

            if (data.apiChecks.length > 0) {
                addSection('API Verification Results');
                data.apiChecks.forEach(check => {
                    if (check.found) {
                        addSuccess(`${check.platform}: FOUND`);
                        if (check.profile) {
                            if (check.profile.name) addItem(`Name: ${this._esc(check.profile.name)}`);
                            if (check.profile.bio) addItem(`Bio: ${this._esc(check.profile.bio)}`);
                            if (check.profile.location) addItem(`Location: ${this._esc(check.profile.location)}`);
                            if (check.profile.repos !== undefined) addItem(`Public Repos: ${check.profile.repos}`);
                            if (check.profile.followers !== undefined) addItem(`Followers: ${check.profile.followers}`);
                            if (check.profile.url) addItem(this._link(check.profile.url, 'View Profile'));
                        }
                    } else {
                        addError(`${check.platform}: NOT FOUND`);
                    }
                });
                lines.push('');
            }

            const categories = {
                'Social Media': data.platforms.filter(p => p.icon === 'social'),
                'Developer / Code': data.platforms.filter(p => p.icon === 'code'),
                'Art / Design': data.platforms.filter(p => p.icon === 'art'),
                'Music / Audio': data.platforms.filter(p => p.icon === 'music'),
                'Gaming': data.platforms.filter(p => p.icon === 'gaming'),
                'Security': data.platforms.filter(p => p.icon === 'security'),
                'Finance': data.platforms.filter(p => p.icon === 'finance')
            };

            Object.entries(categories).forEach(([cat, platforms]) => {
                if (platforms.length === 0) return;
                addSection(cat);
                platforms.forEach(p => addLink(p.name, p.url));
                lines.push('');
            });

            addSection('Username Meta-Search Tools');
            data.metaSearchLinks.forEach(l => addLink(l.name, l.url));
        }

        lines.push('');
        lines.push(`<span class="term-dim">─────────────────────────────────────────────────────────</span>`);
        lines.push(`<span class="term-success">[+] Search complete. All results from publicly available sources.</span>`);
        lines.push(`<span class="term-dim">[*] Timestamp: ${new Date().toISOString()}</span>`);

        const html = `<span class="term-prompt">root@fllc:~$</span> osint search ${type} "${this._esc(data.query)}"\n\n` + lines.join('\n');
        this.resultsEl.innerHTML = html;
    }

    // ── EXPORT FUNCTIONS (real, working) ───────────────────
    exportJSON() {
        if (!this.lastResults) {
            alert('No results to export. Run a search first.');
            return;
        }
        const blob = new Blob(
            [JSON.stringify(this.lastResults, null, 2)],
            { type: 'application/json' }
        );
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `fuperson_${this.lastType}_${this.lastQuery.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    exportCSV() {
        if (!this.lastResults) {
            alert('No results to export. Run a search first.');
            return;
        }
        const rows = [['Field', 'Value']];

        const flatten = (obj, prefix) => {
            for (const [key, val] of Object.entries(obj)) {
                const path = prefix ? `${prefix}.${key}` : key;
                if (val === null || val === undefined) {
                    rows.push([path, '']);
                } else if (Array.isArray(val)) {
                    val.forEach((item, i) => {
                        if (typeof item === 'object') {
                            flatten(item, `${path}[${i}]`);
                        } else {
                            rows.push([`${path}[${i}]`, String(item)]);
                        }
                    });
                } else if (typeof val === 'object') {
                    flatten(val, path);
                } else {
                    rows.push([path, String(val)]);
                }
            }
        };
        flatten(this.lastResults, '');

        const csvContent = rows.map(row =>
            row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
        ).join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `fuperson_${this.lastType}_${this.lastQuery.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    exportPDF() {
        if (!this.lastResults) {
            alert('No results to export. Run a search first.');
            return;
        }
        const printWin = window.open('', '_blank');
        if (!printWin) {
            alert('Pop-up blocked. Allow pop-ups for this site to export PDF.');
            return;
        }
        const content = this.resultsEl ? this.resultsEl.innerHTML : '';
        printWin.document.write(`<!DOCTYPE html>
<html><head><title>FU PERSON OSINT Report — ${this._esc(this.lastQuery)}</title>
<style>
    body { background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; padding: 40px; font-size: 12px; line-height: 1.6; }
    pre { white-space: pre-wrap; word-wrap: break-word; }
    a { color: #00bfff; }
    .term-success { color: #00ff41; }
    .term-info { color: #00bfff; }
    .term-warning { color: #ffaa00; }
    .term-error { color: #ff4444; }
    .term-prompt { color: #ff00ff; }
    .term-accent { color: #ff00ff; }
    .term-dim { color: #666; }
    .term-link { color: #00bfff; text-decoration: underline; }
    h1 { color: #ff00ff; border-bottom: 1px solid #333; padding-bottom: 10px; }
    .footer { margin-top: 40px; color: #666; border-top: 1px solid #333; padding-top: 10px; }
    @media print { body { background: white; color: black; } a { color: blue; } .term-success, .term-info, .term-warning, .term-error, .term-prompt, .term-accent { color: black; } }
</style></head><body>
<h1>FU PERSON OSINT Report</h1>
<p>Query: ${this._esc(this.lastQuery)} | Type: ${this._esc(this.lastType)} | Date: ${new Date().toISOString()}</p>
<pre>${content}</pre>
<div class="footer">Generated by FU PERSON OSINT Finder — All data from public sources</div>
</body></html>`);
        printWin.document.close();
        setTimeout(() => { printWin.print(); }, 500);
    }
}
