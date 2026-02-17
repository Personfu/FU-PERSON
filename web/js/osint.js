/**
 * FU PERSON OSINT Finder — Mock OSINT Search Module
 */

class OSINTSearch {
    constructor() {
        this.resultsEl = document.getElementById('results-content');
    }

    searchPerson(name) {
        return {
            type: 'person',
            query: name,
            name: name,
            addresses: ['123 Main St, Anytown, CA 90210', '456 Oak Ave, Somewhere, NY 10001'],
            phones: [{ number: '+1-555-123-4567', type: 'Mobile' }, { number: '+1-555-987-6543', type: 'Landline' }],
            emails: ['john.doe@example.com', 'jdoe@gmail.com'],
            socialProfiles: [
                { platform: 'Twitter', handle: '@johndoe' },
                { platform: 'LinkedIn', url: 'linkedin.com/in/johndoe' },
                { platform: 'Facebook', url: 'facebook.com/johndoe' }
            ],
            publicRecords: ['Voter registration (California)', 'Business filings (2020)', 'Court records: 1 public case']
        };
    }

    searchPhone(phone) {
        return {
            type: 'phone',
            query: phone,
            carrier: 'AT&T Wireless',
            location: 'US (California)',
            callerName: 'John Doe',
            lineType: 'Mobile'
        };
    }

    searchEmail(email) {
        return {
            type: 'email',
            query: email,
            valid: true,
            provider: 'example.com',
            breachCount: 2,
            socialLinks: ['LinkedIn', 'Twitter']
        };
    }

    searchDomain(domain) {
        return {
            type: 'domain',
            query: domain,
            dns: { A: ['93.184.216.34'], MX: ['mx.example.com'] },
            subdomains: ['www', 'mail', 'api'],
            techStack: ['nginx', 'PHP', 'Cloudflare'],
            whois: { registrant: 'Example Corp', expiry: '2026-01-15' }
        };
    }

    searchIP(ip) {
        return {
            type: 'ip',
            query: ip,
            geolocation: { country: 'US', city: 'Los Angeles', lat: 34.05, lon: -118.24 },
            isp: 'Example ISP',
            asn: 'AS15169',
            threatScore: 0
        };
    }

    searchUsername(username) {
        return {
            type: 'username',
            query: username,
            platforms: ['Twitter', 'Instagram', 'GitHub', 'LinkedIn', 'Reddit']
        };
    }

    formatAsTerminal(lines) {
        return lines.map(line => {
            if (line.startsWith('[+]')) return `<span class="term-success">${line}</span>`;
            if (line.startsWith('[*]')) return `<span class="term-info">${line}</span>`;
            if (line.startsWith('[-]')) return `<span class="term-error">${line}</span>`;
            return line;
        }).join('\n');
    }

    renderResults(type, data) {
        const lines = [];

        if (type === 'person') {
            lines.push(`══════════════════════════════════════════════════════════`);
            lines.push(` PERSON SEARCH: ${data.name} — PUBLIC DATABASE RESULT`);
            lines.push(`══════════════════════════════════════════════════════════`);
            lines.push('');
            lines.push(`[*] Name: ${data.name}`);
            lines.push(`[*] Possible Addresses:`);
            data.addresses.forEach(a => lines.push(`    • ${a}`));
            lines.push('');
            lines.push(`[*] Phone Numbers:`);
            data.phones.forEach(p => lines.push(`    • ${p.number} (${p.type})`));
            lines.push('');
            lines.push(`[*] Email Addresses:`);
            data.emails.forEach(e => lines.push(`    • ${e}`));
            lines.push('');
            lines.push(`[*] Social Media Profiles Found:`);
            data.socialProfiles.forEach(s => lines.push(`    • ${s.platform}: ${s.handle || s.url}`));
            lines.push('');
            lines.push(`[*] Public Records:`);
            data.publicRecords.forEach(r => lines.push(`    • ${r}`));
        } else if (type === 'phone') {
            lines.push(`[+] Carrier: ${data.carrier}`);
            lines.push(`[+] Location: ${data.location}`);
            lines.push(`[+] Caller: ${data.callerName}`);
            lines.push(`[+] Type: ${data.lineType} (PUBLIC DATABASE RESULT)`);
        } else if (type === 'email') {
            lines.push(`[+] Valid: ${data.valid}`);
            lines.push(`[+] Provider: ${data.provider}`);
            lines.push(`[+] Breach appearances: ${data.breachCount}`);
            lines.push(`[+] Social links: ${data.socialLinks.join(', ')} (PUBLIC DATABASE RESULT)`);
        } else if (type === 'domain') {
            lines.push(`[+] DNS A: ${data.dns.A.join(', ')}`);
            lines.push(`[+] MX: ${data.dns.MX.join(', ')}`);
            lines.push(`[*] Subdomains: ${data.subdomains.join(', ')}`);
            lines.push(`[*] Tech: ${data.techStack.join(', ')}`);
            lines.push(`[*] WHOIS: ${data.whois.registrant}, Expires: ${data.whois.expiry} (PUBLIC DATABASE RESULT)`);
        } else if (type === 'ip') {
            lines.push(`[+] Location: ${data.geolocation.city}, ${data.geolocation.country}`);
            lines.push(`[+] ISP: ${data.isp}`);
            lines.push(`[+] ASN: ${data.asn}`);
            lines.push(`[+] Threat Score: ${data.threatScore} (PUBLIC DATABASE RESULT)`);
        } else if (type === 'username') {
            lines.push(`[+] Platforms found: ${data.platforms.length}`);
            lines.push(`[*] ${data.platforms.join(', ')} (PUBLIC DATABASE RESULT)`);
        }

        lines.push('');
        lines.push(`[+] All results from publicly available databases.`);

        const html = `<span class="term-prompt">root@fllc:~$</span> osint search ${type} "${data.query}"\n\n` + this.formatAsTerminal(lines);
        if (this.resultsEl) {
            this.resultsEl.innerHTML = html;
        }
    }

    exportPDF() {
        alert('Coming soon — subscribe for export');
    }

    exportJSON() {
        alert('Coming soon — subscribe for export');
    }

    exportCSV() {
        alert('Coming soon — subscribe for export');
    }
}
