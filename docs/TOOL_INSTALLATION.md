# Security Tools Installation Guide

```
╔══════════════════════════════════════════════════════════════╗
║  FLLC ARMORY — TOOL INSTALLATION GUIDE                       ║
║  200+ security tools for the FU PERSON ecosystem             ║
╚══════════════════════════════════════════════════════════════╝
```

## `[root@fuperson]─[~/quick-install]`

```bash
# Kali Linux / Parrot OS — most tools pre-installed
root@kali:~# apt update && apt upgrade -y
[+] Package lists updated
[+] All packages upgraded to latest versions
```

## `[root@fuperson]─[~/network-tools]`

### Network Tools

```bash
# [+] Install nmap — the gold standard
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install nmap

# macOS
root@fuperson:~# brew install nmap

# Windows: Download from https://nmap.org/download.html
```

```bash
# [+] Install masscan — blazing fast scanner
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install masscan

# macOS
root@fuperson:~# brew install masscan

# Compile from source
root@fuperson:~# git clone https://github.com/robertdavidgraham/masscan
root@fuperson:~# cd masscan && make
```

```bash
# [*] Install rustscan — Rust-powered port scanner
# Download from https://github.com/RustScan/RustScan/releases
root@fuperson:~# cargo install rustscan
```

```bash
# [+] Install zmap — internet-wide scanner
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install zmap

# macOS
root@fuperson:~# brew install zmap
```

## `[root@fuperson]─[~/web-app-tools]`

### Web Application Tools

```bash
# [+] Install nikto — web server scanner
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install nikto

# macOS
root@fuperson:~# brew install nikto

# Or from source
root@fuperson:~# git clone https://github.com/sullo/nikto
```

```bash
# [+] Install sqlmap — SQL injection framework
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install sqlmap

# macOS
root@fuperson:~# brew install sqlmap

# Or from GitHub
root@fuperson:~# git clone https://github.com/sqlmapproject/sqlmap.git
```

```bash
# [+] Install gobuster — directory/DNS bruteforcer
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install gobuster

# macOS
root@fuperson:~# brew install gobuster

# Or via Go
root@fuperson:~# go install github.com/OJ/gobuster/v3@latest
```

```bash
# [+] Install dirb — web content scanner
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install dirb

# Or from source
root@fuperson:~# git clone https://gitlab.com/kalilinux/packages/dirb.git
```

```bash
# [*] Install ffuf — fast web fuzzer
root@fuperson:~# go install github.com/ffuf/ffuf/v2@latest
# Download from https://github.com/ffuf/ffuf/releases
# Or via Go
# go install github.com/ffuf/ffuf/v2@latest
```

```bash
# [+] Install wpscan — WordPress security scanner
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install wpscan

# Or via Ruby gem
root@fuperson:~# gem install wpscan
```

```bash
# [+] Install whatweb — web fingerprinting
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install whatweb

# Or from GitHub
root@fuperson:~# git clone https://github.com/urbanadventurer/WhatWeb.git
```

```bash
# [+] Install wafw00f — WAF fingerprinting
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install wafw00f

# Or from GitHub
root@fuperson:~# git clone https://github.com/EnableSecurity/wafw00f.git
```

```bash
# [+] Install commix — command injection exploiter
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install commix

# Or from GitHub
root@fuperson:~# git clone https://github.com/commixproject/commix.git
```

```bash
# [*] Install NoSQLMap — NoSQL injection tool
root@fuperson:~# git clone https://github.com/codingo/NoSQLMap.git
root@fuperson:~# cd NoSQLMap && python setup.py install
```

## `[root@fuperson]─[~/osint-tools]`

### OSINT Tools

```bash
# [+] Install theHarvester — email/subdomain hunter
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install theharvester

# Or from GitHub
root@fuperson:~# git clone https://github.com/laramies/theHarvester.git
root@fuperson:~# cd theHarvester && pip3 install -r requirements.txt
```

```bash
# [+] Install amass — in-depth attack surface mapper
root@fuperson:~# go install -v github.com/OWASP/Amass/v4/...@master
# Download from https://github.com/OWASP/Amass/releases
# Or via Go
# go install -v github.com/OWASP/Amass/v4/...@master
```

```bash
# [*] Install sublist3r — subdomain enumeration
root@fuperson:~# git clone https://github.com/aboul3la/Sublist3r.git
root@fuperson:~# cd Sublist3r && pip3 install -r requirements.txt
```

```bash
# [+] Install dnsrecon — DNS enumeration
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install dnsrecon

# Or from GitHub
root@fuperson:~# git clone https://github.com/darkoperator/dnsrecon.git
```

```bash
# [+] Install dnsenum — DNS enumerator
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install dnsenum

# Or from GitHub
root@fuperson:~# git clone https://github.com/fwaeytens/dnsenum.git
```

```bash
# [+] Install fierce — DNS reconnaissance
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install fierce

# Or from GitHub
root@fuperson:~# git clone https://github.com/mschwager/fierce.git
```

## `[root@fuperson]─[~/ssl-tools]`

### SSL/TLS Tools

```bash
# [+] Install sslscan — SSL/TLS analyzer
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install sslscan

# macOS
root@fuperson:~# brew install sslscan
```

```bash
# [*] Install testssl.sh — comprehensive TLS tester
root@fuperson:~# git clone https://github.com/drwetter/testssl.sh.git
root@fuperson:~# cd testssl.sh
```

```bash
# [+] Install sslyze — SSL configuration analyzer
root@fuperson:~# pip3 install sslyze

# Or from GitHub
root@fuperson:~# git clone https://github.com/nabla-c0d3/sslyze.git
```

## `[root@fuperson]─[~/password-tools]`

### Password Tools

```bash
# [+] Install hydra — network login cracker
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install hydra

# macOS
root@fuperson:~# brew install hydra
```

```bash
# [+] Install john — password cracker
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install john

# macOS
root@fuperson:~# brew install john-jumbo
```

```bash
# [+] Install hashcat — GPU password recovery
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install hashcat

# macOS
root@fuperson:~# brew install hashcat

# Or from GitHub
root@fuperson:~# git clone https://github.com/hashcat/hashcat.git
```

## `[root@fuperson]─[~/additional-tools]`

### Additional Recommended Tools

```bash
# [+] Install Metasploit Framework — exploitation platform
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install metasploit-framework

# Or from Rapid7
root@fuperson:~# curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
root@fuperson:~# chmod 755 msfinstall && ./msfinstall
```

```bash
# [*] Burp Suite — web security testing
# Download from https://portswigger.net/burp/communitydownload
# Professional version available for purchase
```

```bash
# [*] OWASP ZAP — security scanner
# Download from https://www.zaproxy.org/download/
# Or via Docker
# docker pull owasp/zap2docker-stable
```

```bash
# [+] Install Wireshark / TShark — packet analysis
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install wireshark tshark

# macOS
root@fuperson:~# brew install wireshark
```

```bash
# [+] Install aircrack-ng — WiFi security auditing
# Debian/Ubuntu/Kali
root@fuperson:~# sudo apt install aircrack-ng

# macOS
root@fuperson:~# brew install aircrack-ng
```

## `[root@fuperson]─[~/docker]`

### Docker Installation

```bash
# [+] Many tools available as Docker containers
root@fuperson:~# docker pull owasp/zap2docker-stable   # OWASP ZAP
root@fuperson:~# docker pull paoloo/sqlmap             # SQLMap
root@fuperson:~# docker pull hysnsec/nikto             # Nikto
root@fuperson:~# docker pull uzyexe/nmap                # Nmap
```

## `[root@fuperson]─[~/python]`

### Python Tools (via pip)

```bash
root@fuperson:~# pip3 install sqlmap nikto theharvester amass recon-ng
[+] Python tools installed
```

## `[root@fuperson]─[~/go]`

### Go Tools (via go install)

```bash
root@fuperson:~# go install github.com/OJ/gobuster/v3@latest
root@fuperson:~# go install github.com/ffuf/ffuf/v2@latest
root@fuperson:~# go install -v github.com/OWASP/Amass/v4/...@master
root@fuperson:~# go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
[+] Go tools installed to $GOPATH/bin
```

## `[root@fuperson]─[~/verification]`

### Verification

```bash
# [+] Verify tools after installation
root@fuperson:~# nmap --version
root@fuperson:~# nikto -Version
root@fuperson:~# sqlmap --version
root@fuperson:~# gobuster version

# Or run the suite - it will auto-detect available tools
root@fuperson:~# python pentest_suite.py <target> --authorized
```

## `[root@fuperson]─[~/wordlists]`

### Wordlists

```bash
# [+] Install SecLists — comprehensive wordlist collection
root@fuperson:~# git clone https://github.com/danielmiessler/SecLists.git
# cd SecLists

# RockYou wordlist (if not already installed)
# Usually in /usr/share/wordlists/rockyou.txt on Kali
# Or download from: https://github.com/brannondorsey/naive-hashcat/releases
```

## `[root@fuperson]─[~/troubleshooting]`

### Troubleshooting

```bash
# [!] Tool Not Found
# Verify installation: which <tool>
# Check PATH: echo $PATH
# Reinstall tool
# Use full path to tool

# [!] Permission Issues
# Some tools require root: sudo <tool>
# Check file permissions: chmod +x <tool>
```

```bash
# [*] Python Dependencies
root@fuperson:~# pip3 install --upgrade pip
root@fuperson:~# pip3 install -r requirements.txt
```

```bash
# [*] Go Tools Not Working
root@fuperson:~# go version
# Add Go bin to PATH
root@fuperson:~# export PATH=$PATH:$(go env GOPATH)/bin
```

## `[root@fuperson]─[~/platform-notes]`

### Platform-Specific Notes

```bash
# [-] Windows: Use WSL2 with Kali Linux for best compatibility
# [-] macOS: Use Homebrew — brew install <tool>
# [-] Linux: Use apt, yum, or pacman
```

- **Windows**: Use WSL2 with Kali Linux for best compatibility. Or install tools individually. Some tools may require Cygwin.
- **macOS**: Use Homebrew for most tools. Some tools may require Xcode Command Line Tools. Install via: `xcode-select --install`
- **Linux**: Use package manager (apt, yum, pacman). Check tool repositories. Compile from source if needed.

## `[root@fuperson]─[~/automation]`

### Automation Script

```bash
#!/bin/bash
# install_tools.sh

echo "[*] Installing security tools..."

# [+] Network tools
root@fuperson:~# apt install -y nmap masscan zmap rustscan

# [+] Web tools
root@fuperson:~# apt install -y nikto sqlmap gobuster dirb wpscan whatweb wafw00f commix

# [+] OSINT tools
root@fuperson:~# apt install -y theharvester amass dnsrecon dnsenum fierce

# [+] SSL tools
root@fuperson:~# apt install -y sslscan sslyze

# [+] Password tools
root@fuperson:~# apt install -y hydra john hashcat

# [+] Additional
root@fuperson:~# apt install -y metasploit-framework wireshark aircrack-ng

echo "[+] Installation complete!"
# Make executable: chmod +x install_tools.sh
```

---

**FLLC | Armory Guide | 2026**
