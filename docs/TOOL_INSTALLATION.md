# Security Tools Installation Guide

This guide helps you install the 200+ security tools that can be integrated with the Penetration Testing Suite.

## Quick Install (Kali Linux / Parrot OS)

Most tools are pre-installed. Update with:
```bash
sudo apt update && sudo apt upgrade
```

## Category-by-Category Installation

### Network Tools

#### Nmap
```bash
# Debian/Ubuntu/Kali
sudo apt install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

#### Masscan
```bash
# Debian/Ubuntu/Kali
sudo apt install masscan

# macOS
brew install masscan

# Compile from source
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
```

#### RustScan
```bash
# Download from https://github.com/RustScan/RustScan/releases
# Or install via cargo
cargo install rustscan
```

#### Zmap
```bash
# Debian/Ubuntu/Kali
sudo apt install zmap

# macOS
brew install zmap
```

### Web Application Tools

#### Nikto
```bash
# Debian/Ubuntu/Kali
sudo apt install nikto

# macOS
brew install nikto

# Or from source
git clone https://github.com/sullo/nikto
```

#### SQLMap
```bash
# Debian/Ubuntu/Kali
sudo apt install sqlmap

# macOS
brew install sqlmap

# Or from GitHub
git clone https://github.com/sqlmapproject/sqlmap.git
```

#### Gobuster
```bash
# Debian/Ubuntu/Kali
sudo apt install gobuster

# macOS
brew install gobuster

# Or via Go
go install github.com/OJ/gobuster/v3@latest
```

#### DIRB
```bash
# Debian/Ubuntu/Kali
sudo apt install dirb

# Or from source
git clone https://gitlab.com/kalilinux/packages/dirb.git
```

#### FFuF
```bash
# Download from https://github.com/ffuf/ffuf/releases
# Or via Go
go install github.com/ffuf/ffuf/v2@latest
```

#### WPScan
```bash
# Debian/Ubuntu/Kali
sudo apt install wpscan

# Or via Ruby gem
gem install wpscan
```

#### WhatWeb
```bash
# Debian/Ubuntu/Kali
sudo apt install whatweb

# Or from GitHub
git clone https://github.com/urbanadventurer/WhatWeb.git
```

#### WAFW00F
```bash
# Debian/Ubuntu/Kali
sudo apt install wafw00f

# Or from GitHub
git clone https://github.com/EnableSecurity/wafw00f.git
```

#### Commix
```bash
# Debian/Ubuntu/Kali
sudo apt install commix

# Or from GitHub
git clone https://github.com/commixproject/commix.git
```

#### NoSQLMap
```bash
# From GitHub
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
python setup.py install
```

### OSINT Tools

#### TheHarvester
```bash
# Debian/Ubuntu/Kali
sudo apt install theharvester

# Or from GitHub
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip3 install -r requirements.txt
```

#### Amass
```bash
# Download from https://github.com/OWASP/Amass/releases
# Or via Go
go install -v github.com/OWASP/Amass/v4/...@master
```

#### Sublist3r
```bash
# From GitHub
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip3 install -r requirements.txt
```

#### DNSRecon
```bash
# Debian/Ubuntu/Kali
sudo apt install dnsrecon

# Or from GitHub
git clone https://github.com/darkoperator/dnsrecon.git
```

#### DNSEnum
```bash
# Debian/Ubuntu/Kali
sudo apt install dnsenum

# Or from GitHub
git clone https://github.com/fwaeytens/dnsenum.git
```

#### Fierce
```bash
# Debian/Ubuntu/Kali
sudo apt install fierce

# Or from GitHub
git clone https://github.com/mschwager/fierce.git
```

### SSL/TLS Tools

#### SSLScan
```bash
# Debian/Ubuntu/Kali
sudo apt install sslscan

# macOS
brew install sslscan
```

#### testssl.sh
```bash
# From GitHub
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
```

#### SSLyze
```bash
# Via pip
pip3 install sslyze

# Or from GitHub
git clone https://github.com/nabla-c0d3/sslyze.git
```

### Password Tools

#### Hydra
```bash
# Debian/Ubuntu/Kali
sudo apt install hydra

# macOS
brew install hydra
```

#### John the Ripper
```bash
# Debian/Ubuntu/Kali
sudo apt install john

# macOS
brew install john-jumbo
```

#### Hashcat
```bash
# Debian/Ubuntu/Kali
sudo apt install hashcat

# macOS
brew install hashcat

# Or from GitHub
git clone https://github.com/hashcat/hashcat.git
```

### Additional Recommended Tools

#### Metasploit Framework
```bash
# Debian/Ubuntu/Kali
sudo apt install metasploit-framework

# Or from Rapid7
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

#### Burp Suite
```bash
# Download from https://portswigger.net/burp/communitydownload
# Professional version available for purchase
```

#### OWASP ZAP
```bash
# Download from https://www.zaproxy.org/download/
# Or via Docker
docker pull owasp/zap2docker-stable
```

#### Wireshark / TShark
```bash
# Debian/Ubuntu/Kali
sudo apt install wireshark tshark

# macOS
brew install wireshark
```

#### Aircrack-ng
```bash
# Debian/Ubuntu/Kali
sudo apt install aircrack-ng

# macOS
brew install aircrack-ng
```

## Docker Installation

Many tools are available as Docker containers:

```bash
# OWASP ZAP
docker pull owasp/zap2docker-stable

# SQLMap
docker pull paoloo/sqlmap

# Nikto
docker pull hysnsec/nikto

# Nmap
docker pull uzyexe/nmap
```

## Python Tools (via pip)

```bash
pip3 install sqlmap nikto theharvester amass recon-ng
```

## Go Tools (via go install)

```bash
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
go install -v github.com/OWASP/Amass/v4/...@master
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Verification

After installation, verify tools are available:

```bash
# Check individual tools
nmap --version
nikto -Version
sqlmap --version
gobuster version

# Or run the suite - it will auto-detect available tools
python pentest_suite.py <target> --authorized
```

## Wordlists

Install wordlists for brute-forcing:

```bash
# SecLists (comprehensive wordlist collection)
git clone https://github.com/danielmiessler/SecLists.git
cd SecLists

# RockYou wordlist (if not already installed)
# Usually in /usr/share/wordlists/rockyou.txt on Kali
# Or download from: https://github.com/brannondorsey/naive-hashcat/releases
```

## Troubleshooting

### Tool Not Found
- Verify installation: `which <tool>`
- Check PATH: `echo $PATH`
- Reinstall tool
- Use full path to tool

### Permission Issues
- Some tools require root: `sudo <tool>`
- Check file permissions: `chmod +x <tool>`

### Python Dependencies
```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

### Go Tools Not Working
```bash
# Ensure Go is installed
go version

# Add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

## Platform-Specific Notes

### Windows
- Use WSL2 with Kali Linux for best compatibility
- Or install tools individually
- Some tools may require Cygwin

### macOS
- Use Homebrew for most tools
- Some tools may require Xcode Command Line Tools
- Install via: `xcode-select --install`

### Linux
- Use package manager (apt, yum, pacman)
- Check tool repositories
- Compile from source if needed

## Automation Script

Create a setup script:

```bash
#!/bin/bash
# install_tools.sh

echo "Installing security tools..."

# Network tools
sudo apt install -y nmap masscan zmap rustscan

# Web tools
sudo apt install -y nikto sqlmap gobuster dirb wpscan whatweb wafw00f commix

# OSINT tools
sudo apt install -y theharvester amass dnsrecon dnsenum fierce

# SSL tools
sudo apt install -y sslscan sslyze

# Password tools
sudo apt install -y hydra john hashcat

# Additional
sudo apt install -y metasploit-framework wireshark aircrack-ng

echo "Installation complete!"
```

Make executable: `chmod +x install_tools.sh`
