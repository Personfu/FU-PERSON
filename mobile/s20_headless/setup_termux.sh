#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  FLLC | FU PERSON | S20+ HEADLESS PLATFORM
#  ╔══════════════════════════════════════════════════════════════════╗
#  ║  Termux Bootstrap & Tool Installation                          ║
#  ║  Galaxy S20+ with Magisk root                                   ║
#  ╚══════════════════════════════════════════════════════════════════╝
# ═══════════════════════════════════════════════════════════════════════
#  Prerequisites:
#    - Samsung Galaxy S20+ with Magisk root
#    - Termux installed (F-Droid version, NOT Play Store)
#    - Termux:API addon installed
#    - USB debugging enabled
#    - Connected via ADB: adb shell (then run this script)
#      OR: copy to device and run in Termux directly
#
#  Since the screen is broken, control via:
#    1. ADB shell:     adb shell
#    2. ADB + Termux:  adb shell 'am start -n com.termux/.app.TermuxActivity'
#    3. SSH (after setup): ssh -p 8022 user@<phone_ip>
#    4. scrcpy (screen mirror): scrcpy --no-video (audio/control only)
#
#  Ref: topjohnwu/Magisk for root

set -e

echo "============================================"
echo "  FLLC - S20+ ATTACK PLATFORM SETUP"
echo "============================================"
echo ""

# ============================================================================
#  STEP 1: Termux Package Updates
# ============================================================================
echo "[1/8] Updating Termux packages..."
pkg update -y
pkg upgrade -y

# ============================================================================
#  STEP 2: Core Utilities
# ============================================================================
echo "[2/8] Installing core utilities..."
pkg install -y \
    git \
    wget \
    curl \
    openssh \
    nmap \
    python \
    python-pip \
    nodejs \
    ruby \
    perl \
    clang \
    make \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    openssl \
    openssl-tool \
    libffi \
    libxml2 \
    libxslt \
    zlib \
    bzip2 \
    tar \
    unzip \
    zip \
    jq \
    tmux \
    screen \
    vim \
    nano \
    net-tools \
    iproute2 \
    dnsutils \
    traceroute \
    whois \
    tcpdump \
    tshark \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    mtr \
    socat \
    netcat-openbsd \
    ngrep \
    sqlmap \
    tor \
    proxychains-ng \
    crunch \
    wordlists \
    libpcap \
    root-repo \
    termux-api \
    termux-tools

echo "[+] Core utilities installed"

# ============================================================================
#  STEP 3: Python Penetration Testing Tools
# ============================================================================
echo "[3/8] Installing Python pentest tools..."
pip install --upgrade pip setuptools wheel

pip install \
    requests \
    beautifulsoup4 \
    lxml \
    scrapy \
    scapy \
    paramiko \
    pycryptodome \
    impacket \
    ldap3 \
    dnspython \
    python-nmap \
    shodan \
    censys \
    netaddr \
    ipwhois \
    python-whois \
    waybackpy \
    holehe \
    socialscan \
    maigret \
    pwntools \
    volatility3 \
    yara-python \
    oletools \
    pillow \
    pyperclip \
    flask \
    aiohttp \
    httpx \
    rich \
    click \
    colorama

echo "[+] Python tools installed"

# ============================================================================
#  STEP 4: Clone Essential Repositories
# ============================================================================
echo "[4/8] Cloning offensive security repositories..."
mkdir -p ~/tools
cd ~/tools

# Network reconnaissance
git clone --depth 1 https://github.com/nmap/nmap.git 2>/dev/null || echo "nmap already cloned"
git clone --depth 1 https://github.com/xnl-h4ck3r/waymore.git 2>/dev/null || echo "waymore already cloned"
git clone --depth 1 https://github.com/Lissy93/web-check.git 2>/dev/null || echo "web-check already cloned"

# OSINT
git clone --depth 1 https://github.com/iojw/socialscan.git 2>/dev/null || echo "socialscan already cloned"
git clone --depth 1 https://github.com/Ringmast4r/Tower-Hunter.git 2>/dev/null || echo "tower-hunter already cloned"
git clone --depth 1 https://github.com/Ringmast4r/GNSS.git 2>/dev/null || echo "gnss already cloned"

# Exploitation
git clone --depth 1 https://github.com/BC-SECURITY/Empire.git 2>/dev/null || echo "empire already cloned"
git clone --depth 1 https://github.com/Ringmast4r/PathFinder.git 2>/dev/null || echo "pathfinder already cloned"
git clone --depth 1 https://github.com/daviddias/node-dirbuster.git 2>/dev/null || echo "dirbuster already cloned"

# Wordlists
git clone --depth 1 https://github.com/Ringmast4r/website-lists.git 2>/dev/null || echo "website-lists already cloned"
git clone --depth 1 https://github.com/public-apis/public-apis.git 2>/dev/null || echo "public-apis already cloned"

# AI Hacking
git clone --depth 1 https://github.com/KeygraphHQ/shannon.git 2>/dev/null || echo "shannon already cloned"

echo "[+] Repositories cloned to ~/tools"

# ============================================================================
#  STEP 5: SSH Server (for headless access)
# ============================================================================
echo "[5/8] Configuring SSH server..."

# Generate SSH keys if not exists
if [ ! -f ~/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -q
fi

# Set password for SSH
echo "Setting SSH password..."
passwd <<EOF
FLLC
FLLC
EOF

# Start SSH server
sshd

# Get IP for connection
PHONE_IP=$(ifconfig wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}')
echo "[+] SSH server started on port 8022"
echo "[+] Connect: ssh -p 8022 $(whoami)@${PHONE_IP:-<phone_ip>}"

# ============================================================================
#  STEP 6: Persistent Services (auto-start on boot)
# ============================================================================
echo "[6/8] Setting up persistent services..."

mkdir -p ~/.termux/boot

# Auto-start SSH on boot
cat > ~/.termux/boot/start_sshd.sh << 'BOOTEOF'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sshd
BOOTEOF
chmod +x ~/.termux/boot/start_sshd.sh

# Auto-start recon on boot (optional, uncomment to enable)
cat > ~/.termux/boot/start_recon.sh << 'BOOTEOF'
#!/data/data/com.termux/files/usr/bin/bash
# Uncomment below to auto-run recon on phone boot
# sleep 30  # Wait for WiFi
# ~/scripts/headless_recon.sh &
BOOTEOF
chmod +x ~/.termux/boot/start_recon.sh

echo "[+] Boot scripts configured"

# ============================================================================
#  STEP 7: Termux API Setup (use phone sensors)
# ============================================================================
echo "[7/8] Configuring Termux API access..."

# Test API access
termux-battery-status 2>/dev/null && echo "[+] Termux API working" || echo "[!] Install Termux:API addon"

# Create sensor scripts
mkdir -p ~/scripts

# WiFi scanner using Termux API
cat > ~/scripts/wifi_scan.sh << 'WIFISCRIPT'
#!/data/data/com.termux/files/usr/bin/bash
# Quick WiFi scan using Termux API
echo "=== WIFI SCAN $(date) ==="
termux-wifi-scaninfo | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Found {len(data)} networks:\n')
print(f'{\"SSID\":<32} {\"BSSID\":<18} {\"RSSI\":>5} {\"CH\":>3} {\"Security\":<15}')
print('-' * 80)
for n in sorted(data, key=lambda x: x.get('level', -100), reverse=True):
    ssid = n.get('ssid', '<hidden>')[:31]
    bssid = n.get('bssid', 'unknown')
    rssi = n.get('level', 0)
    freq = n.get('frequency', 0)
    ch = (freq - 2407) // 5 if freq < 5000 else (freq - 5000) // 5 + 36
    sec = n.get('capabilities', 'OPEN')[:14]
    print(f'{ssid:<32} {bssid:<18} {rssi:>5} {ch:>3} {sec:<15}')
"
WIFISCRIPT
chmod +x ~/scripts/wifi_scan.sh

# Location tracker
cat > ~/scripts/location.sh << 'LOCSCRIPT'
#!/data/data/com.termux/files/usr/bin/bash
echo "=== LOCATION $(date) ==="
termux-location -p gps -r once | python3 -c "
import json, sys
loc = json.load(sys.stdin)
print(f'Latitude:  {loc.get(\"latitude\", \"N/A\")}')
print(f'Longitude: {loc.get(\"longitude\", \"N/A\")}')
print(f'Altitude:  {loc.get(\"altitude\", \"N/A\")}m')
print(f'Accuracy:  {loc.get(\"accuracy\", \"N/A\")}m')
print(f'Provider:  {loc.get(\"provider\", \"N/A\")}')
"
LOCSCRIPT
chmod +x ~/scripts/location.sh

echo "[+] Sensor scripts created"

# ============================================================================
#  STEP 8: Root-Specific Setup (Magisk)
# ============================================================================
echo "[8/8] Configuring root-specific tools..."

# Check for root
if command -v su &>/dev/null; then
    echo "[+] Root access detected (Magisk)"

    # Install root-only tools
    su -c "
        # Enable monitor mode on WiFi (if supported)
        ip link set wlan0 down 2>/dev/null
        iw dev wlan0 set type monitor 2>/dev/null
        ip link set wlan0 up 2>/dev/null
        echo '[+] WiFi monitor mode attempted'

        # Enable packet forwarding (for MITM)
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo '[+] IP forwarding enabled'
    " 2>/dev/null || echo "[!] Some root operations failed (expected on first run)"
else
    echo "[!] Root not detected - some features will be limited"
fi

# ============================================================================
#  SETUP COMPLETE
# ============================================================================
echo ""
echo "============================================"
echo "  SETUP COMPLETE"
echo "============================================"
echo ""
echo "  HEADLESS ACCESS METHODS:"
echo "    1. ADB:    adb shell"
echo "    2. SSH:    ssh -p 8022 $(whoami)@${PHONE_IP:-<phone_ip>}"
echo "    3. scrcpy: scrcpy --no-video"
echo ""
echo "  QUICK COMMANDS:"
echo "    ~/scripts/wifi_scan.sh    - Scan WiFi networks"
echo "    ~/scripts/location.sh     - Get GPS location"
echo "    nmap -sn 192.168.1.0/24   - Network host discovery"
echo "    sqlmap -u <url>            - SQL injection"
echo "    hydra -L users -P pass <host> ssh"
echo ""
echo "  TOOLS DIRECTORY: ~/tools"
echo "============================================"
