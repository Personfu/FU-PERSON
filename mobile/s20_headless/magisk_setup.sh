#!/data/data/com.termux/files/usr/bin/bash
# ============================================================================
#  FLLC — Android Magisk Root + Attack Platform Setup
#  ═══════════════════════════════════════════════════
#
#  FULL SETUP GUIDE FOR SAMSUNG GALAXY S20+ (OR ANY ANDROID)
#
#  PREREQUISITES:
#  ──────────────
#  1. Unlock bootloader:
#     - Settings > About > Tap "Build Number" 7x (enable Developer Options)
#     - Settings > Developer Options > Enable "OEM Unlocking"
#     - Power off, hold Volume Down + Power to enter Download Mode
#     - Long press Volume Up to unlock (WIPES ALL DATA)
#
#  2. Install Magisk:
#     - Download Magisk APK: https://github.com/topjohnwu/Magisk/releases
#     - Extract boot.img from your stock firmware (use Samsung's Odin/Frija)
#     - Install Magisk APK on phone
#     - Open Magisk > Install > Select boot.img > Patch
#     - Flash patched boot.img via Odin:
#       a. Download Odin (Windows) or Heimdall (Linux/Mac)
#       b. Put phone in Download Mode (Vol Down + Power)
#       c. Flash patched boot.img to AP slot
#     - Reboot. Magisk app should show "Installed" with version
#
#  3. Install Termux + Addons (FROM F-DROID, NOT PLAY STORE):
#     - Termux:           https://f-droid.org/packages/com.termux/
#     - Termux:API:       https://f-droid.org/packages/com.termux.api/
#     - Termux:Boot:      https://f-droid.org/packages/com.termux.boot/
#     - Termux:Widget:    https://f-droid.org/packages/com.termux.widget/
#     - Termux:Styling:   https://f-droid.org/packages/com.termux.styling/
#
#  4. Grant permissions:
#     - Settings > Apps > Termux > Permissions > Grant ALL
#     - Open Termux, run: termux-setup-storage
#
#  5. Enable ADB over WiFi (for headless control):
#     - Settings > Developer Options > Wireless debugging > Enable
#     - Or via USB: adb tcpip 5555
#
#  THIS SCRIPT:
#  ────────────
#  Run this AFTER Magisk + Termux are installed.
#  It installs everything needed for a full attack platform.
#
#  FLLC | Authorized use only.
# ============================================================================

set -euo pipefail

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'

banner() {
    echo -e "${C}${B}"
    echo "  ╔═══════════════════════════════════════════════╗"
    echo "  ║   FLLC — ANDROID ATTACK PLATFORM SETUP       ║"
    echo "  ║   Magisk Root + Full Pentest Environment      ║"
    echo "  ╚═══════════════════════════════════════════════╝"
    echo -e "${N}"
}

section() { echo -e "\n${Y}[*] ═══ $1 ═══${N}"; }
ok()      { echo -e "  ${G}[+]${N} $1"; }
warn()    { echo -e "  ${Y}[!]${N} $1"; }
fail()    { echo -e "  ${R}[-]${N} $1"; }

banner

# ============================================================================
#  STEP 1: VERIFY ENVIRONMENT
# ============================================================================
section "STEP 1/10: Verify Environment"

# Check root
if su -c "id" 2>/dev/null | grep -q "uid=0"; then
    ok "Root access confirmed (Magisk)"
    ROOT=true
else
    warn "No root access. Some features will be limited."
    warn "Install Magisk: https://github.com/topjohnwu/Magisk/releases"
    ROOT=false
fi

# Check Termux API
if command -v termux-battery-status &>/dev/null; then
    ok "Termux:API installed"
else
    warn "Termux:API not detected. Install from F-Droid."
fi

# Check boot addon
if [ -d "$HOME/.termux/boot" ] 2>/dev/null; then
    ok "Termux:Boot directory exists"
else
    mkdir -p "$HOME/.termux/boot"
    ok "Created Termux:Boot directory"
fi

# ============================================================================
#  STEP 2: UPDATE & INSTALL PACKAGES
# ============================================================================
section "STEP 2/10: Package Installation"

pkg update -y 2>/dev/null
pkg upgrade -y 2>/dev/null

# Core packages
CORE_PKGS="git wget curl openssh python python-pip nodejs ruby clang make cmake"
CORE_PKGS="$CORE_PKGS autoconf automake libtool pkg-config openssl openssl-tool"
CORE_PKGS="$CORE_PKGS libffi libxml2 libxslt zlib bzip2 tar unzip zip jq"
CORE_PKGS="$CORE_PKGS tmux screen vim nano crunch"

# Network packages
NET_PKGS="nmap net-tools iproute2 dnsutils traceroute whois mtr"
NET_PKGS="$NET_PKGS tcpdump tshark socat netcat-openbsd ngrep"
NET_PKGS="$NET_PKGS tor proxychains-ng libpcap"

# Security packages
SEC_PKGS="hydra john hashcat aircrack-ng sqlmap"

# Termux-specific
TERM_PKGS="termux-api termux-tools root-repo"

for pkg_group in "$CORE_PKGS" "$NET_PKGS" "$SEC_PKGS" "$TERM_PKGS"; do
    for pkg in $pkg_group; do
        pkg install -y "$pkg" 2>/dev/null && ok "Installed: $pkg" || warn "Skipped: $pkg"
    done
done

# ============================================================================
#  STEP 3: PYTHON SECURITY TOOLS
# ============================================================================
section "STEP 3/10: Python Security Tools"

pip install --upgrade pip setuptools wheel 2>/dev/null

PYTHON_TOOLS=(
    requests beautifulsoup4 lxml scrapy scapy
    paramiko pycryptodome impacket ldap3 dnspython
    python-nmap shodan censys netaddr ipwhois python-whois
    waybackpy holehe socialscan maigret
    pwntools volatility3 yara-python oletools
    pillow flask aiohttp httpx rich click colorama
    mitmproxy certipy-ad bloodhound
)

for tool in "${PYTHON_TOOLS[@]}"; do
    pip install "$tool" 2>/dev/null && ok "pip: $tool" || warn "pip skip: $tool"
done

# ============================================================================
#  STEP 4: MAGISK MODULES
# ============================================================================
section "STEP 4/10: Magisk Modules"

if $ROOT; then
    echo -e "  ${C}Install these Magisk modules via the Magisk app:${N}"
    echo ""
    echo "  RECOMMENDED MODULES:"
    echo "  ─────────────────────"
    echo "  1. BusyBox for Android NDK"
    echo "     - Full set of Unix utilities"
    echo "     - Required for many pentest tools"
    echo ""
    echo "  2. Shamiko (or Zygisk)"
    echo "     - Hide root from apps that detect it"
    echo "     - Banking apps, SafetyNet, etc."
    echo ""
    echo "  3. LSPosed / Xposed Framework"
    echo "     - Module framework for deep Android hooks"
    echo "     - Enables SSL pinning bypass, app modification"
    echo ""
    echo "  4. WiFi Bonding / Monitor Mode"
    echo "     - Enable monitor mode on internal WiFi"
    echo "     - Required for aircrack-ng, packet capture"
    echo ""
    echo "  5. Frida Server (as Magisk module)"
    echo "     - Dynamic instrumentation toolkit"
    echo "     - SSL pinning bypass, API hooking"
    echo ""
    echo "  6. Riru + Hide My Applist"
    echo "     - Hide installed pentest tools from detection"
    echo ""
    
    # Install BusyBox if not present
    if ! command -v busybox &>/dev/null; then
        warn "BusyBox not found. Install via Magisk module manager."
    else
        ok "BusyBox detected: $(busybox | head -1)"
    fi
    
    # Setup Frida
    pip install frida-tools objection 2>/dev/null && ok "Frida tools installed" || warn "Frida tools skipped"
else
    warn "Skipping Magisk modules (no root)"
fi

# ============================================================================
#  STEP 5: KALI NETHUNTER (OPTIONAL)
# ============================================================================
section "STEP 5/10: Kali NetHunter Rootless"

echo -e "  ${C}NetHunter extends Termux with full Kali Linux:${N}"
echo ""
echo "  INSTALL NETHUNTER ROOTLESS:"
echo "  ────────────────────────────"
echo "  wget -O install-nethunter-termux https://offs.ec/2MceZWr"
echo "  chmod +x install-nethunter-termux"
echo "  ./install-nethunter-termux"
echo ""
echo "  THEN RUN KALI:"
echo "  ─────────────"
echo "  nethunter              # Start Kali CLI"
echo "  nethunter kex passwd   # Set VNC password"  
echo "  nethunter kex &        # Start desktop (VNC)"
echo ""

# Auto-install if user wants
read -p "  Install NetHunter Rootless now? (y/N): " -t 10 INSTALL_NH || INSTALL_NH="n"
if [[ "$INSTALL_NH" =~ ^[Yy]$ ]]; then
    wget -qO install-nethunter-termux https://offs.ec/2MceZWr 2>/dev/null
    chmod +x install-nethunter-termux 2>/dev/null
    ./install-nethunter-termux 2>/dev/null && ok "NetHunter installed" || warn "NetHunter install failed"
fi

# ============================================================================
#  STEP 6: CLONE ATTACK REPOSITORIES
# ============================================================================
section "STEP 6/10: Clone Attack Repositories"

mkdir -p ~/tools ~/wordlists
cd ~/tools

REPOS=(
    "https://github.com/nmap/nmap.git"
    "https://github.com/xnl-h4ck3r/waymore.git"
    "https://github.com/Lissy93/web-check.git"
    "https://github.com/iojw/socialscan.git"
    "https://github.com/Ringmast4r/Tower-Hunter.git"
    "https://github.com/Ringmast4r/GNSS.git"
    "https://github.com/Ringmast4r/PathFinder.git"
    "https://github.com/BC-SECURITY/Empire.git"
    "https://github.com/KeygraphHQ/shannon.git"
    "https://github.com/Ringmast4r/website-lists.git"
    "https://github.com/public-apis/public-apis.git"
    "https://github.com/daviddias/node-dirbuster.git"
    "https://github.com/Ringmast4r/crystal-vault.git"
)

for repo in "${REPOS[@]}"; do
    name=$(basename "$repo" .git)
    if [ -d "$name" ]; then
        ok "Already cloned: $name"
    else
        git clone --depth 1 "$repo" 2>/dev/null && ok "Cloned: $name" || warn "Failed: $name"
    fi
done

# ============================================================================
#  STEP 7: SSH + REMOTE ACCESS
# ============================================================================
section "STEP 7/10: Remote Access Configuration"

# Generate SSH key
if [ ! -f ~/.ssh/id_rsa ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -q 2>/dev/null || \
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -q
    ok "SSH key generated"
fi

# Set SSH password
echo -e "fllc\nfllc" | passwd 2>/dev/null
ok "SSH password set"

# Start SSH
sshd 2>/dev/null
PHONE_IP=$(ifconfig wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}')
ok "SSH server: ssh -p 8022 $(whoami)@${PHONE_IP:-<phone_ip>}"

# ============================================================================
#  STEP 8: BOOT SCRIPTS (AUTO-START ON REBOOT)
# ============================================================================
section "STEP 8/10: Persistent Boot Services"

mkdir -p ~/.termux/boot

# Auto-start SSH
cat > ~/.termux/boot/01_ssh.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
sshd
EOF
chmod +x ~/.termux/boot/01_ssh.sh
ok "Boot: SSH auto-start"

# Auto-start WiFi monitoring
cat > ~/.termux/boot/02_wifi_monitor.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
sleep 15
mkdir -p /sdcard/FLLC/wifi_logs
while true; do
    termux-wifi-scaninfo > "/sdcard/FLLC/wifi_logs/scan_$(date +%Y%m%d_%H%M%S).json" 2>/dev/null
    sleep 60
done
EOF
chmod +x ~/.termux/boot/02_wifi_monitor.sh
ok "Boot: WiFi auto-scan (every 60s)"

# Auto-start location tracking
cat > ~/.termux/boot/03_location.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
sleep 20
mkdir -p /sdcard/FLLC/location_logs
while true; do
    termux-location -p gps -r once >> "/sdcard/FLLC/location_logs/track_$(date +%Y%m%d).jsonl" 2>/dev/null
    sleep 300
done
EOF
chmod +x ~/.termux/boot/03_location.sh
ok "Boot: GPS tracking (every 5min)"

# Auto-start cell tower logging
cat > ~/.termux/boot/04_cell_towers.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
sleep 25
mkdir -p /sdcard/FLLC/cell_logs
while true; do
    termux-telephony-cellinfo >> "/sdcard/FLLC/cell_logs/towers_$(date +%Y%m%d).jsonl" 2>/dev/null
    sleep 120
done
EOF
chmod +x ~/.termux/boot/04_cell_towers.sh
ok "Boot: Cell tower logging (every 2min)"

# ============================================================================
#  STEP 9: TERMUX WIDGET SHORTCUTS
# ============================================================================
section "STEP 9/10: Quick-Launch Shortcuts"

mkdir -p ~/.shortcuts

# WiFi scan shortcut
cat > ~/.shortcuts/wifi_scan.sh << 'SHORTCUT'
#!/data/data/com.termux/files/usr/bin/bash
echo "=== WiFi Scan ==="
termux-wifi-scaninfo | python3 -c "
import json,sys
nets=json.load(sys.stdin)
for n in sorted(nets,key=lambda x:x.get('level',-100),reverse=True):
    print(f\"{n.get('ssid','<hidden>'):<30} {n.get('level','?'):>5}dBm {n.get('capabilities','')[:20]}\")
print(f'\n{len(nets)} networks found')
"
SHORTCUT
chmod +x ~/.shortcuts/wifi_scan.sh

# Quick recon shortcut
cat > ~/.shortcuts/quick_recon.sh << 'SHORTCUT'
#!/data/data/com.termux/files/usr/bin/bash
echo "=== Quick Network Recon ==="
GW=$(ip route | grep default | awk '{print $3}' | head -1)
SUB=$(echo "$GW" | sed 's/\.[0-9]*$/.0\/24/')
echo "Gateway: $GW | Subnet: $SUB"
nmap -sn "$SUB" 2>/dev/null | grep "report\|MAC"
SHORTCUT
chmod +x ~/.shortcuts/quick_recon.sh

# Full attack shortcut
cat > ~/.shortcuts/full_attack.sh << 'SHORTCUT'
#!/data/data/com.termux/files/usr/bin/bash
echo "=== Full Attack Suite ==="
cd ~/scripts 2>/dev/null || cd ~
bash headless_recon.sh 2>/dev/null || echo "Run setup first"
SHORTCUT
chmod +x ~/.shortcuts/full_attack.sh

ok "Termux Widget shortcuts created (add widget to home screen)"

# ============================================================================
#  STEP 10: ADB WIRELESS SETUP
# ============================================================================
section "STEP 10/10: ADB Wireless Configuration"

if $ROOT; then
    su -c "setprop service.adb.tcp.port 5555; stop adbd; start adbd" 2>/dev/null
    ok "ADB TCP/IP on port 5555"
    ok "Connect from PC: adb connect ${PHONE_IP:-<phone_ip>}:5555"
fi

# ============================================================================
#  SETUP COMPLETE
# ============================================================================
echo ""
echo -e "${G}${B}"
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║   SETUP COMPLETE                              ║"
echo "  ╠═══════════════════════════════════════════════╣"
echo "  ║                                               ║"
echo "  ║   ACCESS METHODS:                             ║"
echo "  ║   ─────────────                               ║"
echo "  ║   SSH:    ssh -p 8022 user@${PHONE_IP:-<ip>}        ║"
echo "  ║   ADB:    adb connect ${PHONE_IP:-<ip>}:5555        ║"
echo "  ║   scrcpy: scrcpy --turn-screen-off            ║"
echo "  ║                                               ║"
echo "  ║   AUTO-RUNNING ON BOOT:                       ║"
echo "  ║   ─────────────────────                       ║"
echo "  ║   - SSH server (port 8022)                    ║"
echo "  ║   - WiFi scanning (every 60s)                 ║"
echo "  ║   - GPS tracking (every 5min)                 ║"
echo "  ║   - Cell tower logging (every 2min)           ║"
echo "  ║                                               ║"
echo "  ║   DATA COLLECTION: /sdcard/FLLC/              ║"
echo "  ║                                               ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo -e "${N}"
