#!/data/data/com.termux/files/usr/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  FLLC | FU PERSON | S20+ HEADLESS RECON
#  ╔══════════════════════════════════════════════════════════════════╗
#  ║  Automated Reconnaissance — WiFi, GPS, Cellular                  ║
#  ║  Passive & active recon sweep, headless operation               ║
#  ╚══════════════════════════════════════════════════════════════════╝
# ═══════════════════════════════════════════════════════════════════════
#  Usage:
#    ./headless_recon.sh                     # Full recon
#    ./headless_recon.sh --target 192.168.1.0/24  # Target specific network
#    ./headless_recon.sh --passive           # Passive only (no active scans)
#    ./headless_recon.sh --output /sdcard/recon  # Custom output dir
#
#  Ref: NoorQureshi/kali-linux-cheatsheet, Werewolf-p/nmap-cheat-sheet

set -e

# Parse arguments
TARGET=""
PASSIVE_ONLY=false
OUTPUT_DIR="/sdcard/recon_$(date +%Y%m%d_%H%M%S)"

while [[ $# -gt 0 ]]; do
    case $1 in
        --target|-t) TARGET="$2"; shift 2;;
        --passive|-p) PASSIVE_ONLY=true; shift;;
        --output|-o) OUTPUT_DIR="$2"; shift 2;;
        *) echo "Unknown: $1"; shift;;
    esac
done

mkdir -p "$OUTPUT_DIR"/{wifi,network,osint,location,ble}

echo "============================================"
echo "  FLLC - HEADLESS RECON"
echo "  $(date)"
echo "  Output: $OUTPUT_DIR"
echo "============================================"

# ============================================================================
#  PHASE 1: ENVIRONMENT DISCOVERY
# ============================================================================
echo -e "\n[PHASE 1] Environment Discovery..."

# Device info
echo "--- Device Info ---" > "$OUTPUT_DIR/device_info.txt"
uname -a >> "$OUTPUT_DIR/device_info.txt"
echo "Hostname: $(hostname)" >> "$OUTPUT_DIR/device_info.txt"
ip addr >> "$OUTPUT_DIR/device_info.txt"
echo "[+] Device info captured"

# Battery status (to estimate runtime)
if command -v termux-battery-status &>/dev/null; then
    termux-battery-status > "$OUTPUT_DIR/battery.json"
    BATTERY=$(python3 -c "import json; print(json.load(open('$OUTPUT_DIR/battery.json'))['percentage'])" 2>/dev/null || echo "?")
    echo "[+] Battery: ${BATTERY}%"
fi

# ============================================================================
#  PHASE 2: WiFi RECONNAISSANCE
# ============================================================================
echo -e "\n[PHASE 2] WiFi Reconnaissance..."

# Scan WiFi networks using Termux API
if command -v termux-wifi-scaninfo &>/dev/null; then
    echo "[*] Scanning WiFi networks..."
    termux-wifi-scaninfo > "$OUTPUT_DIR/wifi/scan_raw.json"

    # Parse and format results
    python3 << 'PYSCRIPT' "$OUTPUT_DIR"
import json, sys, os

output_dir = sys.argv[1]
with open(f"{output_dir}/wifi/scan_raw.json") as f:
    networks = json.load(f)

# Summary report
with open(f"{output_dir}/wifi/scan_summary.txt", "w") as out:
    out.write(f"WiFi Scan Results - {len(networks)} networks found\n")
    out.write("=" * 80 + "\n\n")
    out.write(f"{'SSID':<32} {'BSSID':<18} {'RSSI':>5} {'CH':>3} {'Security':<20}\n")
    out.write("-" * 80 + "\n")

    for n in sorted(networks, key=lambda x: x.get('level', -100), reverse=True):
        ssid = n.get('ssid', '<hidden>')[:31]
        bssid = n.get('bssid', '?')
        rssi = n.get('level', 0)
        freq = n.get('frequency', 0)
        ch = (freq - 2407) // 5 if 2400 < freq < 2500 else (freq - 5000) // 5 + 36 if freq > 5000 else 0
        sec = n.get('capabilities', 'OPEN')[:19]
        out.write(f"{ssid:<32} {bssid:<18} {rssi:>5} {ch:>3} {sec:<20}\n")

# Separate open networks
open_nets = [n for n in networks if 'WPA' not in n.get('capabilities', '') and 'WEP' not in n.get('capabilities', '')]
if open_nets:
    with open(f"{output_dir}/wifi/open_networks.txt", "w") as out:
        out.write("OPEN WiFi Networks (potential targets)\n")
        out.write("=" * 60 + "\n")
        for n in open_nets:
            out.write(f"{n.get('ssid', '<hidden>')} | {n.get('bssid', '?')} | RSSI: {n.get('level', 0)}\n")

# WPA networks (for handshake targeting)
wpa_nets = [n for n in networks if 'WPA' in n.get('capabilities', '')]
if wpa_nets:
    with open(f"{output_dir}/wifi/wpa_targets.txt", "w") as out:
        out.write("WPA/WPA2 Networks (handshake targets)\n")
        out.write("=" * 60 + "\n")
        for n in wpa_nets:
            out.write(f"{n.get('ssid', '<hidden>')} | {n.get('bssid', '?')} | {n.get('capabilities', '')}\n")

print(f"[+] WiFi: {len(networks)} networks ({len(open_nets)} open, {len(wpa_nets)} WPA)")
PYSCRIPT
fi

# WiFi connection info
termux-wifi-connectioninfo > "$OUTPUT_DIR/wifi/connection.json" 2>/dev/null || true

# ============================================================================
#  PHASE 3: NETWORK SCANNING
# ============================================================================
echo -e "\n[PHASE 3] Network Scanning..."

# Get current gateway/subnet
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
SUBNET=$(echo "$GATEWAY" | sed 's/\.[0-9]*$/.0\/24/')

if [ -z "$TARGET" ]; then
    TARGET="$SUBNET"
fi

echo "[*] Target network: $TARGET"
echo "[*] Gateway: $GATEWAY"

if ! $PASSIVE_ONLY; then
    # Host discovery (ping sweep)
    echo "[*] Running host discovery..."
    nmap -sn "$TARGET" -oN "$OUTPUT_DIR/network/host_discovery.txt" \
         -oX "$OUTPUT_DIR/network/host_discovery.xml" 2>/dev/null || true

    # Quick port scan on discovered hosts
    echo "[*] Running quick port scan..."
    nmap -sS -sV --top-ports 1000 "$TARGET" \
         -oN "$OUTPUT_DIR/network/port_scan.txt" \
         -oX "$OUTPUT_DIR/network/port_scan.xml" 2>/dev/null || \
    nmap -sT -sV --top-ports 100 "$TARGET" \
         -oN "$OUTPUT_DIR/network/port_scan.txt" 2>/dev/null || true

    # OS detection on live hosts
    echo "[*] Running OS detection..."
    nmap -O --osscan-guess "$TARGET" \
         -oN "$OUTPUT_DIR/network/os_detect.txt" 2>/dev/null || true

    # Vulnerability scan (light)
    echo "[*] Running vulnerability scan..."
    nmap --script vuln --top-ports 100 "$TARGET" \
         -oN "$OUTPUT_DIR/network/vuln_scan.txt" 2>/dev/null || true

    echo "[+] Network scans complete"
else
    echo "[*] Passive mode - skipping active network scans"

    # Passive: ARP table
    ip neigh show > "$OUTPUT_DIR/network/arp_table.txt" 2>/dev/null || true

    # Passive: Listening services
    ss -tlnp > "$OUTPUT_DIR/network/listening_services.txt" 2>/dev/null || true
fi

# DNS info
echo "[*] Collecting DNS info..."
cat /etc/resolv.conf > "$OUTPUT_DIR/network/dns_config.txt" 2>/dev/null || true
nslookup google.com > "$OUTPUT_DIR/network/dns_test.txt" 2>/dev/null || true

# Route info
ip route > "$OUTPUT_DIR/network/routes.txt" 2>/dev/null || true

# ============================================================================
#  PHASE 4: GPS / LOCATION
# ============================================================================
echo -e "\n[PHASE 4] Location Data..."

if command -v termux-location &>/dev/null; then
    echo "[*] Getting GPS location..."
    termux-location -p gps -r once > "$OUTPUT_DIR/location/gps.json" 2>/dev/null || \
    termux-location -p network -r once > "$OUTPUT_DIR/location/gps.json" 2>/dev/null || true

    # Cell tower info (for Tower-Hunter correlation)
    termux-telephony-cellinfo > "$OUTPUT_DIR/location/cell_towers.json" 2>/dev/null || true
    termux-telephony-deviceinfo > "$OUTPUT_DIR/location/device_radio.json" 2>/dev/null || true

    echo "[+] Location data captured"
fi

# ============================================================================
#  PHASE 5: BLUETOOTH SCAN
# ============================================================================
echo -e "\n[PHASE 5] Bluetooth Discovery..."

if command -v termux-bluetooth-scan &>/dev/null; then
    echo "[*] Scanning Bluetooth devices..."
    timeout 15 termux-bluetooth-scan > "$OUTPUT_DIR/ble/bluetooth_devices.json" 2>/dev/null || true
    echo "[+] Bluetooth scan complete"
fi

# Also try hcitool if available (root)
if command -v hcitool &>/dev/null; then
    timeout 10 hcitool scan > "$OUTPUT_DIR/ble/hci_scan.txt" 2>/dev/null || true
    timeout 10 hcitool lescan --duplicates > "$OUTPUT_DIR/ble/ble_scan.txt" 2>/dev/null &
    BLE_PID=$!
    sleep 10
    kill $BLE_PID 2>/dev/null || true
fi

# ============================================================================
#  PHASE 6: TRAFFIC CAPTURE
# ============================================================================
echo -e "\n[PHASE 6] Traffic Capture..."

if ! $PASSIVE_ONLY; then
    # Capture 60 seconds of traffic
    echo "[*] Capturing network traffic (60 seconds)..."
    timeout 60 tcpdump -i any -w "$OUTPUT_DIR/network/capture.pcap" -c 10000 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 60
    kill $TCPDUMP_PID 2>/dev/null || true
    echo "[+] Traffic capture complete"
fi

# ============================================================================
#  GENERATE REPORT
# ============================================================================
echo -e "\n[REPORT] Generating summary report..."

python3 << 'REPORT' "$OUTPUT_DIR"
import json, os, sys, glob

output_dir = sys.argv[1]
report_path = os.path.join(output_dir, "RECON_REPORT.txt")

with open(report_path, "w") as r:
    r.write("=" * 60 + "\n")
    r.write("  FLLC - HEADLESS RECON REPORT\n")
    r.write("=" * 60 + "\n\n")

    # WiFi
    try:
        with open(os.path.join(output_dir, "wifi/scan_raw.json")) as f:
            nets = json.load(f)
        r.write(f"WiFi Networks Found: {len(nets)}\n")
        open_count = len([n for n in nets if 'WPA' not in n.get('capabilities', '') and 'WEP' not in n.get('capabilities', '')])
        r.write(f"  Open Networks: {open_count}\n")
        r.write(f"  WPA/WPA2 Networks: {len(nets) - open_count}\n\n")
    except: pass

    # Location
    try:
        with open(os.path.join(output_dir, "location/gps.json")) as f:
            loc = json.load(f)
        r.write(f"GPS Location: {loc.get('latitude', 'N/A')}, {loc.get('longitude', 'N/A')}\n")
        r.write(f"  Accuracy: {loc.get('accuracy', 'N/A')}m\n\n")
    except: pass

    # Cell towers
    try:
        with open(os.path.join(output_dir, "location/cell_towers.json")) as f:
            towers = json.load(f)
        r.write(f"Cell Towers Visible: {len(towers)}\n\n")
    except: pass

    # Files generated
    all_files = []
    for root, dirs, files in os.walk(output_dir):
        for f in files:
            fp = os.path.join(root, f)
            size = os.path.getsize(fp)
            rel = os.path.relpath(fp, output_dir)
            all_files.append((rel, size))

    r.write("Files Generated:\n")
    total_size = 0
    for name, size in sorted(all_files):
        r.write(f"  {name} ({size:,} bytes)\n")
        total_size += size
    r.write(f"\nTotal: {len(all_files)} files, {total_size:,} bytes\n")

print(f"[+] Report saved to {report_path}")
REPORT

echo ""
echo "============================================"
echo "  RECON COMPLETE"
echo "  Output: $OUTPUT_DIR"
echo "============================================"
