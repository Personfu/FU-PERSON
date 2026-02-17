#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  FLLC | FU PERSON | USB OUTPUT v2.0
#  ╔══════════════════════════════════════════════════════════════════╗
#  ║  Auto-detect USB drive and dump all Android loot to it          ║
#  ║  Galaxy S20+ Headless Pentest Platform                          ║
#  ╚══════════════════════════════════════════════════════════════════╝
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'
DIM='\033[2m'

banner() {
    echo -e "${CYAN}"
    echo "    ╔══════════════════════════════════════════════════════════╗"
    echo "    ║  FU PERSON — USB LOOT DUMP                              ║"
    echo "    ║  Galaxy S20+ → USB Drive                                ║"
    echo "    ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "    ${CYAN}[*]${NC} $1"; }
log_success() { echo -e "    ${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "    ${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "    ${RED}[-]${NC} $1"; }

# Detect USB storage
detect_usb() {
    log_info "Scanning for USB storage devices..."
    
    USB_PATH=""
    
    # Check common Android USB mount points
    MOUNT_POINTS=(
        "/storage/usb"
        "/storage/usb0"
        "/storage/usb1"
        "/mnt/usb_storage"
        "/mnt/media_rw/usb"
    )
    
    for mp in "${MOUNT_POINTS[@]}"; do
        if [ -d "$mp" ] && [ "$(ls -A $mp 2>/dev/null)" ]; then
            USB_PATH="$mp"
            log_success "USB drive found at: $USB_PATH"
            return 0
        fi
    done
    
    # Try to find via /proc/mounts
    USB_MOUNT=$(grep -i "usb\|vfat\|ntfs" /proc/mounts 2>/dev/null | grep -v "/storage/emulated" | head -1 | awk '{print $2}')
    if [ -n "$USB_MOUNT" ] && [ -d "$USB_MOUNT" ]; then
        USB_PATH="$USB_MOUNT"
        log_success "USB drive found at: $USB_PATH"
        return 0
    fi
    
    log_error "No USB drive detected"
    return 1
}

# Collect loot from all sources
collect_loot() {
    local LOOT_SRC="/sdcard/loot"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOOT_DEST="${USB_PATH}/android_loot_${TIMESTAMP}"
    
    mkdir -p "$LOOT_DEST"
    
    log_info "Collecting loot to: $LOOT_DEST"
    
    # Scan results
    SOURCES=(
        "/sdcard/loot:loot"
        "/sdcard/scan_results:scan_results"
        "/sdcard/wifi_data:wifi_data"
        "/sdcard/recon:recon"
        "/sdcard/nmap_output:nmap"
        "/sdcard/captures:captures"
        "/data/data/com.termux/files/home/loot:termux_loot"
    )
    
    TOTAL_FILES=0
    
    for source in "${SOURCES[@]}"; do
        SRC_PATH="${source%%:*}"
        DEST_NAME="${source##*:}"
        
        if [ -d "$SRC_PATH" ]; then
            mkdir -p "${LOOT_DEST}/${DEST_NAME}"
            FILE_COUNT=$(find "$SRC_PATH" -type f 2>/dev/null | wc -l)
            if [ "$FILE_COUNT" -gt 0 ]; then
                cp -r "$SRC_PATH/"* "${LOOT_DEST}/${DEST_NAME}/" 2>/dev/null
                log_success "Copied ${DEST_NAME}: ${FILE_COUNT} files"
                TOTAL_FILES=$((TOTAL_FILES + FILE_COUNT))
            fi
        fi
    done
    
    # Device info
    log_info "Capturing device information..."
    {
        echo "═══════════════════════════════════════════"
        echo "  FU PERSON — Android Device Report"
        echo "  Generated: $(date)"
        echo "═══════════════════════════════════════════"
        echo ""
        echo "[*] Device Model: $(getprop ro.product.model 2>/dev/null)"
        echo "[*] Android Version: $(getprop ro.build.version.release 2>/dev/null)"
        echo "[*] Build: $(getprop ro.build.display.id 2>/dev/null)"
        echo "[*] Serial: $(getprop ro.serialno 2>/dev/null)"
        echo "[*] Root Status: $(which su >/dev/null 2>&1 && echo 'ROOTED' || echo 'NOT ROOTED')"
        echo "[*] WiFi SSID: $(dumpsys wifi 2>/dev/null | grep 'mWifiInfo' | head -1)"
        echo "[*] IP Address: $(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}')"
        echo "[*] Disk Usage:"
        df -h 2>/dev/null
    } > "${LOOT_DEST}/device_info.txt"
    log_success "Device info captured"
    
    # WiFi passwords (requires root)
    if [ "$(which su 2>/dev/null)" ]; then
        log_info "Dumping WiFi passwords (root)..."
        WIFI_CONF="/data/misc/wifi/WifiConfigStore.xml"
        if su -c "test -f $WIFI_CONF"; then
            su -c "cat $WIFI_CONF" > "${LOOT_DEST}/wifi_passwords.xml" 2>/dev/null
            log_success "WiFi passwords dumped"
        fi
    fi
    
    # Summary
    TOTAL_SIZE=$(du -sh "$LOOT_DEST" 2>/dev/null | awk '{print $1}')
    
    echo ""
    echo -e "    ${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "    ${GREEN}║  LOOT DUMP COMPLETE                                      ║${NC}"
    echo -e "    ${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "    ${GREEN}║  Files: ${TOTAL_FILES}                                   ║${NC}"
    echo -e "    ${GREEN}║  Size: ${TOTAL_SIZE}                                     ║${NC}"
    echo -e "    ${GREEN}║  Path: ${LOOT_DEST}                                      ║${NC}"
    echo -e "    ${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
}

# Main
banner

if detect_usb; then
    collect_loot
else
    log_error "Cannot proceed without USB storage"
    log_warning "Connect a USB drive via OTG and try again"
    exit 1
fi
