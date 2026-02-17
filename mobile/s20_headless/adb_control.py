#!/usr/bin/env python3
"""
# ═══════════════════════════════════════════════════════════════════════
#  FLLC | FU PERSON | S20+ ADB CONTROL
#  ╔══════════════════════════════════════════════════════════════════╗
#  ║  Remote Control — Headless Galaxy S20+ (broken screen)         ║
#  ║  ADB over USB/WiFi — commands, transfer, attack platform        ║
#  ╚══════════════════════════════════════════════════════════════════╝
# ═══════════════════════════════════════════════════════════════════════
#
# Control the headless Samsung Galaxy S20+ (broken screen) from your PC.
# Uses ADB over USB or WiFi to execute commands, transfer files,
# and manage the attack platform.

Requirements (on PC):
    pip install adbutils rich
    - ADB installed and in PATH
    - USB debugging enabled on phone
    - Phone connected via USB (or WiFi ADB enabled)

Usage:
    python adb_control.py                    # Interactive menu
    python adb_control.py shell              # Drop to shell
    python adb_control.py recon              # Run headless recon
    python adb_control.py wifi-scan          # Quick WiFi scan
    python adb_control.py exfil <local_dir>  # Pull all collected data
    python adb_control.py push <file>        # Push file to phone
    python adb_control.py scrcpy             # Start screen mirror

FLLC
"""

import subprocess
import sys
import os
import time
import json
import argparse
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class FakeConsole:
        def print(self, *a, **kw): print(*[str(x) for x in a])
    console = FakeConsole()


class S20Controller:
    """Control interface for the headless S20+."""

    def __init__(self):
        self.device_serial = None
        self.phone_ip = None
        self.ssh_port = 8022
        self.termux_home = "/data/data/com.termux/files/home"
        self.sdcard = "/sdcard"

    def adb(self, *args, capture=True, timeout=30):
        """Execute an ADB command."""
        cmd = ['adb']
        if self.device_serial:
            cmd += ['-s', self.device_serial]
        cmd += list(args)

        try:
            result = subprocess.run(
                cmd, capture_output=capture, text=True,
                timeout=timeout
            )
            return result.stdout.strip() if capture else None
        except subprocess.TimeoutExpired:
            console.print("[yellow]Command timed out[/yellow]" if HAS_RICH else "Command timed out")
            return ""
        except FileNotFoundError:
            console.print("[red]ADB not found. Install Android platform-tools.[/red]" if HAS_RICH
                          else "ADB not found")
            return ""

    def shell(self, command, timeout=30):
        """Execute a shell command on the phone."""
        return self.adb('shell', command, timeout=timeout)

    def connect(self):
        """Find and connect to the S20+."""
        console.print("\n[bold cyan]Searching for S20+...[/bold cyan]" if HAS_RICH
                      else "\nSearching for S20+...")

        # List connected devices
        output = self.adb('devices')
        lines = [l for l in output.split('\n') if '\t' in l and 'device' in l]

        if not lines:
            console.print("[yellow]No devices found via USB. Trying WiFi ADB...[/yellow]" if HAS_RICH
                          else "No USB devices. Trying WiFi...")
            # Try common WiFi ADB ports
            for port in [5555, 5556]:
                self.adb('connect', f'192.168.1.100:{port}')
            output = self.adb('devices')
            lines = [l for l in output.split('\n') if '\t' in l and 'device' in l]

        if lines:
            self.device_serial = lines[0].split('\t')[0]
            model = self.shell('getprop ro.product.model')
            android = self.shell('getprop ro.build.version.release')
            console.print(f"[green]Connected: {model} (Android {android}) [{self.device_serial}][/green]"
                          if HAS_RICH else f"Connected: {model} (Android {android})")

            # Get phone IP
            self.phone_ip = self.shell("ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1")
            if self.phone_ip:
                console.print(f"[green]Phone IP: {self.phone_ip}[/green]" if HAS_RICH
                              else f"Phone IP: {self.phone_ip}")
            return True
        else:
            console.print("[red]No device found. Check USB cable and debugging settings.[/red]"
                          if HAS_RICH else "No device found.")
            return False

    def enable_wifi_adb(self):
        """Enable wireless ADB for cable-free control."""
        self.shell('setprop service.adb.tcp.port 5555')
        self.shell('stop adbd')
        self.shell('start adbd')
        if self.phone_ip:
            console.print(f"[green]WiFi ADB enabled. Connect with: adb connect {self.phone_ip}:5555[/green]"
                          if HAS_RICH else f"WiFi ADB enabled: adb connect {self.phone_ip}:5555")

    def get_status(self):
        """Get comprehensive device status."""
        info = {}
        info['model'] = self.shell('getprop ro.product.model')
        info['android'] = self.shell('getprop ro.build.version.release')
        info['serial'] = self.shell('getprop ro.serialno')
        info['battery'] = self.shell('dumpsys battery | grep level')
        info['wifi_ssid'] = self.shell("dumpsys wifi | grep 'mWifiInfo' | grep -oP 'SSID: [^,]+'")
        info['ip'] = self.phone_ip
        info['root'] = 'Yes' if 'uid=0' in self.shell('su -c id 2>/dev/null') else 'No'
        info['uptime'] = self.shell('uptime -p')
        info['storage'] = self.shell('df -h /sdcard | tail -1')

        if HAS_RICH:
            table = Table(title="S20+ Device Status", show_header=True)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            for k, v in info.items():
                table.add_row(k.title(), str(v))
            console.print(table)
        else:
            print("\n=== S20+ Status ===")
            for k, v in info.items():
                print(f"  {k}: {v}")
        return info

    def run_recon(self):
        """Execute the headless recon script on the phone."""
        console.print("[bold yellow]Starting headless recon on S20+...[/bold yellow]"
                      if HAS_RICH else "Starting recon...")

        # Check if script exists
        exists = self.shell(f'test -f {self.termux_home}/scripts/headless_recon.sh && echo YES')
        if 'YES' not in exists:
            console.print("[yellow]Pushing recon scripts to phone...[/yellow]"
                          if HAS_RICH else "Pushing scripts...")
            self.push_scripts()

        # Run via Termux
        output = self.shell(
            f'su -c "cd {self.termux_home} && bash scripts/headless_recon.sh 2>&1"',
            timeout=300
        )
        console.print(output)

    def wifi_scan(self):
        """Quick WiFi scan using Termux API."""
        console.print("[cyan]Scanning WiFi networks...[/cyan]" if HAS_RICH else "Scanning WiFi...")

        result = self.shell(
            'am broadcast -n com.termux.api/.TermuxApiReceiver '
            '--es com.termux.api.command wifi-scan-results 2>/dev/null; '
            'sleep 2; termux-wifi-scaninfo 2>/dev/null',
            timeout=15
        )

        try:
            networks = json.loads(result)
            if HAS_RICH:
                table = Table(title=f"WiFi Networks ({len(networks)} found)")
                table.add_column("SSID", style="cyan")
                table.add_column("BSSID")
                table.add_column("RSSI", justify="right")
                table.add_column("Security", style="yellow")
                for n in sorted(networks, key=lambda x: x.get('level', -100), reverse=True):
                    table.add_row(
                        n.get('ssid', '<hidden>'),
                        n.get('bssid', '?'),
                        str(n.get('level', '?')),
                        n.get('capabilities', 'OPEN')[:20]
                    )
                console.print(table)
            else:
                print(f"\nFound {len(networks)} networks:")
                for n in networks:
                    print(f"  {n.get('ssid', '<hidden>'):<30} {n.get('level', '?'):>5}dBm  {n.get('capabilities', '')[:20]}")
        except json.JSONDecodeError:
            console.print(result or "[red]No scan results[/red]")

    def exfil_data(self, local_dir=None):
        """Pull all collected data from the phone."""
        local_dir = local_dir or f"s20_exfil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(local_dir, exist_ok=True)

        console.print(f"[yellow]Pulling data to {local_dir}...[/yellow]"
                      if HAS_RICH else f"Pulling to {local_dir}...")

        # Pull recon data
        pull_dirs = [
            '/sdcard/recon_*',
            '/sdcard/wifi_attacks_*',
            f'{self.termux_home}/tools',
        ]

        for pattern in pull_dirs:
            # Find matching directories
            matches = self.shell(f'ls -d {pattern} 2>/dev/null')
            for match in matches.split('\n'):
                match = match.strip()
                if match:
                    dirname = os.path.basename(match)
                    console.print(f"  Pulling {match}...")
                    self.adb('pull', match, os.path.join(local_dir, dirname), capture=False)

        console.print(f"[green]Data saved to {os.path.abspath(local_dir)}[/green]"
                      if HAS_RICH else f"Data saved to {os.path.abspath(local_dir)}")

    def push_scripts(self):
        """Push attack scripts to the phone."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        scripts = ['setup_termux.sh', 'headless_recon.sh', 'wifi_attacks.sh']

        self.shell(f'mkdir -p {self.termux_home}/scripts')

        for script in scripts:
            local = os.path.join(script_dir, script)
            if os.path.exists(local):
                remote = f'{self.termux_home}/scripts/{script}'
                self.adb('push', local, remote, capture=False)
                self.shell(f'chmod +x {remote}')
                console.print(f"  [green]Pushed {script}[/green]" if HAS_RICH else f"  Pushed {script}")

    def start_scrcpy(self):
        """Start scrcpy for screen mirroring (even with broken screen)."""
        console.print("[cyan]Starting scrcpy...[/cyan]" if HAS_RICH else "Starting scrcpy...")
        try:
            # Try with video first, fall back to no-video
            subprocess.Popen(['scrcpy', '--turn-screen-off', '--stay-awake',
                              '--power-off-on-close'], shell=False)
            console.print("[green]scrcpy started. You can now see and control the phone.[/green]")
        except FileNotFoundError:
            console.print("[yellow]scrcpy not found. Install from: https://github.com/Genymobile/scrcpy[/yellow]"
                          if HAS_RICH else "scrcpy not found")

    def start_ssh_tunnel(self):
        """Set up SSH tunnel for persistent access."""
        if not self.phone_ip:
            console.print("[red]Phone IP not available[/red]")
            return

        # Start sshd on phone
        self.shell(f'su -c "{self.termux_home}/../usr/bin/sshd"')

        # Port forward
        self.adb('forward', 'tcp:8022', 'tcp:8022')

        console.print(f"[green]SSH tunnel ready![/green]" if HAS_RICH else "SSH tunnel ready!")
        console.print(f"  Connect: ssh -p 8022 localhost")
        console.print(f"  Or:      ssh -p 8022 $(whoami)@{self.phone_ip}")

    def interactive_menu(self):
        """Interactive control menu."""
        while True:
            console.print("\n" + "=" * 50)
            console.print("[bold cyan]  FLLC - S20+ COMMAND CENTER[/bold cyan]"
                          if HAS_RICH else "  FLLC - S20+ COMMAND CENTER")
            console.print("=" * 50)
            options = [
                "1. Device Status",
                "2. WiFi Scan",
                "3. Run Full Recon",
                "4. Interactive Shell",
                "5. Push Scripts to Phone",
                "6. Pull Collected Data",
                "7. Start scrcpy (Screen Mirror)",
                "8. Enable WiFi ADB",
                "9. Start SSH Tunnel",
                "10. WiFi Attacks Menu",
                "0. Exit"
            ]
            for opt in options:
                console.print(f"  {opt}")

            try:
                choice = input("\n  Select: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if choice == '1':
                self.get_status()
            elif choice == '2':
                self.wifi_scan()
            elif choice == '3':
                self.run_recon()
            elif choice == '4':
                console.print("[yellow]Dropping to ADB shell... (type 'exit' to return)[/yellow]")
                subprocess.run(['adb', 'shell'], shell=False)
            elif choice == '5':
                self.push_scripts()
            elif choice == '6':
                self.exfil_data()
            elif choice == '7':
                self.start_scrcpy()
            elif choice == '8':
                self.enable_wifi_adb()
            elif choice == '9':
                self.start_ssh_tunnel()
            elif choice == '10':
                self._wifi_attack_menu()
            elif choice == '0':
                break

    def _wifi_attack_menu(self):
        """Sub-menu for WiFi attacks."""
        console.print("\n[bold red]  WiFi Attack Options:[/bold red]" if HAS_RICH
                      else "\n  WiFi Attack Options:")
        console.print("  1. Scan networks")
        console.print("  2. Deauth target")
        console.print("  3. Capture handshake")
        console.print("  4. Evil twin")
        console.print("  5. MITM attack")
        console.print("  0. Back")

        choice = input("\n  Select: ").strip()
        script = f'{self.termux_home}/scripts/wifi_attacks.sh'

        if choice == '1':
            self.shell(f'su -c "bash {script} scan"', timeout=60)
        elif choice == '2':
            bssid = input("  Target BSSID: ").strip()
            self.shell(f'su -c "bash {script} deauth {bssid}"', timeout=30)
        elif choice == '3':
            bssid = input("  Target BSSID: ").strip()
            ch = input("  Channel: ").strip() or "0"
            self.shell(f'su -c "bash {script} handshake {bssid} {ch}"', timeout=120)
        elif choice == '4':
            ssid = input("  SSID to clone: ").strip()
            self.shell(f'su -c "bash {script} evil_twin \'{ssid}\'"', timeout=300)
        elif choice == '5':
            self.shell(f'su -c "bash {script} mitm"', timeout=300)


def main():
    parser = argparse.ArgumentParser(description='FLLC - S20+ ADB Controller')
    parser.add_argument('command', nargs='?', default='menu',
                        choices=['menu', 'shell', 'recon', 'wifi-scan', 'exfil',
                                 'push', 'scrcpy', 'status', 'ssh'],
                        help='Command to execute')
    parser.add_argument('extra', nargs='?', help='Extra argument (e.g., local dir for exfil)')
    args = parser.parse_args()

    ctrl = S20Controller()

    console.print(Panel.fit("[bold]FLLC - S20+ Attack Platform Controller[/bold]",
                            border_style="cyan") if HAS_RICH else
                  "=== FLLC - S20+ Controller ===")

    if not ctrl.connect():
        sys.exit(1)

    if args.command == 'menu':
        ctrl.interactive_menu()
    elif args.command == 'shell':
        subprocess.run(['adb', 'shell'])
    elif args.command == 'recon':
        ctrl.run_recon()
    elif args.command == 'wifi-scan':
        ctrl.wifi_scan()
    elif args.command == 'exfil':
        ctrl.exfil_data(args.extra)
    elif args.command == 'push':
        ctrl.push_scripts()
    elif args.command == 'scrcpy':
        ctrl.start_scrcpy()
    elif args.command == 'status':
        ctrl.get_status()
    elif args.command == 'ssh':
        ctrl.start_ssh_tunnel()


if __name__ == '__main__':
    main()
