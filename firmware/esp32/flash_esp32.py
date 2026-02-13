#!/usr/bin/env python3
"""
============================================================================
 flash_esp32.py — FLLC Wardriver v3  Auto-Flash Utility
 
 Detects ESP32 on serial, compiles firmware, and flashes.
 
 Usage:
   python flash_esp32.py              # auto-detect + flash
   python flash_esp32.py --port COM5  # manual port
   python flash_esp32.py --build-only # compile without flashing
   python flash_esp32.py --monitor    # flash then open serial monitor
============================================================================
"""

import subprocess
import sys
import os
import glob
import time
import argparse
import platform

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR  = SCRIPT_DIR  # platformio.ini lives here
FW_DIR       = os.path.join(SCRIPT_DIR, "FLLC_wardriver")
BAUD         = 921600
MONITOR_BAUD = 115200


def find_serial_ports():
    """Auto-detect serial ports with ESP32 candidates."""
    ports = []
    system = platform.system()
    
    if system == "Windows":
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM")
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    ports.append(val)
                    i += 1
                except WindowsError:
                    break
        except Exception:
            # Fallback: try common COM ports
            for i in range(1, 33):
                ports.append(f"COM{i}")
    elif system == "Linux":
        ports = glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")
    elif system == "Darwin":
        ports = glob.glob("/dev/cu.usbserial*") + glob.glob("/dev/cu.SLAB*") + glob.glob("/dev/cu.wchusbserial*")
    
    # Verify ports are openable
    valid = []
    for p in ports:
        try:
            import serial
            s = serial.Serial(p, 115200, timeout=0.1)
            s.close()
            valid.append(p)
        except Exception:
            # Try without pyserial
            if system == "Windows":
                valid.append(p)  # Can't verify on Windows without pyserial
    
    return valid


def check_platformio():
    """Check if PlatformIO CLI is available."""
    try:
        result = subprocess.run(["pio", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [✓] PlatformIO: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    # Try platformio command
    try:
        result = subprocess.run(["platformio", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [✓] PlatformIO: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    return False


def check_esptool():
    """Check if esptool is available (fallback flash method)."""
    try:
        result = subprocess.run([sys.executable, "-m", "esptool", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  [✓] esptool: {result.stdout.strip().splitlines()[0]}")
            return True
    except Exception:
        pass
    return False


def build_firmware():
    """Compile firmware using PlatformIO."""
    print("\n═══ COMPILING FIRMWARE ═══")
    print(f"  Source: {FW_DIR}")
    print(f"  Config: {os.path.join(PROJECT_DIR, 'platformio.ini')}")
    
    cmd = ["pio", "run", "-d", PROJECT_DIR]
    print(f"  Command: {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, cwd=PROJECT_DIR)
    
    if result.returncode != 0:
        print("\n  [✗] Compilation FAILED")
        print("  Common fixes:")
        print("    1. Install ESP32 platform:  pio platform install espressif32")
        print("    2. Check config.h pin definitions match your board")
        print("    3. Verify FLLC_wardriver/ directory has all .h files")
        return False
    
    print("\n  [✓] Compilation SUCCESSFUL")
    
    # Find firmware binary
    fw_path = os.path.join(PROJECT_DIR, ".pio", "build", "esp32dev", "firmware.bin")
    if os.path.exists(fw_path):
        size = os.path.getsize(fw_path) / 1024
        print(f"  Binary: {fw_path} ({size:.1f} KB)")
    
    return True


def flash_firmware(port=None):
    """Flash firmware to ESP32."""
    if not port:
        print("\n═══ DETECTING ESP32 ═══")
        ports = find_serial_ports()
        if not ports:
            print("  [✗] No serial ports found!")
            print("  1. Connect ESP32 via USB")
            print("  2. Install CP2102/CH340 drivers if needed")
            print("  3. Specify port manually: --port COM5")
            return False
        
        if len(ports) == 1:
            port = ports[0]
            print(f"  [✓] Found: {port}")
        else:
            print(f"  Found {len(ports)} ports: {', '.join(ports)}")
            port = ports[0]
            print(f"  Using: {port} (specify --port to override)")
    
    print(f"\n═══ FLASHING ESP32 on {port} ═══")
    print(f"  Baud: {BAUD}")
    print("  ⚡ DO NOT DISCONNECT during flash!\n")
    
    cmd = ["pio", "run", "-d", PROJECT_DIR, "-t", "upload", "--upload-port", port]
    result = subprocess.run(cmd, cwd=PROJECT_DIR)
    
    if result.returncode != 0:
        print("\n  [✗] Flash FAILED")
        print("  Try:")
        print("    1. Hold BOOT button on ESP32 during flash start")
        print("    2. Try lower baud: edit platformio.ini upload_speed")
        print("    3. Try different USB cable (data cable, not charge-only)")
        return False
    
    print("\n  [✓] Flash SUCCESSFUL")
    print("  ESP32 will reboot and start autopilot in 3 seconds")
    return True


def open_monitor(port=None):
    """Open serial monitor."""
    if not port:
        ports = find_serial_ports()
        port = ports[0] if ports else "auto"
    
    print(f"\n═══ SERIAL MONITOR ({port} @ {MONITOR_BAUD}) ═══")
    print("  Press Ctrl+C to exit\n")
    
    cmd = ["pio", "device", "monitor", "-b", str(MONITOR_BAUD)]
    if port != "auto":
        cmd += ["-p", port]
    
    try:
        subprocess.run(cmd, cwd=PROJECT_DIR)
    except KeyboardInterrupt:
        print("\n  Monitor closed.")


def install_prerequisites():
    """Attempt to install PlatformIO if missing."""
    print("\n═══ INSTALLING PLATFORMIO ═══")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "platformio"], check=True)
        # Install ESP32 platform
        subprocess.run(["pio", "platform", "install", "espressif32"], check=True)
        print("  [✓] PlatformIO + ESP32 platform installed")
        return True
    except Exception as e:
        print(f"  [✗] Install failed: {e}")
        print("  Manual install: pip install platformio && pio platform install espressif32")
        return False


def main():
    parser = argparse.ArgumentParser(description="FLLC Wardriver v3 — ESP32 Flash Utility")
    parser.add_argument("--port", help="Serial port (e.g. COM5, /dev/ttyUSB0)")
    parser.add_argument("--build-only", action="store_true", help="Compile only, don't flash")
    parser.add_argument("--flash-only", action="store_true", help="Flash only (assumes already built)")
    parser.add_argument("--monitor", action="store_true", help="Open serial monitor after flash")
    parser.add_argument("--install", action="store_true", help="Install PlatformIO + ESP32 platform")
    args = parser.parse_args()
    
    print("╔══════════════════════════════════════════╗")
    print("║  FLLC Wardriver v3 — Flash Utility    ║")
    print("║  ESP32 Autonomous WiFi/BLE Platform      ║")
    print("╚══════════════════════════════════════════╝")
    
    # Check prerequisites
    print("\n═══ CHECKING PREREQUISITES ═══")
    has_pio = check_platformio()
    has_esptool = check_esptool()
    
    if not has_pio:
        print("  [✗] PlatformIO not found")
        if args.install or input("  Install PlatformIO? (y/n): ").lower() == 'y':
            if not install_prerequisites():
                return 1
            has_pio = True
        else:
            print("  Install manually: pip install platformio")
            return 1
    
    # Verify source files exist
    ino_path = os.path.join(FW_DIR, "FLLC_wardriver.ino")
    cfg_path = os.path.join(FW_DIR, "config.h")
    oui_path = os.path.join(FW_DIR, "oui.h")
    
    for f, name in [(ino_path,"firmware"), (cfg_path,"config"), (oui_path,"OUI database")]:
        if os.path.exists(f):
            print(f"  [✓] {name}: {os.path.basename(f)} ({os.path.getsize(f)//1024}KB)")
        else:
            print(f"  [✗] {name} MISSING: {f}")
            return 1
    
    # Build
    if not args.flash_only:
        if not build_firmware():
            return 1
    
    # Flash
    if not args.build_only:
        if not flash_firmware(args.port):
            return 1
    
    # Monitor
    if args.monitor:
        open_monitor(args.port)
    else:
        print("\n  Tip: Run with --monitor to see ESP32 output")
        print(f"  Or:  pio device monitor -b {MONITOR_BAUD}")
    
    print("\n  Done. 🔥")
    return 0


if __name__ == "__main__":
    sys.exit(main())
