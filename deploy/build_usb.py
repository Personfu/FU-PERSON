#!/usr/bin/env python3
"""
FLLC - USB Tri-Drive Build & Deploy
===========================================
Master orchestrator for the new organized repository structure.

Reads from the reorganized project layout:
    core/         -> H:/pt_suite/
    payloads/     -> I:/payloads/
    firmware/     -> H:/esp32/
    flipper/      -> H:/flipper/
    mobile/       -> H:/mobile/
    recorder/     -> J:/ (or ESP32 SD)

Drives:
    H: (SD)       ATTACK toolkit
    I: (Micro SD) DATA DUMP payloads + loot directories
    J: (Optional) Recorder / ESP32

Usage:
    python deploy/build_usb.py
    python deploy/build_usb.py --deploy-only
    python deploy/build_usb.py --sd H --micro I

Authorized use only. FLLC.
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime


# Project root is one level up from deploy/
PROJECT_ROOT = Path(os.path.dirname(os.path.abspath(__file__))).parent

# Default drive letters
DEFAULT_SD_DRIVE = 'H'
DEFAULT_MICRO_DRIVE = 'I'
DEFAULT_AUX_DRIVE = 'J'


class C:
    CYAN = '\033[96m';  GREEN = '\033[92m';  YELLOW = '\033[93m'
    RED  = '\033[91m';  BOLD  = '\033[1m';   DIM    = '\033[2m'
    R    = '\033[0m'


def safe_copytree(src: Path, dst: Path, **kwargs):
    """Copy directory tree with Python 3.7 compatibility."""
    try:
        shutil.copytree(str(src), str(dst), dirs_exist_ok=True, **kwargs)
    except TypeError:
        if dst.exists():
            shutil.rmtree(str(dst))
        shutil.copytree(str(src), str(dst))


def safe_copy(src: Path, dst: Path):
    """Copy single file."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(dst))
    return True


class TriDriveBuilder:
    def __init__(self, sd_drive, micro_drive, aux_drive):
        self.sd = Path(f"{sd_drive}:\\")
        self.micro = Path(f"{micro_drive}:\\")
        self.aux = Path(f"{aux_drive}:\\")
        self.root = PROJECT_ROOT

    def banner(self):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"""
{C.BOLD}================================================================
  FLLC - TRI-DRIVE DEPLOYMENT
================================================================{C.R}
  SD (Attack):   {self.sd}
  Micro (Dump):  {self.micro}
  Aux (ESP32):   {self.aux}
  Source:        {self.root}
  Timestamp:     {ts}
{C.BOLD}================================================================{C.R}
""")

    def check_drives(self) -> bool:
        ok = True
        for label, path in [("SD", self.sd), ("Micro", self.micro)]:
            if path.exists():
                total, used, free = shutil.disk_usage(str(path))
                print(f"  {C.GREEN}[OK]{C.R} {label} ({path}) - {free/(1024**3):.1f} GB free")
            else:
                print(f"  {C.RED}[--]{C.R} {label} ({path}) - not mounted")
                ok = False
        # Aux is optional
        if self.aux.exists():
            total, used, free = shutil.disk_usage(str(self.aux))
            print(f"  {C.GREEN}[OK]{C.R} Aux  ({self.aux}) - {free/(1024**3):.1f} GB free")
        else:
            print(f"  {C.YELLOW}[..]{C.R} Aux  ({self.aux}) - not mounted (optional)")
        print()
        return ok

    # ──────────────────────────────────────────────────────────────
    #  H: DRIVE (SD) - ATTACK
    # ──────────────────────────────────────────────────────────────

    def deploy_sd(self):
        print(f"\n{C.BOLD}--- H: SD CARD (ATTACK) ---{C.R}\n")
        sd = self.sd
        count = 0

        # core/ -> pt_suite/
        pt_dst = sd / "pt_suite"
        pt_dst.mkdir(parents=True, exist_ok=True)
        core_files = [
            "pentest_suite.py", "osint_recon_suite.py", "galaxy_recon_suite.py",
            "people_finder.py", "repo_collector.py", "list_consolidator.py",
            "consolidated_lists.py",
        ]
        for f in core_files:
            src = self.root / "core" / f
            if src.exists():
                safe_copy(src, pt_dst / f)
                count += 1

        # core/data/ -> pt_suite/data/
        data_src = self.root / "core" / "data"
        if data_src.exists():
            safe_copytree(data_src, pt_dst / "data")
            count += 1

        # requirements.txt
        req = self.root / "requirements.txt"
        if req.exists():
            safe_copy(req, pt_dst / "requirements.txt")
            count += 1

        # Launchers
        for bat in ["Run_Pentest_Suite.bat", "Run_OSINT_Recon.bat",
                     "Run_Galaxy_Recon.bat", "Run_People_Finder.bat",
                     "LAUNCH.bat", "Install_Dependencies.bat"]:
            src = self.root / "deploy" / bat
            if src.exists():
                safe_copy(src, pt_dst / bat)
                count += 1

        print(f"  {C.GREEN}[OK]{C.R} pt_suite/ - {count} items")

        # firmware/esp32/ -> esp32/
        esp_src = self.root / "firmware" / "esp32"
        if esp_src.exists():
            esp_dst = sd / "esp32"
            if esp_dst.exists():
                shutil.rmtree(str(esp_dst), ignore_errors=True)
            safe_copytree(esp_src, esp_dst,
                          ignore=shutil.ignore_patterns('.pio', '__pycache__'))
            print(f"  {C.GREEN}[OK]{C.R} esp32/ - wardriver firmware")

        # flipper/ -> flipper/
        flip_src = self.root / "flipper"
        if flip_src.exists():
            flip_dst = sd / "flipper"
            try:
                if flip_dst.exists():
                    shutil.rmtree(str(flip_dst), ignore_errors=True)
                safe_copytree(flip_src, flip_dst)
            except PermissionError:
                # If rmtree failed, copy files individually
                for sub in flip_src.rglob("*"):
                    if sub.is_file():
                        rel = sub.relative_to(flip_src)
                        dst_file = flip_dst / rel
                        dst_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(str(sub), str(dst_file))
            print(f"  {C.GREEN}[OK]{C.R} flipper/ - BadUSB + GPIO + SubGHz + NFC + IR")

        # mobile/ -> mobile/
        mob_src = self.root / "mobile"
        if mob_src.exists():
            mob_dst = sd / "mobile"
            try:
                if mob_dst.exists():
                    shutil.rmtree(str(mob_dst), ignore_errors=True)
                safe_copytree(mob_src, mob_dst)
            except PermissionError:
                for sub in mob_src.rglob("*"):
                    if sub.is_file():
                        rel = sub.relative_to(mob_src)
                        dst_file = mob_dst / rel
                        dst_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(str(sub), str(dst_file))
            print(f"  {C.GREEN}[OK]{C.R} mobile/ - S20 headless + DSi")

        # consolidated lists from repo_downloads if they exist
        lists_src = self.root / "consolidated_lists"
        if lists_src.exists():
            lists_dst = sd / "lists"
            lists_dst.mkdir(parents=True, exist_ok=True)
            for f in lists_src.iterdir():
                if f.is_file():
                    safe_copy(f, lists_dst / f.name)
            print(f"  {C.GREEN}[OK]{C.R} lists/ - consolidated wordlists")

        # extracted repo tools if they exist
        extracted = self.root / "repo_downloads" / "extracted"
        if extracted.exists():
            tools_dst = sd / "tools"
            tools_dst.mkdir(parents=True, exist_ok=True)
            for d in extracted.iterdir():
                if d.is_dir():
                    safe_copytree(d, tools_dst / d.name)
            print(f"  {C.GREEN}[OK]{C.R} tools/ - extracted repositories")

        print(f"\n  {C.GREEN}SD card deployment complete.{C.R}")

    # ──────────────────────────────────────────────────────────────
    #  I: DRIVE (MICRO SD) - DATA DUMP
    # ──────────────────────────────────────────────────────────────

    def deploy_micro(self):
        print(f"\n{C.BOLD}--- I: MICRO SD (DATA DUMP) ---{C.R}\n")
        micro = self.micro

        # payloads/windows/ -> payloads/
        pay_dst = micro / "payloads"
        pay_dst.mkdir(parents=True, exist_ok=True)

        win_src = self.root / "payloads" / "windows"
        if win_src.exists():
            for f in win_src.iterdir():
                if f.is_file():
                    safe_copy(f, pay_dst / f.name)
            print(f"  {C.GREEN}[OK]{C.R} payloads/ - Windows scripts")

        linux_src = self.root / "payloads" / "linux"
        if linux_src.exists():
            for f in linux_src.iterdir():
                if f.is_file():
                    safe_copy(f, pay_dst / f.name)
            print(f"  {C.GREEN}[OK]{C.R} payloads/ - Linux scripts")

        # Autorun entry points at root for easy access
        root_files = [
            ("run_me.bat", "run_me.bat"),
            ("phantom.bat", "phantom.bat"),
            ("autorun_service.ps1", "autorun_service.ps1"),
        ]
        for src_name, dst_name in root_files:
            src = self.root / "payloads" / "windows" / src_name
            if src.exists():
                safe_copy(src, micro / dst_name)
                print(f"  {C.GREEN}[OK]{C.R} {dst_name} (root)")
        
        # Also copy phantom.bat as alternate names for different delivery methods
        phantom = self.root / "payloads" / "windows" / "phantom.bat"
        if phantom.exists():
            for alias in ["setup.bat", "install.bat", "USB_Driver_Update.bat"]:
                safe_copy(phantom, micro / alias)

        # Loot directories
        loot_dirs = [
            "loot", "loot/input_logs", "loot/privesc", "loot/sqli",
            "loot/npp", "loot/system_info", "loot/browser_data",
            "loot/wifi_profiles", "loot/recordings"
        ]
        for d in loot_dirs:
            (micro / d).mkdir(parents=True, exist_ok=True)
        print(f"  {C.GREEN}[OK]{C.R} loot/ - {len(loot_dirs)} collection directories")

        # People finder tool copy for portable use
        pf = self.root / "core" / "people_finder.py"
        if pf.exists():
            tools_dst = micro / "tools"
            tools_dst.mkdir(parents=True, exist_ok=True)
            safe_copy(pf, tools_dst / "people_finder.py")
            pf_bat = self.root / "deploy" / "Run_People_Finder.bat"
            if pf_bat.exists():
                safe_copy(pf_bat, tools_dst / "Run_People_Finder.bat")
            print(f"  {C.GREEN}[OK]{C.R} tools/ - People Finder")

        print(f"\n  {C.GREEN}Micro SD deployment complete.{C.R}")

    # ──────────────────────────────────────────────────────────────
    #  J: DRIVE (AUX) - RECORDER / ESP32 BACKUP
    # ──────────────────────────────────────────────────────────────

    def deploy_aux(self):
        if not self.aux.exists():
            print(f"\n{C.YELLOW}--- J: AUX DRIVE (not mounted, skipping) ---{C.R}")
            return

        print(f"\n{C.BOLD}--- J: AUX DRIVE ---{C.R}\n")
        aux = self.aux

        rec_src = self.root / "recorder"
        if rec_src.exists():
            for f in rec_src.iterdir():
                if f.is_file():
                    safe_copy(f, aux / f.name)
            (aux / "recordings").mkdir(parents=True, exist_ok=True)
            print(f"  {C.GREEN}[OK]{C.R} recorder files + recordings/")

        print(f"\n  {C.GREEN}Aux drive deployment complete.{C.R}")

    # ──────────────────────────────────────────────────────────────
    #  BUILD (clone repos + consolidate)
    # ──────────────────────────────────────────────────────────────

    def build(self):
        print(f"\n{C.BOLD}--- BUILD PHASE ---{C.R}\n")

        collector = self.root / "core" / "repo_collector.py"
        if collector.exists():
            print(f"  Running repo_collector.py...")
            subprocess.run([sys.executable, str(collector)], cwd=str(self.root))

        consolidator = self.root / "core" / "list_consolidator.py"
        if consolidator.exists():
            print(f"  Running list_consolidator.py...")
            subprocess.run([sys.executable, str(consolidator)], cwd=str(self.root))

    # ──────────────────────────────────────────────────────────────
    #  SUMMARY
    # ──────────────────────────────────────────────────────────────

    def summary(self):
        print(f"""
{C.BOLD}================================================================
  DEPLOYMENT COMPLETE
================================================================{C.R}""")
        for label, path in [("SD", self.sd), ("Micro", self.micro), ("Aux", self.aux)]:
            if path.exists():
                total, used, free = shutil.disk_usage(str(path))
                files = sum(1 for _ in path.rglob('*') if _.is_file())
                print(f"  {C.GREEN}{label}{C.R} ({path}) - {files} files, {used/(1024**2):.0f} MB used, {free/(1024**3):.1f} GB free")
        print(f"""
{C.BOLD}================================================================{C.R}
  Authorized use only. FLLC.
{C.BOLD}================================================================{C.R}
""")

    # ──────────────────────────────────────────────────────────────
    #  RUN
    # ──────────────────────────────────────────────────────────────

    def run(self, do_build=True, do_deploy=True):
        self.banner()
        if do_deploy and not self.check_drives():
            resp = input("  Not all drives mounted. Continue? (y/N): ").strip().lower()
            if resp != 'y':
                sys.exit(1)
        if do_build:
            self.build()
        if do_deploy:
            self.deploy_sd()
            self.deploy_micro()
            self.deploy_aux()
            self.summary()


def main():
    parser = argparse.ArgumentParser(description="FLLC Tri-Drive Deployment")
    parser.add_argument("--sd", default=DEFAULT_SD_DRIVE, help="SD card drive letter")
    parser.add_argument("--micro", default=DEFAULT_MICRO_DRIVE, help="Micro SD drive letter")
    parser.add_argument("--aux", default=DEFAULT_AUX_DRIVE, help="Aux drive letter")
    parser.add_argument("--build-only", action="store_true", help="Build without deploying")
    parser.add_argument("--deploy-only", action="store_true", help="Deploy without building")
    args = parser.parse_args()

    builder = TriDriveBuilder(args.sd, args.micro, args.aux)

    if args.build_only:
        builder.run(do_build=True, do_deploy=False)
    elif args.deploy_only:
        builder.run(do_build=False, do_deploy=True)
    else:
        builder.run()


if __name__ == "__main__":
    main()
