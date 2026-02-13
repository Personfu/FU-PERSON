#!/usr/bin/env python3
"""
FLLC - PyInstaller Build Script for Listener
=====================================================
Compiles listener.py into a standalone .exe that runs
without requiring Python on the target machine.

Requirements:
    pip install pyinstaller pyaudio numpy pydub

Usage:
    python build_exe.py

Output:
    dist/listener.exe (~15-20MB standalone)
"""

import os
import sys
import subprocess
from pathlib import Path


def main():
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    listener_path = script_dir / 'listener.py'

    if not listener_path.exists():
        print("[!] listener.py not found in current directory")
        sys.exit(1)

    # Check PyInstaller
    try:
        import PyInstaller
        print(f"[+] PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("[!] PyInstaller not installed. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'],
                       check=True)

    print("[*] Building standalone executable...")
    print(f"    Source: {listener_path}")
    print(f"    Output: {script_dir / 'dist' / 'listener.exe'}")
    print()

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',                   # Single .exe file
        '--noconsole',                 # No console window (runs hidden)
        '--name', 'listener',          # Output name
        '--distpath', str(script_dir / 'dist'),
        '--workpath', str(script_dir / 'build'),
        '--specpath', str(script_dir),
        '--clean',                     # Clean build
        '--noconfirm',                 # Don't ask confirmation
        # Hidden imports that PyInstaller might miss
        '--hidden-import', 'pyaudio',
        '--hidden-import', 'numpy',
        '--hidden-import', 'pydub',
        '--hidden-import', 'wave',
        '--hidden-import', 'struct',
        str(listener_path),
    ]

    result = subprocess.run(cmd)

    if result.returncode == 0:
        exe_path = script_dir / 'dist' / 'listener.exe'
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"\n[+] Build successful!")
            print(f"    Executable: {exe_path}")
            print(f"    Size: {size_mb:.1f} MB")
            print(f"\n    Copy {exe_path} to the MP3 drive (J:\\)")
        else:
            print("\n[!] Build completed but executable not found")
    else:
        print(f"\n[!] Build failed with exit code {result.returncode}")

    # Cleanup build artifacts
    build_dir = script_dir / 'build'
    spec_file = script_dir / 'listener.spec'
    if build_dir.exists():
        import shutil
        shutil.rmtree(str(build_dir), ignore_errors=True)
        print("[*] Cleaned up build directory")
    if spec_file.exists():
        spec_file.unlink()
        print("[*] Cleaned up spec file")


if __name__ == '__main__':
    main()
