#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: REVERSE ENGINEERING HELPER v1.0
  PE / ELF / Strings / Entropy / Disassembly / YARA
  Binary Analysis | Packer Detection | String Scoring | Entropy Mapping
===============================================================================

  AUTHORIZATION REQUIRED - FOR LAWFUL SECURITY RESEARCH ONLY

  FLLC
  Government-Cleared Security Operations
"""

import os
import sys
import re
import math
import struct
import hashlib
import argparse
import textwrap
from dataclasses import dataclass, field
from typing import (
    List, Dict, Optional, Tuple, BinaryIO, Any, Sequence,
)
from pathlib import Path
from collections import defaultdict

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


# =============================================================================
#  ANSI COLORS & DISPLAY
# =============================================================================

class C:
    R   = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"

    @staticmethod
    def p(text: str):
        try:
            print(text)
        except UnicodeEncodeError:
            print(text.encode("ascii", "replace").decode())

    @staticmethod
    def ok(msg: str):
        C.p(f"  {C.GRN}[+]{C.R} {msg}")

    @staticmethod
    def info(msg: str):
        C.p(f"  {C.CYN}[*]{C.R} {msg}")

    @staticmethod
    def warn(msg: str):
        C.p(f"  {C.YLW}[!]{C.R} {msg}")

    @staticmethod
    def fail(msg: str):
        C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def head(msg: str):
        C.p(f"\n{C.BLD}{C.MAG}{'=' * 60}{C.R}")
        C.p(f"{C.BLD}{C.MAG}  {msg}{C.R}")
        C.p(f"{C.BLD}{C.MAG}{'=' * 60}{C.R}")


# =============================================================================
#  UTILITY HELPERS
# =============================================================================

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def safe_read(fp: BinaryIO, offset: int, size: int) -> bytes:
    fp.seek(offset)
    data = fp.read(size)
    if len(data) < size:
        raise ValueError(f"Truncated read at offset 0x{offset:X}: wanted {size}, got {len(data)}")
    return data


def read_cstring(fp: BinaryIO, offset: int, max_len: int = 512) -> str:
    fp.seek(offset)
    buf = bytearray()
    for _ in range(max_len):
        ch = fp.read(1)
        if not ch or ch == b"\x00":
            break
        buf.append(ch[0])
    return buf.decode("ascii", errors="replace")


# =============================================================================
#  DATA CLASSES
# =============================================================================

@dataclass
class PEHeader:
    machine: int = 0
    num_sections: int = 0
    timestamp: int = 0
    characteristics: int = 0
    magic: int = 0
    entry_point: int = 0
    image_base: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    pe_offset: int = 0
    is_64bit: bool = False
    md5: str = ""
    sha256: str = ""


@dataclass
class Section:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_offset: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    characteristics: int = 0
    md5: str = ""


@dataclass
class ImportEntry:
    dll: str = ""
    functions: List[str] = field(default_factory=list)


@dataclass
class ExportEntry:
    ordinal: int = 0
    name: str = ""
    rva: int = 0


@dataclass
class ResourceEntry:
    type_id: int = 0
    type_name: str = ""
    name_id: int = 0
    language: int = 0
    offset: int = 0
    size: int = 0


@dataclass
class ELFHeader:
    ei_class: int = 0
    ei_data: int = 0
    ei_osabi: int = 0
    e_type: int = 0
    e_machine: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_phnum: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0
    is_64bit: bool = False
    endian: str = "little"
    md5: str = ""
    sha256: str = ""


@dataclass
class ELFSection:
    name: str = ""
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    entropy: float = 0.0


@dataclass
class ELFSegment:
    p_type: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_flags: int = 0
    type_name: str = ""


@dataclass
class ELFSymbol:
    name: str = ""
    value: int = 0
    size: int = 0
    sym_type: int = 0
    bind: int = 0
    section_idx: int = 0


@dataclass
class ExtractedString:
    value: str = ""
    offset: int = 0
    encoding: str = "ascii"
    entropy: float = 0.0
    category: str = "unknown"


# =============================================================================
#  MACHINE / SUBSYSTEM / SECTION LOOKUPS
# =============================================================================

PE_MACHINES: Dict[int, str] = {
    0x0: "Unknown", 0x14c: "i386", 0x8664: "AMD64",
    0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA64",
}

PE_SUBSYSTEMS: Dict[int, str] = {
    0: "Unknown", 1: "Native", 2: "Windows GUI", 3: "Windows CUI",
    5: "OS/2 CUI", 7: "POSIX CUI", 9: "WinCE", 10: "EFI App",
    11: "EFI Boot", 12: "EFI Runtime", 13: "EFI ROM", 14: "Xbox",
    16: "Win Boot App",
}

ELF_TYPES: Dict[int, str] = {
    0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE",
}

ELF_MACHINES: Dict[int, str] = {
    0: "None", 3: "x86", 8: "MIPS", 20: "PowerPC",
    40: "ARM", 43: "SPARC v9", 62: "x86-64", 183: "AArch64",
    243: "RISC-V",
}

PT_TYPES: Dict[int, str] = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP",
    4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS",
    0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
    0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY",
}

SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2", "UPX0", "UPX1", "UPX2",
    ".themida", ".vmp0", ".vmp1", ".aspack", ".adata",
    ".nsp0", ".nsp1", ".enigma1", ".enigma2",
}

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
    "NtUnmapViewOfSection", "RtlCreateUserThread",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "HttpOpenRequestA",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
    "RegSetValueExA", "RegSetValueExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
}

CATEGORY_PATTERNS: Dict[str, re.Pattern] = {
    "url":          re.compile(r"https?://[^\s\"'<>]{4,}", re.I),
    "ip":           re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email":        re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),
    "path_win":     re.compile(r"[A-Z]:\\(?:[^\\\s\"<>|?*]+\\)*[^\\\s\"<>|?*]*", re.I),
    "path_unix":    re.compile(r"/(?:usr|etc|var|tmp|home|opt|bin|sbin|dev|proc)/\S+"),
    "registry":     re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\.+", re.I),
    "api_call":     re.compile(r"\b(?:Nt|Zw|Rtl|Ldr|Virtual|Create|Open|Write|Read|Set|Get|Reg)[A-Z]\w{4,}"),
    "crypto_const": re.compile(r"\b(?:AES|RSA|SHA[0-9]*|MD5|HMAC|BEGIN (?:RSA|CERTIFICATE|PGP))\b", re.I),
}

INTERESTING_KEYWORDS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "authorization", "bearer", "private", "credential", "login",
    "admin", "root", "cmd.exe", "/bin/sh", "/bin/bash",
    "powershell", "wget", "curl", "invoke-", "iex(",
    "base64", "encrypt", "decrypt", "backdoor", "payload",
    "c2", "beacon", "callback", "exfil",
]


# =============================================================================
#  PE ANALYZER
# =============================================================================

class PEAnalyzer:

    def __init__(self) -> None:
        self._fp: Optional[BinaryIO] = None
        self.header: PEHeader = PEHeader()
        self._section_headers: List[Section] = []
        self._file_data: bytes = b""

    def parse(self, filepath: str) -> PEHeader:
        self._file_data = Path(filepath).read_bytes()
        self._fp = open(filepath, "rb")

        md5 = hashlib.md5(self._file_data).hexdigest()
        sha256 = hashlib.sha256(self._file_data).hexdigest()

        dos = safe_read(self._fp, 0, 64)
        magic = struct.unpack_from("<H", dos, 0)[0]
        if magic != 0x5A4D:
            raise ValueError("Not a valid PE file (missing MZ signature)")

        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        sig = safe_read(self._fp, pe_offset, 4)
        if sig != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")

        coff = safe_read(self._fp, pe_offset + 4, 20)
        machine, num_sections, timestamp = struct.unpack_from("<HHI", coff, 0)
        characteristics = struct.unpack_from("<H", coff, 18)[0]

        opt_offset = pe_offset + 24
        opt_magic_raw = safe_read(self._fp, opt_offset, 2)
        opt_magic = struct.unpack_from("<H", opt_magic_raw, 0)[0]
        is_64 = opt_magic == 0x20B

        if is_64:
            opt = safe_read(self._fp, opt_offset, 112)
            entry = struct.unpack_from("<I", opt, 16)[0]
            image_base = struct.unpack_from("<Q", opt, 24)[0]
            section_align = struct.unpack_from("<I", opt, 32)[0]
            file_align = struct.unpack_from("<I", opt, 36)[0]
            size_image = struct.unpack_from("<I", opt, 56)[0]
            size_headers = struct.unpack_from("<I", opt, 60)[0]
            subsystem = struct.unpack_from("<H", opt, 68)[0]
            dll_chars = struct.unpack_from("<H", opt, 70)[0]
        else:
            opt = safe_read(self._fp, opt_offset, 96)
            entry = struct.unpack_from("<I", opt, 16)[0]
            image_base = struct.unpack_from("<I", opt, 28)[0]
            section_align = struct.unpack_from("<I", opt, 32)[0]
            file_align = struct.unpack_from("<I", opt, 36)[0]
            size_image = struct.unpack_from("<I", opt, 56)[0]
            size_headers = struct.unpack_from("<I", opt, 60)[0]
            subsystem = struct.unpack_from("<H", opt, 68)[0]
            dll_chars = struct.unpack_from("<H", opt, 70)[0]

        self.header = PEHeader(
            machine=machine, num_sections=num_sections, timestamp=timestamp,
            characteristics=characteristics, magic=opt_magic,
            entry_point=entry, image_base=image_base,
            section_alignment=section_align, file_alignment=file_align,
            size_of_image=size_image, size_of_headers=size_headers,
            subsystem=subsystem, dll_characteristics=dll_chars,
            pe_offset=pe_offset, is_64bit=is_64, md5=md5, sha256=sha256,
        )

        opt_size = 112 if is_64 else 96
        ndd = struct.unpack_from("<I", opt, opt_size - 4 if is_64 else 92)[0]
        dd_size = ndd * 8
        sec_table = opt_offset + (240 if is_64 else 224)

        self._section_headers = []
        for i in range(num_sections):
            raw = safe_read(self._fp, sec_table + i * 40, 40)
            name_raw = raw[:8].rstrip(b"\x00").decode("ascii", errors="replace")
            vs, va, rs, ro = struct.unpack_from("<IIII", raw, 8)
            chars = struct.unpack_from("<I", raw, 36)[0]
            sec_data = self._file_data[ro:ro + rs] if ro and rs else b""
            ent = shannon_entropy(sec_data)
            sec_md5 = hashlib.md5(sec_data).hexdigest() if sec_data else ""
            self._section_headers.append(Section(
                name=name_raw, virtual_address=va, virtual_size=vs,
                raw_offset=ro, raw_size=rs, entropy=ent,
                characteristics=chars, md5=sec_md5,
            ))

        return self.header

    def get_sections(self) -> List[Section]:
        return list(self._section_headers)

    def _rva_to_offset(self, rva: int) -> int:
        for s in self._section_headers:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return rva - s.virtual_address + s.raw_offset
        return rva

    def get_imports(self) -> List[ImportEntry]:
        if not self._fp:
            return []
        pe_off = self.header.pe_offset
        opt_off = pe_off + 24
        dd_off = opt_off + (112 if self.header.is_64bit else 96)

        try:
            imp_dir = safe_read(self._fp, dd_off + 8, 8)
        except ValueError:
            return []
        imp_rva, imp_size = struct.unpack_from("<II", imp_dir, 0)
        if imp_rva == 0:
            return []

        imp_offset = self._rva_to_offset(imp_rva)
        imports: List[ImportEntry] = []

        idx = 0
        while True:
            entry_off = imp_offset + idx * 20
            if entry_off + 20 > len(self._file_data):
                break
            raw = self._file_data[entry_off:entry_off + 20]
            ilt_rva, ts, fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", raw, 0)
            if name_rva == 0:
                break
            dll_name = read_cstring(self._fp, self._rva_to_offset(name_rva))

            functions: List[str] = []
            thunk_rva = ilt_rva if ilt_rva else iat_rva
            if thunk_rva:
                thunk_off = self._rva_to_offset(thunk_rva)
                fi = 0
                while True:
                    if self.header.is_64bit:
                        if thunk_off + fi * 8 + 8 > len(self._file_data):
                            break
                        val = struct.unpack_from("<Q", self._file_data, thunk_off + fi * 8)[0]
                        ordinal_flag = 1 << 63
                    else:
                        if thunk_off + fi * 4 + 4 > len(self._file_data):
                            break
                        val = struct.unpack_from("<I", self._file_data, thunk_off + fi * 4)[0]
                        ordinal_flag = 1 << 31
                    if val == 0:
                        break
                    if val & ordinal_flag:
                        functions.append(f"Ordinal_{val & 0xFFFF}")
                    else:
                        hint_off = self._rva_to_offset(val & 0x7FFFFFFF)
                        fname = read_cstring(self._fp, hint_off + 2)
                        if fname:
                            functions.append(fname)
                    fi += 1
                    if fi > 4096:
                        break

            imports.append(ImportEntry(dll=dll_name, functions=functions))
            idx += 1
            if idx > 256:
                break

        return imports

    def get_exports(self) -> List[ExportEntry]:
        if not self._fp:
            return []
        pe_off = self.header.pe_offset
        opt_off = pe_off + 24
        dd_off = opt_off + (112 if self.header.is_64bit else 96)

        try:
            exp_dir = safe_read(self._fp, dd_off, 8)
        except ValueError:
            return []
        exp_rva, exp_size = struct.unpack_from("<II", exp_dir, 0)
        if exp_rva == 0:
            return []

        exp_offset = self._rva_to_offset(exp_rva)
        if exp_offset + 40 > len(self._file_data):
            return []

        raw = self._file_data[exp_offset:exp_offset + 40]
        num_funcs = struct.unpack_from("<I", raw, 20)[0]
        num_names = struct.unpack_from("<I", raw, 24)[0]
        addr_rva = struct.unpack_from("<I", raw, 28)[0]
        name_ptr_rva = struct.unpack_from("<I", raw, 32)[0]
        ordinal_rva = struct.unpack_from("<I", raw, 36)[0]
        base_ordinal = struct.unpack_from("<I", raw, 16)[0]

        addr_off = self._rva_to_offset(addr_rva)
        name_off = self._rva_to_offset(name_ptr_rva)
        ord_off = self._rva_to_offset(ordinal_rva)

        exports: List[ExportEntry] = []
        for i in range(min(num_names, 4096)):
            try:
                nrva = struct.unpack_from("<I", self._file_data, name_off + i * 4)[0]
                ordinal_idx = struct.unpack_from("<H", self._file_data, ord_off + i * 2)[0]
                func_rva = struct.unpack_from("<I", self._file_data, addr_off + ordinal_idx * 4)[0]
                fname = read_cstring(self._fp, self._rva_to_offset(nrva))
                exports.append(ExportEntry(
                    ordinal=base_ordinal + ordinal_idx, name=fname, rva=func_rva,
                ))
            except (struct.error, ValueError):
                break

        return exports

    def get_resources(self) -> List[ResourceEntry]:
        if not self._fp:
            return []
        pe_off = self.header.pe_offset
        opt_off = pe_off + 24
        dd_off = opt_off + (112 if self.header.is_64bit else 96)

        try:
            rsrc_dir = safe_read(self._fp, dd_off + 16, 8)
        except ValueError:
            return []
        rsrc_rva, rsrc_size = struct.unpack_from("<II", rsrc_dir, 0)
        if rsrc_rva == 0:
            return []

        rsrc_base = self._rva_to_offset(rsrc_rva)
        resources: List[ResourceEntry] = []

        def _walk_dir(offset: int, depth: int, type_id: int, name_id: int) -> None:
            if depth > 3 or offset + 16 > len(self._file_data):
                return
            raw = self._file_data[offset:offset + 16]
            num_named = struct.unpack_from("<H", raw, 12)[0]
            num_id = struct.unpack_from("<H", raw, 14)[0]
            pos = offset + 16
            for _ in range(min(num_named + num_id, 256)):
                if pos + 8 > len(self._file_data):
                    break
                eid, eoff = struct.unpack_from("<II", self._file_data, pos)
                pos += 8
                tid = type_id if depth > 0 else eid
                nid = name_id if depth > 1 else eid
                if eoff & 0x80000000:
                    _walk_dir(rsrc_base + (eoff & 0x7FFFFFFF), depth + 1, tid, nid)
                else:
                    leaf_off = rsrc_base + eoff
                    if leaf_off + 16 <= len(self._file_data):
                        drva, dsz, dcp, _ = struct.unpack_from("<IIII", self._file_data, leaf_off)
                        resources.append(ResourceEntry(
                            type_id=tid, type_name=self._resource_type_name(tid),
                            name_id=nid, language=eid,
                            offset=self._rva_to_offset(drva), size=dsz,
                        ))

        _walk_dir(rsrc_base, 0, 0, 0)
        return resources

    @staticmethod
    def _resource_type_name(tid: int) -> str:
        names = {
            1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU",
            5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT",
            9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
            12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
            24: "MANIFEST",
        }
        return names.get(tid, f"TYPE_{tid}")

    def detect_packing(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "likely_packed": False, "reasons": [], "score": 0,
        }
        high_ent = [s for s in self._section_headers if s.entropy > 7.0]
        if high_ent:
            results["reasons"].append(
                f"High entropy sections: {', '.join(s.name + f'({s.entropy:.2f})' for s in high_ent)}"
            )
            results["score"] += len(high_ent) * 20

        sus_names = [s.name for s in self._section_headers if s.name.strip() in SUSPICIOUS_SECTION_NAMES]
        if sus_names:
            results["reasons"].append(f"Suspicious section names: {', '.join(sus_names)}")
            results["score"] += 30

        imports = self.get_imports()
        total_funcs = sum(len(i.functions) for i in imports)
        if total_funcs < 10 and self._section_headers:
            results["reasons"].append(f"Very low import count ({total_funcs})")
            results["score"] += 25

        rwx = [s for s in self._section_headers if s.characteristics & 0xE0000000 == 0xE0000000]
        if rwx:
            results["reasons"].append(f"RWX sections: {', '.join(s.name for s in rwx)}")
            results["score"] += 25

        for s in self._section_headers:
            if s.virtual_size > 0 and s.raw_size > 0:
                ratio = s.virtual_size / s.raw_size
                if ratio > 10:
                    results["reasons"].append(
                        f"Section {s.name} unpacks {ratio:.1f}x (virt/raw)"
                    )
                    results["score"] += 15

        results["likely_packed"] = results["score"] >= 40
        return results

    def close(self) -> None:
        if self._fp:
            self._fp.close()
            self._fp = None


# =============================================================================
#  ELF ANALYZER
# =============================================================================

class ELFAnalyzer:

    def __init__(self) -> None:
        self._fp: Optional[BinaryIO] = None
        self.header: ELFHeader = ELFHeader()
        self._sections: List[ELFSection] = []
        self._file_data: bytes = b""
        self._shstrtab: bytes = b""
        self._strtab: bytes = b""

    def parse(self, filepath: str) -> ELFHeader:
        self._file_data = Path(filepath).read_bytes()
        self._fp = open(filepath, "rb")

        md5 = hashlib.md5(self._file_data).hexdigest()
        sha256 = hashlib.sha256(self._file_data).hexdigest()

        ident = self._file_data[:16]
        if ident[:4] != b"\x7fELF":
            raise ValueError("Not a valid ELF file (missing magic)")

        ei_class = ident[4]
        ei_data = ident[5]
        ei_osabi = ident[7]
        is_64 = ei_class == 2
        endian = "little" if ei_data == 1 else "big"
        fmt = "<" if endian == "little" else ">"

        if is_64:
            hdr = struct.unpack_from(f"{fmt}HHIQQQIHHHHHH", self._file_data, 16)
        else:
            hdr = struct.unpack_from(f"{fmt}HHIIIIIHHHHHH", self._file_data, 16)

        self.header = ELFHeader(
            ei_class=ei_class, ei_data=ei_data, ei_osabi=ei_osabi,
            e_type=hdr[0], e_machine=hdr[1], e_entry=hdr[3],
            e_phoff=hdr[4], e_shoff=hdr[5],
            e_phnum=hdr[8], e_shnum=hdr[9], e_shstrndx=hdr[10],
            is_64bit=is_64, endian=endian, md5=md5, sha256=sha256,
        )

        self._parse_section_headers(fmt)
        return self.header

    def _parse_section_headers(self, fmt: str) -> None:
        shoff = self.header.e_shoff
        shnum = self.header.e_shnum
        is_64 = self.header.is_64bit
        entry_size = 64 if is_64 else 40

        raw_sections = []
        for i in range(shnum):
            off = shoff + i * entry_size
            if off + entry_size > len(self._file_data):
                break
            if is_64:
                vals = struct.unpack_from(f"{fmt}IIQQQQIIQQ", self._file_data, off)
            else:
                vals = struct.unpack_from(f"{fmt}IIIIIIIIII", self._file_data, off)
            raw_sections.append(vals)

        if self.header.e_shstrndx < len(raw_sections):
            strtab_vals = raw_sections[self.header.e_shstrndx]
            str_off = strtab_vals[4]
            str_sz = strtab_vals[5]
            self._shstrtab = self._file_data[str_off:str_off + str_sz]

        self._sections = []
        for vals in raw_sections:
            name_idx = vals[0]
            name = self._read_strtab_entry(self._shstrtab, name_idx)
            sh_type, sh_flags, sh_addr, sh_offset, sh_size = vals[1], vals[2], vals[3], vals[4], vals[5]
            sh_link, sh_info = vals[6], vals[7]
            sec_data = self._file_data[sh_offset:sh_offset + sh_size] if sh_size > 0 else b""
            ent = shannon_entropy(sec_data) if sh_size > 0 else 0.0

            if name == ".strtab":
                self._strtab = sec_data

            self._sections.append(ELFSection(
                name=name, sh_type=sh_type, sh_flags=sh_flags,
                sh_addr=sh_addr, sh_offset=sh_offset, sh_size=sh_size,
                sh_link=sh_link, sh_info=sh_info, entropy=ent,
            ))

    @staticmethod
    def _read_strtab_entry(strtab: bytes, idx: int) -> str:
        if not strtab or idx >= len(strtab):
            return ""
        end = strtab.index(b"\x00", idx) if b"\x00" in strtab[idx:] else len(strtab)
        return strtab[idx:end].decode("ascii", errors="replace")

    def get_sections(self) -> List[ELFSection]:
        return list(self._sections)

    def get_segments(self) -> List[ELFSegment]:
        if not self._fp:
            return []
        phoff = self.header.e_phoff
        phnum = self.header.e_phnum
        is_64 = self.header.is_64bit
        fmt = "<" if self.header.endian == "little" else ">"
        entry_size = 56 if is_64 else 32

        segments: List[ELFSegment] = []
        for i in range(phnum):
            off = phoff + i * entry_size
            if off + entry_size > len(self._file_data):
                break
            if is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _ = \
                    struct.unpack_from(f"{fmt}IIQQQQQQ", self._file_data, off)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, _ = \
                    struct.unpack_from(f"{fmt}IIIIIIII", self._file_data, off)

            segments.append(ELFSegment(
                p_type=p_type, p_offset=p_offset, p_vaddr=p_vaddr,
                p_paddr=p_paddr, p_filesz=p_filesz, p_memsz=p_memsz,
                p_flags=p_flags, type_name=PT_TYPES.get(p_type, f"0x{p_type:X}"),
            ))

        return segments

    def get_symbols(self) -> List[ELFSymbol]:
        symbols: List[ELFSymbol] = []
        fmt = "<" if self.header.endian == "little" else ">"

        for sec in self._sections:
            if sec.sh_type not in (2, 11):  # SHT_SYMTAB=2, SHT_DYNSYM=11
                continue
            strtab_sec = self._sections[sec.sh_link] if sec.sh_link < len(self._sections) else None
            strtab_data = b""
            if strtab_sec:
                strtab_data = self._file_data[strtab_sec.sh_offset:strtab_sec.sh_offset + strtab_sec.sh_size]

            entry_size = 24 if self.header.is_64bit else 16
            count = sec.sh_size // entry_size if entry_size else 0

            for i in range(min(count, 8192)):
                off = sec.sh_offset + i * entry_size
                if off + entry_size > len(self._file_data):
                    break
                if self.header.is_64bit:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from(f"{fmt}IBBHQQ", self._file_data, off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = \
                        struct.unpack_from(f"{fmt}IIIBBH", self._file_data, off)

                name = self._read_strtab_entry(strtab_data, st_name)
                symbols.append(ELFSymbol(
                    name=name, value=st_value, size=st_size,
                    sym_type=st_info & 0xF, bind=st_info >> 4,
                    section_idx=st_shndx,
                ))

        return symbols

    def get_dynamic(self) -> Dict[str, List[str]]:
        dynamic: Dict[str, List[str]] = defaultdict(list)
        fmt = "<" if self.header.endian == "little" else ">"

        dyn_sec = None
        dynstr_data = b""
        for sec in self._sections:
            if sec.sh_type == 6:  # SHT_DYNAMIC
                dyn_sec = sec
            if sec.name == ".dynstr":
                dynstr_data = self._file_data[sec.sh_offset:sec.sh_offset + sec.sh_size]

        if not dyn_sec:
            return dict(dynamic)

        entry_size = 16 if self.header.is_64bit else 8
        count = dyn_sec.sh_size // entry_size if entry_size else 0

        DT_TAGS = {1: "NEEDED", 14: "SONAME", 15: "RPATH", 29: "RUNPATH"}

        for i in range(min(count, 4096)):
            off = dyn_sec.sh_offset + i * entry_size
            if off + entry_size > len(self._file_data):
                break
            if self.header.is_64bit:
                d_tag, d_val = struct.unpack_from(f"{fmt}qQ", self._file_data, off)
            else:
                d_tag, d_val = struct.unpack_from(f"{fmt}iI", self._file_data, off)

            if d_tag == 0:
                break

            tag_name = DT_TAGS.get(d_tag)
            if tag_name and dynstr_data:
                val_str = self._read_strtab_entry(dynstr_data, d_val)
                dynamic[tag_name].append(val_str)

        return dict(dynamic)

    def close(self) -> None:
        if self._fp:
            self._fp.close()
            self._fp = None


# =============================================================================
#  STRING EXTRACTOR
# =============================================================================

class StringExtractor:

    def __init__(self) -> None:
        self._strings: List[ExtractedString] = []

    def extract(self, filepath: str, min_length: int = 4) -> List[ExtractedString]:
        data = Path(filepath).read_bytes()
        self._strings = []

        ascii_re = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
        for m in ascii_re.finditer(data):
            val = m.group().decode("ascii")
            self._strings.append(ExtractedString(
                value=val, offset=m.start(), encoding="ascii",
                entropy=string_entropy(val),
            ))

        unicode_re = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_length)
        for m in unicode_re.finditer(data):
            try:
                val = m.group().decode("utf-16-le").rstrip("\x00")
                if len(val) >= min_length:
                    self._strings.append(ExtractedString(
                        value=val, offset=m.start(), encoding="utf-16-le",
                        entropy=string_entropy(val),
                    ))
            except UnicodeDecodeError:
                pass

        self.categorize()
        return self._strings

    def categorize(self) -> None:
        for s in self._strings:
            for cat, pattern in CATEGORY_PATTERNS.items():
                if pattern.search(s.value):
                    s.category = cat
                    break

    def find_interesting(self) -> List[ExtractedString]:
        interesting: List[ExtractedString] = []
        for s in self._strings:
            low = s.value.lower()
            if any(kw in low for kw in INTERESTING_KEYWORDS):
                interesting.append(s)
            elif s.category not in ("unknown",):
                interesting.append(s)
            elif s.entropy > 4.5 and len(s.value) >= 16:
                interesting.append(s)
        return interesting


# =============================================================================
#  ENTROPY ANALYZER
# =============================================================================

class EntropyAnalyzer:

    @staticmethod
    def file_entropy(filepath: str) -> float:
        data = Path(filepath).read_bytes()
        return shannon_entropy(data)

    @staticmethod
    def section_entropy(filepath: str) -> List[Dict[str, Any]]:
        data = Path(filepath).read_bytes()
        results: List[Dict[str, Any]] = []

        if len(data) >= 2 and data[:2] == b"MZ":
            pe = PEAnalyzer()
            pe.parse(filepath)
            for s in pe.get_sections():
                results.append({
                    "name": s.name, "offset": s.raw_offset,
                    "size": s.raw_size, "entropy": s.entropy,
                })
            pe.close()
        elif len(data) >= 4 and data[:4] == b"\x7fELF":
            elf = ELFAnalyzer()
            elf.parse(filepath)
            for s in elf.get_sections():
                if s.sh_size > 0:
                    results.append({
                        "name": s.name, "offset": s.sh_offset,
                        "size": s.sh_size, "entropy": s.entropy,
                    })
            elf.close()
        else:
            results.append({
                "name": "(file)", "offset": 0,
                "size": len(data), "entropy": shannon_entropy(data),
            })

        return results

    @staticmethod
    def sliding_window(filepath: str, window_size: int = 256) -> List[Tuple[int, float]]:
        data = Path(filepath).read_bytes()
        points: List[Tuple[int, float]] = []
        step = max(window_size // 4, 1)
        for i in range(0, len(data) - window_size + 1, step):
            chunk = data[i:i + window_size]
            points.append((i, shannon_entropy(chunk)))
        return points

    @staticmethod
    def detect_encryption(filepath: str, window_size: int = 256) -> List[Dict[str, Any]]:
        points = EntropyAnalyzer.sliding_window(filepath, window_size)
        regions: List[Dict[str, Any]] = []
        in_region = False
        start = 0

        for offset, ent in points:
            if ent > 7.9 and not in_region:
                in_region = True
                start = offset
            elif ent <= 7.9 and in_region:
                in_region = False
                regions.append({
                    "start": start, "end": offset,
                    "size": offset - start, "label": "possible_encryption",
                })

        if in_region:
            regions.append({
                "start": start, "end": points[-1][0] + window_size,
                "size": points[-1][0] + window_size - start,
                "label": "possible_encryption",
            })

        return regions

    @staticmethod
    def detect_compression(filepath: str, window_size: int = 256) -> List[Dict[str, Any]]:
        points = EntropyAnalyzer.sliding_window(filepath, window_size)
        regions: List[Dict[str, Any]] = []
        in_region = False
        start = 0

        for offset, ent in points:
            if 7.0 <= ent <= 7.9 and not in_region:
                in_region = True
                start = offset
            elif (ent < 7.0 or ent > 7.9) and in_region:
                in_region = False
                regions.append({
                    "start": start, "end": offset,
                    "size": offset - start, "label": "possible_compression",
                })

        if in_region:
            regions.append({
                "start": start, "end": points[-1][0] + window_size,
                "size": points[-1][0] + window_size - start,
                "label": "possible_compression",
            })

        return regions


# =============================================================================
#  DISASSEMBLER (CAPSTONE)
# =============================================================================

class Disassembler:

    def __init__(self) -> None:
        if not HAS_CAPSTONE:
            C.warn("capstone not installed -- disassembly disabled. pip install capstone")

    @staticmethod
    def _get_arch(filepath: str) -> Tuple[int, int, int]:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic[:2] == b"MZ":
                pe = PEAnalyzer()
                pe.parse(filepath)
                entry = pe.header.entry_point + pe.header.image_base
                is64 = pe.header.is_64bit
                pe.close()
                if is64:
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_64, entry
                return capstone.CS_ARCH_X86, capstone.CS_MODE_32, entry
            elif magic == b"\x7fELF":
                elf = ELFAnalyzer()
                elf.parse(filepath)
                entry = elf.header.e_entry
                is64 = elf.header.is_64bit
                machine = elf.header.e_machine
                elf.close()
                if machine == 62:
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_64, entry
                elif machine == 3:
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_32, entry
                elif machine in (40, 183):
                    mode = capstone.CS_MODE_ARM if not is64 else capstone.CS_MODE_ARM + capstone.CS_MODE_V8
                    return capstone.CS_ARCH_ARM64 if is64 else capstone.CS_ARCH_ARM, mode, entry
                return capstone.CS_ARCH_X86, capstone.CS_MODE_64, entry
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, 0

    @staticmethod
    def _read_at_vaddr(filepath: str, vaddr: int, size: int) -> Tuple[bytes, int]:
        data = Path(filepath).read_bytes()
        if data[:2] == b"MZ":
            pe = PEAnalyzer()
            pe.parse(filepath)
            file_off = pe._rva_to_offset(vaddr - pe.header.image_base)
            pe.close()
            return data[file_off:file_off + size], vaddr
        elif data[:4] == b"\x7fELF":
            elf = ELFAnalyzer()
            elf.parse(filepath)
            for seg in elf.get_segments():
                if seg.p_type == 1 and seg.p_vaddr <= vaddr < seg.p_vaddr + seg.p_memsz:
                    file_off = seg.p_offset + (vaddr - seg.p_vaddr)
                    elf.close()
                    return data[file_off:file_off + size], vaddr
            elf.close()
        return data[:size], 0

    def disassemble(self, filepath: str, offset: int = 0, count: int = 50) -> List[Dict[str, Any]]:
        if not HAS_CAPSTONE:
            return []
        arch, mode, entry = self._get_arch(filepath)
        addr = offset if offset else entry
        code, base = self._read_at_vaddr(filepath, addr, count * 15)

        md = capstone.Cs(arch, mode)
        md.detail = True
        instructions: List[Dict[str, Any]] = []
        for insn in md.disasm(code, base):
            instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
            if len(instructions) >= count:
                break

        return instructions

    def disassemble_function(self, filepath: str, entry_point: int = 0) -> List[Dict[str, Any]]:
        if not HAS_CAPSTONE:
            return []
        arch, mode, default_entry = self._get_arch(filepath)
        addr = entry_point if entry_point else default_entry
        code, base = self._read_at_vaddr(filepath, addr, 4096)

        md = capstone.Cs(arch, mode)
        md.detail = True
        instructions: List[Dict[str, Any]] = []

        for insn in md.disasm(code, base):
            instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
            if insn.mnemonic in ("ret", "retn", "retf", "hlt"):
                break
            if len(instructions) >= 500:
                break

        return instructions

    def find_calls(self, filepath: str) -> List[Dict[str, Any]]:
        if not HAS_CAPSTONE:
            return []
        arch, mode, entry = self._get_arch(filepath)
        code, base = self._read_at_vaddr(filepath, entry, 8192)

        md = capstone.Cs(arch, mode)
        md.detail = True
        calls: List[Dict[str, Any]] = []

        for insn in md.disasm(code, base):
            if insn.mnemonic in ("call", "bl", "blr", "blx"):
                calls.append({
                    "from": insn.address,
                    "mnemonic": insn.mnemonic,
                    "target": insn.op_str,
                })

        return calls

    def find_string_refs(self, filepath: str) -> List[Dict[str, Any]]:
        if not HAS_CAPSTONE:
            return []
        extractor = StringExtractor()
        strings = extractor.extract(filepath, min_length=4)
        str_offsets = {s.offset: s.value for s in strings[:2048]}

        arch, mode, entry = self._get_arch(filepath)
        code, base = self._read_at_vaddr(filepath, entry, 8192)

        md = capstone.Cs(arch, mode)
        md.detail = True
        refs: List[Dict[str, Any]] = []

        data = Path(filepath).read_bytes()
        is_pe = data[:2] == b"MZ"

        for insn in md.disasm(code, base):
            for op in insn.operands:
                val = 0
                if hasattr(op, "imm"):
                    val = op.imm
                elif hasattr(op, "mem") and hasattr(op.mem, "disp"):
                    val = op.mem.disp
                if val in str_offsets:
                    refs.append({
                        "address": insn.address,
                        "instruction": f"{insn.mnemonic} {insn.op_str}",
                        "string_offset": val,
                        "string": str_offsets[val][:80],
                    })

        return refs


# =============================================================================
#  YARA SCANNER
# =============================================================================

_BUILTIN_YARA_RULES = """
rule UPX_Packed {
    meta:
        description = "UPX packed binary"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx3 = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and any of ($upx*)
}

rule Themida_Packed {
    meta:
        description = "Themida / WinLicense protected"
    strings:
        $s1 = ".themida" ascii
        $s2 = ".winlice" ascii
        $s3 = "THEMIDA" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VMProtect_Packed {
    meta:
        description = "VMProtect protected binary"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_API_Usage {
    meta:
        description = "Uses suspicious process injection APIs"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtUnmapViewOfSection" ascii wide
        $a5 = "RtlCreateUserThread" ascii wide
        $a6 = "NtCreateThreadEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($a*)
}

rule Crypto_Constants {
    meta:
        description = "Contains cryptographic constants"
    strings:
        $aes_sbox  = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $aes_rcon  = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }
        $rc4_init  = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
        $sha256_k  = { 42 8A 2F 98 }
        $rsa_begin = "-----BEGIN RSA" ascii
        $cert_begin = "-----BEGIN CERTIFICATE" ascii
    condition:
        any of them
}

rule Shellcode_Patterns {
    meta:
        description = "Common shellcode byte patterns"
    strings:
        $getpc1 = { E8 00 00 00 00 58 }
        $getpc2 = { E8 00 00 00 00 5B }
        $getpc3 = { E8 FF FF FF FF C3 }
        $fs_peb  = { 64 A1 30 00 00 00 }
        $gs_peb  = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        any of them
}
"""


class YaraScanner:

    def __init__(self) -> None:
        if not HAS_YARA:
            C.warn("yara-python not installed -- YARA scanning disabled. pip install yara-python")
        self._rules: List[Any] = []
        self._builtin_loaded: bool = False

    def _ensure_builtin(self) -> None:
        if not HAS_YARA or self._builtin_loaded:
            return
        try:
            compiled = yara.compile(source=_BUILTIN_YARA_RULES)
            self._rules.append(compiled)
            self._builtin_loaded = True
        except Exception as e:
            C.warn(f"Failed to compile built-in YARA rules: {e}")

    def load_rules(self, rules_dir: str) -> int:
        if not HAS_YARA:
            return 0
        self._ensure_builtin()
        loaded = 0
        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            C.fail(f"YARA rules directory not found: {rules_dir}")
            return 0

        for yar_file in sorted(rules_path.glob("*.yar")) + sorted(rules_path.glob("*.yara")):
            try:
                compiled = yara.compile(filepath=str(yar_file))
                self._rules.append(compiled)
                loaded += 1
            except yara.Error as e:
                C.warn(f"Failed to compile {yar_file.name}: {e}")

        return loaded

    def scan(self, filepath: str) -> List[Dict[str, Any]]:
        if not HAS_YARA:
            return []
        self._ensure_builtin()

        results: List[Dict[str, Any]] = []
        for rules in self._rules:
            try:
                matches = rules.match(filepath)
                for m in matches:
                    match_info: Dict[str, Any] = {
                        "rule": m.rule,
                        "meta": dict(m.meta) if m.meta else {},
                        "tags": list(m.tags) if m.tags else [],
                        "strings": [],
                    }
                    for s in m.strings:
                        for instance in s.instances:
                            match_info["strings"].append({
                                "offset": instance.offset,
                                "identifier": s.identifier,
                                "data": instance.matched_data[:64].hex(),
                            })
                    results.append(match_info)
            except yara.Error as e:
                C.warn(f"YARA scan error: {e}")

        return results


# =============================================================================
#  DISPLAY / REPORT HELPERS
# =============================================================================

def _print_pe_report(filepath: str) -> None:
    C.head("PE ANALYSIS")
    pe = PEAnalyzer()
    try:
        hdr = pe.parse(filepath)
    except ValueError as e:
        C.fail(str(e))
        return

    C.info(f"File    : {filepath}")
    C.info(f"MD5     : {hdr.md5}")
    C.info(f"SHA-256 : {hdr.sha256}")
    C.info(f"Machine : {PE_MACHINES.get(hdr.machine, hex(hdr.machine))}")
    C.info(f"Magic   : {'PE32+' if hdr.is_64bit else 'PE32'}")
    C.info(f"Entry   : 0x{hdr.entry_point:X}")
    C.info(f"ImgBase : 0x{hdr.image_base:X}")
    C.info(f"Subsys  : {PE_SUBSYSTEMS.get(hdr.subsystem, str(hdr.subsystem))}")

    C.p(f"\n  {C.BLD}Sections:{C.R}")
    C.p(f"  {'Name':<10} {'VirtAddr':<12} {'RawSize':<12} {'Entropy':<10} {'Flags':<12}")
    C.p(f"  {'-'*10} {'-'*12} {'-'*12} {'-'*10} {'-'*12}")
    for s in pe.get_sections():
        ent_color = C.RED if s.entropy > 7.0 else (C.YLW if s.entropy > 6.5 else C.GRN)
        C.p(f"  {s.name:<10} 0x{s.virtual_address:<10X} {s.raw_size:<12} "
            f"{ent_color}{s.entropy:<10.4f}{C.R} 0x{s.characteristics:08X}")

    imports = pe.get_imports()
    if imports:
        C.p(f"\n  {C.BLD}Imports ({sum(len(i.functions) for i in imports)} functions from {len(imports)} DLLs):{C.R}")
        for imp in imports:
            C.p(f"    {C.CYN}{imp.dll}{C.R}")
            suspicious = [f for f in imp.functions if f in SUSPICIOUS_IMPORTS]
            for fn in imp.functions[:15]:
                marker = f"{C.RED}  [!]" if fn in SUSPICIOUS_IMPORTS else ""
                C.p(f"      {fn}{marker}{C.R}")
            if len(imp.functions) > 15:
                C.p(f"      ... and {len(imp.functions) - 15} more")

    exports = pe.get_exports()
    if exports:
        C.p(f"\n  {C.BLD}Exports ({len(exports)}):{C.R}")
        for exp in exports[:30]:
            C.p(f"    {exp.ordinal:>5}  {exp.name}  (0x{exp.rva:X})")

    resources = pe.get_resources()
    if resources:
        C.p(f"\n  {C.BLD}Resources ({len(resources)}):{C.R}")
        for r in resources[:30]:
            C.p(f"    Type={r.type_name:<16} ID={r.name_id:<8} Size={r.size}")

    packing = pe.detect_packing()
    if packing["reasons"]:
        C.p(f"\n  {C.BLD}Packing Analysis (score={packing['score']}):{C.R}")
        verdict = f"{C.RED}LIKELY PACKED{C.R}" if packing["likely_packed"] else f"{C.GRN}Not obviously packed{C.R}"
        C.p(f"    Verdict: {verdict}")
        for r in packing["reasons"]:
            C.p(f"    {C.YLW}- {r}{C.R}")

    pe.close()


def _print_elf_report(filepath: str) -> None:
    C.head("ELF ANALYSIS")
    elf = ELFAnalyzer()
    try:
        hdr = elf.parse(filepath)
    except ValueError as e:
        C.fail(str(e))
        return

    C.info(f"File    : {filepath}")
    C.info(f"MD5     : {hdr.md5}")
    C.info(f"SHA-256 : {hdr.sha256}")
    C.info(f"Class   : {'ELF64' if hdr.is_64bit else 'ELF32'}")
    C.info(f"Endian  : {hdr.endian}")
    C.info(f"Type    : {ELF_TYPES.get(hdr.e_type, str(hdr.e_type))}")
    C.info(f"Machine : {ELF_MACHINES.get(hdr.e_machine, str(hdr.e_machine))}")
    C.info(f"Entry   : 0x{hdr.e_entry:X}")

    C.p(f"\n  {C.BLD}Sections:{C.R}")
    C.p(f"  {'Name':<20} {'Type':<8} {'Offset':<12} {'Size':<12} {'Entropy':<10}")
    C.p(f"  {'-'*20} {'-'*8} {'-'*12} {'-'*12} {'-'*10}")
    for s in elf.get_sections():
        if s.sh_size == 0:
            continue
        ent_color = C.RED if s.entropy > 7.0 else (C.YLW if s.entropy > 6.5 else C.GRN)
        C.p(f"  {s.name:<20} {s.sh_type:<8} 0x{s.sh_offset:<10X} {s.sh_size:<12} "
            f"{ent_color}{s.entropy:<10.4f}{C.R}")

    segments = elf.get_segments()
    if segments:
        C.p(f"\n  {C.BLD}Segments:{C.R}")
        C.p(f"  {'Type':<16} {'Offset':<12} {'VAddr':<16} {'FileSz':<12} {'MemSz':<12} {'Flags'}")
        C.p(f"  {'-'*16} {'-'*12} {'-'*16} {'-'*12} {'-'*12} {'-'*6}")
        for seg in segments:
            flags = ""
            flags += "R" if seg.p_flags & 4 else "-"
            flags += "W" if seg.p_flags & 2 else "-"
            flags += "X" if seg.p_flags & 1 else "-"
            C.p(f"  {seg.type_name:<16} 0x{seg.p_offset:<10X} 0x{seg.p_vaddr:<14X} "
                f"{seg.p_filesz:<12} {seg.p_memsz:<12} {flags}")

    symbols = elf.get_symbols()
    named = [s for s in symbols if s.name]
    if named:
        C.p(f"\n  {C.BLD}Symbols ({len(named)} named / {len(symbols)} total):{C.R}")
        for sym in named[:40]:
            bind = ["LOCAL", "GLOBAL", "WEAK"].pop(min(sym.bind, 2)) if sym.bind < 3 else str(sym.bind)
            C.p(f"    0x{sym.value:016X}  {bind:<8} {sym.name}")
        if len(named) > 40:
            C.p(f"    ... and {len(named) - 40} more")

    dyn = elf.get_dynamic()
    if dyn:
        C.p(f"\n  {C.BLD}Dynamic Linking:{C.R}")
        for tag, vals in dyn.items():
            for v in vals:
                C.p(f"    {tag:<10} {v}")

    elf.close()


def _print_strings_report(filepath: str, min_len: int = 4) -> None:
    C.head("STRING EXTRACTION")
    ext = StringExtractor()
    strings = ext.extract(filepath, min_length=min_len)
    interesting = ext.find_interesting()

    C.info(f"Total strings   : {len(strings)}")
    C.info(f"Interesting     : {len(interesting)}")

    cats: Dict[str, int] = defaultdict(int)
    for s in strings:
        cats[s.category] += 1
    C.p(f"\n  {C.BLD}Categories:{C.R}")
    for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        C.p(f"    {cat:<16} {cnt}")

    if interesting:
        C.p(f"\n  {C.BLD}Interesting Strings:{C.R}")
        for s in interesting[:60]:
            cat_tag = f" [{s.category}]" if s.category != "unknown" else ""
            truncated = s.value[:100] + "..." if len(s.value) > 100 else s.value
            C.p(f"    0x{s.offset:08X}  {C.YLW}{truncated}{C.R}{cat_tag}")
        if len(interesting) > 60:
            C.p(f"    ... and {len(interesting) - 60} more")


def _print_entropy_report(filepath: str) -> None:
    C.head("ENTROPY ANALYSIS")
    ea = EntropyAnalyzer()

    total = ea.file_entropy(filepath)
    C.info(f"Overall entropy : {total:.4f}")

    secs = ea.section_entropy(filepath)
    if secs:
        C.p(f"\n  {C.BLD}Section Entropy:{C.R}")
        for s in secs:
            bar_len = int(s["entropy"] / 8.0 * 40)
            bar = "#" * bar_len + "." * (40 - bar_len)
            ent_color = C.RED if s["entropy"] > 7.0 else (C.YLW if s["entropy"] > 6.5 else C.GRN)
            C.p(f"    {s['name']:<16} {ent_color}{s['entropy']:.4f}{C.R} [{bar}]")

    enc_regions = ea.detect_encryption(filepath)
    comp_regions = ea.detect_compression(filepath)

    if enc_regions:
        C.p(f"\n  {C.RED}{C.BLD}Possible Encrypted Regions:{C.R}")
        for r in enc_regions:
            C.p(f"    0x{r['start']:08X} - 0x{r['end']:08X}  ({r['size']} bytes)")

    if comp_regions:
        C.p(f"\n  {C.YLW}{C.BLD}Possible Compressed Regions:{C.R}")
        for r in comp_regions:
            C.p(f"    0x{r['start']:08X} - 0x{r['end']:08X}  ({r['size']} bytes)")


def _print_disasm_report(filepath: str, offset: int = 0, count: int = 50) -> None:
    C.head("DISASSEMBLY")
    if not HAS_CAPSTONE:
        C.fail("capstone not installed. pip install capstone")
        return

    dis = Disassembler()
    instructions = dis.disassemble(filepath, offset, count)
    C.info(f"Disassembled {len(instructions)} instructions")

    for insn in instructions:
        addr = insn["address"]
        byt = insn["bytes"]
        mnemonic = insn["mnemonic"]
        ops = insn["op_str"]
        is_call = mnemonic in ("call", "bl", "blr", "blx")
        is_jmp = mnemonic.startswith("j") or mnemonic in ("b", "br", "cbz", "cbnz")
        color = C.RED if is_call else (C.YLW if is_jmp else C.DIM)
        C.p(f"    0x{addr:08X}  {byt:<24} {color}{mnemonic:<8} {ops}{C.R}")

    calls = dis.find_calls(filepath)
    if calls:
        C.p(f"\n  {C.BLD}CALL targets ({len(calls)}):{C.R}")
        for c in calls[:30]:
            C.p(f"    0x{c['from']:08X}  {c['mnemonic']} {c['target']}")


def _print_yara_report(filepath: str, rules_dir: Optional[str] = None) -> None:
    C.head("YARA SCAN")
    if not HAS_YARA:
        C.fail("yara-python not installed. pip install yara-python")
        return

    scanner = YaraScanner()
    if rules_dir:
        loaded = scanner.load_rules(rules_dir)
        C.info(f"Loaded {loaded} rule file(s) from {rules_dir}")
    else:
        C.info("Using built-in rules only")

    matches = scanner.scan(filepath)
    if not matches:
        C.ok("No YARA matches")
        return

    C.warn(f"{len(matches)} rule(s) matched:")
    for m in matches:
        desc = m["meta"].get("description", "")
        C.p(f"\n    {C.RED}{C.BLD}{m['rule']}{C.R}")
        if desc:
            C.p(f"    {C.DIM}{desc}{C.R}")
        for s in m["strings"][:10]:
            C.p(f"      0x{s['offset']:08X}  {s['identifier']}  {s['data'][:40]}")


# =============================================================================
#  BANNER
# =============================================================================

BANNER = f"""
{C.MAG}{C.BLD}===============================================================================
  FU PERSON :: REVERSE ENGINEERING HELPER v1.0
  Binary Analysis  |  PE / ELF  |  Strings  |  Entropy  |  YARA
  FLLC -- Government-Cleared Security Operations
==============================================================================={C.R}
"""


# =============================================================================
#  CLI ENTRY POINT
# =============================================================================

def main() -> None:
    C.p(BANNER)

    parser = argparse.ArgumentParser(
        prog="reverse_engineer",
        description=f"{C.CYN}FU PERSON :: Reverse Engineering Helper v1.0{C.R}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        {C.CYN}Examples:{C.R}
          python reverse_engineer.py pe malware.exe
          python reverse_engineer.py elf suspicious_bin
          python reverse_engineer.py strings sample.dll --min-len 6
          python reverse_engineer.py entropy packed.exe
          python reverse_engineer.py disasm trojan.exe --count 100
          python reverse_engineer.py yara dropper.exe --rules ./yara_rules/
        """),
    )

    sub = parser.add_subparsers(dest="command", help="Analysis module")

    pe_p = sub.add_parser("pe", help="Windows PE file analysis")
    pe_p.add_argument("file", help="Path to PE file")

    elf_p = sub.add_parser("elf", help="Linux ELF file analysis")
    elf_p.add_argument("file", help="Path to ELF file")

    str_p = sub.add_parser("strings", help="String extraction & scoring")
    str_p.add_argument("file", help="Path to binary file")
    str_p.add_argument("--min-len", type=int, default=4, help="Minimum string length (default: 4)")

    ent_p = sub.add_parser("entropy", help="Entropy analysis")
    ent_p.add_argument("file", help="Path to binary file")

    dis_p = sub.add_parser("disasm", help="Disassemble (requires capstone)")
    dis_p.add_argument("file", help="Path to binary file")
    dis_p.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="Start address (hex or dec)")
    dis_p.add_argument("--count", type=int, default=50, help="Number of instructions (default: 50)")

    yara_p = sub.add_parser("yara", help="YARA rule scanning (requires yara-python)")
    yara_p.add_argument("file", help="Path to file to scan")
    yara_p.add_argument("--rules", help="Directory containing .yar/.yara rule files")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if not os.path.isfile(args.file):
        C.fail(f"File not found: {args.file}")
        return

    dispatch = {
        "pe":      lambda: _print_pe_report(args.file),
        "elf":     lambda: _print_elf_report(args.file),
        "strings": lambda: _print_strings_report(args.file, args.min_len),
        "entropy": lambda: _print_entropy_report(args.file),
        "disasm":  lambda: _print_disasm_report(args.file, args.offset, args.count),
        "yara":    lambda: _print_yara_report(args.file, getattr(args, "rules", None)),
    }

    handler = dispatch.get(args.command)
    if handler:
        handler()


if __name__ == "__main__":
    main()
