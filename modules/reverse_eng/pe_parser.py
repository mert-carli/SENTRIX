import struct
import math
import os
from typing import Dict, List, Any

SUSPICIOUS_APIS = {
    "VirtualAlloc": "Memory Allocation for Shellcode",
    "VirtualProtect": "Changing Memory Permissions (W+X)",
    "WriteProcessMemory": "Process Injection / Memory Modification",
    "CreateRemoteThread": "Remote Thread Injection",
    "SetWindowsHookEx": "Keystroke / Message Hooking",
    "IsDebuggerPresent": "Anti-Debugging Technique",
    "CheckRemoteDebuggerPresent": "Anti-Debugging Technique",
    "URLDownloadToFile": "Malware Dropper / Downloader",
    "WinExec": "Arbitrary Command Execution",
    "ShellExecute": "Process Spawning",
    "RegSetValueEx": "Persistence via Registry Modification",
    "CryptEncrypt": "Ransomware Encryption Routine"
}

class PEParser:
    def __init__(self):
        pass

    def parse_pe(self, file_path: str) -> Dict[str, Any]:
        """Parses Windows PE (.exe, .dll, .sys) headers natively without external binaries."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 64 or data[:2] != b"MZ":
            return {"error": "Not a valid Windows DOS/PE executable (MZ header missing)."}

        # Offset to PE Signature at 0x3C
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return {"error": "Valid PE Signature (PE\\0\\0) not found at expected offset."}

        # COFF File Header (20 bytes)
        coff_offset = pe_offset + 4
        machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, coff_offset
        )

        arch = "x86 (32-bit)" if machine == 0x14C else ("x64 (64-bit AMD64)" if machine == 0x8664 else f"Other (0x{machine:X})")

        # Optional Header
        opt_offset = coff_offset + 20
        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_pe32_plus = (opt_magic == 0x20B)

        entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
        
        # Section Headers follow Optional Header
        section_table_offset = opt_offset + opt_hdr_size
        sections = []
        for i in range(num_sections):
            sec_offset = section_table_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break
            sec_name_raw = data[sec_offset:sec_offset+8]
            sec_name = sec_name_raw.decode('latin1', errors='ignore').strip('\x00')
            vsize, vaddr, raw_size, raw_ptr, _, _, _, _, characts = struct.unpack_from(
                "<IIIIIIHHI", data, sec_offset + 8
            )

            # Section entropy calculation
            sec_bytes = data[raw_ptr:raw_ptr+raw_size]
            sec_entropy = 0.0
            if sec_bytes:
                prob = [float(sec_bytes.count(b)) / len(sec_bytes) for b in set(sec_bytes)]
                sec_entropy = round(-sum([p * math.log2(p) for p in prob]), 3)

            sections.append({
                "name": sec_name,
                "virtual_address": f"0x{vaddr:X}",
                "virtual_size": vsize,
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "is_packed": (sec_entropy > 7.1)
            })

        # Scan for suspicious API strings
        found_suspicious_apis = []
        for api, desc in SUSPICIOUS_APIS.items():
            if api.encode('latin1') in data:
                found_suspicious_apis.append({"api": api, "description": desc})

        return {
            "file_name": os.path.basename(file_path),
            "architecture": arch,
            "number_of_sections": num_sections,
            "timedatestamp": timedatestamp,
            "entry_point": f"0x{entry_point:X}",
            "is_pe32_plus": is_pe32_plus,
            "sections": sections,
            "suspicious_apis": found_suspicious_apis
        }

    def check_external_tools(self) -> Dict[str, bool]:
        """Verifies if Ghidra, DIE, or YARA CLI are available on PATH."""
        import shutil
        return {
            "Ghidra": bool(shutil.which("ghidraRun") or os.environ.get("GHIDRA_HOME")),
            "DetectItEasy": bool(shutil.which("diec") or shutil.which("die")),
            "YARA": bool(shutil.which("yara"))
        }

pe_parser_engine = PEParser()
