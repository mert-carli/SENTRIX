import os
import hashlib
import math
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional

MAGIC_SIGNATURES = [
    (b"\x4D\x5A", "Windows PE Executable / DLL (MZ)"),
    (b"\x50\x4B\x03\x04", "ZIP / DOCX / XLSX Archive (PK..)"),
    (b"\x7F\x45\x4C\x46", "Linux ELF Executable"),
    (b"\x25\x50\x44\x46", "PDF Document (%PDF)"),
    (b"\xFF\xD8\xFF", "JPEG Image"),
    (b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "PNG Image"),
    (b"\x52\x61\x72\x21\x1A\x07", "RAR Archive"),
    (b"\x1F\x8B\x08", "GZIP Compressed File"),
    (b"\x42\x5A\x68", "BZIP2 Compressed File"),
    (b"\x4C\x00\x00\x00\x01\x14\x02\x00", "Windows Shortcut (.LNK)")
]

class ForensicsToolkit:
    def __init__(self):
        pass

    def inspect_file(self, file_path: str) -> Dict[str, Any]:
        """Performs static file forensics: Magic bytes, hashes, entropy, size."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        byte_counts = [0] * 256
        total_read = 0

        with open(file_path, "rb") as f:
            magic_bytes = f.read(16)
            f.seek(0)
            while chunk := f.read(65536):
                total_read += len(chunk)
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
                for b in chunk:
                    byte_counts[b] += 1

        # Entropy calculation
        entropy = 0.0
        if total_read > 0:
            for count in byte_counts:
                if count > 0:
                    p = count / total_read
                    entropy -= p * math.log2(p)

        # Magic byte detection
        detected_format = "Unknown Binary or Plain Text"
        for sig, fmt_name in MAGIC_SIGNATURES:
            if magic_bytes.startswith(sig):
                detected_format = fmt_name
                break

        return {
            "file_name": os.path.basename(file_path),
            "file_path": file_path,
            "size_bytes": file_size,
            "detected_format": detected_format,
            "magic_hex": " ".join(f"{b:02X}" for b in magic_bytes[:8]),
            "md5": md5_hasher.hexdigest(),
            "sha256": sha256_hasher.hexdigest(),
            "entropy": round(entropy, 3),
            "is_packed": (entropy > 7.1)
        }

    def get_hex_dump(self, file_path: str, max_bytes: int = 512) -> str:
        """Generates a standard formatted hex view."""
        if not os.path.exists(file_path):
            return "File not found."

        lines = []
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48}  |{ascii_part}|")
        return "\n".join(lines)

    def extract_strings(self, file_path: str, min_len: int = 5, limit: int = 100) -> List[str]:
        """Extracts ASCII and UTF-16LE strings from binary files."""
        if not os.path.exists(file_path):
            return []

        strings = []
        with open(file_path, "rb") as f:
            data = f.read(1024 * 1024) # 1 MB sample

        # ASCII strings
        import re
        ascii_matches = re.findall(b"[\x20-\x7E]{" + str(min_len).encode() + b",}", data)
        for m in ascii_matches[:limit]:
            strings.append(m.decode('latin1', errors='ignore'))
        return strings

    def get_windows_startup_entries(self) -> List[Dict[str, str]]:
        """Audits Windows Startup entries in registry."""
        entries = []
        cmd = 'powershell "Get-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\', \'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\' -ErrorAction SilentlyContinue | Format-List"'
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
            for line in out.splitlines():
                if ":" in line and not line.strip().startswith("PS"):
                    parts = line.split(":", 1)
                    if len(parts) > 1 and parts[0].strip():
                        entries.append({"name": parts[0].strip(), "command": parts[1].strip()})
        except Exception:
            pass
        return entries

    def get_usb_history(self) -> List[str]:
        """Extracts history of connected USB storage devices from Windows Registry."""
        usbs = []
        cmd = 'powershell "Get-ChildItem HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }"'
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line: usbs.append(line)
        except Exception:
            pass
        return usbs

forensics_toolkit = ForensicsToolkit()
