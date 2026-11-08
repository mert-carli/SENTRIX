import shutil
import os
import subprocess
from typing import Dict, Any, List

class ExternalToolManager:
    """Discovers, audits, and manages external cybersecurity tools and dependencies."""

    SUPPORTED_TOOLS = [
        ("Nmap", "nmap", ["C:\\Program Files (x86)\\Nmap\\nmap.exe", "C:\\Program Files\\Nmap\\nmap.exe"]),
        ("Wireshark", "wireshark", ["C:\\Program Files\\Wireshark\\wireshark.exe"]),
        ("TShark", "tshark", ["C:\\Program Files\\Wireshark\\tshark.exe"]),
        ("Volatility 3", "vol", ["C:\\Volatility3\\vol.py", "C:\\Python311\\Scripts\\vol.exe"]),
        ("YARA", "yara64", ["C:\\Program Files\\YARA\\yara64.exe", "C:\\Tools\\yara64.exe"]),
        ("Ghidra", "ghidraRun.bat", ["C:\\ghidra\\ghidraRun.bat"]),
        ("Trivy", "trivy", []),
        ("Binwalk", "binwalk", []),
        ("OpenSSL", "openssl", ["C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"]),
        ("Docker", "docker", ["C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"]),
        ("VirtualBox", "VBoxManage", ["C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"])
    ]

    def audit_all_tools(self) -> List[Dict[str, Any]]:
        results = []
        for name, cmd, default_paths in self.SUPPORTED_TOOLS:
            path = shutil.which(cmd)
            if not path:
                for alt in default_paths:
                    if os.path.isfile(alt):
                        path = alt
                        break

            status = "AVAILABLE" if path else "NOT_INSTALLED"
            results.append({
                "name": name,
                "command": cmd,
                "path": path,
                "status": status,
                "is_available": bool(path),
                "install_guide": f"Install {name} and ensure '{cmd}' is added to Windows PATH." if not path else "Configured and operational."
            })
        return results

    def get_tool_path(self, tool_name: str) -> str:
        for t in self.audit_all_tools():
            if t["name"].lower() == tool_name.lower():
                return t.get("path") or ""
        return ""

tool_manager = ExternalToolManager()
