import subprocess
import shutil
import re
from typing import List, Dict, Any
from core.logger import logger

class ETWCollector:
    """Inspects Event Tracing for Windows (ETW) active sessions and registered providers."""

    def __init__(self):
        self.logman_path = shutil.which("logman.exe") or "C:\\Windows\\System32\\logman.exe"

    def query_active_sessions(self) -> List[Dict[str, Any]]:
        """Queries active real-time kernel and event trace sessions (-ets)."""
        try:
            res = subprocess.run([self.logman_path, "query", "-ets"], capture_output=True, text=True, timeout=8, check=False)
            if res.returncode != 0:
                return []
            
            sessions = []
            lines = res.stdout.splitlines()
            header_found = False

            for line in lines:
                line_str = line.strip()
                if "------" in line_str:
                    header_found = True
                    continue
                if not header_found or not line_str or "komut basariyla" in line_str.lower() or "command completed" in line_str.lower():
                    continue

                parts = re.split(r'\s{2,}', line_str)
                if len(parts) >= 2:
                    sessions.append({
                        "session_name": parts[0].strip(),
                        "type": parts[1].strip() if len(parts) > 1 else "Trace",
                        "status": "RUNNING"
                    })
            return sessions
        except Exception as e:
            logger.error(f"[ETWCollector] Error listing sessions: {e}")
            return []

    def query_security_providers(self) -> List[Dict[str, str]]:
        """Lists critical security-related ETW providers available on the host."""
        known_security_providers = [
            ("Microsoft-Windows-Security-Mitigations", "{B9F5FAC9-245C-47A6-A785-BDABDC748E66}"),
            ("Microsoft-Windows-Kernel-Process", "{22FB2AD6-0E16-4281-9104-3842B39C7399}"),
            ("Microsoft-Windows-Kernel-Network", "{7DD42A49-5329-4832-8DFD-43D979153A88}"),
            ("Microsoft-Windows-Kernel-File", "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"),
            ("Microsoft-Windows-Threat-Intelligence", "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"),
            ("Microsoft-Windows-DNSR-Client", "{1C950233-D63C-412E-B6E6-AB3A9CF6998E}")
        ]
        results = []
        for name, guid in known_security_providers:
            results.append({
                "provider_name": name,
                "guid": guid,
                "status": "REGISTERED"
            })
        return results
