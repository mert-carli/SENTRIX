import subprocess
import json
from typing import List, Dict, Any
from core.logger import logger

class ServiceMonitor:
    """Inventories and audits Windows Services for security misconfigurations and unquoted service paths."""

    def get_service_inventory(self, limit: int = 100) -> List[Dict[str, Any]]:
        ps_script = f"""
        Get-CimInstance Win32_Service | Select-Object -First {limit} Name, DisplayName, State, StartMode, PathName, StartName | ConvertTo-Json -Compress
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True, timeout=10, check=False)
            if res.returncode != 0 or not res.stdout.strip():
                return []

            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]

            services = []
            for item in data:
                path_name = item.get("PathName") or ""
                # Check for Unquoted Service Path vulnerability (spaces in path without quotes)
                unquoted_vuln = False
                if path_name and " " in path_name and not path_name.startswith('"'):
                    unquoted_vuln = True

                services.append({
                    "name": item.get("Name") or "",
                    "display_name": item.get("DisplayName") or "",
                    "state": item.get("State") or "",
                    "start_mode": item.get("StartMode") or "",
                    "path_name": path_name,
                    "account": item.get("StartName") or "",
                    "unquoted_path_vulnerability": unquoted_vuln
                })
            return services
        except Exception as e:
            logger.error(f"[ServiceMonitor] Error querying services: {e}")
            return []
