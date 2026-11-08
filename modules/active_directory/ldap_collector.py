import subprocess
import json
from typing import List, Dict, Any
from core.logger import logger

class LDAPCollector:
    """Collects Active Directory identity objects via read-only directory queries."""

    def collect_domain_users(self) -> List[Dict[str, Any]]:
        ps = """
        Get-CimInstance Win32_UserAccount | Select-Object Name, Caption, Domain, Disabled, PasswordRequired, SID | ConvertTo-Json -Compress
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=10, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                return data if isinstance(data, list) else [data]
            return []
        except Exception as e:
            logger.error(f"[LDAPCollector] Error querying users: {e}")
            return []

    def collect_domain_groups(self) -> List[Dict[str, Any]]:
        ps = """
        Get-CimInstance Win32_Group | Select-Object Name, Caption, Domain, SID | ConvertTo-Json -Compress
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=10, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                return data if isinstance(data, list) else [data]
            return []
        except Exception as e:
            logger.error(f"[LDAPCollector] Error querying groups: {e}")
            return []
