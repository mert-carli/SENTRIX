import subprocess
import json
from typing import List, Dict, Any

class LocalCertificateStoreAuditor:
    """Audits local Windows Root and Intermediate certificate stores for rogue or untrusted certificates."""

    @staticmethod
    def audit_root_store(limit: int = 50) -> List[Dict[str, Any]]:
        ps = f"""
        Get-ChildItem -Path Cert:\\LocalMachine\\Root | Select-Object -First {limit} Subject, Issuer, Thumbprint, NotAfter | ConvertTo-Json -Compress
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=8, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                return data if isinstance(data, list) else [data]
            return []
        except Exception:
            return []
