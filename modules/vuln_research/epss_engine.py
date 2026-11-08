import urllib.request
import json
from typing import Dict, Any

class EPSSEngine:
    def __init__(self):
        pass

    def get_epss_score(self, cve_id: str) -> Dict[str, Any]:
        """
        Queries FIRST.org EPSS (Exploit Prediction Scoring System) API.
        Returns exploit probability (0.0 to 1.0) and percentile.
        """
        cve_id = cve_id.strip().upper()
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            req = urllib.request.Request(url, headers={'User-Agent': 'SENTRIX/3.0'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                records = data.get("data", [])
                if records:
                    epss_val = float(records[0].get("epss", 0.0))
                    percentile_val = float(records[0].get("percentile", 0.0))
                    return {
                        "cve_id": cve_id,
                        "epss_score": round(epss_val, 4),
                        "epss_percentile": round(percentile_val * 100, 1),
                        "source": "FIRST_LIVE_EPSS_API"
                    }
        except Exception:
            pass

        # High-profile offline fallback estimates
        known_epss = {
            "CVE-2017-0144": 0.975, # EternalBlue
            "CVE-2019-0708": 0.968, # BlueKeep
            "CVE-2021-44228": 0.975, # Log4Shell
            "CVE-2024-6387": 0.650,  # regreSSHion
            "CVE-2020-0796": 0.970   # SMBGhost
        }
        val = known_epss.get(cve_id, 0.015)
        return {
            "cve_id": cve_id,
            "epss_score": val,
            "epss_percentile": 85.0 if val > 0.5 else 40.0,
            "source": "SENTRIX_OFFLINE_ESTIMATE"
        }

    def compute_risk_priority(self, cvss: float, epss: float, is_cisa_kev: bool) -> str:
        """Determines unified operational risk priority based on CISA KEV, EPSS, and CVSS."""
        if is_cisa_kev or (cvss >= 9.0 and epss >= 0.3):
            return "P1 - CRITICAL (Actively Exploited / Immediate Remediation)"
        elif cvss >= 7.0 and epss >= 0.1:
            return "P2 - HIGH (Elevated Exploit Likelihood)"
        elif cvss >= 7.0:
            return "P3 - MEDIUM-HIGH (High Severity, Low In-The-Wild Exploitability)"
        return "P4 - STANDARD (Scheduled Maintenance)"

epss_engine = EPSSEngine()
