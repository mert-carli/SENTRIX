import urllib.request
import json
from typing import Dict, List, Any

# Local curated offline CVE Knowledge Base for rapid query without network dependency
LOCAL_CVE_CORRELATION = {
    "CVE-2017-0144": {
        "title": "EternalBlue SMBv1 Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "affected_service": "SMBv1",
        "remediation": "Disable SMBv1 protocol and apply Microsoft security update MS17-010."
    },
    "CVE-2019-0708": {
        "title": "BlueKeep Windows Remote Desktop Services RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cisa_kev": True,
        "affected_service": "RDP (Port 3389)",
        "remediation": "Apply Microsoft patch KB4499175 or block TCP port 3389 at perimeter."
    },
    "CVE-2020-0796": {
        "title": "SMBGhost Windows 10/Server SMBv3 Compression RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cisa_kev": True,
        "affected_service": "SMBv3",
        "remediation": "Apply Microsoft security advisory ADV200005 patch."
    },
    "CVE-2024-6387": {
        "title": "regreSSHion OpenSSH Server Remote Code Execution",
        "severity": "HIGH",
        "cvss": 8.1,
        "cisa_kev": False,
        "affected_service": "OpenSSH",
        "remediation": "Upgrade OpenSSH to version 9.8p1 or newer."
    },
    "CVE-2021-44228": {
        "title": "Log4Shell Apache Log4j2 JNDI RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "cisa_kev": True,
        "affected_service": "Java Log4j",
        "remediation": "Upgrade log4j to version 2.17.1 or set log4j2.formatMsgNoLookups=true."
    }
}

class VulnerabilityEngine:
    def __init__(self):
        pass

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """Lookups CVE information from local threat knowledgebase or NVD API."""
        cve_id = cve_id.strip().upper()
        if cve_id in LOCAL_CVE_CORRELATION:
            return {"cve_id": cve_id, **LOCAL_CVE_CORRELATION[cve_id], "source": "SENTRIX_CURATED_KEV"}

        # Fallback to online NVD API if available
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(url, headers={'User-Agent': 'SentrixSecOps/1.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_item = vulns[0].get("cve", {})
                    metrics = cve_item.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    return {
                        "cve_id": cve_id,
                        "title": cve_item.get("descriptions", [{}])[0].get("value", "No description available")[:150],
                        "severity": metrics.get("baseSeverity", "MEDIUM"),
                        "cvss": metrics.get("baseScore", 5.0),
                        "cisa_kev": False,
                        "source": "NVD_LIVE_API"
                    }
        except Exception:
            pass

        return {
            "cve_id": cve_id,
            "title": "Uncached CVE identifier. Refer to NVD for details.",
            "severity": "UNKNOWN",
            "cvss": 0.0,
            "cisa_kev": False,
            "source": "UNKNOWN"
        }

    def evaluate_service_vulnerabilities(self, service_name: str, version_str: str = "") -> List[Dict[str, Any]]:
        """Finds known vulnerabilities matching detected service."""
        matches = []
        for cve, details in LOCAL_CVE_CORRELATION.items():
            if details["affected_service"].lower() in service_name.lower() or service_name.lower() in details["affected_service"].lower():
                matches.append({"cve_id": cve, **details})
        return matches

vulnerability_engine = VulnerabilityEngine()
