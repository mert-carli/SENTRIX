import requests
from typing import Dict, Any, List

class OSVClient:
    """Queries Google's Open Source Vulnerabilities (OSV.dev) API for known package vulnerabilities."""

    API_URL = "https://api.osv.dev/v1/query"

    @classmethod
    def query_package(cls, package_name: str, version: str = "", ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        if version and version != "latest":
            payload["version"] = version

        try:
            resp = requests.post(cls.API_URL, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                results = []
                for v in vulns:
                    results.append({
                        "id": v.get("id"),
                        "summary": v.get("summary", "No summary"),
                        "details": v.get("details", "")[:200],
                        "aliases": v.get("aliases", [])
                    })
                return results
            return []
        except Exception:
            return []
