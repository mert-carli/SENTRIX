from typing import Dict, Any

class LicenseAnalyzer:
    """Analyzes open source software licenses for legal risk and copyleft contamination."""

    COPYLEFT = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-3.0"]
    PERMISSIVE = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]

    @classmethod
    def evaluate_license(cls, license_name: str) -> Dict[str, Any]:
        lic = license_name.upper().strip()
        if any(c in lic for c in ["AGPL", "GPL"]):
            return {
                "license": license_name,
                "type": "COPYLEFT",
                "risk": "HIGH",
                "commercial_risk": "Requires open-sourcing derivative work under same license."
            }
        elif any(p in lic for p in ["MIT", "APACHE", "BSD", "ISC"]):
            return {
                "license": license_name,
                "type": "PERMISSIVE",
                "risk": "LOW",
                "commercial_risk": "Safe for commercial and proprietary integration with attribution."
            }
        return {
            "license": license_name,
            "type": "UNKNOWN",
            "risk": "MEDIUM",
            "commercial_risk": "Unverified license terms require manual legal review."
        }
