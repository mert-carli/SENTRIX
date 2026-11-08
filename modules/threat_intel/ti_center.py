import urllib.request
import json
from typing import Dict, Any, List
from core.database import db

# Curated High-Confidence Known Malicious IOC Feed
KNOWN_MALICIOUS_IOCS = {
    "185.220.101.5": {"type": "IP", "threat": "Tor Exit Node / Scanner", "confidence": 95},
    "194.26.29.114": {"type": "IP", "threat": "Mirai / Botnet C2", "confidence": 90},
    "45.154.255.88": {"type": "IP", "threat": "Brute Force / Scanner", "confidence": 85},
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"type": "HASH", "threat": "Empty File (Zero-byte)", "confidence": 100}
}

class ThreatIntelligenceCenter:
    def __init__(self):
        pass

    def check_ioc(self, indicator: str) -> Dict[str, Any]:
        """Checks an indicator (IP, Domain, or Hash) against local and threat feeds."""
        indicator = indicator.strip().lower()

        # Check local DB
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_indicators WHERE indicator = ?", (indicator,))
            row = cursor.fetchone()
            if row:
                return {
                    "indicator": indicator,
                    "is_malicious": True,
                    "threat_type": row["threat_type"],
                    "confidence": row["confidence"],
                    "source": row["source"] or "LOCAL_THREAT_CACHE"
                }

        # Check curated IOCs
        if indicator in KNOWN_MALICIOUS_IOCS:
            data = KNOWN_MALICIOUS_IOCS[indicator]
            return {
                "indicator": indicator,
                "is_malicious": True,
                "threat_type": data["threat"],
                "confidence": data["confidence"],
                "source": "CURATED_GLOBAL_FEED"
            }

        return {
            "indicator": indicator,
            "is_malicious": False,
            "threat_type": "Clean / Unlisted",
            "confidence": 50,
            "source": "REPUTATION_DATABASE"
        }

threat_intel_center = ThreatIntelligenceCenter()
