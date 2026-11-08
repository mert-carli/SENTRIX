from typing import List, Dict, Any
from core.database import db
from modules.risk_engine.scoring_engine import ExplainableRiskScorer

class AttackSurfaceRiskMapper:
    """Aggregates discovered open ports, web findings, and host exposures into prioritized asset risk profiles."""

    def evaluate_host_risk(self, host_id: int, ip: str, hostname: str = "") -> Dict[str, Any]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM open_ports WHERE host_id = ?", (host_id,))
            ports = [dict(r) for r in cursor.fetchall()]

        critical_ports = [p for p in ports if p["port"] in [21, 23, 445, 3389]]
        web_ports = [p for p in ports if p["port"] in [80, 443, 8080, 8443]]

        base_cvss = 5.0
        if critical_ports:
            base_cvss = 8.5
        elif web_ports:
            base_cvss = 6.0

        risk_eval = ExplainableRiskScorer.calculate_risk(
            base_cvss=base_cvss,
            epss_score=0.15 if critical_ports else 0.02,
            is_cisa_kev=bool(critical_ports),
            is_internet_exposed=True,
            asset_criticality=1.2 if critical_ports else 1.0
        )

        return {
            "host_id": host_id,
            "ip": ip,
            "hostname": hostname,
            "open_ports_count": len(ports),
            "critical_ports": [p["port"] for p in critical_ports],
            "risk_score": risk_eval["overall_score"],
            "rating": risk_eval["rating"],
            "explanation": risk_eval["explanation"]
        }
