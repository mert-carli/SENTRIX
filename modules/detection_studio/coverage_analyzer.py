from typing import List, Dict, Any

class DetectionCoverageAnalyzer:
    """Analyzes detection coverage across the MITRE ATT&CK enterprise matrix."""

    CORE_TACTICS = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    ]

    @classmethod
    def evaluate_coverage(cls, active_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        covered_techniques = set()
        for r in active_rules:
            tech = r.get("mitre_technique")
            if tech:
                covered_techniques.add(tech.upper())

        return {
            "total_active_rules": len(active_rules),
            "covered_techniques_count": len(covered_techniques),
            "covered_techniques": list(covered_techniques),
            "tactics": cls.CORE_TACTICS,
            "status": "EVALUATED"
        }
