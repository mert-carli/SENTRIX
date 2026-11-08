import time
from typing import Dict, Any, List
from modules.detection_studio.sigma_adapter import SigmaAdapter
from modules.detection_studio.yara_adapter import YaraAdapter

class RuleTestRunner:
    """Executes detection rules against sample telemetry and benign event baselines to detect false positives."""

    @staticmethod
    def test_sigma_rule(rule_dict: Dict[str, Any], test_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.time()
        matches = []
        for ev in test_events:
            if SigmaAdapter.evaluate_rule(rule_dict, ev):
                matches.append(ev)
        duration_ms = (time.time() - start) * 1000

        return {
            "tested_events_count": len(test_events),
            "matches_count": len(matches),
            "duration_ms": round(duration_ms, 2),
            "matches": matches
        }
