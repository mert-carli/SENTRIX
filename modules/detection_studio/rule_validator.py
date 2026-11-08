from typing import Dict, Any
from modules.detection_studio.sigma_adapter import SigmaAdapter
from modules.detection_studio.yara_adapter import YaraAdapter
from modules.detection_studio.suricata_adapter import SuricataAdapter

class RuleValidator:
    """Unified validator for Sigma, YARA, and Suricata detection rules."""

    @staticmethod
    def validate_rule(rule_format: str, content: str) -> Dict[str, Any]:
        fmt = rule_format.upper()
        if fmt == "SIGMA":
            parsed = SigmaAdapter.parse_simple_yaml(content)
            has_title = "title" in parsed
            return {
                "valid": has_title,
                "format": "SIGMA",
                "title": parsed.get("title", "Untitled"),
                "error": None if has_title else "Missing 'title' in Sigma YAML."
            }
        elif fmt == "YARA":
            return YaraAdapter.validate_rule_syntax(content)
        elif fmt in ["SURICATA", "SNORT"]:
            return SuricataAdapter.validate_rule(content)
        else:
            return {"valid": False, "error": f"Unsupported rule format: {rule_format}"}
