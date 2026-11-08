import re
from typing import Dict, Any, List

class SigmaAdapter:
    """Parses and compiles Sigma detection rules into evaluation trees."""

    @staticmethod
    def parse_simple_yaml(yaml_content: str) -> Dict[str, Any]:
        """Lightweight YAML parser for Sigma rules without heavy external dependencies."""
        rule = {}
        current_section = None
        for line in yaml_content.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if ":" in line_str:
                key, val = line_str.split(":", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                rule[key] = val
        return rule

    @classmethod
    def evaluate_rule(cls, rule_dict: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Evaluates whether event fields match rule selection criteria."""
        field = rule_dict.get("field")
        pattern = rule_dict.get("value")
        if not field or not pattern:
            return False

        event_val = str(event.get(field, "")).lower()
        return pattern.lower() in event_val
