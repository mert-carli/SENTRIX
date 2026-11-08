import re
from typing import Dict, Any, List

class YaraAdapter:
    """Validates YARA rule syntax and matches string/hex patterns against files."""

    @staticmethod
    def validate_rule_syntax(rule_text: str) -> Dict[str, Any]:
        """Basic syntax check for rule keyword, strings, and condition sections."""
        has_rule = bool(re.search(r'\brule\s+[A-Za-z0-9_]+', rule_text))
        has_condition = bool(re.search(r'\bcondition\s*:', rule_text))

        if not has_rule:
            return {"valid": False, "error": "Missing 'rule <name>' declaration."}
        if not has_condition:
            return {"valid": False, "error": "Missing 'condition:' block in YARA rule."}

        rule_name = re.search(r'\brule\s+([A-Za-z0-9_]+)', rule_text).group(1)
        return {
            "valid": True,
            "rule_name": rule_name,
            "error": None
        }

    @classmethod
    def scan_bytes(cls, rule_text: str, data: bytes) -> Dict[str, Any]:
        val = cls.validate_rule_syntax(rule_text)
        if not val["valid"]:
            return {"matched": False, "error": val["error"]}

        # Extract $string identifiers
        string_matches = []
        pattern_matches = re.findall(r'\$([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', rule_text)
        for var_name, pattern in pattern_matches:
            if pattern.encode() in data:
                string_matches.append(var_name)

        matched = len(string_matches) > 0 if pattern_matches else False
        return {
            "matched": matched,
            "rule_name": val["rule_name"],
            "matched_strings": string_matches
        }
