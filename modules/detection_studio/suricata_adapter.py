import re
from typing import Dict, Any

class SuricataAdapter:
    """Parses and validates Suricata / Snort network intrusion detection rules."""

    ACTION_KEYWORDS = ["alert", "pass", "drop", "reject", "log"]
    PROTOCOLS = ["tcp", "udp", "icmp", "ip", "http", "tls", "dns"]

    @classmethod
    def validate_rule(cls, rule_text: str) -> Dict[str, Any]:
        line = rule_text.strip()
        if not line or line.startswith("#"):
            return {"valid": False, "error": "Empty or commented line."}

        parts = line.split(maxsplit=7)
        if len(parts) < 7:
            return {"valid": False, "error": "Invalid Suricata rule format (too few tokens)."}

        action = parts[0].lower()
        protocol = parts[1].lower()

        if action not in cls.ACTION_KEYWORDS:
            return {"valid": False, "error": f"Invalid action '{action}'. Expected one of {cls.ACTION_KEYWORDS}."}
        if protocol not in cls.PROTOCOLS:
            return {"valid": False, "error": f"Unknown protocol '{protocol}'."}

        # Check options enclosed in parentheses
        opt_match = re.search(r'\((.*)\)', line)
        if not opt_match:
            return {"valid": False, "error": "Missing rule options enclosed in parentheses."}

        options_raw = opt_match.group(1)
        sid_match = re.search(r'sid\s*:\s*(\d+)', options_raw)
        msg_match = re.search(r'msg\s*:\s*"([^"]+)"', options_raw)

        return {
            "valid": True,
            "action": action,
            "protocol": protocol,
            "sid": sid_match.group(1) if sid_match else "0",
            "message": msg_match.group(1) if msg_match else "No message provided",
            "error": None
        }
