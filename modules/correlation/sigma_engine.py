from typing import Dict, List, Any
from core.database import db

CURATED_SIGMA_RULES = [
    {
        "id": "SIGMA-WIN-001",
        "title": "Suspicious PowerShell EncodedCommand Execution",
        "logsource": "process_creation",
        "level": "HIGH",
        "mitre": "T1059.001",
        "keywords": ["-enc", "-encodedcommand", "frombase64string"],
        "description": "Detects execution of PowerShell with base64-encoded command lines, typical of malware droppers."
    },
    {
        "id": "SIGMA-WIN-002",
        "title": "Whoami / Net User Execution via Script",
        "logsource": "process_creation",
        "level": "MEDIUM",
        "mitre": "T1087.001",
        "keywords": ["whoami.exe", "net.exe user", "net1.exe user"],
        "description": "Detects basic local account discovery commands executed in rapid sequence."
    },
    {
        "id": "SIGMA-WIN-003",
        "title": "Known Command and Control (C2) Port Connection",
        "logsource": "network_connection",
        "level": "CRITICAL",
        "mitre": "T1071",
        "ports": [4444, 1337, 31337, 6667, 9999],
        "description": "Detects network sockets communicating over common Metasploit, Cobalt Strike, or IRC backdoor ports."
    }
]

class SigmaDetectionEngine:
    def __init__(self):
        self.rules = CURATED_SIGMA_RULES

    def evaluate_process_event(self, cmdline: str, proc_name: str) -> List[Dict[str, Any]]:
        """Evaluates a process creation event against process_creation Sigma rules."""
        matched_rules = []
        full_text = f"{proc_name} {cmdline}".lower()

        for rule in self.rules:
            if rule["logsource"] == "process_creation":
                for kw in rule.get("keywords", []):
                    if kw.lower() in full_text:
                        matched_rules.append(rule)
                        db.add_alert(
                            severity=rule["level"],
                            source="SigmaEngine",
                            title=rule["title"],
                            evidence=f"Matched keyword: '{kw}' in '{cmdline[:100]}'",
                            mitre_technique=rule["mitre"],
                            recommended_action="Inspect parent process and kill malicious child PID."
                        )
                        break
        return matched_rules

    def evaluate_socket_event(self, dst_port: int, remote_ip: str) -> List[Dict[str, Any]]:
        """Evaluates a network connection event against network_connection Sigma rules."""
        matched_rules = []
        for rule in self.rules:
            if rule["logsource"] == "network_connection":
                if dst_port in rule.get("ports", []):
                    matched_rules.append(rule)
                    db.add_alert(
                        severity=rule["level"],
                        source="SigmaEngine",
                        title=rule["title"],
                        evidence=f"Outbound connection to {remote_ip}:{dst_port}",
                        mitre_technique=rule["mitre"],
                        recommended_action="Block remote IP at perimeter and isolate local socket."
                    )
        return matched_rules

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return self.rules

sigma_detection_engine = SigmaDetectionEngine()
