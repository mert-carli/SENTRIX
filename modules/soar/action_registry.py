from typing import Dict, Any, Callable
from core.database import db

class ActionRegistry:
    """Maintains catalog of automated and approved incident response actions."""

    def __init__(self):
        self._actions: Dict[str, Dict[str, Any]] = {}
        self._register_default_actions()

    def _register_default_actions(self):
        self.register_action(
            action_type="CREATE_INCIDENT",
            description="Escalates high-priority alert into an Incident Record",
            is_destructive=False,
            requires_approval=False,
            handler=self._action_create_incident
        )
        self.register_action(
            action_type="ENRICH_IOC",
            description="Queries Threat Intelligence for IP/Domain/Hash",
            is_destructive=False,
            requires_approval=False,
            handler=self._action_enrich_ioc
        )
        self.register_action(
            action_type="FIREWALL_BLOCK",
            description="Blocks malicious remote IP address via Windows Defender Firewall",
            is_destructive=True,
            requires_approval=True,
            handler=self._action_firewall_block
        )

    def register_action(self, action_type: str, description: str, is_destructive: bool, requires_approval: bool, handler: Callable):
        self._actions[action_type] = {
            "type": action_type,
            "description": description,
            "is_destructive": is_destructive,
            "requires_approval": requires_approval,
            "handler": handler
        }

    def get_action(self, action_type: str) -> Dict[str, Any]:
        return self._actions.get(action_type, {})

    def _action_create_incident(self, params: Dict[str, Any]) -> Dict[str, Any]:
        title = params.get("title", "SOAR Automated Incident")
        severity = params.get("severity", "HIGH")
        summary = params.get("summary", "Automatically escalated via SOAR Playbook.")
        inc_id = db.create_incident(title, severity, summary)
        return {"status": "SUCCESS", "incident_id": inc_id}

    def _action_enrich_ioc(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ioc = params.get("indicator", "")
        return {"status": "ENRICHED", "ioc": ioc, "reputation": "SUSPICIOUS", "confidence": 85}

    def _action_firewall_block(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target_ip = params.get("ip", "")
        # Simulated safe containment confirmation
        return {"status": "BLOCKED", "target_ip": target_ip, "rule_name": f"SENTRIX_BLOCK_{target_ip}"}
