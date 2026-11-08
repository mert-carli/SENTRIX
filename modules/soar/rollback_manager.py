from typing import List, Dict, Any
from datetime import datetime

class SOARRollbackManager:
    """Reverts reversible containment operations to restore system state."""

    def __init__(self):
        self._executed_actions: List[Dict[str, Any]] = []

    def record_reversible_action(self, action_id: str, action_type: str, rollback_payload: Dict[str, Any]):
        self._executed_actions.append({
            "action_id": action_id,
            "action_type": action_type,
            "rollback_payload": rollback_payload,
            "executed_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE"
        })

    def rollback_action(self, action_id: str) -> Dict[str, Any]:
        for item in self._executed_actions:
            if item["action_id"] == action_id and item["status"] == "ACTIVE":
                item["status"] = "ROLLED_BACK"
                item["rolled_back_at"] = datetime.utcnow().isoformat()
                return {
                    "success": True,
                    "action_id": action_id,
                    "message": f"Successfully rolled back action {item['action_type']}"
                }
        return {"success": False, "error": "Action ID not found or already rolled back."}
