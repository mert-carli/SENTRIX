from typing import Dict, Any, List
from datetime import datetime

class SOARApprovalManager:
    """Enforces human-in-the-loop operator authorization for intrusive response actions."""

    def __init__(self):
        self._pending_approvals: Dict[str, Dict[str, Any]] = {}

    def request_approval(self, request_id: str, action_type: str, target: str, justification: str) -> Dict[str, Any]:
        record = {
            "request_id": request_id,
            "action_type": action_type,
            "target": target,
            "justification": justification,
            "status": "PENDING_OPERATOR_APPROVAL",
            "requested_at": datetime.utcnow().isoformat()
        }
        self._pending_approvals[request_id] = record
        return record

    def approve_action(self, request_id: str, operator_name: str) -> bool:
        if request_id in self._pending_approvals:
            self._pending_approvals[request_id]["status"] = "APPROVED"
            self._pending_approvals[request_id]["approved_by"] = operator_name
            self._pending_approvals[request_id]["approved_at"] = datetime.utcnow().isoformat()
            return True
        return False

    def reject_action(self, request_id: str, reason: str) -> bool:
        if request_id in self._pending_approvals:
            self._pending_approvals[request_id]["status"] = "REJECTED"
            self._pending_approvals[request_id]["rejection_reason"] = reason
            return True
        return False

    def get_pending(self) -> List[Dict[str, Any]]:
        return [v for v in self._pending_approvals.values() if v["status"] == "PENDING_OPERATOR_APPROVAL"]
