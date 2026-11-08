import time
from typing import Dict, Any, List
from modules.soar.action_registry import ActionRegistry
from modules.soar.approval_manager import SOARApprovalManager
from modules.soar.rollback_manager import SOARRollbackManager
from modules.soar.execution_history import SOARExecutionHistory

class SOARPlaybookEngine:
    """Executes multi-step automated response workflows with safety rails and operator approvals."""

    def __init__(self):
        self.actions = ActionRegistry()
        self.approvals = SOARApprovalManager()
        self.rollback = SOARRollbackManager()
        self.history = SOARExecutionHistory()

    def execute_playbook(self, playbook_def: Dict[str, Any], trigger_context: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()
        name = playbook_def.get("name", "Unnamed Playbook")
        steps = playbook_def.get("steps", [])
        executed_steps = []

        status = "COMPLETED"
        for idx, step in enumerate(steps):
            action_type = step.get("action")
            action_meta = self.actions.get_action(action_type)

            if not action_meta:
                status = "FAILED"
                executed_steps.append({"step": idx, "action": action_type, "status": "UNKNOWN_ACTION"})
                break

            # Check if approval required
            if action_meta.get("requires_approval"):
                req_id = f"REQ-{int(time.time())}-{idx}"
                self.approvals.request_approval(
                    request_id=req_id,
                    action_type=action_type,
                    target=str(trigger_context.get("target", "Target")),
                    justification=step.get("description", "Playbook response trigger")
                )
                executed_steps.append({
                    "step": idx,
                    "action": action_type,
                    "status": "WAITING_OPERATOR_APPROVAL",
                    "request_id": req_id
                })
                status = "WAITING_APPROVAL"
                break
            else:
                handler = action_meta.get("handler")
                res = handler(trigger_context) if handler else {}
                executed_steps.append({"step": idx, "action": action_type, "status": "SUCCESS", "result": res})

        duration_ms = (time.time() - start) * 1000
        run_id = self.history.record_run(name, trigger_context.get("trigger", "MANUAL"), len(executed_steps), status, duration_ms)

        return {
            "run_id": run_id,
            "playbook_name": name,
            "status": status,
            "steps": executed_steps,
            "duration_ms": round(duration_ms, 2)
        }
