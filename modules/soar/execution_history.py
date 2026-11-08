from typing import List, Dict, Any
from datetime import datetime

class SOARExecutionHistory:
    """Maintains audited record of playbook runs and step executions."""

    def __init__(self):
        self._history: List[Dict[str, Any]] = []

    def record_run(self, playbook_name: str, trigger: str, steps_count: int, status: str, duration_ms: float) -> str:
        run_id = f"RUN-{len(self._history)+1:04d}"
        self._history.append({
            "run_id": run_id,
            "playbook_name": playbook_name,
            "trigger": trigger,
            "steps_count": steps_count,
            "status": status,
            "duration_ms": duration_ms,
            "timestamp": datetime.utcnow().isoformat()
        })
        return run_id

    def get_runs(self) -> List[Dict[str, Any]]:
        return list(reversed(self._history))
