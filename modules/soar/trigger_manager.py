from typing import List, Dict, Any, Callable
from datetime import datetime

class TriggerManager:
    """Manages event and schedule triggers that fire SOAR playbooks."""

    def __init__(self):
        self._triggers: Dict[str, List[str]] = {
            "ON_ALERT": [],
            "ON_SCAN_COMPLETE": [],
            "ON_SUSPICIOUS_PROCESS": []
        }

    def register_playbook_trigger(self, trigger_type: str, playbook_id: str):
        if trigger_type not in self._triggers:
            self._triggers[trigger_type] = []
        if playbook_id not in self._triggers[trigger_type]:
            self._triggers[trigger_type].append(playbook_id)

    def get_playbooks_for_trigger(self, trigger_type: str) -> List[str]:
        return self._triggers.get(trigger_type, [])
