import time
from typing import List, Dict, Any
from datetime import datetime

class DeceptionSessionTracker:
    """Tracks and logs interaction attempts made against decoy and honeypot services."""

    def __init__(self):
        self._interactions: List[Dict[str, Any]] = []

    def record_interaction(self, service: str, src_ip: str, src_port: int, payload_preview: str = ""):
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": service,
            "src_ip": src_ip,
            "src_port": src_port,
            "payload_preview": payload_preview[:120],
            "action": "INTERACTION_LOGGED"
        }
        self._interactions.append(event)
        if len(self._interactions) > 500:
            self._interactions.pop(0)

    def get_recent_interactions(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self._interactions[-limit:])
