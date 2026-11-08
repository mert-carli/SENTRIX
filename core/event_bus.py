import logging
import threading
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Any, Optional

logger = logging.getLogger("Sentrix.EventBus")

@dataclass
class SecurityEvent:
    event_type: str
    source_module: str
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: int = 80
    source_host: str = "localhost"
    asset_id: Optional[str] = None
    process_id: Optional[int] = None
    correlation_id: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = "4.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        fields_set = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in fields_set}
        return cls(**filtered)

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = {}
        self._lock = threading.Lock()
        self._event_history: List[Dict[str, Any]] = []
        self._max_history = 1000

    def subscribe(self, event_name: str, callback: Callable[[Any], None]):
        with self._lock:
            if event_name not in self._subscribers:
                self._subscribers[event_name] = []
            if callback not in self._subscribers[event_name]:
                self._subscribers[event_name].append(callback)

    def unsubscribe(self, event_name: str, callback: Callable[[Any], None]):
        with self._lock:
            if event_name in self._subscribers and callback in self._subscribers[event_name]:
                self._subscribers[event_name].remove(callback)

    def publish(self, event_name: str, data: Any = None):
        # Record into history buffer if it's a SecurityEvent or dictionary
        with self._lock:
            callbacks = list(self._subscribers.get(event_name, []))
            wildcard_callbacks = list(self._subscribers.get("*", []))
            if isinstance(data, SecurityEvent):
                self._event_history.append(data.to_dict())
            elif isinstance(data, dict):
                self._event_history.append({"event_name": event_name, **data})
            if len(self._event_history) > self._max_history:
                self._event_history.pop(0)

        for cb in callbacks + wildcard_callbacks:
            try:
                cb(data)
            except Exception as e:
                logger.error(f"Error executing callback for event {event_name}: {e}")

    def emit_security_event(self, event: SecurityEvent):
        """Emits a standardized v4 SecurityEvent across the bus and to the specific event_type channel."""
        self.publish(event.event_type, event)
        self.publish("SECURITY_EVENT", event)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._event_history[-limit:])

event_bus = EventBus()
