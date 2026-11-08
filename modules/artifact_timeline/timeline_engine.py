from typing import List, Dict, Any
from modules.artifact_timeline.prefetch_parser import PrefetchParser
from modules.windows_internals.eventlog_collector import EventLogCollector

class ArtifactTimelineEngine:
    """Aggregates Prefetch, Event Logs, and system artifacts into a unified forensic timeline."""

    def __init__(self):
        self.prefetch = PrefetchParser()
        self.eventlog = EventLogCollector()

    def build_unified_timeline(self, limit: int = 50) -> List[Dict[str, Any]]:
        timeline = []

        # 1. Prefetch artifacts
        pf_items = self.prefetch.list_prefetch_artifacts(limit=limit)
        for item in pf_items:
            timeline.append({
                "timestamp": item.get("last_execution_time"),
                "event_type": "PROCESS_EXECUTION",
                "source": "Windows Prefetch",
                "entity": item.get("executable_name"),
                "details": f"Prefetch file: {item.get('filename')}"
            })

        # 2. Recent System Event Logs
        logs = self.eventlog.query_recent_events(channel="System", max_events=limit)
        for l in logs:
            timeline.append({
                "timestamp": l.get("timestamp"),
                "event_type": f"SYSTEM_LOG_{l.get('event_id')}",
                "source": "EventLog:System",
                "entity": l.get("provider"),
                "details": str(l.get("fields", {}))[:120]
            })

        # Sort timeline chronologically (latest first)
        return sorted(timeline, key=lambda x: str(x.get("timestamp") or ""), reverse=True)
