from typing import List, Dict, Any

class TimelineBuilder:
    """Builds unified chronologically ordered event timelines from disparate investigation findings."""

    @staticmethod
    def build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for ev in events:
            timestamp = ev.get("timestamp") or ev.get("TimeCreated") or "Unknown"
            title = ev.get("title") or ev.get("process_name") or ev.get("event_type") or "Event"
            source = ev.get("source") or ev.get("channel") or "Unknown Source"
            severity = ev.get("severity") or "INFO"

            normalized.append({
                "timestamp": timestamp,
                "title": title,
                "source": source,
                "severity": severity,
                "details": ev
            })

        return sorted(normalized, key=lambda x: str(x["timestamp"]), reverse=True)
