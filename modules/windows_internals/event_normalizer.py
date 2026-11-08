from typing import Dict, Any, Optional
from datetime import datetime, timezone
from core.event_bus import SecurityEvent

class EventNormalizer:
    """Normalizes various Windows Event Logs, Sysmon events, and ETW traces into uniform SecurityEvents."""

    EVENT_ID_MAP = {
        # Windows Security
        "4624": ("AUTHENTICATION", "Logon Success", "LOW", "T1078"),
        "4625": ("AUTHENTICATION", "Logon Failure", "MEDIUM", "T1110"),
        "4688": ("PROCESS", "Process Creation", "LOW", "T1059"),
        "4689": ("PROCESS", "Process Termination", "INFO", "T1059"),
        "4697": ("PERSISTENCE", "Service Installed", "MEDIUM", "T1543.003"),
        "4698": ("PERSISTENCE", "Scheduled Task Created", "MEDIUM", "T1053.005"),
        "4720": ("IDENTITY", "User Account Created", "LOW", "T1136"),
        "4738": ("IDENTITY", "User Account Modified", "LOW", "T1098"),
        # System
        "7045": ("PERSISTENCE", "New Service Installed", "MEDIUM", "T1543.003"),
        # PowerShell
        "4104": ("EXECUTION", "PowerShell Script Block Execution", "MEDIUM", "T1059.001"),
        # Sysmon
        "1": ("PROCESS", "Sysmon Process Create", "LOW", "T1059"),
        "3": ("NETWORK", "Sysmon Network Connection", "INFO", "T1071"),
        "7": ("DEFENSE_EVASION", "Sysmon Image Loaded", "INFO", "T1073"),
        "11": ("FILE", "Sysmon File Create", "INFO", "T1044"),
        "12": ("REGISTRY", "Sysmon Registry Create/Delete", "INFO", "T1112"),
        "13": ("REGISTRY", "Sysmon Registry Value Set", "INFO", "T1112"),
        "22": ("NETWORK", "Sysmon DNS Query", "INFO", "T1071.004")
    }

    @classmethod
    def normalize_windows_event(cls, channel: str, event_id: str, raw_xml: str = "", fields: Optional[Dict[str, Any]] = None) -> SecurityEvent:
        fields = fields or {}
        cat_info = cls.EVENT_ID_MAP.get(str(event_id), ("SECURITY_LOG", f"Event ID {event_id}", "INFO", ""))
        category, desc, severity, mitre = cat_info

        payload = {
            "channel": channel,
            "event_id": str(event_id),
            "description": desc,
            "raw_fields": fields
        }

        pid = None
        if "ProcessId" in fields:
            try:
                pid = int(str(fields["ProcessId"]), 0)
            except Exception:
                pid = None

        return SecurityEvent(
            event_type=f"WIN_{category}",
            source_module="windows_internals",
            severity=severity,
            confidence=85,
            source_host=fields.get("Computer", "localhost"),
            process_id=pid,
            evidence_refs=[f"EventLog:{channel}:{event_id}"],
            payload=payload
        )
