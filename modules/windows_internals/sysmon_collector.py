import subprocess
import shutil
from typing import Dict, Any, List
from core.logger import logger
from modules.windows_internals.eventlog_collector import EventLogCollector

class SysmonCollector:
    """Detects, inspects, and streams Microsoft Sysmon operational telemetry."""

    CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self):
        self.wevtutil = shutil.which("wevtutil.exe") or "C:\\Windows\\System32\\wevtutil.exe"
        self._collector = EventLogCollector()

    def check_availability(self) -> Dict[str, Any]:
        """Verifies if Sysmon is installed and operational on the host."""
        try:
            res = subprocess.run(
                [self.wevtutil, "gl", self.CHANNEL_NAME],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            if res.returncode == 0 and "enabled: true" in res.stdout.lower():
                return {
                    "installed": True,
                    "status": "AVAILABLE",
                    "channel": self.CHANNEL_NAME,
                    "message": "Sysmon driver and operational log channel are active."
                }
            elif res.returncode == 0:
                return {
                    "installed": True,
                    "status": "DISABLED",
                    "channel": self.CHANNEL_NAME,
                    "message": "Sysmon is installed but the operational channel is disabled."
                }
            else:
                return {
                    "installed": False,
                    "status": "NOT_INSTALLED",
                    "channel": self.CHANNEL_NAME,
                    "message": "Sysmon service / operational event channel not detected on host."
                }
        except Exception as e:
            return {
                "installed": False,
                "status": "ERROR",
                "message": f"Error querying Sysmon channel: {e}"
            }

    def get_recent_sysmon_events(self, max_events: int = 50, event_id: int = None) -> List[Dict[str, Any]]:
        status = self.check_availability()
        if not status["installed"]:
            return []
        return self._collector.query_recent_events(self.CHANNEL_NAME, max_events=max_events, event_id=event_id)
