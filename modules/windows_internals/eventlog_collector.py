import subprocess
import xml.etree.ElementTree as ET
import shutil
from typing import List, Dict, Any, Optional
from core.database import db
from core.logger import logger
from core.permission import is_admin
from modules.windows_internals.event_normalizer import EventNormalizer

class EventLogCollector:
    """Collects security, system, and operational events from native Windows Event Log infrastructure."""

    def __init__(self):
        self.wevtutil_path = shutil.which("wevtutil.exe") or "C:\\Windows\\System32\\wevtutil.exe"

    def get_supported_channels(self) -> List[str]:
        return [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Defender/Operational"
        ]

    def query_recent_events(self, channel: str = "System", max_events: int = 25, event_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Queries recent events from specified channel using wevtutil.
        Gracefully handles non-admin restrictions for Security channel.
        """
        if channel.lower() == "security" and not is_admin():
            logger.warning("[EventLogCollector] Security channel requires Administrator privilege. Falling back to System/Application.")
            return [{
                "status": "PERMISSION_REQUIRED",
                "channel": channel,
                "message": "Administrator privilege required to read Windows Security event channel."
            }]

        xpath_query = "*"
        if event_id:
            xpath_query = f"*[System[(EventID={event_id})]]"

        cmd = [
            self.wevtutil_path,
            "qe",
            channel,
            f"/q:{xpath_query}",
            f"/c:{max_events}",
            "/rd:true",
            "/f:xml"
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if res.returncode != 0:
                logger.error(f"[EventLogCollector] wevtutil error on channel {channel}: {res.stderr.strip()}")
                return []

            raw_xml = f"<Events>{res.stdout}</Events>"
            events = []
            
            try:
                root = ET.fromstring(raw_xml)
                ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                for ev in root.findall('ns:Event', ns) or root.findall('Event'):
                    # Extract system tags
                    sys_tag = ev.find('ns:System', ns) or ev.find('System')
                    ev_id = "0"
                    provider = "Unknown"
                    time_created = ""
                    computer = "localhost"

                    if sys_tag is not None:
                        id_node = sys_tag.find('ns:EventID', ns) or sys_tag.find('EventID')
                        if id_node is not None:
                            ev_id = id_node.text or "0"
                        prov_node = sys_tag.find('ns:Provider', ns) or sys_tag.find('Provider')
                        if prov_node is not None:
                            provider = prov_node.attrib.get('Name', 'Unknown')
                        time_node = sys_tag.find('ns:TimeCreated', ns) or sys_tag.find('TimeCreated')
                        if time_node is not None:
                            time_created = time_node.attrib.get('SystemTime', '')
                        comp_node = sys_tag.find('ns:Computer', ns) or sys_tag.find('Computer')
                        if comp_node is not None:
                            computer = comp_node.text or "localhost"

                    fields = {
                        "EventID": ev_id,
                        "Provider": provider,
                        "TimeCreated": time_created,
                        "Computer": computer
                    }

                    # Event Data
                    data_tag = ev.find('ns:EventData', ns) or ev.find('EventData')
                    if data_tag is not None:
                        for item in data_tag:
                            name = item.attrib.get('Name')
                            if name:
                                fields[name] = item.text or ""

                    sec_event = EventNormalizer.normalize_windows_event(channel, ev_id, fields=fields)
                    
                    event_record = {
                        "channel": channel,
                        "event_id": ev_id,
                        "provider": provider,
                        "timestamp": time_created,
                        "computer": computer,
                        "severity": sec_event.severity,
                        "fields": fields
                    }
                    events.append(event_record)

                    # Persist to database security_events
                    try:
                        with db.get_connection() as conn:
                            conn.execute(
                                "INSERT INTO security_events (event_type, source, severity, title, raw_data) VALUES (?, ?, ?, ?, ?)",
                                (f"WIN_EVT_{ev_id}", f"EventLog:{channel}", sec_event.severity, f"Event {ev_id} ({provider})", str(fields))
                            )
                            conn.commit()
                    except Exception:
                        pass

            except ET.ParseError:
                # Fallback if XML fragment parsing encounters malformed entities
                pass

            return events

        except Exception as e:
            logger.error(f"[EventLogCollector] Failed reading {channel}: {e}")
            return []
