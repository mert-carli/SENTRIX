import psutil
from datetime import datetime
from typing import List, Dict, Any
from core.database import db
from core.event_bus import event_bus
from core.logger import audit_logger

class CentralCorrelationEngine:
    def __init__(self):
        pass

    def run_all_correlation_checks(self) -> List[Dict[str, Any]]:
        """Runs all correlation rules across system, network, and endpoint state."""
        generated_alerts = []

        # Rule 1: High-Risk Ports Listening on All Interfaces (0.0.0.0 or ::)
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.status == 'LISTEN' and c.laddr:
                    ip, port = c.laddr.ip, c.laddr.port
                    if port in [3389, 445, 135, 4444, 1337]:
                        proc_name = "UNKNOWN"
                        if c.pid:
                            try: proc_name = psutil.Process(c.pid).name()
                            except: pass

                        alert_title = f"High-Risk Port {port} Listening ({proc_name})"
                        evidence = f"Socket={ip}:{port}, PID={c.pid}, Process={proc_name}"
                        mitre = "T1049 - System Network Connections Discovery"
                        rec = f"Audit firewall rule for port {port}. Block unauthorized external access."

                        aid = db.add_alert("HIGH", "NetworkCorrelation", alert_title, evidence, mitre, rec, confidence=90)
                        generated_alerts.append({"id": aid, "title": alert_title, "severity": "HIGH"})
        except Exception:
            pass

        # Rule 2: Suspicious Established C2 Ports
        try:
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    r_port = c.raddr.port
                    if r_port in [4444, 1337, 31337, 6667, 9999]:
                        proc_name = "UNKNOWN"
                        if c.pid:
                            try: proc_name = psutil.Process(c.pid).name()
                            except: pass

                        alert_title = f"Suspicious Outbound Connection to Port {r_port} ({proc_name})"
                        evidence = f"Local={c.laddr.ip}:{c.laddr.port} -> Remote={c.raddr.ip}:{r_port}, PID={c.pid}"
                        mitre = "T1071 - Application Layer Protocol"
                        rec = "Terminate process immediately and inspect endpoint executable."

                        aid = db.add_alert("CRITICAL", "C2Correlation", alert_title, evidence, mitre, rec, confidence=95)
                        generated_alerts.append({"id": aid, "title": alert_title, "severity": "CRITICAL"})
        except Exception:
            pass

        audit_logger.log_action("CORRELATION_AUDIT_COMPLETED", f"AlertsGenerated={len(generated_alerts)}")
        event_bus.publish("ALERTS_UPDATED", generated_alerts)
        return generated_alerts

central_correlation_engine = CentralCorrelationEngine()
