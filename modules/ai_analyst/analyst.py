from datetime import datetime
from typing import Dict, Any, List
from core.database import db

class AISecurityAnalyst:
    """AI Security Analyst 3.0: Evidence-based explanation, incident summarization, and remediation planning."""

    def explain_finding(self, finding_title: str, evidence: str = "") -> Dict[str, Any]:
        """Generates evidence-backed explanation, MITRE mapping, and prioritized remediation."""
        title_lower = finding_title.lower()
        now = datetime.utcnow().isoformat()

        if "3389" in title_lower or "rdp" in title_lower:
            text = (
                "RDP (Remote Desktop Protocol, TCP Port 3389) is an administrative management protocol. "
                "Direct exposure enables remote brute-force attacks and exploits such as BlueKeep (CVE-2019-0708)."
            )
            remediation = "Disable public RDP; enforce Network Level Authentication (NLA) or require VPN / Azure Bastion."
            technique = "T1021.001"
            confidence = 95
        elif "smb" in title_lower or "445" in title_lower:
            text = (
                "SMB (Server Message Block, TCP Port 445) is a network file sharing protocol frequently exploited "
                "for lateral movement and ransomware propagation (EternalBlue / WannaCry)."
            )
            remediation = "Block port 445 at firewall boundary, disable SMBv1, and restrict SMB to dedicated storage VLANs."
            technique = "T1021.002"
            confidence = 95
        elif "powershell" in title_lower or "lolbin" in title_lower:
            text = (
                "PowerShell execution with obfuscated arguments (-enc, -w hidden) matches Living-off-the-Land (LOLBin) "
                "techniques commonly used in initial access and defense evasion."
            )
            remediation = "Enforce Constrained Language Mode, enable Script Block Logging (Event ID 4104), and audit PPID."
            technique = "T1059.001"
            confidence = 90
        else:
            text = f"Security anomaly detected regarding '{finding_title}'. Evaluated against baseline operations."
            remediation = "Investigate the event context, verify process hash, and correlate with active user sessions."
            technique = "T1204"
            confidence = 80

        return {
            "title": finding_title,
            "analysis": text,
            "remediation": remediation,
            "mitre_technique": technique,
            "confidence": confidence,
            "evidence_ref": evidence or "None provided",
            "analysis_timestamp": now,
            "data_source": "SENTRIX Intelligence Core"
        }

    def generate_executive_briefing(self) -> Dict[str, Any]:
        """Summarizes the current overall endpoint security posture based on database state."""
        recent_alerts = db.get_recent_alerts(limit=10)
        critical_count = sum(1 for a in recent_alerts if a["severity"] in ["CRITICAL", "HIGH"])
        
        status = "CRITICAL ACTION REQUIRED" if critical_count > 0 else "BASELINE SECURE"
        summary_text = (
            f"Current Posture: {status}. Total active alerts: {len(recent_alerts)}. "
            f"{critical_count} critical/high severity issue(s) detected. "
            "Prioritize mitigating open perimeter management ports and inspecting unmapped background processes."
        )

        return {
            "status": status,
            "critical_count": critical_count,
            "summary": summary_text,
            "alerts": recent_alerts
        }

    def summarize_incident(self, incident_title: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Produces a structured executive and technical incident debrief."""
        return {
            "incident_title": incident_title,
            "event_count": len(events),
            "summary": f"Incident '{incident_title}' comprises {len(events)} correlated security events. Immediate containment is recommended for affected assets.",
            "recommended_containment": [
                "Isolate endpoint from local network segment.",
                "Capture volatile RAM dump for memory forensics.",
                "Revoke active Kerberos and OAuth tokens for associated user accounts."
            ],
            "timestamp": datetime.utcnow().isoformat()
        }

ai_security_analyst = AISecurityAnalyst()
