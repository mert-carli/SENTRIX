import json
import os
from datetime import datetime
from typing import Dict, Any, List
from core.database import db

class ReportGenerator:
    def __init__(self):
        pass

    def generate_comprehensive_report(self, project_id: int = 1, lang: str = "EN") -> str:
        """Compiles a complete professional cybersecurity assessment report in Markdown."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hosts = db.get_all_hosts(project_id)
        alerts = db.get_recent_alerts(limit=50)

        critical_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        high_count = sum(1 for a in alerts if a["severity"] == "HIGH")
        medium_count = sum(1 for a in alerts if a["severity"] == "MEDIUM")

        is_tr = (lang.upper() == "TR")

        title = "SİBER GÜVENLİK VE SIZMA TESTİ OPERASYON RAPORU" if is_tr else "CYBERSECURITY & PENETRATION TESTING ASSESSMENT REPORT"
        exec_summary_title = "1. Yönetici Özeti" if is_tr else "1. Executive Summary"
        scope_title = "2. Yetkili Kapsam & Metodoloji" if is_tr else "2. Scope & Methodology"
        asset_title = "3. Varlık ve Port Envanteri" if is_tr else "3. Asset & Port Inventory"
        findings_title = "4. Teknik Bulgular ve Tehdit Alarmları" if is_tr else "4. Technical Findings & Security Alerts"
        remediation_title = "5. İyileştirme ve Güvenlik Önerileri" if is_tr else "5. Remediation Recommendations"

        md = []
        md.append(f"# {title}\n")
        md.append(f"**Platform:** SENTRIX Cyber Operations Platform v2.0  ")
        md.append(f"**Date:** {now}  ")
        md.append(f"**Classification:** RESTRICTED / CONFIDENTIAL\n")
        md.append("---\n")

        # 1. Executive Summary
        md.append(f"## {exec_summary_title}\n")
        if critical_count > 0 or high_count > 0:
            summary = (
                "Yapılan analizler sonucunda sistemde derhal müdahale gerektiren kritik ve yüksek seviyeli güvenlik bulguları tespit edilmiştir."
                if is_tr else
                "Security assessments identified critical and high severity findings requiring immediate remediation."
            )
        else:
            summary = (
                "Temel denetimlerde doğrudan kritik bir açık tespit edilmemiştir; sistem temel güvenlik seviyesindedir."
                if is_tr else
                "Baseline audits did not identify unauthenticated critical exploits; the endpoint adheres to standard baselines."
            )
        md.append(f"{summary}\n")
        md.append(f"- **Critical Vulnerabilities:** {critical_count}")
        md.append(f"- **High Severity Issues:** {high_count}")
        md.append(f"- **Medium Severity Issues:** {medium_count}")
        md.append(f"- **Total Discovered Hosts:** {len(hosts)}\n")

        # 2. Scope
        md.append(f"## {scope_title}\n")
        md.append("All testing activities complied strictly with the Authorized Scope Management rules. Tests adhered to non-destructive validation principles.\n")

        # 3. Asset Inventory
        md.append(f"## {asset_title}\n")
        if hosts:
            md.append("| IP Address | MAC Address | Hostname | OS Fingerprint | Latency |")
            md.append("|------------|-------------|----------|----------------|---------|")
            for h in hosts:
                md.append(f"| {h['ip']} | {h['mac'] or 'N/A'} | {h['hostname'] or 'N/A'} | {h['os_guess'] or 'Generic'} | {h['latency'] or 'N/A'} |")
        else:
            md.append("No network hosts recorded in current scope.\n")
        md.append("\n")

        # 4. Findings
        md.append(f"## {findings_title}\n")
        if alerts:
            for idx, a in enumerate(alerts, 1):
                md.append(f"### 4.{idx}. [{a['severity']}] {a['title']}")
                md.append(f"- **Source:** {a['source']}")
                md.append(f"- **Confidence:** {a['confidence']}%")
                if a.get('mitre_technique'):
                    md.append(f"- **MITRE ATT&CK:** {a['mitre_technique']}")
                if a.get('evidence'):
                    md.append(f"- **Evidence:** `{a['evidence']}`")
                if a.get('recommended_action'):
                    md.append(f"- **Recommendation:** {a['recommended_action']}")
                md.append("\n")
        else:
            md.append("No active alerts recorded.\n")

        # 5. Remediation
        md.append(f"## {remediation_title}\n")
        md.append("1. Close or strictly firewall unused administrative ports (e.g. 3389 RDP, 445 SMB).\n")
        md.append("2. Enforce Script Block Logging and deploy Sysmon telemetry for enhanced host detection.\n")
        md.append("3. Implement robust Password Policies and remove unnecessary accounts from Administrators groups.\n")

        return "\n".join(md)

report_generator = ReportGenerator()
