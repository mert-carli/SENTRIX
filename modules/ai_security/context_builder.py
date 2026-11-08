"""
SENTRIX v5.0 — Security Context Builder
Gathers real-time operational context (scans, ports, CVEs, alerts, processes, scope)
with strict secret redaction for consumption by the AI Copilot and Heuristic Engine.
"""

import re
from typing import Dict, Any, List
from core.database import db
from core.scope import scope_manager
from core.logger import log

class SecurityContextBuilder:
    """Builds a verified, sanitized operational snapshot of the endpoint and scanned network."""

    SECRET_PATTERNS = [
        re.compile(r'(?i)Bearer\s+[A-Za-z0-9\-_\.=]+', re.IGNORECASE),
        re.compile(r'(?i)(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*(?:Bearer\s+)?([^\s;,\'"]+)', re.IGNORECASE),
        re.compile(r'-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]+?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----')
    ]

    def build_snapshot(self) -> Dict[str, Any]:
        """Constructs an integrated security context dictionary."""
        # 1. Hosts & Network
        hosts = db.get_all_hosts()
        online_hosts = [h for h in hosts if h.get("status") == "up" or h.get("status") is None]
        
        # 2. Open Ports
        open_ports = db.get_all_open_ports()
        critical_ports = [p for p in open_ports if p.get("port") in [21, 22, 23, 445, 1433, 3389, 5985, 5986]]

        # 3. Vulnerabilities
        vulns = db.get_all_vulnerabilities()
        critical_vulns = [v for v in vulns if str(v.get("severity", "")).upper() in ["CRITICAL", "HIGH"]]

        # 4. Recent Security Alerts
        alerts = db.get_recent_alerts(limit=25)

        # 5. Scope boundaries
        scope_targets = scope_manager.get_allowed_targets()

        snapshot = {
            "summary": {
                "total_hosts": len(hosts),
                "online_hosts": len(online_hosts),
                "total_open_ports": len(open_ports),
                "critical_ports_exposed": len(critical_ports),
                "total_vulnerabilities": len(vulns),
                "critical_vulnerabilities": len(critical_vulns),
                "recent_alerts_count": len(alerts),
                "scope_target_count": len(scope_targets)
            },
            "critical_ports": critical_ports[:15],
            "critical_vulnerabilities": critical_vulns[:15],
            "recent_alerts": alerts[:15],
            "sample_hosts": online_hosts[:10],
            "scope_targets": scope_targets
        }

        return snapshot

    def sanitize_text(self, text: str) -> str:
        """Strips out sensitive credentials and tokens to preserve privacy."""
        if not text:
            return ""
        sanitized = text
        for pat in self.SECRET_PATTERNS:
            sanitized = pat.sub("[REDACTED_CREDENTIAL]", sanitized)
        return sanitized

    def format_prompt_context(self, max_items: int = 10) -> str:
        """Formats the context snapshot into a concise, readable prompt header."""
        ctx = self.build_snapshot()
        summ = ctx["summary"]

        lines = [
            f"[GÜNCEL SİSTEM DURUMU]",
            f"- Keşfedilen Cihazlar: {summ['total_hosts']} ({summ['online_hosts']} aktif)",
            f"- Açık Portlar: {summ['total_open_ports']} (Kritik/Yönetim Portu: {summ['critical_ports_exposed']})",
            f"- Tespit Edilen Zafiyetler: {summ['total_vulnerabilities']} (Kritik/Yüksek: {summ['critical_vulnerabilities']})",
            f"- Son Güvenlik Uyarıları: {summ['recent_alerts_count']} adet",
            f"- Yetkili Kapsam (Scope): {len(ctx['scope_targets'])} hedef tanımlı"
        ]

        if ctx["critical_ports"]:
            lines.append("\n[RİSKLİ / YÖNETİM PORTLARI]")
            for p in ctx["critical_ports"][:max_items]:
                lines.append(f"  • {p.get('ip')}:{p.get('port')} ({p.get('service', 'Bilinmiyor')})")

        if ctx["critical_vulnerabilities"]:
            lines.append("\n[KRİTİK GÜVENLİK AÇIKLARI]")
            for v in ctx["critical_vulnerabilities"][:max_items]:
                lines.append(f"  • {v.get('cve_id', 'Zafiyet')} - {v.get('title', 'İsimsiz')} [{v.get('severity')}]")

        if ctx["recent_alerts"]:
            lines.append("\n[SON ALARMLAR VE ETKİNLİKLER]")
            for a in ctx["recent_alerts"][:max_items]:
                lines.append(f"  • [{a.get('severity', 'INFO')}] {a.get('title', 'Olay')} - {a.get('description', '')[:80]}")

        raw_context = "\n".join(lines)
        return self.sanitize_text(raw_context)

context_builder = SecurityContextBuilder()
