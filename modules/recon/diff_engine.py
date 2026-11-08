from typing import Dict, List, Any
from core.database import db

class ScanDiffEngine:
    def __init__(self):
        pass

    def compare_target_scans(self, target: str, project_id: int = 1) -> Dict[str, Any]:
        """
        Compares historical scan sessions for a specific target to detect:
        - Newly opened ports
        - Closed ports
        - Version/banner modifications
        - Risk drift
        """
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, started_at, total_found 
            FROM scan_sessions 
            WHERE project_id = ? AND target = ? 
            ORDER BY id DESC LIMIT 2
            """, (project_id, target))
            sessions = cursor.fetchall()

        if len(sessions) < 2:
            return {
                "has_diff": False,
                "message": "At least 2 historical scan sessions are required to compute differential analysis."
            }

        latest_id = sessions[0]["id"]
        previous_id = sessions[1]["id"]

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT port, protocol, service, version FROM open_ports WHERE scan_session_id = ?", (latest_id,))
            latest_ports = { (r["port"], r["protocol"]): (r["service"], r["version"]) for r in cursor.fetchall() }

            cursor.execute("SELECT port, protocol, service, version FROM open_ports WHERE scan_session_id = ?", (previous_id,))
            previous_ports = { (r["port"], r["protocol"]): (r["service"], r["version"]) for r in cursor.fetchall() }

        new_ports = []
        for key in latest_ports:
            if key not in previous_ports:
                new_ports.append({"port": key[0], "protocol": key[1], "service": latest_ports[key][0], "version": latest_ports[key][1]})

        closed_ports = []
        for key in previous_ports:
            if key not in latest_ports:
                closed_ports.append({"port": key[0], "protocol": key[1], "service": previous_ports[key][0], "version": previous_ports[key][1]})

        changed_services = []
        for key in latest_ports:
            if key in previous_ports:
                old_svc, old_ver = previous_ports[key]
                new_svc, new_ver = latest_ports[key]
                if (old_svc != new_svc) or (old_ver != new_ver):
                    changed_services.append({
                        "port": key[0],
                        "protocol": key[1],
                        "old": f"{old_svc} {old_ver}".strip(),
                        "new": f"{new_svc} {new_ver}".strip()
                    })

        return {
            "has_diff": True,
            "target": target,
            "latest_session": {"id": latest_id, "timestamp": sessions[0]["started_at"]},
            "previous_session": {"id": previous_id, "timestamp": sessions[1]["started_at"]},
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "changed_services": changed_services,
            "drift_severity": "HIGH" if new_ports else ("MEDIUM" if changed_services else "LOW")
        }

scan_diff_engine = ScanDiffEngine()
