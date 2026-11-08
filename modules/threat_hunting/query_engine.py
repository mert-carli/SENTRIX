from typing import Dict, Any, List
from core.database import db

class ThreatQueryEngine:
    """Executes structured hunt queries across processes, security events, network flows, and alerts."""

    def execute_hunt_query(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if "process_name" in filters and filters["process_name"]:
            conditions.append("process_name LIKE ?")
            params.append(f"%{filters['process_name']}%")

        if "command_line" in filters and filters["command_line"]:
            conditions.append("command_line LIKE ?")
            params.append(f"%{filters['command_line']}%")

        if "is_suspicious" in filters:
            conditions.append("is_suspicious = ?")
            params.append(1 if filters["is_suspicious"] else 0)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM process_events WHERE {where_clause} ORDER BY id DESC LIMIT 100"

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []

    def query_security_events(self, event_id: str = None, severity: str = None) -> List[Dict[str, Any]]:
        conditions = []
        params = []
        if event_id:
            conditions.append("event_type LIKE ?")
            params.append(f"%{event_id}%")
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM security_events WHERE {where} ORDER BY id DESC LIMIT 100"

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []
