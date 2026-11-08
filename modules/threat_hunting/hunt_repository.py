from typing import List, Dict, Any, Optional
from datetime import datetime
from core.database import db

class HuntRepository:
    """Stores and retrieves active and closed threat hunt investigations in SQLite database."""

    def create_hunt(self, hunt_id: str, title: str, hypothesis: str, mitre_technique: str = "") -> int:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO threat_hunts (hunt_id, title, hypothesis, mitre_technique, status)
            VALUES (?, ?, ?, ?, 'IN_PROGRESS')
            """, (hunt_id, title, hypothesis, mitre_technique))
            conn.commit()
            return cursor.lastrowid

    def list_hunts(self) -> List[Dict[str, Any]]:
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM threat_hunts ORDER BY id DESC")
                return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []

    def close_hunt(self, hunt_id: str, status: str, findings_summary: str):
        with db.get_connection() as conn:
            conn.execute("""
            UPDATE threat_hunts SET status = ?, findings_summary = ?, closed_at = CURRENT_TIMESTAMP
            WHERE hunt_id = ?
            """, (status, findings_summary, hunt_id))
            conn.commit()
