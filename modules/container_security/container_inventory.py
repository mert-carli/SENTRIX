from typing import List, Dict, Any
from core.database import db

class ContainerInventory:
    """Persists and queries container and Kubernetes assets in database."""

    @staticmethod
    def record_asset(asset_type: str, asset_id: str, name: str, is_privileged: bool = False, exposed_ports: str = "", vulnerabilities_json: str = ""):
        try:
            with db.get_connection() as conn:
                conn.execute("""
                INSERT INTO container_assets (asset_type, asset_id, name, is_privileged, exposed_ports, vulnerabilities_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_type, asset_id) DO UPDATE SET
                    name = excluded.name,
                    is_privileged = excluded.is_privileged,
                    exposed_ports = excluded.exposed_ports,
                    vulnerabilities_json = excluded.vulnerabilities_json,
                    last_scanned = CURRENT_TIMESTAMP;
                """, (asset_type, asset_id, name, is_privileged, exposed_ports, vulnerabilities_json))
                conn.commit()
        except Exception:
            pass

    @staticmethod
    def get_inventory() -> List[Dict[str, Any]]:
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM container_assets ORDER BY id DESC")
                return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []
