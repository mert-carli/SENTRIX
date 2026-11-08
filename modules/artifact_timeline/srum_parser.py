import os
from typing import Dict, Any

class SRUMParser:
    """Checks and parses Windows System Resource Usage Monitor (SRUM) artifacts."""

    SRUM_DB_PATH = r"C:\Windows\System32\sru\SRUDB.dat"

    @classmethod
    def check_srum_status(cls) -> Dict[str, Any]:
        if os.path.isfile(cls.SRUM_DB_PATH):
            try:
                sz = os.path.getsize(cls.SRUM_DB_PATH)
                return {
                    "found": True,
                    "path": cls.SRUM_DB_PATH,
                    "file_size": sz,
                    "status": "ACCESSIBLE"
                }
            except PermissionError:
                return {"found": True, "path": cls.SRUM_DB_PATH, "status": "LOCKED_OR_ADMIN_REQUIRED"}
        return {"found": False, "status": "NOT_FOUND"}
