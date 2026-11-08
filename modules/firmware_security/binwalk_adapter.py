import subprocess
import shutil
from typing import Dict, Any

class BinwalkAdapter:
    """Interfaces with Binwalk for firmware signature scanning and extraction."""

    def __init__(self):
        self.binwalk_path = shutil.which("binwalk")

    def check_availability(self) -> Dict[str, Any]:
        if self.binwalk_path:
            return {"available": True, "path": self.binwalk_path, "status": "AVAILABLE"}
        return {
            "available": False,
            "path": None,
            "status": "NOT_INSTALLED",
            "message": "Binwalk extraction tool not detected in PATH. Static signature analysis used as fallback."
        }
