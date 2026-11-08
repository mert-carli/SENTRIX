import subprocess
import shutil
import json
import os
from typing import Dict, Any, List, Optional
from core.logger import logger

class VolatilityAdapter:
    """Interfaces with Volatility 3 for memory dump forensic artifact extraction."""

    SUPPORTED_PLUGINS = [
        "windows.pslist",
        "windows.pstree",
        "windows.netscan",
        "windows.malfind",
        "windows.dlllist",
        "windows.cmdline"
    ]

    def __init__(self):
        self.vol_path = shutil.which("vol") or shutil.which("volatility3") or shutil.which("vol.py")

    def check_volatility_installed(self) -> Dict[str, Any]:
        if self.vol_path:
            return {
                "available": True,
                "path": self.vol_path,
                "version": "Volatility 3 Framework",
                "status": "AVAILABLE"
            }
        return {
            "available": False,
            "path": None,
            "version": None,
            "status": "NOT_INSTALLED",
            "message": "Volatility 3 binary (vol / vol.py) not found in PATH."
        }

    def run_plugin(self, image_path: str, plugin_name: str, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
        vol_info = self.check_volatility_installed()
        if not vol_info["available"]:
            return {
                "success": False,
                "error": "Volatility 3 is not installed on this system.",
                "status": "NOT_INSTALLED",
                "rows": []
            }

        if plugin_name not in self.SUPPORTED_PLUGINS:
            return {
                "success": False,
                "error": f"Unsupported plugin: {plugin_name}",
                "rows": []
            }

        cmd = [self.vol_path, "-f", image_path, plugin_name]
        if extra_args:
            cmd.extend(extra_args)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            return {
                "success": res.returncode == 0,
                "raw_output": res.stdout,
                "error": res.stderr if res.returncode != 0 else "",
                "plugin": plugin_name
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Volatility execution timed out (120s limit).", "rows": []}
        except Exception as e:
            return {"success": False, "error": str(e), "rows": []}
