import winreg
from typing import List, Dict, Any

class ShimcacheParser:
    """Audits Windows Application Compatibility Cache (AppCompatCache) registry keys."""

    SHIMCACHE_PATH = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"

    @classmethod
    def check_shimcache_presence(cls) -> Dict[str, Any]:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls.SHIMCACHE_PATH, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, "AppCompatCache")
                return {
                    "available": True,
                    "data_size_bytes": len(val) if val else 0,
                    "status": "ACCESSIBLE"
                }
        except PermissionError:
            return {"available": True, "status": "PERMISSION_REQUIRED", "message": "Admin privileges required to read SYSTEM hive."}
        except Exception as e:
            return {"available": False, "status": "NOT_FOUND", "error": str(e)}
