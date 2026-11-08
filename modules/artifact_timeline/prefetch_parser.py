import os
from datetime import datetime
from typing import List, Dict, Any
from core.permission import is_admin

class PrefetchParser:
    """Extracts Windows Prefetch (.pf) application execution artifacts."""

    PREFETCH_DIR = r"C:\Windows\Prefetch"

    def list_prefetch_artifacts(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not os.path.exists(self.PREFETCH_DIR):
            return []

        artifacts = []
        try:
            files = [os.path.join(self.PREFETCH_DIR, f) for f in os.listdir(self.PREFETCH_DIR) if f.endswith(".pf")]
            files.sort(key=os.path.getmtime, reverse=True)

            for pf_path in files[:limit]:
                fname = os.path.basename(pf_path)
                mtime = os.path.getmtime(pf_path)
                fsize = os.path.getsize(pf_path)
                
                # Format: APPNAME.EXE-HASH.pf
                exe_name = fname.split("-")[0] if "-" in fname else fname

                artifacts.append({
                    "executable_name": exe_name,
                    "filename": fname,
                    "full_path": pf_path,
                    "last_execution_time": datetime.fromtimestamp(mtime).isoformat(),
                    "file_size_bytes": fsize,
                    "source": "Windows Prefetch"
                })
        except PermissionError:
            artifacts.append({
                "executable_name": "ACCESS_DENIED",
                "filename": "Prefetch requires Administrator privilege",
                "last_execution_time": datetime.utcnow().isoformat(),
                "source": "Windows Prefetch"
            })
        except Exception:
            pass

        return artifacts
