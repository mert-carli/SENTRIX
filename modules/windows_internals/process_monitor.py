import subprocess
import json
import os
import hashlib
from typing import List, Dict, Any, Optional
from core.database import db
from core.logger import logger

class ProcessMonitor:
    """Monitors live Windows processes, parent-child relationships, command lines, and security indicators."""

    SUSPICIOUS_PARENTS = {
        "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe"]
    }

    def get_process_snapshot(self) -> List[Dict[str, Any]]:
        """Retrieves active processes with PID, PPID, executable path, and command line."""
        ps_script = """
        Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | ConvertTo-Json -Compress
        """
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True, timeout=12, check=False)
            if res.returncode != 0 or not res.stdout.strip():
                return []

            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]

            results = []
            for item in data:
                pid = item.get("ProcessId") or 0
                ppid = item.get("ParentProcessId") or 0
                name = item.get("Name") or "Unknown"
                exe_path = item.get("ExecutablePath") or ""
                cmd_line = item.get("CommandLine") or ""

                is_suspicious = False
                flag_reason = ""

                # Check suspicious parent execution
                # We will resolve parent name later if needed, or by inspecting command line
                if "powershell" in name.lower() and ("-enc" in cmd_line.lower() or "-nop" in cmd_line.lower()):
                    is_suspicious = True
                    flag_reason = "Encoded or unprofiled PowerShell execution"
                elif "certutil" in name.lower() and "-urlcache" in cmd_line.lower():
                    is_suspicious = True
                    flag_reason = "Living-off-the-land (LOLBin) Certutil download pattern"

                proc_record = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "executable_path": exe_path,
                    "command_line": cmd_line,
                    "is_suspicious": is_suspicious,
                    "flag_reason": flag_reason
                }
                results.append(proc_record)

                # Ingest to database process_events table if suspicious
                if is_suspicious:
                    try:
                        with db.get_connection() as conn:
                            conn.execute("""
                            INSERT INTO process_events (pid, ppid, process_name, image_path, command_line, is_suspicious)
                            VALUES (?, ?, ?, ?, ?, 1)
                            """, (pid, ppid, name, exe_path, cmd_line))
                            conn.commit()
                    except Exception:
                        pass

            return results
        except Exception as e:
            logger.error(f"[ProcessMonitor] Error querying processes: {e}")
            return []
