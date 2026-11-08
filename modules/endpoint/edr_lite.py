import psutil
import hashlib
import os
import subprocess
from typing import Dict, List, Any
from core.database import db

class EDRLiteEngine:
    """EDR Lite 2.0: Process tree telemetry, suspicious parent-child behavior analysis, FIM, and scheduled tasks."""

    SUSPICIOUS_SPAWN_RULES = [
        ("excel.exe", ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]),
        ("winword.exe", ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]),
        ("powerpnt.exe", ["powershell.exe", "cmd.exe"]),
        ("outlook.exe", ["powershell.exe", "cmd.exe", "certutil.exe"])
    ]

    def __init__(self):
        self.fim_baselines = {}  # {path: {file: sha256}}

    def get_process_tree(self) -> List[Dict[str, Any]]:
        """Extracts complete process execution hierarchy and evaluates suspicious execution trees."""
        procs = []
        pid_to_name = {}

        # First pass to index names
        for p in psutil.process_iter(['pid', 'name']):
            try:
                pid_to_name[p.info['pid']] = (p.info['name'] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for p in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'memory_info']):
            try:
                info = p.info
                pid = info['pid']
                ppid = info.get('ppid') or 0
                name = info['name'] or "Unknown"
                exe_path = info.get('exe') or "Access Denied"
                cmdline_str = " ".join(info.get('cmdline') or [])
                mem_mb = round((info['memory_info'].rss / (1024*1024)), 1) if info.get('memory_info') else 0.0

                parent_name = pid_to_name.get(ppid, "Unknown")
                is_suspicious = False
                reason = ""

                # Evaluate suspicious parent-child rules
                for parent_pattern, suspicious_children in self.SUSPICIOUS_SPAWN_RULES:
                    if parent_pattern in parent_name:
                        if any(c in name.lower() for c in suspicious_children):
                            is_suspicious = True
                            reason = f"Suspicious child process spawned by {parent_name}"

                if "powershell" in name.lower() and ("-enc" in cmdline_str.lower() or "-w hidden" in cmdline_str.lower()):
                    is_suspicious = True
                    reason = "Obfuscated / Hidden PowerShell execution"

                proc_item = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "parent_name": parent_name,
                    "path": exe_path,
                    "cmdline": cmdline_str[:120],
                    "memory_mb": mem_mb,
                    "is_suspicious": is_suspicious,
                    "flag_reason": reason
                }
                procs.append(proc_item)

                if is_suspicious:
                    try:
                        with db.get_connection() as conn:
                            conn.execute("""
                            INSERT INTO process_events (pid, ppid, process_name, image_path, command_line, is_suspicious)
                            VALUES (?, ?, ?, ?, ?, 1)
                            """, (pid, ppid, name, exe_path, cmdline_str))
                            conn.commit()
                    except Exception:
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return procs

    def create_fim_baseline(self, directory_path: str) -> Dict[str, str]:
        """Creates a cryptographic SHA-256 baseline for a target directory."""
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        baseline = {}
        for root, _, files in os.walk(directory_path):
            for f in files:
                full_p = os.path.join(root, f)
                try:
                    with open(full_p, "rb") as fh:
                        h = hashlib.sha256(fh.read()).hexdigest()
                    baseline[full_p] = h
                except Exception:
                    continue
        self.fim_baselines[directory_path] = baseline
        return baseline

    def check_fim_integrity(self, directory_path: str) -> Dict[str, Any]:
        """Compares current directory state against saved SHA-256 baseline."""
        if directory_path not in self.fim_baselines:
            return {"error": "No baseline exists for this path. Create baseline first."}

        baseline = self.fim_baselines[directory_path]
        modified = []
        created = []
        current_files = set()

        for root, _, files in os.walk(directory_path):
            for f in files:
                full_p = os.path.join(root, f)
                current_files.add(full_p)
                try:
                    with open(full_p, "rb") as fh:
                        current_hash = hashlib.sha256(fh.read()).hexdigest()
                    if full_p in baseline:
                        if current_hash != baseline[full_p]:
                            modified.append(full_p)
                    else:
                        created.append(full_p)
                except Exception:
                    continue

        deleted = [f for f in baseline if f not in current_files]

        return {
            "directory": directory_path,
            "total_monitored": len(baseline),
            "modified_files": modified,
            "created_files": created,
            "deleted_files": deleted,
            "integrity_breached": bool(modified or created or deleted)
        }

    def audit_scheduled_tasks(self, limit: int = 25) -> List[Dict[str, str]]:
        tasks = []
        try:
            out = subprocess.check_output('schtasks /query /fo csv /nh', shell=True, text=True, stderr=subprocess.STDOUT, timeout=5)
            for line in out.splitlines()[:limit]:
                parts = line.split('","')
                if len(parts) >= 2:
                    name = parts[0].strip('"')
                    next_run = parts[1].strip('"')
                    status = parts[2].strip('"') if len(parts) > 2 else "Unknown"
                    tasks.append({"task_name": name, "next_run": next_run, "status": status})
        except Exception:
            pass
        return tasks

edr_lite_engine = EDRLiteEngine()
