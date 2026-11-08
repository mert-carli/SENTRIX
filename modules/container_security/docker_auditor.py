import subprocess
import shutil
import json
from typing import List, Dict, Any
from core.logger import logger

class DockerAuditor:
    """Audits local Docker containers, images, and daemon security posture."""

    def __init__(self):
        self.docker_path = shutil.which("docker")

    def check_docker_available(self) -> Dict[str, Any]:
        if not self.docker_path:
            return {
                "installed": False,
                "status": "NOT_INSTALLED",
                "message": "Docker CLI binary not found in PATH."
            }
        try:
            res = subprocess.run([self.docker_path, "info", "--format", "{{json .}}"], capture_output=True, text=True, timeout=5, check=False)
            if res.returncode == 0:
                return {
                    "installed": True,
                    "status": "AVAILABLE",
                    "message": "Docker daemon is running and responsive."
                }
            return {
                "installed": True,
                "status": "DAEMON_NOT_RUNNING",
                "message": "Docker CLI found, but daemon is not running or unreachable."
            }
        except Exception as e:
            return {"installed": False, "status": "ERROR", "message": str(e)}

    def audit_running_containers(self) -> List[Dict[str, Any]]:
        status = self.check_docker_available()
        if status["status"] != "AVAILABLE":
            return []

        try:
            res = subprocess.run(
                [self.docker_path, "ps", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if res.returncode != 0 or not res.stdout.strip():
                return []

            containers = []
            for line in res.stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    c = json.loads(line)
                    cid = c.get("ID", "")
                    
                    # Inspect container for privileged and security options
                    insp = self.inspect_container(cid)
                    is_privileged = insp.get("HostConfig", {}).get("Privileged", False)
                    user = insp.get("Config", {}).get("User", "")
                    is_root = user in ["", "0", "root"]

                    containers.append({
                        "container_id": cid,
                        "image": c.get("Image", ""),
                        "names": c.get("Names", ""),
                        "ports": c.get("Ports", ""),
                        "status": c.get("Status", ""),
                        "is_privileged": is_privileged,
                        "runs_as_root": is_root,
                        "security_risks": [
                            "Container running with --privileged flag!" if is_privileged else None,
                            "Container executing as root user (UID 0)" if is_root else None
                        ]
                    })
                except Exception:
                    continue
            return containers
        except Exception as e:
            logger.error(f"[DockerAuditor] Error auditing containers: {e}")
            return []

    def inspect_container(self, container_id: str) -> Dict[str, Any]:
        try:
            res = subprocess.run([self.docker_path, "inspect", container_id], capture_output=True, text=True, timeout=5, check=False)
            if res.returncode == 0 and res.stdout.strip():
                parsed = json.loads(res.stdout)
                return parsed[0] if parsed else {}
            return {}
        except Exception:
            return {}
