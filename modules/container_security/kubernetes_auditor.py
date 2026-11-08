import subprocess
import shutil
import json
from typing import Dict, Any, List

class KubernetesAuditor:
    """Audits Kubernetes cluster context, namespaces, pods, and security standards."""

    def __init__(self):
        self.kubectl_path = shutil.which("kubectl")

    def check_kubectl_status(self) -> Dict[str, Any]:
        if not self.kubectl_path:
            return {"installed": False, "status": "NOT_INSTALLED", "message": "kubectl CLI not found in PATH."}
        try:
            res = subprocess.run([self.kubectl_path, "config", "current-context"], capture_output=True, text=True, timeout=5, check=False)
            if res.returncode == 0 and res.stdout.strip():
                return {
                    "installed": True,
                    "status": "CONNECTED",
                    "current_context": res.stdout.strip(),
                    "message": f"Connected to cluster context: {res.stdout.strip()}"
                }
            return {
                "installed": True,
                "status": "NO_CONTEXT",
                "message": "kubectl installed, but no active cluster context or cluster unreachable."
            }
        except Exception as e:
            return {"installed": False, "status": "ERROR", "message": str(e)}

    def audit_pods(self, namespace: str = "default") -> List[Dict[str, Any]]:
        status = self.check_kubectl_status()
        if status["status"] != "CONNECTED":
            return []

        try:
            cmd = [self.kubectl_path, "get", "pods", "-n", namespace, "-o", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            if res.returncode != 0:
                return []

            data = json.loads(res.stdout)
            pods = []
            for item in data.get("items", []):
                metadata = item.get("metadata", {})
                spec = item.get("spec", {})
                pod_name = metadata.get("name", "Unknown")

                # Check security context
                is_privileged = False
                for c in spec.get("containers", []):
                    sec_ctx = c.get("securityContext", {})
                    if sec_ctx.get("privileged", False):
                        is_privileged = True

                pods.append({
                    "name": pod_name,
                    "namespace": namespace,
                    "node": spec.get("nodeName", ""),
                    "is_privileged": is_privileged,
                    "service_account": spec.get("serviceAccountName", "default")
                })
            return pods
        except Exception:
            return []
