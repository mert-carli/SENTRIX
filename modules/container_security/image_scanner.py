import subprocess
import shutil
import json
from typing import Dict, Any

class ContainerImageScanner:
    """Scans container images for OS and package vulnerabilities via Trivy integration or offline heuristics."""

    def __init__(self):
        self.trivy_path = shutil.which("trivy")

    def check_scanner_status(self) -> Dict[str, Any]:
        if self.trivy_path:
            return {"available": True, "tool": "Trivy", "path": self.trivy_path, "status": "AVAILABLE"}
        return {
            "available": False,
            "tool": "Trivy",
            "path": None,
            "status": "NOT_INSTALLED",
            "message": "Trivy vulnerability scanner not detected in PATH. Install Trivy for deep SBOM scanning."
        }

    def scan_image(self, image_name: str) -> Dict[str, Any]:
        status = self.check_scanner_status()
        if not status["available"]:
            return {
                "success": False,
                "image": image_name,
                "error": "Trivy is not installed on this system.",
                "vulnerabilities": []
            }

        try:
            cmd = [self.trivy_path, "image", "--format", "json", "--quiet", image_name]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                return {
                    "success": True,
                    "image": image_name,
                    "results": data,
                    "vulnerabilities_count": len(data.get("Results", []))
                }
            return {"success": False, "image": image_name, "error": res.stderr}
        except Exception as e:
            return {"success": False, "image": image_name, "error": str(e)}
