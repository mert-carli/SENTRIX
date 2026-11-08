import subprocess
import shutil
import threading
from typing import Dict, List, Any, Callable, Optional
from core.logger import audit_logger

SUPPORTED_EXTERNAL_TOOLS = ["nmap", "tshark", "yara", "python", "powershell"]

class ToolOrchestrator:
    def __init__(self):
        pass

    def detect_available_tools(self) -> Dict[str, bool]:
        """Scans system PATH to discover installed CLI tools."""
        return {tool: bool(shutil.which(tool)) for tool in SUPPORTED_EXTERNAL_TOOLS}

    def execute_safe_command(self, cmd_args: List[str], cwd: Optional[str] = None, timeout: float = 30.0, output_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """
        Executes an external security tool safely with structured arguments.
        Prevents shell injection vulnerabilities by avoiding shell=True where possible.
        """
        audit_logger.log_action("CLI_COMMAND_EXECUTE", f"Args={' '.join(cmd_args)}")
        
        try:
            proc = subprocess.Popen(
                cmd_args,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            full_output = []
            for line in iter(proc.stdout.readline, ''):
                full_output.append(line)
                if output_callback:
                    output_callback(line)

            proc.wait(timeout=timeout)
            return {
                "exit_code": proc.returncode,
                "output": "".join(full_output),
                "success": (proc.returncode == 0)
            }
        except subprocess.TimeoutExpired:
            proc.kill()
            return {"exit_code": -1, "output": "[!] Command timed out.", "success": False}
        except Exception as e:
            return {"exit_code": -1, "output": f"[!] Execution failed: {e}", "success": False}

tool_orchestrator = ToolOrchestrator()
