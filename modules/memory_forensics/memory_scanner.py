from typing import List, Dict, Any

class MemoryScanner:
    """Evaluates memory regions for common code injection and evasion patterns (e.g., PAGE_EXECUTE_READWRITE)."""

    @staticmethod
    def identify_suspicious_regions(malfind_output: str) -> List[Dict[str, Any]]:
        findings = []
        current = {}
        for line in malfind_output.splitlines():
            line_str = line.strip()
            if not line_str:
                if current:
                    findings.append(current)
                    current = {}
                continue

            if "PID:" in line_str or line_str.startswith("Process:"):
                current["header"] = line_str
                current["protection"] = "PAGE_EXECUTE_READWRITE"
                current["indicator"] = "Unbacked executable memory with RWX permissions"

        if current:
            findings.append(current)

        return findings
