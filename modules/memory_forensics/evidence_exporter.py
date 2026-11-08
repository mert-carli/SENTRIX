import json
import os
from typing import Dict, Any

class EvidenceExporter:
    """Exports structured memory forensics analysis records to JSON / Case reports."""

    @staticmethod
    def export_case_report(case_id: str, data: Dict[str, Any], output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({
                "case_id": case_id,
                "exported_by": "SENTRIX v4.0 Memory Forensics Lab",
                "analysis_data": data
            }, f, indent=2)
        return output_path
