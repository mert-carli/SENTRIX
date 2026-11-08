import json
import uuid
from datetime import datetime
from typing import List, Dict, Any

class SBOMEngine:
    """Generates Software Bill of Materials (SBOM) in CycloneDX and SPDX standard formats."""

    @staticmethod
    def generate_cyclonedx_json(components: List[Dict[str, str]], project_name: str = "SENTRIX") -> Dict[str, Any]:
        bom_components = []
        for c in components:
            bom_components.append({
                "type": "library",
                "name": c.get("name"),
                "version": c.get("version", "latest"),
                "purl": f"pkg:pypi/{c.get('name')}@{c.get('version', 'latest')}"
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": "4.0.0"
                }
            },
            "components": bom_components
        }
