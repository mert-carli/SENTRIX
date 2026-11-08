import re
import os
import subprocess
from typing import List, Dict, Any

class DependencyScanner:
    """Scans and inventories Python and npm project dependencies."""

    @staticmethod
    def parse_requirements_txt(file_path: str) -> List[Dict[str, str]]:
        if not os.path.isfile(file_path):
            return []

        packages = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([>=<~!]+)?\s*([0-9A-Za-z_\.\-]+)?', line_str)
                if match:
                    pkg_name = match.group(1)
                    version = match.group(3) or "latest"
                    packages.append({
                        "name": pkg_name,
                        "version": version,
                        "package_type": "PyPI"
                    })
        return packages
