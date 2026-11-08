import hashlib
import os
from typing import Dict, Any, List
from modules.reverse_eng.pe_parser import pe_parser_engine

class BinaryComparisonEngine:
    def __init__(self):
        pass

    def compare_binaries(self, path_a: str, path_b: str) -> Dict[str, Any]:
        """Performs a structured static differential analysis between two PE executable files."""
        if not os.path.exists(path_a) or not os.path.exists(path_b):
            raise FileNotFoundError("One or both target files do not exist.")

        pe_a = pe_parser_engine.parse_pe(path_a)
        pe_b = pe_parser_engine.parse_pe(path_b)

        # Hash comparison
        def get_hashes(p):
            with open(p, "rb") as f:
                d = f.read()
            return {
                "size": len(d),
                "md5": hashlib.md5(d).hexdigest(),
                "sha256": hashlib.sha256(d).hexdigest()
            }

        h_a = get_hashes(path_a)
        h_b = get_hashes(path_b)

        # Sections diff
        sec_names_a = [s["name"] for s in pe_a.get("sections", [])]
        sec_names_b = [s["name"] for s in pe_b.get("sections", [])]

        added_sections = [s for s in sec_names_b if s not in sec_names_a]
        removed_sections = [s for s in sec_names_a if s not in sec_names_b]

        # Suspicious API diff
        apis_a = set(a["api"] for a in pe_a.get("suspicious_apis", []))
        apis_b = set(a["api"] for a in pe_b.get("suspicious_apis", []))

        new_suspicious_apis = list(apis_b - apis_a)
        removed_suspicious_apis = list(apis_a - apis_b)

        return {
            "file_a": {"name": os.path.basename(path_a), **h_a, "arch": pe_a.get("architecture")},
            "file_b": {"name": os.path.basename(path_b), **h_b, "arch": pe_b.get("architecture")},
            "hashes_match": (h_a["sha256"] == h_b["sha256"]),
            "sections_diff": {
                "added_in_b": added_sections,
                "removed_in_b": removed_sections
            },
            "api_diff": {
                "new_suspicious_in_b": new_suspicious_apis,
                "removed_in_b": removed_suspicious_apis
            },
            "similarity_verdict": "IDENTICAL" if h_a["sha256"] == h_b["sha256"] else (
                "VARIANT / SIMILAR" if sec_names_a == sec_names_b and pe_a.get("architecture") == pe_b.get("architecture") else "DIFFERENT BINARY"
            )
        }

binary_diff_engine = BinaryComparisonEngine()
