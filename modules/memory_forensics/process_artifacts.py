from typing import List, Dict, Any

class ProcessArtifactExtractor:
    """Parses and models process artifacts extracted from memory dumps."""

    @staticmethod
    def parse_pslist_output(raw_text: str) -> List[Dict[str, Any]]:
        processes = []
        lines = raw_text.splitlines()
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("PID") or line_str.startswith("---"):
                continue
            parts = line_str.split()
            if len(parts) >= 3 and parts[0].isdigit():
                try:
                    pid = int(parts[0])
                    ppid = int(parts[1]) if parts[1].isdigit() else 0
                    name = parts[2]
                    processes.append({
                        "pid": pid,
                        "ppid": ppid,
                        "image_filename": name,
                        "raw_line": line_str
                    })
                except Exception:
                    continue
        return processes

    @staticmethod
    def build_process_tree(processes: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
        tree = {}
        for p in processes:
            pid = p["pid"]
            tree[pid] = {**p, "children": []}

        for pid, p in list(tree.items()):
            ppid = p.get("ppid", 0)
            if ppid in tree and ppid != pid:
                tree[ppid]["children"].append(p)

        return tree
