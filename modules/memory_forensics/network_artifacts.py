from typing import List, Dict, Any

class NetworkArtifactExtractor:
    """Extracts and models active and closed network connections recovered from memory dumps."""

    @staticmethod
    def parse_netscan_output(raw_text: str) -> List[Dict[str, Any]]:
        connections = []
        for line in raw_text.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Offset") or line_str.startswith("---"):
                continue
            parts = line_str.split()
            if len(parts) >= 6:
                proto = parts[0]
                local_addr = parts[1]
                foreign_addr = parts[2]
                state = parts[3]
                pid = parts[4] if parts[4].isdigit() else "0"
                owner = parts[5] if len(parts) > 5 else "Unknown"

                connections.append({
                    "protocol": proto,
                    "local_address": local_addr,
                    "foreign_address": foreign_addr,
                    "state": state,
                    "pid": int(pid),
                    "owner": owner
                })
        return connections
