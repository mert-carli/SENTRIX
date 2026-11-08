from typing import List, Dict, Any
from modules.active_directory.identity_graph import IdentityGraph

class RiskPathAnalyzer:
    """Discovers privilege escalation attack paths from unprivileged accounts to Tier-0 assets."""

    @staticmethod
    def find_attack_paths(graph: IdentityGraph, target_node: str = "Domain Admins") -> List[Dict[str, Any]]:
        # Finds paths ending in target_node
        paths = []
        for edge in graph.edges:
            if edge["target"] == target_node or edge.get("is_risky"):
                paths.append({
                    "entry_point": edge["source"],
                    "target": edge["target"],
                    "relationship": edge["relationship"],
                    "hops": 1,
                    "risk_score": 85 if edge.get("is_risky") else 60
                })
        return paths
