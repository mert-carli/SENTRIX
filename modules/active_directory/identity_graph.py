from typing import List, Dict, Any

class IdentityGraph:
    """Models Active Directory graph structures (Nodes: Users/Groups/Computers; Edges: MemberOf/AdminRights)."""

    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_node(self, node_id: str, label: str, node_type: str, domain: str = ""):
        if not any(n["id"] == node_id for n in self.nodes):
            self.nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "domain": domain
            })

    def add_edge(self, source_id: str, target_id: str, relationship: str, is_risky: bool = False):
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "is_risky": is_risky
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges
        }
