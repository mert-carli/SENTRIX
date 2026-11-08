from typing import List, Dict, Any

class ThreatEntityGraph:
    """Builds graph relationships between Users, Processes, Files, Network Connections, and Domains."""

    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_node(self, node_id: str, label: str, node_type: str, metadata: Dict[str, Any] = None):
        if not any(n["id"] == node_id for n in self.nodes):
            self.nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {}
            })

    def add_edge(self, source_id: str, target_id: str, relation: str):
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "relation": relation
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges
        }
