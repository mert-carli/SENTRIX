from typing import Dict, Any, List, Optional
from modules.investigation_graph.entity_models import GraphNode, GraphEdge

class CentralInvestigationGraph:
    """Unified cross-module entity relationship graph for comprehensive investigations."""

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []

    def add_node(self, node_id: str, label: str, node_type: str, properties: Dict[str, Any] = None) -> GraphNode:
        if node_id not in self._nodes:
            node = GraphNode(id=node_id, label=label, node_type=node_type, properties=properties or {})
            self._nodes[node_id] = node
        return self._nodes[node_id]

    def add_edge(self, source_id: str, target_id: str, relationship: str, is_threat: bool = False, metadata: Dict[str, Any] = None):
        edge = GraphEdge(source_id=source_id, target_id=target_id, relationship=relationship, is_threat=is_threat, metadata=metadata or {})
        self._edges.append(edge)

    def find_connected_entities(self, entity_id: str) -> List[Dict[str, Any]]:
        connected = []
        for e in self._edges:
            if e.source_id == entity_id:
                target_node = self._nodes.get(e.target_id)
                connected.append({
                    "direction": "OUTBOUND",
                    "relationship": e.relationship,
                    "target": target_node.label if target_node else e.target_id,
                    "is_threat": e.is_threat
                })
            elif e.target_id == entity_id:
                source_node = self._nodes.get(e.source_id)
                connected.append({
                    "direction": "INBOUND",
                    "relationship": e.relationship,
                    "source": source_node.label if source_node else e.source_id,
                    "is_threat": e.is_threat
                })
        return connected

    def export_graph_json(self) -> Dict[str, Any]:
        return {
            "nodes_count": len(self._nodes),
            "edges_count": len(self._edges),
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.node_type, "properties": n.properties}
                for n in self._nodes.values()
            ],
            "edges": [
                {"source": e.source_id, "target": e.target_id, "relationship": e.relationship, "is_threat": e.is_threat}
                for e in self._edges
            ]
        }
