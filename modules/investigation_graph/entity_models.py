from dataclasses import dataclass, field
from typing import Dict, Any, List

@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # HOST, USER, PROCESS, FILE, IP, DOMAIN, SERVICE, CVE, ALERT, INCIDENT, EVIDENCE
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str  # SPAWNED, CONNECTED_TO, RESOLVES_TO, COMMUNICATES_WITH, VULNERABLE_TO, CONTAINS, TRIGGERED
    is_threat: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
