import uuid
from typing import Dict, Any, List
from modules.threat_hunting.hypothesis_manager import HypothesisManager
from modules.threat_hunting.query_engine import ThreatQueryEngine
from modules.threat_hunting.timeline_builder import TimelineBuilder
from modules.threat_hunting.entity_graph import ThreatEntityGraph
from modules.threat_hunting.hunt_repository import HuntRepository

class ThreatHuntingEngine:
    """Orchestrates end-to-end threat hunting campaigns from hypothesis generation to evidence correlation."""

    def __init__(self):
        self.hypothesis_mgr = HypothesisManager()
        self.query_engine = ThreatQueryEngine()
        self.repository = HuntRepository()

    def start_hunt_campaign(self, hypothesis_id: str) -> Dict[str, Any]:
        hyp = self.hypothesis_mgr.get_hypothesis_by_id(hypothesis_id)
        if not hyp:
            return {"success": False, "error": "Hypothesis not found"}

        hunt_id = f"HUNT-{uuid.uuid4().hex[:6].upper()}"
        row_id = self.repository.create_hunt(hunt_id, hyp["title"], hyp["description"], hyp.get("technique", ""))

        # Execute initial queries
        findings = self.query_engine.execute_hunt_query({"is_suspicious": True})

        # Build timeline & entity graph
        timeline = TimelineBuilder.build_timeline(findings)
        graph = ThreatEntityGraph()

        for f in findings:
            pid = str(f.get("pid", "0"))
            pname = f.get("process_name", "Unknown")
            graph.add_node(f"proc_{pid}", f"{pname} ({pid})", "PROCESS")
            if f.get("ppid"):
                ppid = str(f["ppid"])
                graph.add_node(f"proc_{ppid}", f"Parent ({ppid})", "PROCESS")
                graph.add_edge(f"proc_{ppid}", f"proc_{pid}", "SPAWNED")

        return {
            "success": True,
            "hunt_id": hunt_id,
            "title": hyp["title"],
            "technique": hyp.get("technique"),
            "matches_count": len(findings),
            "findings": findings,
            "timeline": timeline,
            "graph": graph.to_dict()
        }
