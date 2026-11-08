from typing import Dict, Any
from modules.active_directory.ldap_collector import LDAPCollector
from modules.active_directory.identity_graph import IdentityGraph
from modules.active_directory.acl_analyzer import ACLAnalyzer
from modules.active_directory.risk_path_analyzer import RiskPathAnalyzer

class ADGraphExplorer:
    """Explores Active Directory relationship graphs and evaluates escalation vectors."""

    def __init__(self):
        self.collector = LDAPCollector()

    def build_exploration_graph(self) -> Dict[str, Any]:
        users = self.collector.collect_domain_users()
        groups = self.collector.collect_domain_groups()

        graph = IdentityGraph()

        # Add domain node
        graph.add_node("Domain", "Active Directory Domain", "DOMAIN")

        for u in users:
            uid = u.get("Name") or "User"
            graph.add_node(uid, uid, "USER", u.get("Domain", ""))

        for g in groups:
            gid = g.get("Name") or "Group"
            graph.add_node(gid, gid, "GROUP", g.get("Domain", ""))

        # Check Administrators
        for u in users:
            name = (u.get("Name") or "").lower()
            if name in ["administrator", "admin"]:
                graph.add_edge(u.get("Name"), "Administrators", "MemberOf", is_risky=True)

        paths = RiskPathAnalyzer.find_attack_paths(graph, "Administrators")

        return {
            "users_count": len(users),
            "groups_count": len(groups),
            "graph": graph.to_dict(),
            "critical_paths": paths
        }
