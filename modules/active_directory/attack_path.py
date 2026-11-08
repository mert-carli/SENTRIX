from typing import Dict, List, Any

class AttackPathGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_node(self, node_id: str, label: str, node_type: str):
        self.nodes.append({"id": node_id, "label": label, "type": node_type})

    def add_edge(self, source: str, target: str, relationship: str, risk: str = "HIGH"):
        self.edges.append({"source": source, "target": target, "relation": relationship, "risk": risk})

class ActiveDirectoryAttackPathAnalyzer:
    def __init__(self):
        pass

    def build_sample_attack_paths(self, domain_name: str, privileged_members: List[str]) -> Dict[str, Any]:
        """
        Constructs an Active Directory Identity and Privilege graph based on audited group memberships.
        Identifies transitive privilege escalation paths to Domain Admins / Enterprise Admins.
        """
        graph = AttackPathGraph()

        # Add Core Target Assets
        graph.add_node("DC01", f"DC01.{domain_name} (Domain Controller)", "COMPUTER")
        graph.add_node("GRP_DA", "Domain Admins", "SECURITY_GROUP")
        graph.add_node("GRP_EA", "Enterprise Admins", "SECURITY_GROUP")

        graph.add_edge("GRP_DA", "DC01", "AdministerComputer", risk="CRITICAL")
        graph.add_edge("GRP_EA", "GRP_DA", "MemberOf", risk="CRITICAL")

        # Map Audited Members
        paths = []
        for member in privileged_members:
            node_id = f"USR_{member.replace(' ', '_')}"
            graph.add_node(node_id, member, "USER")
            graph.add_edge(node_id, "GRP_DA", "DirectMember", risk="HIGH")

            paths.append({
                "starting_principal": member,
                "target_asset": "DC01 (Domain Controller)",
                "chain": f"{member} ──(DirectMember)──> Domain Admins ──(AdministerComputer)──> DC01",
                "risk_level": "CRITICAL",
                "mitre": "T1078 - Valid Accounts",
                "remediation": "Audit account necessity. Enforce FIDO2 MFA and Privileged Access Workstation (PAW)."
            })

        # Calculate Identity Security Score (100 base)
        identity_score = 100
        if len(privileged_members) > 2:
            identity_score -= (len(privileged_members) - 2) * 10
        identity_score = max(20, min(100, identity_score))

        return {
            "domain": domain_name,
            "identity_security_score": identity_score,
            "attack_paths": paths,
            "graph_summary": {
                "nodes_count": len(graph.nodes),
                "edges_count": len(graph.edges)
            }
        }

ad_attack_path_analyzer = ActiveDirectoryAttackPathAnalyzer()
ADAttackPathVisualizer = ActiveDirectoryAttackPathAnalyzer
