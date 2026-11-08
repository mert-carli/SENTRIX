from typing import List, Dict, Any

class KubernetesRBACAnalyzer:
    """Evaluates Kubernetes Role and ClusterRole definitions for dangerous privilege escalation permissions."""

    RISKY_VERBS = ["*", "create", "update", "patch", "escalate", "bind", "impersonate"]
    RISKY_RESOURCES = ["*", "secrets", "pods/exec", "clusterroles", "rolebindings"]

    @classmethod
    def analyze_role_rules(cls, role_name: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for r in rules:
            verbs = r.get("verbs", [])
            resources = r.get("resources", [])

            # Check wildcard permissions
            if "*" in verbs and "*" in resources:
                findings.append({
                    "role_name": role_name,
                    "severity": "CRITICAL",
                    "issue": "Full cluster-admin equivalent wildcard (*:*) permission granted.",
                    "remediation": "Restrict verbs and resource scopes according to least privilege."
                })
            elif "secrets" in resources and any(v in verbs for v in ["get", "list", "*"]):
                findings.append({
                    "role_name": role_name,
                    "severity": "HIGH",
                    "issue": "Secret retrieval permission detected.",
                    "remediation": "Audit if this service account strictly requires raw secret access."
                })
            elif "pods/exec" in resources:
                findings.append({
                    "role_name": role_name,
                    "severity": "HIGH",
                    "issue": "Pod execution (pods/exec) permission allows arbitrary command execution in pods.",
                    "remediation": "Restrict pods/exec to dedicated emergency admin roles."
                })
        return findings
