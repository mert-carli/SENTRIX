from typing import List, Dict, Any
from modules.cloud_security.common.finding import CloudFinding

class GCPSecurityAuditor:
    """Evaluates Google Cloud Platform configurations (Cloud Storage, Firewall Rules, IAM)."""

    def audit_firewall_rules(self, firewalls: List[Dict[str, Any]]) -> List[CloudFinding]:
        findings = []
        for fw in firewalls:
            name = fw.get("name", "Unknown-FW")
            source_ranges = fw.get("sourceRanges", [])
            allowed = fw.get("allowed", [])

            if "0.0.0.0/0" in source_ranges:
                for a in allowed:
                    ports = a.get("ports", [])
                    if any(p in ["22", "3389"] for p in ports) or not ports:
                        findings.append(CloudFinding(
                            provider="GCP",
                            account_id=fw.get("project", "GCP-Project"),
                            resource_id=name,
                            resource_type="compute.firewalls",
                            region="global",
                            severity="CRITICAL",
                            title=f"GCP Firewall rule '{name}' exposes management ports to 0.0.0.0/0",
                            evidence=f"Protocols/Ports: {allowed} open to 0.0.0.0/0",
                            remediation="Restrict firewall rules using Identity-Aware Proxy (IAP) or internal VPC ranges."
                        ))
        return findings
