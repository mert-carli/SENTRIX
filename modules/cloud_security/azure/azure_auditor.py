from typing import List, Dict, Any
from modules.cloud_security.common.finding import CloudFinding

class AzureSecurityAuditor:
    """Evaluates Microsoft Azure security configurations (Storage, NSG, Entra ID)."""

    def audit_nsg_rules(self, nsg_list: List[Dict[str, Any]]) -> List[CloudFinding]:
        findings = []
        for nsg in nsg_list:
            nsg_name = nsg.get("name", "Unknown-NSG")
            for rule in nsg.get("securityRules", []):
                access = rule.get("access", "").lower()
                direction = rule.get("direction", "").lower()
                prefix = rule.get("sourceAddressPrefix", "")
                dest_port = str(rule.get("destinationPortRange", ""))

                if access == "allow" and direction == "inbound" and prefix in ["*", "Internet"]:
                    if dest_port in ["22", "3389", "*"]:
                        findings.append(CloudFinding(
                            provider="AZURE",
                            account_id=nsg.get("subscriptionId", "Sub"),
                            resource_id=nsg_name,
                            resource_type="Microsoft.Network/networkSecurityGroups",
                            region=nsg.get("location", "westeurope"),
                            severity="CRITICAL",
                            title=f"Azure NSG allows inbound Internet access to port {dest_port}",
                            evidence=f"Rule '{rule.get('name')}' grants access from '{prefix}' to port '{dest_port}'",
                            remediation="Use Azure Bastion or VPN Gateway instead of opening management ports to Internet."
                        ))
        return findings
