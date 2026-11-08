from typing import List, Dict, Any

class ACLAnalyzer:
    """Analyzes dangerous Access Control List (ACL) relationships (GenericAll, WriteDacl, ResetPassword)."""

    DANGEROUS_PERMISSIONS = [
        "GenericAll", "WriteDacl", "WriteOwner", "ForceChangePassword", "AllExtendedRights"
    ]

    @classmethod
    def evaluate_relationship(cls, principal: str, target: str, permission: str) -> Dict[str, Any]:
        is_critical = permission in cls.DANGEROUS_PERMISSIONS
        risk_score = 90 if is_critical else 30
        return {
            "principal": principal,
            "target": target,
            "permission": permission,
            "is_dangerous": is_critical,
            "risk_score": risk_score,
            "remediation": f"Remove {permission} granted to {principal} on {target} unless strictly required."
        }
