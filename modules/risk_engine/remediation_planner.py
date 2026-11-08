from typing import List, Dict, Any
from datetime import datetime, timedelta

class RemediationPlanner:
    """Generates structured remediation action plans with finding owners, SLA deadlines, and verification targets."""

    @staticmethod
    def generate_remediation_plan(critical_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        plan = []
        now = datetime.utcnow()

        for idx, finding in enumerate(critical_findings):
            rating = finding.get("rating", "MEDIUM")
            if rating == "CRITICAL":
                sla_days = 3
                priority = "P1 - Immediate"
            elif rating == "HIGH":
                sla_days = 14
                priority = "P2 - High"
            else:
                sla_days = 30
                priority = "P3 - Standard"

            due_date = (now + timedelta(days=sla_days)).strftime("%Y-%m-%d")

            plan.append({
                "plan_id": f"REM-{idx+1:03d}",
                "target": finding.get("ip") or finding.get("resource_id", "Asset"),
                "priority": priority,
                "due_date": due_date,
                "action": f"Apply security hardening or patches to mitigate {finding.get('rating')} vulnerability.",
                "status": "OPEN",
                "assigned_team": "SecOps Infrastructure"
            })
        return plan
