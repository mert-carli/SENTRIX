from dataclasses import dataclass, asdict
from typing import Dict, Any
from datetime import datetime

@dataclass
class CloudFinding:
    provider: str  # AWS, AZURE, GCP
    account_id: str
    resource_id: str
    resource_type: str
    region: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    evidence: str
    remediation: str
    timestamp: str = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
