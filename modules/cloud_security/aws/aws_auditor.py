from typing import List, Dict, Any
from modules.cloud_security.common.finding import CloudFinding

class AWSSecurityAuditor:
    """Evaluates AWS configuration baselines (S3, Security Groups, IAM, CloudTrail)."""

    def audit_security_group_rules(self, security_groups: List[Dict[str, Any]]) -> List[CloudFinding]:
        findings = []
        for sg in security_groups:
            sg_id = sg.get("GroupId", "Unknown")
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                ip_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]

                if "0.0.0.0/0" in ip_ranges and from_port in [22, 3389, 445]:
                    findings.append(CloudFinding(
                        provider="AWS",
                        account_id=sg.get("OwnerId", "Self"),
                        resource_id=sg_id,
                        resource_type="AWS::EC2::SecurityGroup",
                        region=sg.get("Region", "us-east-1"),
                        severity="CRITICAL",
                        title=f"Security Group exposes administrative port {from_port} to 0.0.0.0/0",
                        evidence=f"Ingress rule allows 0.0.0.0/0 to port range {from_port}-{to_port}",
                        remediation=f"Restrict port {from_port} access to authorized corporate IP ranges or VPN endpoints."
                    ))
        return findings

    def audit_s3_bucket(self, bucket_name: str, is_public: bool, encryption_enabled: bool) -> List[CloudFinding]:
        findings = []
        if is_public:
            findings.append(CloudFinding(
                provider="AWS",
                account_id="Self",
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                region="global",
                severity="CRITICAL",
                title=f"S3 Bucket '{bucket_name}' has Public Access enabled",
                evidence="Bucket policy or ACL permits public read/list access.",
                remediation="Enable S3 Block Public Access at the account and bucket levels."
            ))
        if not encryption_enabled:
            findings.append(CloudFinding(
                provider="AWS",
                account_id="Self",
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                region="global",
                severity="HIGH",
                title=f"S3 Bucket '{bucket_name}' missing Default Server-Side Encryption",
                evidence="ServerSideEncryptionConfiguration is not enforced.",
                remediation="Configure default AES-256 or KMS encryption for the bucket."
            ))
        return findings
