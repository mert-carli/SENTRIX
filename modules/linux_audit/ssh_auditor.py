from typing import Dict, List, Any

# Standard Linux Security Checklist
LINUX_AUDIT_COMMANDS = {
    "os_version": "cat /etc/os-release | grep PRETTY_NAME",
    "kernel": "uname -r",
    "open_ports": "ss -tuln",
    "sudo_rules": "sudo -l -n 2>&1",
    "suid_binaries": "find / -perm -4000 -type f 2>/dev/null | head -n 30",
    "cron_jobs": "ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null",
    "ssh_config": "cat /etc/ssh/sshd_config | grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)'"
}

class LinuxSSHAuditor:
    def __init__(self):
        pass

    def evaluate_audit_results(self, raw_outputs: Dict[str, str]) -> List[Dict[str, Any]]:
        """Evaluates raw audit command outputs against security baselines."""
        findings = []
        
        # Check PermitRootLogin
        ssh_cfg = raw_outputs.get("ssh_config", "")
        if "PermitRootLogin yes" in ssh_cfg:
            findings.append({
                "severity": "HIGH",
                "title": "SSH Direct Root Login Enabled",
                "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd."
            })

        # Check PasswordAuthentication
        if "PasswordAuthentication yes" in ssh_cfg:
            findings.append({
                "severity": "MEDIUM",
                "title": "SSH Password Authentication Allowed",
                "recommendation": "Enforce SSH public key authentication and disable PasswordAuthentication."
            })

        return findings

linux_ssh_auditor = LinuxSSHAuditor()
