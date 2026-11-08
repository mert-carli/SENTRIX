import subprocess
import os
import json
from typing import Dict, List, Any

class ActiveDirectoryAnalyzer:
    def __init__(self):
        pass

    def check_domain_membership(self) -> Dict[str, Any]:
        """Checks whether the current system is joined to an Active Directory Domain."""
        info = {
            "is_domain_joined": False,
            "domain_name": "WORKGROUP",
            "computer_name": os.environ.get("COMPUTERNAME", "UNKNOWN"),
            "logon_server": os.environ.get("LOGONSERVER", "UNKNOWN"),
            "user_domain": os.environ.get("USERDOMAIN", "UNKNOWN")
        }
        try:
            cmd = 'powershell "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"'
            res = subprocess.check_output(cmd, shell=True, text=True, timeout=5).strip()
            info["is_domain_joined"] = (res.lower() == "true")
            if info["is_domain_joined"]:
                cmd_dom = 'powershell "(Get-CimInstance Win32_ComputerSystem).Domain"'
                info["domain_name"] = subprocess.check_output(cmd_dom, shell=True, text=True, timeout=5).strip()
        except Exception:
            pass
        return info

    def get_password_policy(self) -> Dict[str, Any]:
        """Audits local / domain password policy via net accounts."""
        policy = {}
        try:
            output = subprocess.check_output('net accounts', shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
            for line in output.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    policy[parts[0].strip()] = parts[1].strip()
        except Exception as e:
            policy["error"] = str(e)
        return policy

    def get_privileged_groups(self) -> Dict[str, List[str]]:
        """Audits membership of Administrators and Remote Desktop Users groups."""
        groups = {"Administrators": [], "Remote Desktop Users": []}
        try:
            out_admin = subprocess.check_output('net localgroup administrators', shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
            start = False
            for line in out_admin.splitlines():
                if "---" in line:
                    start = True
                    continue
                if start:
                    if "The command completed" in line or "Komut başarıyla" in line:
                        break
                    val = line.strip()
                    if val: groups["Administrators"].append(val)
        except Exception:
            pass
        return groups

    def run_ad_audit(self) -> Dict[str, Any]:
        """Runs a complete read-only AD & Identity assessment."""
        dom_info = self.check_domain_membership()
        pwd_policy = self.get_password_policy()
        priv_groups = self.get_privileged_groups()

        findings = []

        # Evaluate Password Policy
        min_len = 0
        for k, v in pwd_policy.items():
            if "Minimum password length" in k or "En az parola uzunluğu" in k:
                try: min_len = int(v.split()[0])
                except: pass

        if min_len < 12:
            findings.append({
                "severity": "HIGH",
                "title": "Weak Minimum Password Length Policy",
                "description": f"Minimum password length is set to {min_len} characters. Industry baseline requires at least 14 characters.",
                "mitre": "T1201 - Password Policy Discovery",
                "remediation": "Enforce minimum password length >= 14 via Group Policy (GPO)."
            })

        # Evaluate Admin Accounts count
        admin_count = len(priv_groups.get("Administrators", []))
        if admin_count > 3:
            findings.append({
                "severity": "MEDIUM",
                "title": "Excessive Local Administrators",
                "description": f"Found {admin_count} members in local Administrators group. Increases attack surface for lateral movement.",
                "mitre": "T1078 - Valid Accounts",
                "remediation": "Enforce Least Privilege. Utilize LAPS (Local Administrator Password Solution)."
            })

        return {
            "domain_info": dom_info,
            "password_policy": pwd_policy,
            "privileged_groups": priv_groups,
            "findings": findings
        }

active_directory_analyzer = ActiveDirectoryAnalyzer()
