from typing import Dict, List, Any

MITRE_TECHNIQUES = [
    {
        "id": "T1059.001",
        "name": "PowerShell Execution",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "detection_source": "Event ID 4104 (Script Block Logging), Sysmon Event 1",
        "test_command": "powershell -NoProfile -Command Write-Output 'Sentrix_Safe_Simulation_T1059'"
    },
    {
        "id": "T1087.001",
        "name": "Local Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to find a list of local system accounts.",
        "detection_source": "Process creation auditing (net.exe user), Event ID 4688",
        "test_command": "net user"
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "detection_source": "Process creation (systeminfo.exe), WMI queries",
        "test_command": "systeminfo"
    },
    {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system.",
        "detection_source": "Process creation (netstat.exe), Sysmon Event 3",
        "test_command": "netstat -ano"
    },
    {
        "id": "T1562.001",
        "name": "Disable Windows Event Logging",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable Windows Event Logging to avoid detection.",
        "detection_source": "Event ID 1102 (The audit log was cleared)",
        "test_command": "# AUDIT ONLY: Wevtutil check"
    }
]

class RedTeamSimulator:
    def __init__(self):
        pass

    def get_techniques(self) -> List[Dict[str, Any]]:
        return MITRE_TECHNIQUES

    def generate_gap_report(self) -> Dict[str, Any]:
        """Generates a Purple Team Detection Gap analysis for the workstation."""
        import subprocess
        
        # Check if PowerShell script block logging is enabled
        ps_audit_enabled = False
        try:
            cmd = 'powershell "Get-ItemProperty HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableScriptBlockLogging"'
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=5).strip()
            ps_audit_enabled = (out == "1")
        except Exception:
            pass

        # Check Sysmon service presence
        sysmon_installed = False
        try:
            cmd_sys = 'powershell "Get-Service -Name Sysmon, Sysmon64 -ErrorAction SilentlyContinue"'
            out_sys = subprocess.check_output(cmd_sys, shell=True, text=True, timeout=5).strip()
            sysmon_installed = bool(out_sys)
        except Exception:
            pass

        gaps = []
        if not ps_audit_enabled:
            gaps.append({
                "technique": "T1059.001 - PowerShell Execution",
                "gap": "PowerShell Script Block Logging (Event 4104) is NOT enabled.",
                "recommendation": "Enable via Group Policy: Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging."
            })
        if not sysmon_installed:
            gaps.append({
                "technique": "T1049 / T1087 / T1082 - Discovery & Process Creation",
                "gap": "Sysmon driver is not installed on endpoint.",
                "recommendation": "Install Microsoft Sysmon with SwiftOnSecurity configuration for comprehensive endpoint telemetry."
            })

        return {
            "tested_techniques_count": len(MITRE_TECHNIQUES),
            "script_block_logging": ps_audit_enabled,
            "sysmon_installed": sysmon_installed,
            "detected_gaps": gaps
        }

red_team_simulator = RedTeamSimulator()
