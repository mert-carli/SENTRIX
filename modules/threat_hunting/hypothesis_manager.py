from typing import List, Dict, Any

class HypothesisManager:
    """Manages pre-defined and custom threat hunting hypotheses mapped to MITRE ATT&CK."""

    DEFAULT_HYPOTHESES = [
        {
            "id": "HUNT-HYP-01",
            "title": "Abnormal Office Child Process (LOLBin Execution)",
            "technique": "T1059.001",
            "description": "Adversary leverages Word or Excel macros to spawn PowerShell, cmd, or mshta.",
            "query_type": "PROCESS",
            "condition": "parent_process_name IN ('winword.exe', 'excel.exe', 'powerpnt.exe') AND process_name IN ('powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe')"
        },
        {
            "id": "HUNT-HYP-02",
            "title": "Living-off-the-land Binary (Certutil Download)",
            "technique": "T1105",
            "description": "Certutil utility executed with -urlcache or -split to stage remote payloads.",
            "query_type": "PROCESS",
            "condition": "process_name = 'certutil.exe' AND command_line LIKE '%-urlcache%'"
        },
        {
            "id": "HUNT-HYP-03",
            "title": "Brute Force Followed by Logon Success",
            "technique": "T1110.001",
            "description": "Multiple logon failures (4625) followed by successful logon (4624) within short window.",
            "query_type": "EVENTLOG",
            "condition": "event_id IN ('4624', '4625')"
        },
        {
            "id": "HUNT-HYP-04",
            "title": "Unquoted Service Path Persistence",
            "technique": "T1543.003",
            "description": "Windows Service installed with spaces in path lacking quotation marks.",
            "query_type": "SERVICE",
            "condition": "unquoted_path_vulnerability = 1"
        }
    ]

    def get_all_hypotheses(self) -> List[Dict[str, Any]]:
        return list(self.DEFAULT_HYPOTHESES)

    def get_hypothesis_by_id(self, hyp_id: str) -> Dict[str, Any]:
        for h in self.DEFAULT_HYPOTHESES:
            if h["id"] == hyp_id:
                return h
        return {}
