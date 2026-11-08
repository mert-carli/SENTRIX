import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.soar.playbook_engine import SOARPlaybookEngine

class SOARPlaybookView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.engine = SOARPlaybookEngine()
        self._init_ui()

    def _init_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="SOAR & INCIDENT PLAYBOOK ENGINE", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Automated Incident Escalation & Approved Containment", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        bar = ctk.CTkFrame(self, fg_color=COLOR_BG_SECONDARY, border_width=1, border_color=COLOR_BORDER)
        bar.pack(fill="x", padx=20, pady=(0, 10))

        btn_run = ctk.CTkButton(
            bar, text="Trigger Sample Incident Playbook", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=240,
            command=self._execute_sample_playbook
        )
        btn_run.pack(side="left", padx=15, pady=10)

        btn_appr = ctk.CTkButton(
            bar, text="View Pending Approvals", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, width=190,
            command=self._check_approvals
        )
        btn_appr.pack(side="left", pady=10)

        self.txt_output = ctk.CTkTextbox(self, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_output.pack(fill="both", expand=True, padx=20, pady=(0, 15))

    def _execute_sample_playbook(self):
        self.txt_output.delete("1.0", "end")
        self.txt_output.insert("end", "[*] Executing Playbook: 'Compromised Host Containment'...\n")

        playbook = {
            "name": "Compromised Host Containment",
            "steps": [
                {"action": "ENRICH_IOC", "description": "Query IOC Threat Intel"},
                {"action": "CREATE_INCIDENT", "description": "Escalate to Incident Record"},
                {"action": "FIREWALL_BLOCK", "description": "Block Attacker C2 IP via Host Firewall"}
            ]
        }
        ctx = {"target": "198.51.100.25", "indicator": "198.51.100.25", "ip": "198.51.100.25"}
        res = self.engine.execute_playbook(playbook, ctx)

        self.txt_output.insert("end", f"[+] Execution Completed. Run ID: {res['run_id']}\n")
        self.txt_output.insert("end", f"    Playbook: {res['playbook_name']}\n")
        self.txt_output.insert("end", f"    Overall Status: {res['status']}\n")
        self.txt_output.insert("end", f"    Duration: {res['duration_ms']} ms\n\n")
        self.txt_output.insert("end", "[*] Executed Steps Breakdown:\n")
        for s in res["steps"]:
            self.txt_output.insert("end", f" - Step {s['step']}: {s['action']} -> Status: {s['status']}\n")
            if s.get("request_id"):
                self.txt_output.insert("end", f"   [!] Safety Rail Triggered: Requires Human Operator Approval (Request: {s['request_id']})\n")

    def _check_approvals(self):
        self.txt_output.delete("1.0", "end")
        pending = self.engine.approvals.get_pending()
        self.txt_output.insert("end", f"[+] Operator Approval Queue ({len(pending)} pending):\n\n")
        if not pending:
            self.txt_output.insert("end", "No pending intrusive actions awaiting authorization.\n")
            return
        for p in pending:
            self.txt_output.insert("end", f"Request ID:    {p['request_id']}\n")
            self.txt_output.insert("end", f"Action Type:   {p['action_type']}\n")
            self.txt_output.insert("end", f"Target:        {p['target']}\n")
            self.txt_output.insert("end", f"Justification: {p['justification']}\n")
            self.txt_output.insert("end", "-" * 60 + "\n")
