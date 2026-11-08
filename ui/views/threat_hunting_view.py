import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.threat_hunting.hunt_engine import ThreatHuntingEngine
from modules.threat_hunting.hypothesis_manager import HypothesisManager

class ThreatHuntingWorkspaceView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.hunt_engine = ThreatHuntingEngine()
        self.hypothesis_mgr = HypothesisManager()
        self._init_ui()

    def _init_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="ADVANCED THREAT HUNTING WORKSPACE", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Hypothesis-Driven Behavioral Hunting & Entity Correlation", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        # Action Bar
        bar = ctk.CTkFrame(self, fg_color=COLOR_BG_SECONDARY, border_width=1, border_color=COLOR_BORDER)
        bar.pack(fill="x", padx=20, pady=(0, 10))

        lbl_hyp = ctk.CTkLabel(bar, text="Select Hypothesis:", font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY)
        lbl_hyp.pack(side="left", padx=(15, 5), pady=10)

        hypotheses = self.hypothesis_mgr.get_all_hypotheses()
        self.hyp_map = {h["title"]: h["id"] for h in hypotheses}

        self.combo_hyp = ctk.CTkComboBox(
            bar, values=list(self.hyp_map.keys()),
            width=380, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, font=FONT_CODE
        )
        self.combo_hyp.pack(side="left", padx=(0, 15), pady=10)

        btn_run = ctk.CTkButton(
            bar, text="Execute Threat Hunt", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=170,
            command=self._execute_hunt_threaded
        )
        btn_run.pack(side="left", pady=10)

        # Output Textbox
        self.txt_output = ctk.CTkTextbox(self, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_output.pack(fill="both", expand=True, padx=20, pady=(0, 15))

    def _execute_hunt_threaded(self):
        title = self.combo_hyp.get()
        hyp_id = self.hyp_map.get(title)
        if not hyp_id:
            return

        self.txt_output.delete("1.0", "end")
        self.txt_output.insert("end", f"[*] Initializing Hunt Campaign for: {title}...\n")

        def run():
            res = self.hunt_engine.start_hunt_campaign(hyp_id)
            self.after(0, lambda: self._render_results(res))
        threading.Thread(target=run, daemon=True).start()

    def _render_results(self, res):
        self.txt_output.delete("1.0", "end")
        if not res.get("success"):
            self.txt_output.insert("end", f"[-] Hunt execution failed: {res.get('error')}\n")
            return

        self.txt_output.insert("end", f"[+] HUNT CAMPAIGN REGISTERED: {res['hunt_id']}\n")
        self.txt_output.insert("end", f"    Title:     {res['title']}\n")
        self.txt_output.insert("end", f"    Technique: {res['technique']}\n")
        self.txt_output.insert("end", f"    Findings:  {res['matches_count']} matching suspicious events\n")
        self.txt_output.insert("end", "=" * 70 + "\n\n")

        self.txt_output.insert("end", "[*] INVESTIGATION TIMELINE:\n")
        for t in res.get("timeline", []):
            self.txt_output.insert("end", f" - [{t['timestamp']}] [{t['severity']}] {t['title']} ({t['source']})\n")

        self.txt_output.insert("end", "\n[*] CORRELATED ENTITY GRAPH NODES:\n")
        graph = res.get("graph", {})
        for n in graph.get("nodes", []):
            self.txt_output.insert("end", f" [NODE] Type: {n['type']:<12} | {n['label']}\n")
        for e in graph.get("edges", []):
            self.txt_output.insert("end", f"   [RELATION] {e['source']} --({e['relation']})--> {e['target']}\n")
