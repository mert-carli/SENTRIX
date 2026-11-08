import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.correlation.sigma_engine import sigma_detection_engine
from modules.threat_intel.ti_center import threat_intel_center
from core.database import db

class DetectionIncidentView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "DETECTION ENGINEERING (SIGMA), THREAT INTEL & INCIDENT RESPONSE")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_sigma = self.tabview.add("Sigma Detection Rules")
        self.tab_ti = self.tabview.add("Threat Intel Fusion")
        self.tab_ir = self.tabview.add("Incident Response Workspace")

        self._build_sigma_tab()
        self._build_ti_tab()
        self._build_ir_tab()

    def _build_sigma_tab(self):
        tab = self.tab_sigma
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        create_button(ctrl, "[ VIEW SIGMA RULES ]", self.show_sigma_rules, is_accent=True).grid(row=0, column=0, padx=5)

        self.entry_sigma_test = ctk.CTkEntry(ctrl, placeholder_text="powershell.exe -enc SQBFAFgA...", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_sigma_test.insert(0, "powershell.exe -NoProfile -enc SQBFAFgA...")
        self.entry_sigma_test.grid(row=0, column=1, padx=5, sticky="ew")

        create_button(ctrl, "[ EVALUATE LOG EVENT ]", self.evaluate_sigma_event, is_danger=True).grid(row=0, column=2, padx=5)

        self.tb_sigma = create_textbox(tab)
        self.tb_sigma.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_sigma, "Sigma Rule Detection & Compilation Engine Ready.\n", "accent")

    def _build_ti_tab(self):
        tab = self.tab_ti
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="INDICATOR (IP / HASH / DOMAIN):", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_ioc = ctk.CTkEntry(ctrl, placeholder_text="185.220.101.5", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_ioc.insert(0, "185.220.101.5")
        self.entry_ioc.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ QUERY THREAT FEEDS ]", self.query_ti, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_ti = create_textbox(tab)
        self.tb_ti.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_ti, "Threat Intelligence Fusion Center Ready.\n", "accent")

    def _build_ir_tab(self):
        tab = self.tab_ir
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")

        create_button(ctrl, "[ CREATE NEW INCIDENT ]", self.create_new_incident, is_danger=True).pack(side="left", padx=5)
        create_button(ctrl, "[ REFRESH ACTIVE INCIDENTS ]", self.refresh_incidents).pack(side="left", padx=5)

        self.tb_ir = create_textbox(tab)
        self.tb_ir.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_ir, "Incident Response & Case Management Workspace Ready.\n", "accent")
        self.refresh_incidents()

    # --- Actions ---
    def show_sigma_rules(self):
        rules = sigma_detection_engine.get_all_rules()
        lines = [f"{'RULE ID':<16} {'LEVEL':<10} {'MITRE':<12} {'TITLE'}", "─"*75]
        for r in rules:
            lines.append(f"{r['id']:<16} {r['level']:<10} {r['mitre']:<12} {r['title']}")
        safe_textbox_write(self.tb_sigma, "\n".join(lines) + "\n", "normal", clear_first=True)

    def evaluate_sigma_event(self):
        raw = self.entry_sigma_test.get().strip()
        matched = sigma_detection_engine.evaluate_process_event(raw, "powershell.exe")
        if matched:
            lines = [f"[!] DETECTION ALERT: {len(matched)} Sigma Rule(s) Matched!\n", "─"*75]
            for m in matched:
                lines.append(f"[{m['level']}] {m['id']} - {m['title']}\n  ├── MITRE ATT&CK: {m['mitre']}\n  └── Description: {m['description']}\n")
            safe_textbox_write(self.tb_sigma, "\n".join(lines) + "\n", "danger", clear_first=True)
        else:
            safe_textbox_write(self.tb_sigma, "[✓] Event evaluated against active Sigma rules. No rule triggers observed.\n", "accent", clear_first=True)

    def query_ti(self):
        val = self.entry_ioc.get().strip()
        res = threat_intel_center.check_ioc(val)
        lines = [
            f"INDICATOR        : {res['indicator']}",
            f"MALICIOUS STATUS : {'MALICIOUS THREAT DETECTED' if res['is_malicious'] else 'CLEAN / UNLISTED'}",
            f"THREAT TYPE      : {res['threat_type']}",
            f"CONFIDENCE       : {res['confidence']}%",
            f"SOURCE           : {res['source']}"
        ]
        tag = "danger" if res['is_malicious'] else "accent"
        safe_textbox_write(self.tb_ti, "\n".join(lines) + "\n", tag, clear_first=True)

    def create_new_incident(self):
        inc_id = db.create_incident("Suspicious Lateral Movement & C2 Activity", severity="CRITICAL", summary="Automated alert triage triggered incident investigation.")
        safe_textbox_write(self.tb_ir, f"\n[+] Created Incident Record #{inc_id} in Database.\n", "accent")
        self.refresh_incidents()

    def refresh_incidents(self):
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT incident_number, title, severity, status, assigned_analyst FROM incidents ORDER BY id DESC LIMIT 20")
            rows = cursor.fetchall()

        lines = [f"{'INCIDENT #':<22} {'SEVERITY':<10} {'STATUS':<12} {'TITLE'}", "─"*80]
        for r in rows:
            lines.append(f"{r['incident_number']:<22} {r['severity']:<10} {r['status']:<12} {r['title']}")
        safe_textbox_write(self.tb_ir, "\n".join(lines) + "\n", "normal", clear_first=True)
