import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.deception_lab.honeypot import HoneypotService
from modules.mobile_security.manifest_parser import AndroidManifestAuditor
from modules.firmware_security.firmware_analyzer import FirmwareAnalyzer
from modules.risk_engine.scoring_engine import ExplainableRiskScorer
from modules.risk_engine.remediation_planner import RemediationPlanner

class SpecializedLabsView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.honeypot = HoneypotService(service_type="HTTP", host="127.0.0.1", port=8089)
        self._init_ui()

    def _init_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="SPECIALIZED LABS & ATTACK SURFACE RISK", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Deception Lab, Mobile & Firmware Security, Risk Scoring", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        self.tabview = ctk.CTkTabview(
            self, fg_color=COLOR_BG_SECONDARY,
            segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_HOVER,
            segmented_button_selected_hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        self.tab_deception = self.tabview.add("Honeypot & Deception Lab")
        self.tab_mobile = self.tabview.add("Mobile Security (MASVS)")
        self.tab_firmware = self.tabview.add("Firmware & IoT Security")
        self.tab_risk = self.tabview.add("Attack Surface Risk Engine")

        self._setup_deception_tab()
        self._setup_mobile_tab()
        self._setup_firmware_tab()
        self._setup_risk_tab()

    def _setup_deception_tab(self):
        bar = ctk.CTkFrame(self.tab_deception, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        self.btn_hp = ctk.CTkButton(
            bar, text="Start Isolated Decoy (Port 8089)", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=220,
            command=self._toggle_honeypot
        )
        self.btn_hp.pack(side="left", padx=(0, 10))

        self.txt_deception = ctk.CTkTextbox(self.tab_deception, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_deception.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.txt_deception.insert("end", "[*] Honeypot service is idle. Click Start Isolated Decoy to begin capturing connection attempts.\n")

    def _setup_mobile_tab(self):
        bar = ctk.CTkFrame(self.tab_mobile, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        btn_mob = ctk.CTkButton(
            bar, text="Audit Sample Android Manifest", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=220,
            command=self._audit_mobile
        )
        btn_mob.pack(side="left")

        self.txt_mobile = ctk.CTkTextbox(self.tab_mobile, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_mobile.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_firmware_tab(self):
        bar = ctk.CTkFrame(self.tab_firmware, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        lbl_fw = ctk.CTkLabel(bar, text="Firmware Path:", font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY)
        lbl_fw.pack(side="left", padx=(0, 5))
        self.entry_fw = ctk.CTkEntry(bar, width=300, font=FONT_CODE, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_fw.insert(0, "C:\\Firmware\\router_fw.bin")
        self.entry_fw.pack(side="left", padx=(0, 10))

        btn_fw = ctk.CTkButton(
            bar, text="Analyze Firmware Image", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=190,
            command=self._analyze_firmware
        )
        btn_fw.pack(side="left")

        self.txt_firmware = ctk.CTkTextbox(self.tab_firmware, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_firmware.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_risk_tab(self):
        bar = ctk.CTkFrame(self.tab_risk, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        btn_risk = ctk.CTkButton(
            bar, text="Calculate Risk Posture & Remediation Plan", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=280,
            command=self._calculate_risk
        )
        btn_risk.pack(side="left")

        self.txt_risk = ctk.CTkTextbox(self.tab_risk, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_risk.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _toggle_honeypot(self):
        if not self.honeypot._running:
            res = self.honeypot.start()
            self.txt_deception.insert("end", f"[+] {res.get('message')}\n")
            self.btn_hp.configure(text="Stop Isolated Decoy", text_color=COLOR_STATE_CRITICAL)
        else:
            self.honeypot.stop()
            self.txt_deception.insert("end", "[-] Honeypot decoy stopped.\n")
            self.btn_hp.configure(text="Start Isolated Decoy (Port 8089)", text_color=COLOR_ACCENT_TERMINAL)

    def _audit_mobile(self):
        self.txt_mobile.delete("1.0", "end")
        findings = AndroidManifestAuditor.audit_manifest_flags(
            debuggable=True,
            allow_backup=True,
            uses_cleartext=True,
            exported_components_count=3
        )
        self.txt_mobile.insert("end", f"[+] Android Manifest Audit Results ({len(findings)} findings):\n\n")
        for f in findings:
            self.txt_mobile.insert("end", f"[{f['severity']}] {f['title']} ({f['category']})\n")
            self.txt_mobile.insert("end", f"    Desc:   {f['description']}\n")
            self.txt_mobile.insert("end", f"    Remedy: {f['remediation']}\n")
            self.txt_mobile.insert("end", "-" * 60 + "\n")

    def _analyze_firmware(self):
        path = self.entry_fw.get().strip()
        self.txt_firmware.delete("1.0", "end")
        self.txt_firmware.insert("end", f"[*] Analyzing firmware image: {path}...\n")
        res = FirmwareAnalyzer.analyze_binary(path)
        if not res.get("success"):
            self.txt_firmware.insert("end", f"[-] Analysis notice: {res.get('error')}\n")
            self.txt_firmware.insert("end", "[i] Select an existing raw firmware image (.bin, .img) to inspect filesystems and entropy.\n")
            return
        self.txt_firmware.insert("end", f"[+] Filesystems: {res.get('detected_filesystems')}\n")
        self.txt_firmware.insert("end", f"[+] Entropy:     {res.get('entropy')} / 8.0\n")

    def _calculate_risk(self):
        self.txt_risk.delete("1.0", "end")
        calc = ExplainableRiskScorer.calculate_risk(
            base_cvss=9.8,
            epss_score=0.74,
            is_cisa_kev=True,
            is_internet_exposed=True,
            asset_criticality=1.3
        )
        self.txt_risk.insert("end", "[+] ATTACK SURFACE RISK ASSESSMENT:\n")
        self.txt_risk.insert("end", f"    Risk Score:  {calc['overall_score']} / 100.0\n")
        self.txt_risk.insert("end", f"    Severity:    {calc['rating']}\n")
        self.txt_risk.insert("end", f"    Explanation: {calc['explanation']}\n\n")

        plan = RemediationPlanner.generate_remediation_plan([{"rating": calc['rating'], "ip": "192.168.1.100"}])
        self.txt_risk.insert("end", "[+] RECOMMENDED REMEDIATION ACTION PLAN:\n")
        for p in plan:
            self.txt_risk.insert("end", f" - [{p['priority']}] Target: {p['target']} | Due: {p['due_date']}\n")
            self.txt_risk.insert("end", f"   Action: {p['action']}\n")
