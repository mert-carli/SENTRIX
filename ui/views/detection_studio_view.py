import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.detection_studio.rule_validator import RuleValidator
from modules.detection_studio.coverage_analyzer import DetectionCoverageAnalyzer

class DetectionStudioView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._init_ui()

    def _init_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="DETECTION RULE STUDIO", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Sigma, YARA & Suricata Rule Authoring & MITRE Mapping", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        # Controls Bar
        bar = ctk.CTkFrame(self, fg_color=COLOR_BG_SECONDARY, border_width=1, border_color=COLOR_BORDER)
        bar.pack(fill="x", padx=20, pady=(0, 10))

        lbl_fmt = ctk.CTkLabel(bar, text="Rule Format:", font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY)
        lbl_fmt.pack(side="left", padx=(15, 5), pady=10)

        self.combo_fmt = ctk.CTkComboBox(
            bar, values=["SIGMA", "YARA", "SURICATA"],
            width=140, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, font=FONT_CODE
        )
        self.combo_fmt.pack(side="left", padx=(0, 15), pady=10)

        btn_val = ctk.CTkButton(
            bar, text="Validate Rule Syntax", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=170,
            command=self._validate_rule
        )
        btn_val.pack(side="left", padx=(0, 10), pady=10)

        btn_cov = ctk.CTkButton(
            bar, text="Evaluate MITRE Coverage", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, width=180,
            command=self._evaluate_coverage
        )
        btn_cov.pack(side="left", pady=10)

        # Editor
        self.txt_editor = ctk.CTkTextbox(self, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_editor.pack(fill="both", expand=True, padx=20, pady=(0, 5))

        default_sigma = (
            "title: Suspicious PowerShell Encoded Command\n"
            "status: experimental\n"
            "description: Detects encoded PowerShell command execution.\n"
            "mitre_technique: T1059.001\n"
            "logsource:\n"
            "    category: process_creation\n"
            "    product: windows\n"
            "detection:\n"
            "    field: command_line\n"
            "    value: -enc\n"
        )
        self.txt_editor.insert("1.0", default_sigma)

        # Status output
        self.lbl_feedback = ctk.CTkLabel(self, text="Ready. Click Validate Rule Syntax to verify.", font=FONT_CODE, text_color=COLOR_TEXT_SECONDARY, anchor="w")
        self.lbl_feedback.pack(fill="x", padx=20, pady=(0, 10))

    def _validate_rule(self):
        fmt = self.combo_fmt.get()
        content = self.txt_editor.get("1.0", "end")
        res = RuleValidator.validate_rule(fmt, content)
        if res.get("valid"):
            self.lbl_feedback.configure(
                text=f"[+] Valid {fmt} Rule: {res.get('title') or res.get('rule_name') or 'Rule Validated Successfully'}",
                text_color=COLOR_ACCENT_TERMINAL
            )
        else:
            self.lbl_feedback.configure(
                text=f"[-] {fmt} Validation Error: {res.get('error')}",
                text_color=COLOR_STATE_CRITICAL
            )

    def _evaluate_coverage(self):
        sample_rules = [
            {"mitre_technique": "T1059.001"},
            {"mitre_technique": "T1110"},
            {"mitre_technique": "T1053.005"},
            {"mitre_technique": "T1543.003"},
            {"mitre_technique": "T1105"}
        ]
        cov = DetectionCoverageAnalyzer.evaluate_coverage(sample_rules)
        self.lbl_feedback.configure(
            text=f"[+] MITRE Coverage: {cov['covered_techniques_count']} techniques covered across {len(cov['tactics'])} enterprise tactics.",
            text_color=COLOR_ACCENT_TERMINAL
        )
