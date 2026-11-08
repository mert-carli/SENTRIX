import customtkinter as ctk
import threading
import os
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.reporting.report_generator import report_generator
from modules.terminal.orchestrator import tool_orchestrator
from core.permission import is_admin, get_privilege_status_str
from core.scope import scope_manager
from core.database import db

class ReportingTerminalView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "REPORTING ENGINE, CYBER TERMINAL & AUTHORIZED SCOPE SETTINGS")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_report = self.tabview.add("Security Report Generator")
        self.tab_terminal = self.tabview.add("Cyber Terminal")
        self.tab_scope = self.tabview.add("Scope & System Permissions")

        self._build_report_tab()
        self._build_terminal_tab()
        self._build_scope_tab()

    def _build_report_tab(self):
        tab = self.tab_report
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ COMPILE FULL REPORT (MARKDOWN) ]", lambda: self.compile_report("EN"), is_accent=True).pack(side="left", padx=5)
        create_button(ctrl, "[ RAPORU DERLE (TÜRKÇE) ]", lambda: self.compile_report("TR")).pack(side="left", padx=5)
        create_button(ctrl, "[ SAVE REPORT TO DESKTOP ]", self.save_report_to_desktop).pack(side="left", padx=5)

        self.tb_report = create_textbox(tab)
        self.tb_report.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_report, "Professional Security Assessment Report Generator Ready.\n", "accent")
        self.last_report = ""

    def _build_terminal_tab(self):
        tab = self.tab_terminal
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        tools_status = tool_orchestrator.detect_available_tools()
        tools_str = " | ".join([f"{k}: {'[✓ AVAILABLE]' if v else '[✗ MISSING]'}" for k, v in tools_status.items()])
        lbl_tools = ctk.CTkLabel(tab, text=f"SYSTEM CLI TOOLS: {tools_str}", font=FONT_TEXT, text_color=COLOR_TEXT_SECONDARY)
        lbl_tools.grid(row=0, column=0, pady=5, sticky="w")

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=1, column=0, pady=5, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="EXECUTE CMD:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_cmd = ctk.CTkEntry(ctrl, placeholder_text="powershell -Command Get-Process", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_cmd.insert(0, "powershell -Command Get-Service | Select-Object -First 10")
        self.entry_cmd.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ EXECUTE ]", self.run_terminal_command, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_term = create_textbox(tab)
        self.tb_term.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_term, "Safe Cyber Terminal & Tool Orchestrator Ready.\n", "accent")

    def _build_scope_tab(self):
        tab = self.tab_scope
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        priv_status = get_privilege_status_str()
        lbl_priv = ctk.CTkLabel(tab, text=f"PROCESS PRIVILEGE LEVEL: {priv_status}", font=FONT_SUBTITLE, text_color=COLOR_ACCENT_TERMINAL if is_admin() else COLOR_STATE_WARNING)
        lbl_priv.grid(row=0, column=0, pady=10, sticky="w")

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=1, column=0, pady=5, sticky="ew")
        create_button(ctrl, "[ VIEW AUTHORIZED SCOPE RULES ]", self.show_scope_rules, is_accent=True).pack(side="left", padx=5)
        create_button(ctrl, "[ VIEW AUDIT LOGS ]", self.show_audit_logs).pack(side="left", padx=5)

        self.tb_scope = create_textbox(tab)
        self.tb_scope.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_scope, "Authorized Scope Management & System Integrity Center.\n", "accent")

    # --- Actions ---
    def compile_report(self, lang: str):
        report = report_generator.generate_comprehensive_report(project_id=1, lang=lang)
        self.last_report = report
        safe_textbox_write(self.tb_report, report + "\n", "normal", clear_first=True)

    def save_report_to_desktop(self):
        if not self.last_report:
            self.compile_report("EN")
        desktop = os.path.join(os.environ.get("USERPROFILE", "C:\\"), "Desktop")
        target_path = os.path.join(desktop, "Security_Assessment_Report.md")
        try:
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(self.last_report)
            safe_textbox_write(self.tb_report, f"\n[+] SUCCESS: Assessment report saved to: {target_path}\n", "accent")
        except Exception as e:
            safe_textbox_write(self.tb_report, f"\n[!] Error saving report: {e}\n", "danger")

    def run_terminal_command(self):
        cmd = self.entry_cmd.get().strip()
        safe_textbox_write(self.tb_term, f"[*] Executing: {cmd}...\n\n", "warning", clear_first=True)
        def task():
            import subprocess
            try:
                out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=15)
                self.after(0, lambda: safe_textbox_write(self.tb_term, out + "\n", "normal"))
            except subprocess.CalledProcessError as e:
                self.after(0, lambda: safe_textbox_write(self.tb_term, e.output + "\n", "danger"))
            except Exception as e:
                self.after(0, lambda: safe_textbox_write(self.tb_term, f"[!] Execution failed: {e}\n", "danger"))
        threading.Thread(target=task, daemon=True).start()

    def show_scope_rules(self):
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM projects WHERE id = 1")
            row = cursor.fetchone()

        lines = [
            "AUTHORIZED SCOPE RULES (Project #1):",
            "──────────────────────────────────────────",
            f"PROJECT NAME       : {row['name']}",
            f"AUTHORIZED TARGETS : {row['authorized_targets']}",
            f"ALLOWED IP RANGES  : {row['allowed_ip_ranges']}",
            f"ALLOWED DOMAINS    : {row['allowed_domains']}",
            f"EXCLUDED TARGETS   : {row['excluded_targets'] or 'None'}",
            f"MAX SCAN RATE      : {row['max_scan_rate']} packets/sec\n",
            "[✓] Policy Enforced: Any target not matching these rules will be rejected with ScopeViolationError."
        ]
        safe_textbox_write(self.tb_scope, "\n".join(lines) + "\n", "accent", clear_first=True)

    def show_audit_logs(self):
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, action, details FROM audit_logs ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()

        lines = [f"{'TIMESTAMP':<20} {'ACTION':<25} {'DETAILS'}", "─"*80]
        for r in rows:
            lines.append(f"{r['timestamp'][:19]:<20} {r['action']:<25} {r['details']}")
        safe_textbox_write(self.tb_scope, "\n".join(lines) + "\n", "normal", clear_first=True)
