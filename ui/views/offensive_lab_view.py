import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.redteam.atomic_framework import atomic_test_runner
from modules.vuln_research.epss_engine import epss_engine
from modules.vuln_research.cve_engine import vulnerability_engine
from modules.active_directory.attack_path import ad_attack_path_analyzer

class OffensiveLabView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "OFFENSIVE SECURITY LAB: RED TEAM, EPSS VULN RESEARCH & AD ATTACK PATHS")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_atomic = self.tabview.add("Atomic Red Team Simulation")
        self.tab_epss = self.tabview.add("EPSS & CISA KEV Intelligence")
        self.tab_ad_path = self.tabview.add("AD Attack Path Graph")

        self._build_atomic_tab()
        self._build_epss_tab()
        self._build_ad_path_tab()

    def _build_atomic_tab(self):
        tab = self.tab_atomic
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")

        create_button(ctrl, "[ VIEW COVERAGE MATRIX ]", self.show_coverage_matrix, is_accent=True).pack(side="left", padx=5)
        create_button(ctrl, "[ RUN T1059.001 (PowerShell) ]", lambda: self.run_atomic("T1059.001-TEST1"), is_danger=True).pack(side="left", padx=5)
        create_button(ctrl, "[ RUN T1087.001 (Net User) ]", lambda: self.run_atomic("T1087.001-TEST1")).pack(side="left", padx=5)
        create_button(ctrl, "[ RUN T1049 (Netstat) ]", lambda: self.run_atomic("T1049-TEST1")).pack(side="left", padx=5)

        self.tb_atomic = create_textbox(tab)
        self.tb_atomic.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_atomic, "Atomic Red Team Simulation Lab Ready.\nControlled, safe, non-destructive validation.\n", "accent")

    def _build_epss_tab(self):
        tab = self.tab_epss
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="CVE ID:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_epss_cve = ctk.CTkEntry(ctrl, placeholder_text="CVE-2017-0144", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_epss_cve.insert(0, "CVE-2017-0144")
        self.entry_epss_cve.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ QUERY EPSS & KEV ]", self.run_epss_lookup, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_epss = create_textbox(tab)
        self.tb_epss.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_epss, "FIRST.org EPSS Exploit Probability & CISA KEV Center Ready.\n", "accent")

    def _build_ad_path_tab(self):
        tab = self.tab_ad_path
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="DOMAIN:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_dom = ctk.CTkEntry(ctrl, placeholder_text="corp.local", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_dom.insert(0, "corp.local")
        self.entry_dom.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ MAP ATTACK PATHS ]", self.run_ad_paths, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_ad_path = create_textbox(tab)
        self.tb_ad_path.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_ad_path, "Active Directory Attack Path & Transitive Permission Visualizer Ready.\n", "accent")

    # --- Actions ---
    def show_coverage_matrix(self):
        matrix = atomic_test_runner.get_coverage_matrix()
        lines = [f"{'TECHNIQUE':<14} {'TACTIC':<15} {'TEST ID':<18} {'NAME'}", "─"*75]
        for m in matrix:
            lines.append(f"{m['technique']:<14} {m['tactic']:<15} {m['test_id']:<18} {m['name']}")
        safe_textbox_write(self.tb_atomic, "\n".join(lines) + "\n", "normal", clear_first=True)

    def run_atomic(self, test_id: str):
        safe_textbox_write(self.tb_atomic, f"[*] Executing Atomic Test {test_id}...\n", "warning", clear_first=True)
        def task():
            res = atomic_test_runner.run_atomic_test(test_id)
            lines = [
                f"TEST ID          : {res['test_id']}",
                f"TECHNIQUE        : {res['technique']} ({res.get('name')})",
                f"EXECUTION STATUS : {res['status']}",
                f"DETECTION STATUS : {res['coverage_status']}",
                f"ELAPSED TIME     : {res.get('elapsed_sec', 0)}s",
                f"EXPECTED EVENT   : {res.get('expected_telemetry')}\n",
                "OUTPUT SNIPPET:",
                res.get('stdout', '') or res.get('error', 'None')
            ]
            self.after(0, lambda: safe_textbox_write(self.tb_atomic, "\n".join(lines) + "\n", "accent" if res['status']=="COMPLETED" else "danger"))
        threading.Thread(target=task, daemon=True).start()

    def run_epss_lookup(self):
        cve = self.entry_epss_cve.get().strip()
        safe_textbox_write(self.tb_epss, f"[*] Querying EPSS and CISA KEV for {cve}...\n", "warning", clear_first=True)
        def task():
            epss_data = epss_engine.get_epss_score(cve)
            cve_data = vulnerability_engine.lookup_cve(cve)
            risk = epss_engine.compute_risk_priority(
                cvss=cve_data.get("cvss", 5.0),
                epss=epss_data.get("epss_score", 0.0),
                is_cisa_kev=cve_data.get("cisa_kev", False)
            )

            lines = [
                f"CVE IDENTIFIER   : {cve}",
                f"VULNERABILITY    : {cve_data.get('title')}",
                f"CVSS BASE SCORE  : {cve_data.get('cvss')} ({cve_data.get('severity')})",
                f"EPSS PROBABILITY : {epss_data.get('epss_score')} ({epss_data.get('epss_score', 0)*100:.2f}% chance of exploit in 30 days)",
                f"EPSS PERCENTILE  : Top {100 - epss_data.get('epss_percentile', 0):.1f}% most critical",
                f"CISA KEV STATUS  : {'CRITICAL - ACTIVELY EXPLOITED' if cve_data.get('cisa_kev') else 'No known active campaign'}\n",
                f"PRIORITIZATION   : {risk}",
                f"RECOMMENDATION   : {cve_data.get('remediation', 'Apply official security patches.')}"
            ]
            self.after(0, lambda: safe_textbox_write(self.tb_epss, "\n".join(lines) + "\n", "accent"))
        threading.Thread(target=task, daemon=True).start()

    def run_ad_paths(self):
        dom = self.entry_dom.get().strip()
        safe_textbox_write(self.tb_ad_path, f"[*] Mapping attack paths for domain {dom}...\n", "warning", clear_first=True)
        def task():
            res = ad_attack_path_analyzer.build_sample_attack_paths(dom, ["DomainAdmin_User", "Helpdesk_Admin", "Backup_Operator"])
            lines = [
                f"DOMAIN           : {res['domain']}",
                f"IDENTITY SCORE   : {res['identity_security_score']} / 100\n",
                "DISCOVERED ESCALATION CHAINS:"
            ]
            for p in res["attack_paths"]:
                lines.append(f"[{p['risk_level']}] {p['chain']}\n  └── {p['remediation']}")
            self.after(0, lambda: safe_textbox_write(self.tb_ad_path, "\n".join(lines) + "\n", "normal"))
        threading.Thread(target=task, daemon=True).start()
