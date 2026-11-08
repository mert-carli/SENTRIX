import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.active_directory.ad_analyzer import active_directory_analyzer
from modules.password_lab.pwd_tool import password_lab
from modules.vuln_research.cve_engine import vulnerability_engine
from modules.linux_audit.ssh_auditor import linux_ssh_auditor, LINUX_AUDIT_COMMANDS

class EnterpriseView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "ENTERPRISE SECURITY: ACTIVE DIRECTORY, VULNERABILITIES & IDENTITY")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_ad = self.tabview.add("Active Directory & IAM")
        self.tab_cve = self.tabview.add("Vulnerability Research & CVE")
        self.tab_pwd = self.tabview.add("Password Security Lab")
        self.tab_linux = self.tabview.add("Linux & SSH Audit")

        self._build_ad_tab()
        self._build_cve_tab()
        self._build_pwd_tab()
        self._build_linux_tab()

    def _build_ad_tab(self):
        tab = self.tab_ad
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ RUN ACTIVE DIRECTORY & LOCAL IAM AUDIT ]", self.run_ad_audit, is_accent=True).pack(side="left", padx=5)

        self.tb_ad = create_textbox(tab)
        self.tb_ad.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_ad, "Active Directory & Identity Architecture Auditor Ready.\n", "accent")

    def _build_cve_tab(self):
        tab = self.tab_cve
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="CVE ID / SERVICE:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_cve = ctk.CTkEntry(ctrl, placeholder_text="CVE-2017-0144 or SMB", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_cve.insert(0, "CVE-2017-0144")
        self.entry_cve.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ QUERY CVE DATABASE ]", self.run_cve_lookup, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_cve = create_textbox(tab)
        self.tb_cve.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_cve, "Vulnerability Intelligence & CISA KEV Correlation Center Ready.\n", "accent")

    def _build_pwd_tab(self):
        tab = self.tab_pwd
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="PASSWORD / HASH:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_pwd = ctk.CTkEntry(ctrl, placeholder_text="P@ssw0rd123! or 5d41402abc4b2a76b9719d911017c592", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_pwd.insert(0, "P@ssw0rd123!")
        self.entry_pwd.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ EVALUATE STRENGTH ]", self.run_pwd_strength, is_accent=True).grid(row=0, column=2, padx=5)
        create_button(ctrl, "[ IDENTIFY HASH ]", self.run_hash_id).grid(row=0, column=3, padx=5)
        create_button(ctrl, "[ GENERATE HASHES ]", self.run_hash_gen).grid(row=0, column=4, padx=5)

        self.tb_pwd = create_textbox(tab)
        self.tb_pwd.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_pwd, "Password Security Lab Ready. Strictly offline and adheres to zero credential leakage policy.\n", "accent")

    def _build_linux_tab(self):
        tab = self.tab_linux
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ VIEW LINUX AUDIT CHECKLIST ]", self.show_linux_checklist, is_accent=True).pack(side="left", padx=5)

        self.tb_linux = create_textbox(tab)
        self.tb_linux.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_linux, "Linux & Remote SSH Auditor Ready.\n", "accent")

    # --- Actions ---
    def run_ad_audit(self):
        safe_textbox_write(self.tb_ad, "[*] Running Active Directory and Local IAM audit...\n", "warning", clear_first=True)
        def task():
            audit = active_directory_analyzer.run_ad_audit()
            d_info = audit["domain_info"]
            lines = [
                f"DOMAIN STATUS       : {'JOINED TO DOMAIN' if d_info['is_domain_joined'] else 'STANDALONE WORKGROUP'}",
                f"DOMAIN / WORKGROUP  : {d_info['domain_name']}",
                f"COMPUTER NAME       : {d_info['computer_name']}",
                f"LOGON SERVER        : {d_info['logon_server']}\n",
                f"LOCAL ADMINISTRATORS ({len(audit['privileged_groups'].get('Administrators', []))}):",
                ", ".join(audit['privileged_groups'].get('Administrators', [])) or "None",
                "\nPASSWORD POLICY METRICS:"
            ]
            for k, v in audit["password_policy"].items():
                lines.append(f"  ├── {k:<30}: {v}")

            if audit["findings"]:
                lines.append("\nSECURITY ASSESSMENT FINDINGS:")
                lines.append("──────────────────────────────────────────")
                for f in audit["findings"]:
                    lines.append(f"[{f['severity']}] {f['title']}\n  ├── Description: {f['description']}\n  ├── MITRE ATT&CK: {f['mitre']}\n  └── Remediation: {f['remediation']}")

            self.after(0, lambda: safe_textbox_write(self.tb_ad, "\n".join(lines) + "\n", "normal"))
        threading.Thread(target=task, daemon=True).start()

    def run_cve_lookup(self):
        query = self.entry_cve.get().strip()
        safe_textbox_write(self.tb_cve, f"[*] Querying Vulnerability Knowledgebase for '{query}'...\n", "warning", clear_first=True)
        def task():
            if query.upper().startswith("CVE-"):
                res = vulnerability_engine.lookup_cve(query)
                lines = [
                    f"CVE ID      : {res['cve_id']}",
                    f"TITLE       : {res['title']}",
                    f"SEVERITY    : {res['severity']} (CVSS: {res['cvss']})",
                    f"CISA KEV    : {'YES (Known Exploited Vulnerability)' if res.get('cisa_kev') else 'No'}",
                    f"REMEDIATION : {res.get('remediation', 'Apply official vendor security patch.')}"
                ]
                self.after(0, lambda: safe_textbox_write(self.tb_cve, "\n".join(lines) + "\n", "accent"))
            else:
                matches = vulnerability_engine.evaluate_service_vulnerabilities(query)
                if matches:
                    lines = [f"[+] Discovered {len(matches)} associated vulnerability records:\n", "─"*75]
                    for m in matches:
                        lines.append(f"[{m['severity']}] {m['cve_id']} (CVSS {m['cvss']}): {m['title']}\n  └── Remediation: {m['remediation']}\n")
                    self.after(0, lambda: safe_textbox_write(self.tb_cve, "\n".join(lines), "normal"))
                else:
                    self.after(0, lambda: safe_textbox_write(self.tb_cve, f"[-] No known curated CVEs found matching service '{query}'.\n", "warning"))
        threading.Thread(target=task, daemon=True).start()

    def run_pwd_strength(self):
        pwd = self.entry_pwd.get()
        res = password_lab.evaluate_strength(pwd)
        lines = [
            f"PASSWORD LENGTH : {res['length']}",
            f"CHARSET POOL    : {res['charset_pool']} possible characters",
            f"SHANNON ENTROPY : {res['entropy_bits']} bits",
            f"STRENGTH RATING : {res['rating']}\n",
            f"Contains Lowercase : {res['has_lower']}",
            f"Contains Uppercase : {res['has_upper']}",
            f"Contains Digits    : {res['has_digit']}",
            f"Contains Specials  : {res['has_special']}"
        ]
        tag = "accent" if res['rating'] == "STRONG" else ("warning" if res['rating'] == "MODERATE" else "danger")
        safe_textbox_write(self.tb_pwd, "\n".join(lines) + "\n", tag, clear_first=True)

    def run_hash_id(self):
        val = self.entry_pwd.get().strip()
        cands = password_lab.identify_hash(val)
        lines = [f"INPUT HASH : {val}", f"POSSIBLE ALGORITHMS : {', '.join(cands)}"]
        safe_textbox_write(self.tb_pwd, "\n".join(lines) + "\n", "accent", clear_first=True)

    def run_hash_gen(self):
        val = self.entry_pwd.get()
        hashes = password_lab.generate_hashes(val)
        lines = [f"SOURCE PLAINTEXT : [REDACTED]\n", "CALCULATED CRYPTOGRAPHIC HASHES:", "─"*65]
        for alg, h in hashes.items():
            lines.append(f"{alg:<10} : {h}")
        safe_textbox_write(self.tb_pwd, "\n".join(lines) + "\n", "normal", clear_first=True)

    def show_linux_checklist(self):
        lines = ["LINUX / SSH READ-ONLY SECURITY AUDIT CHECKLIST:", "─"*65]
        for item, cmd in LINUX_AUDIT_COMMANDS.items():
            lines.append(f"{item:<18} : {cmd}")
        safe_textbox_write(self.tb_linux, "\n".join(lines) + "\n", "accent", clear_first=True)
