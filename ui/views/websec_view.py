import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.websec.pentest import web_pentest_suite
from modules.api_sec.api_tester import api_security_tester

class WebSecurityView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "WEB APPLICATION & REST/GRAPHQL API SECURITY SUITE")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_inspector = self.tabview.add("HTTP Inspector & Headers")
        self.tab_endpoints = self.tabview.add("Sensitive Endpoints")
        self.tab_jwt = self.tabview.add("JWT Security Decoder")

        self._build_inspector_tab()
        self._build_endpoints_tab()
        self._build_jwt_tab()

    def _build_inspector_tab(self):
        tab = self.tab_inspector
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="TARGET URL:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_web_url = ctk.CTkEntry(ctrl, placeholder_text="https://example.com", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_web_url.insert(0, "https://google.com")
        self.entry_web_url.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ INSPECT HTTP & AUDIT HEADERS ]", self.run_web_audit, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_web = create_textbox(tab)
        self.tb_web.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_web, "HTTP Inspector Ready. Enter target URL to inspect security headers and cookies.\n", "accent")

    def _build_endpoints_tab(self):
        tab = self.tab_endpoints
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="BASE URL:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_base_url = ctk.CTkEntry(ctrl, placeholder_text="https://example.com", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_base_url.insert(0, "https://google.com")
        self.entry_base_url.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ DISCOVER EXPOSED ENDPOINTS ]", self.run_endpoint_scan, is_danger=True).grid(row=0, column=2, padx=5)

        self.tb_endpoints = create_textbox(tab)
        self.tb_endpoints.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_endpoints, "Exposed & Debug Endpoint Discovery Ready.\n", "accent")

    def _build_jwt_tab(self):
        tab = self.tab_jwt
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(tab, text="PASTE JSON WEB TOKEN (JWT):", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, pady=(10, 5), sticky="w")
        self.entry_jwt = ctk.CTkEntry(tab, placeholder_text="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_jwt.grid(row=1, column=0, pady=(0, 10), sticky="ew")

        create_button(tab, "[ DECODE & AUDIT JWT ]", self.run_jwt_audit, is_accent=True).grid(row=1, column=1, padx=(10, 0), pady=(0, 10))

        self.tb_jwt = create_textbox(tab)
        self.tb_jwt.grid(row=2, column=0, columnspan=2, sticky="nsew")
        safe_textbox_write(self.tb_jwt, "JWT Security Auditor Ready. Analyzes headers, claims, signature, and algorithms.\n", "accent")

    # --- Actions ---
    def run_web_audit(self):
        url = self.entry_web_url.get().strip()
        safe_textbox_write(self.tb_web, f"[*] Auditing {url}...\n", "warning", clear_first=True)
        def task():
            try:
                res = web_pentest_suite.inspect_url(url)
                out = [f"TARGET       : {res['target']}", f"STATUS       : {res['status_code']} {res['reason']}\n"]
                out.append("SECURITY FINDINGS:")
                out.append("──────────────────────────────────────────")
                if res["security_findings"]:
                    for sev, title, desc in res["security_findings"]:
                        out.append(f"[{sev}] {title}\n  └── {desc}")
                else:
                    out.append("[✓] No critical header misconfigurations identified.")

                out.append("\nCOOKIES AUDITED:")
                out.append("──────────────────────────────────────────")
                if res["cookies"]:
                    for c in res["cookies"]:
                        out.append(f"Cookie: {c['raw']} (Secure={c['secure']}, HttpOnly={c['httponly']}, SameSite={c['samesite']})")
                else:
                    out.append("No Set-Cookie headers in response.")

                self.after(0, lambda: safe_textbox_write(self.tb_web, "\n".join(out) + "\n", "normal"))
            except Exception as e:
                self.after(0, lambda err=str(e): safe_textbox_write(self.tb_web, f"\n[!] Audit error: {err}\n", "danger"))
        threading.Thread(target=task, daemon=True).start()

    def run_endpoint_scan(self):
        url = self.entry_base_url.get().strip()
        safe_textbox_write(self.tb_endpoints, f"[*] Checking sensitive paths on {url}...\n", "warning", clear_first=True)
        def task():
            try:
                findings = web_pentest_suite.scan_sensitive_endpoints(url)
                if findings:
                    out = [f"[!] Discovered {len(findings)} exposed endpoint(s):\n"]
                    for f in findings:
                        out.append(f"[{f['severity']}] HTTP {f['status']} : {f['path']} ({f['url']})")
                else:
                    out = ["[✓] No exposed common debug/admin endpoints identified."]
                self.after(0, lambda: safe_textbox_write(self.tb_endpoints, "\n".join(out) + "\n", "accent" if findings else "normal"))
            except Exception as e:
                self.after(0, lambda err=str(e): safe_textbox_write(self.tb_endpoints, f"\n[!] Error: {err}\n", "danger"))
        threading.Thread(target=task, daemon=True).start()

    def run_jwt_audit(self):
        token = self.entry_jwt.get().strip()
        res = api_security_tester.decode_jwt(token)
        import json
        if "error" in res:
            safe_textbox_write(self.tb_jwt, f"[!] JWT Error: {res['error']}\n", "danger", clear_first=True)
            return

        lines = [
            f"JWT ALGORITHM : {res['algorithm']}",
            f"EXPIRED       : {res['is_expired']}",
            f"SIGNATURE     : {'Present' if res['signature_present'] else 'MISSING'}\n",
            "HEADER:",
            json.dumps(res["header"], indent=2),
            "\nPAYLOAD:",
            json.dumps(res["payload"], indent=2),
            "\nSECURITY FINDINGS:"
        ]
        for sev, title, desc in res.get("findings", []):
            lines.append(f"  [{sev}] {title}: {desc}")

        safe_textbox_write(self.tb_jwt, "\n".join(lines) + "\n", "accent", clear_first=True)
