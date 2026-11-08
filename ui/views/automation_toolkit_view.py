import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.automation.workflow_engine import workflow_engine
from modules.security_tools.toolkit import security_toolkit

class AutomationToolkitView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "SECURITY AUTOMATION ENGINE & SECURITY RESEARCH TOOLKIT")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_workflow = self.tabview.add("Workflow Automation")
        self.tab_encoding = self.tabview.add("Encoding & Decoding")
        self.tab_network_calc = self.tabview.add("CIDR & Subnet Calculator")
        self.tab_ts = self.tabview.add("Forensic Timestamp Converter")

        self._build_workflow_tab()
        self._build_encoding_tab()
        self._build_network_calc_tab()
        self._build_ts_tab()

    def _build_workflow_tab(self):
        tab = self.tab_workflow
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="TARGET SCOPE:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_wf_target = ctk.CTkEntry(ctrl, placeholder_text="127.0.0.1", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_wf_target.insert(0, "127.0.0.1")
        self.entry_wf_target.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ EXECUTE END-TO-END SECURITY WORKFLOW ]", self.run_workflow, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_wf = create_textbox(tab)
        self.tb_wf.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_wf, "Security Automation Engine Ready.\nChains Scope Validation -> Port Scan -> CVE Correlation -> Assessment Report.\n", "accent")

    def _build_encoding_tab(self):
        tab = self.tab_encoding
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="TEXT INPUT:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_enc = ctk.CTkEntry(ctrl, font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_enc.insert(0, "SENTRIX Cyber Operations Platform")
        self.entry_enc.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.grid(row=1, column=0, pady=(0, 10), sticky="w")
        create_button(btn_row, "B64 Encode", lambda: self.handle_enc("b64_enc")).pack(side="left", padx=3)
        create_button(btn_row, "B64 Decode", lambda: self.handle_enc("b64_dec")).pack(side="left", padx=3)
        create_button(btn_row, "Hex Encode", lambda: self.handle_enc("hex_enc")).pack(side="left", padx=3)
        create_button(btn_row, "Hex Decode", lambda: self.handle_enc("hex_dec")).pack(side="left", padx=3)
        create_button(btn_row, "URL Encode", lambda: self.handle_enc("url_enc")).pack(side="left", padx=3)
        create_button(btn_row, "URL Decode", lambda: self.handle_enc("url_dec")).pack(side="left", padx=3)

        self.tb_enc = create_textbox(tab)
        self.tb_enc.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_enc, "Encoding & Decoding Utilities Ready.\n", "accent")

    def _build_network_calc_tab(self):
        tab = self.tab_network_calc
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="CIDR NOTATION:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_cidr = ctk.CTkEntry(ctrl, placeholder_text="192.168.1.0/24", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_cidr.insert(0, "192.168.1.0/24")
        self.entry_cidr.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ CALCULATE SUBNET ]", self.run_cidr_calc, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_cidr = create_textbox(tab)
        self.tb_cidr.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_cidr, "Subnet Planner & CIDR Architecture Calculator Ready.\n", "accent")

    def _build_ts_tab(self):
        tab = self.tab_ts
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="UNIX TIMESTAMP:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_ts = ctk.CTkEntry(ctrl, placeholder_text="1730832000", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_ts.insert(0, "1730832000")
        self.entry_ts.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ CONVERT TIMESTAMP ]", self.run_ts_convert, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_ts = create_textbox(tab)
        self.tb_ts.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_ts, "Forensic Timestamp Converter Ready (Unix Epoch <-> Windows FILETIME <-> UTC).\n", "accent")

    # --- Actions ---
    def run_workflow(self):
        target = self.entry_wf_target.get().strip()
        safe_textbox_write(self.tb_wf, f"[*] Initiating Chained Automated Security Assessment on {target}...\n", "warning", clear_first=True)
        def task():
            def cb(msg):
                self.after(0, lambda m=msg: safe_textbox_write(self.tb_wf, m + "\n", "normal"))
            res = workflow_engine.run_automated_audit_workflow(target, project_id=1, progress_cb=cb)
            tag = "accent" if res["status"] == "COMPLETED" else "danger"
            self.after(0, lambda: safe_textbox_write(self.tb_wf, f"\n[+] FINAL WORKFLOW RESULT: {res['status']}\n", tag))
        threading.Thread(target=task, daemon=True).start()

    def handle_enc(self, action: str):
        val = self.entry_enc.get()
        out = ""
        try:
            if action == "b64_enc": out = security_toolkit.encode_base64(val)
            elif action == "b64_dec": out = security_toolkit.decode_base64(val)
            elif action == "hex_enc": out = security_toolkit.encode_hex(val)
            elif action == "hex_dec": out = security_toolkit.decode_hex(val)
            elif action == "url_enc": out = security_toolkit.encode_url(val)
            elif action == "url_dec": out = security_toolkit.decode_url(val)
            safe_textbox_write(self.tb_enc, f"RESULT ({action}):\n{out}\n\n", "accent")
        except Exception as e:
            safe_textbox_write(self.tb_enc, f"[!] Error: {e}\n", "danger")

    def run_cidr_calc(self):
        c = self.entry_cidr.get().strip()
        res = security_toolkit.calculate_cidr(c)
        if "error" in res:
            safe_textbox_write(self.tb_cidr, f"[!] CIDR Error: {res['error']}\n", "danger", clear_first=True)
            return

        lines = [
            f"CIDR BLOCK          : {res['cidr']}",
            f"NETWORK ADDRESS     : {res['network_address']}",
            f"BROADCAST ADDRESS   : {res['broadcast_address']}",
            f"SUBNET NETMASK      : {res['netmask']}",
            f"WILDCARD MASK       : {res['wildcard_mask']}",
            f"TOTAL ADDRESSES     : {res['total_addresses']}",
            f"USABLE HOST COUNT   : {res['usable_hosts']}",
            f"USABLE HOST RANGE   : {res['usable_range']}",
            f"RFC1918 PRIVATE     : {'YES (Internal Private)' if res['is_private'] else 'NO (Publicly Routable)'}"
        ]
        safe_textbox_write(self.tb_cidr, "\n".join(lines) + "\n", "accent", clear_first=True)

    def run_ts_convert(self):
        val = self.entry_ts.get().strip()
        res = security_toolkit.convert_timestamp(val)
        if "error" in res:
            safe_textbox_write(self.tb_ts, f"[!] {res['error']}\n", "danger", clear_first=True)
            return

        lines = [
            f"INPUT VALUE          : {val}",
            f"ISO 8601 UTC         : {res.get('ISO_8601_UTC')}",
            f"UNIX EPOCH (SECONDS) : {res.get('Unix_Epoch_Seconds')}",
            f"WINDOWS FILETIME     : {res.get('Windows_FILETIME')}"
        ]
        safe_textbox_write(self.tb_ts, "\n".join(lines) + "\n", "accent", clear_first=True)
