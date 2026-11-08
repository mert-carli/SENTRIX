import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.forensics.dfir import forensics_toolkit
from modules.reverse_eng.pe_parser import pe_parser_engine
from modules.malware_sandbox.sandbox import malware_sandbox

class ForensicsView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "DIGITAL FORENSICS, REVERSE ENGINEERING & MALWARE LAB")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_file = self.tabview.add("File Forensics & Hex")
        self.tab_pe = self.tabview.add("PE Header Analysis")
        self.tab_artifacts = self.tabview.add("Windows Artifacts & USB")
        self.tab_sandbox = self.tabview.add("Sandbox & IOC Extractor")

        self._build_file_tab()
        self._build_pe_tab()
        self._build_artifacts_tab()
        self._build_sandbox_tab()

    def _build_file_tab(self):
        tab = self.tab_file
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="FILE PATH:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_file_path = ctk.CTkEntry(ctrl, placeholder_text="C:\\Windows\\System32\\cmd.exe", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_file_path.insert(0, "C:\\Windows\\System32\\cmd.exe")
        self.entry_file_path.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ ANALYZE METADATA & HASHES ]", self.run_file_inspect, is_accent=True).grid(row=0, column=2, padx=5)
        create_button(ctrl, "[ VIEW HEX DUMP ]", self.run_hex_dump).grid(row=0, column=3, padx=5)
        create_button(ctrl, "[ EXTRACT STRINGS ]", self.run_extract_strings).grid(row=0, column=4, padx=5)

        self.tb_file = create_textbox(tab)
        self.tb_file.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_file, "Digital Forensics File Analyzer Ready.\n", "accent")

    def _build_pe_tab(self):
        tab = self.tab_pe
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="PE TARGET:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_pe_path = ctk.CTkEntry(ctrl, placeholder_text="C:\\Windows\\System32\\cmd.exe", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_pe_path.insert(0, "C:\\Windows\\System32\\cmd.exe")
        self.entry_pe_path.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ PARSE PE HEADERS & SECTIONS ]", self.run_pe_parse, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_pe = create_textbox(tab)
        self.tb_pe.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_pe, "Portable Executable (PE) Reverse Engineering Engine Ready.\n", "accent")

    def _build_artifacts_tab(self):
        tab = self.tab_artifacts
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ AUDIT STARTUP AUTORUNS ]", self.run_startup_audit, is_accent=True).pack(side="left", padx=5)
        create_button(ctrl, "[ EXTRACT USB STORAGE HISTORY ]", self.run_usb_history).pack(side="left", padx=5)

        self.tb_artifacts = create_textbox(tab)
        self.tb_artifacts.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_artifacts, "Windows Forensics Artifacts Inspector Ready.\n", "accent")

    def _build_sandbox_tab(self):
        tab = self.tab_sandbox
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ CHECK ISOLATED VM ENVIRONMENT ]", self.run_vm_check, is_accent=True).pack(side="left", padx=5)
        create_button(ctrl, "[ EXTRACT NETWORK & REGISTRY IOCS ]", self.run_ioc_extract, is_danger=True).pack(side="left", padx=5)

        self.tb_sandbox = create_textbox(tab)
        self.tb_sandbox.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_sandbox, "Malware Sandbox Safety & IOC Extraction Center Ready.\n", "accent")

    # --- Actions ---
    def run_file_inspect(self):
        path = self.entry_file_path.get().strip()
        try:
            info = forensics_toolkit.inspect_file(path)
            lines = [
                f"FILE NAME   : {info['file_name']}",
                f"SIZE        : {info['size_bytes']} bytes",
                f"FORMAT      : {info['detected_format']}",
                f"MAGIC HEX   : {info['magic_hex']}",
                f"MD5         : {info['md5']}",
                f"SHA256      : {info['sha256']}",
                f"ENTROPY     : {info['entropy']} (Packed/Encrypted: {info['is_packed']})"
            ]
            safe_textbox_write(self.tb_file, "\n".join(lines) + "\n\n", "normal", clear_first=True)
        except Exception as e:
            safe_textbox_write(self.tb_file, f"[!] File error: {e}\n", "danger", clear_first=True)

    def run_hex_dump(self):
        path = self.entry_file_path.get().strip()
        safe_textbox_write(self.tb_file, f"[*] Hex dump (first 512 bytes) for {path}:\n\n", "warning", clear_first=True)
        dump = forensics_toolkit.get_hex_dump(path, max_bytes=512)
        safe_textbox_write(self.tb_file, dump + "\n", "normal")

    def run_extract_strings(self):
        path = self.entry_file_path.get().strip()
        safe_textbox_write(self.tb_file, f"[*] Extracting ASCII strings from {path}:\n\n", "warning", clear_first=True)
        strings = forensics_toolkit.extract_strings(path, min_len=5, limit=50)
        safe_textbox_write(self.tb_file, "\n".join(strings) + "\n", "accent")

    def run_pe_parse(self):
        path = self.entry_pe_path.get().strip()
        res = pe_parser_engine.parse_pe(path)
        if "error" in res:
            safe_textbox_write(self.tb_pe, f"[!] PE Error: {res['error']}\n", "danger", clear_first=True)
            return

        lines = [
            f"BINARY ARCHITECTURE : {res['architecture']}",
            f"ENTRY POINT         : {res['entry_point']}",
            f"NUMBER OF SECTIONS  : {res['number_of_sections']}\n",
            f"{'SECTION':<12} {'VIRTUAL ADDR':<16} {'RAW SIZE':<12} {'ENTROPY':<10} {'PACKED'}",
            "─"*65
        ]
        for s in res["sections"]:
            lines.append(f"{s['name']:<12} {s['virtual_address']:<16} {s['raw_size']:<12} {s['entropy']:<10} {s['is_packed']}")

        if res["suspicious_apis"]:
            lines.append("\nSUSPICIOUS DETECTED APIs:")
            lines.append("──────────────────────────────────────────")
            for a in res["suspicious_apis"]:
                lines.append(f"  [!] {a['api']:<25} : {a['description']}")

        safe_textbox_write(self.tb_pe, "\n".join(lines) + "\n", "accent", clear_first=True)

    def run_startup_audit(self):
        entries = forensics_toolkit.get_windows_startup_entries()
        lines = [f"{'AUTORUN NAME':<25} {'COMMAND / EXECUTABLE'}", "─"*75]
        for e in entries:
            lines.append(f"{e['name']:<25} {e['command']}")
        safe_textbox_write(self.tb_artifacts, "\n".join(lines) + "\n", "normal", clear_first=True)

    def run_usb_history(self):
        usbs = forensics_toolkit.get_usb_history()
        lines = ["HISTORICAL USB STORAGE CONNECTIONS (REGISTRY):", "─"*55]
        for u in usbs:
            lines.append(f"  ├── {u}")
        safe_textbox_write(self.tb_artifacts, "\n".join(lines) + "\n", "accent", clear_first=True)

    def run_vm_check(self):
        vm_info = malware_sandbox.detect_virtual_environment()
        lines = [
            f"IS VIRTUAL MACHINE : {vm_info['is_virtual_machine']}",
            f"SAFETY STATUS      : {vm_info['safety_recommendation']}\n",
            "HARDWARE INDICATORS:"
        ]
        for ind in vm_info["indicators"]:
            lines.append(f"  └── {ind}")
        safe_textbox_write(self.tb_sandbox, "\n".join(lines) + "\n", "accent" if vm_info['is_virtual_machine'] else "danger", clear_first=True)

    def run_ioc_extract(self):
        path = self.entry_file_path.get().strip()
        safe_textbox_write(self.tb_sandbox, f"[*] Extracting IOCs from {path}...\n", "warning", clear_first=True)
        iocs = malware_sandbox.extract_iocs_from_file(path)
        lines = [
            f"EXTRACTED IP ADDRESSES ({len(iocs['ips'])}):",
            ", ".join(iocs['ips']) or "None",
            f"\nEXTRACTED URLs ({len(iocs['urls'])}):",
            "\n".join(iocs['urls']) or "None",
            f"\nREFERENCED REGISTRY KEYS ({len(iocs['registry_keys'])}):",
            "\n".join(iocs['registry_keys']) or "None"
        ]
        safe_textbox_write(self.tb_sandbox, "\n".join(lines) + "\n", "normal")
