import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.endpoint.edr_lite import edr_lite_engine
from modules.reverse_eng.binary_diff import binary_diff_engine

class EndpointSecurityView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "ENDPOINT SECURITY & EDR LITE: PROCESS TREE, FIM & BINARY DIFF")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_proc = self.tabview.add("Process Tree & Ancestry")
        self.tab_fim = self.tabview.add("File Integrity Monitor (FIM)")
        self.tab_tasks = self.tabview.add("Scheduled Tasks Persistence")
        self.tab_diff = self.tabview.add("Binary Comparison Diff")

        self._build_proc_tab()
        self._build_fim_tab()
        self._build_tasks_tab()
        self._build_diff_tab()

    def _build_proc_tab(self):
        tab = self.tab_proc
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ REFRESH PROCESS TREE ]", self.run_proc_tree, is_accent=True).pack(side="left", padx=5)

        self.tb_proc = create_textbox(tab)
        self.tb_proc.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_proc, "Process Hierarchy & Execution Ancestry Ready.\n", "accent")

    def _build_fim_tab(self):
        tab = self.tab_fim
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="MONITOR PATH:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_fim_dir = ctk.CTkEntry(ctrl, placeholder_text="C:\\Windows\\System32\\drivers\\etc", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_fim_dir.insert(0, "C:\\Windows\\System32\\drivers\\etc")
        self.entry_fim_dir.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl, "[ CREATE BASELINE ]", self.create_fim_baseline, is_accent=True).grid(row=0, column=2, padx=5)
        create_button(ctrl, "[ CHECK INTEGRITY ]", self.check_fim, is_danger=True).grid(row=0, column=3, padx=5)

        self.tb_fim = create_textbox(tab)
        self.tb_fim.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_fim, "File Integrity Monitoring (FIM) Ready. Detects modified, added, or deleted files.\n", "accent")

    def _build_tasks_tab(self):
        tab = self.tab_tasks
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ QUERY SCHEDULED TASKS ]", self.run_tasks_audit, is_accent=True).pack(side="left", padx=5)

        self.tb_tasks = create_textbox(tab)
        self.tb_tasks.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_tasks, "Scheduled Tasks Persistence Auditor Ready.\n", "accent")

    def _build_diff_tab(self):
        tab = self.tab_diff
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl.grid_columnconfigure((1, 3), weight=1)

        ctk.CTkLabel(ctrl, text="FILE A:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=5)
        self.entry_diff_a = ctk.CTkEntry(ctrl, font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_diff_a.insert(0, "C:\\Windows\\System32\\cmd.exe")
        self.entry_diff_a.grid(row=0, column=1, padx=5, sticky="ew")

        ctk.CTkLabel(ctrl, text="FILE B:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=2, padx=5)
        self.entry_diff_b = ctk.CTkEntry(ctrl, font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_diff_b.insert(0, "C:\\Windows\\System32\\notepad.exe")
        self.entry_diff_b.grid(row=0, column=3, padx=5, sticky="ew")

        create_button(ctrl, "[ COMPARE BINARIES ]", self.run_binary_diff, is_accent=True).grid(row=0, column=4, padx=5)

        self.tb_diff = create_textbox(tab)
        self.tb_diff.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_diff, "Binary Comparison & Variant Diff Engine Ready.\n", "accent")

    # --- Actions ---
    def run_proc_tree(self):
        safe_textbox_write(self.tb_proc, "[*] Building Process Execution Hierarchy...\n", "warning", clear_first=True)
        def task():
            procs = edr_lite_engine.get_process_tree()
            lines = [f"{'PID':<8} {'PPID':<8} {'MEMORY':<10} {'PROCESS NAME':<24} {'COMMAND LINE / PATH'}", "─"*95]
            for p in procs[:50]:
                lines.append(f"{p['pid']:<8} {p['ppid']:<8} {str(p['memory_mb'])+'MB':<10} {p['name'][:22]:<24} {p['cmdline']}")
            self.after(0, lambda: safe_textbox_write(self.tb_proc, "\n".join(lines) + "\n", "normal"))
        threading.Thread(target=task, daemon=True).start()

    def create_fim_baseline(self):
        d = self.entry_fim_dir.get().strip()
        safe_textbox_write(self.tb_fim, f"[*] Creating SHA-256 cryptographic baseline for {d}...\n", "warning", clear_first=True)
        def task():
            try:
                base = edr_lite_engine.create_fim_baseline(d)
                self.after(0, lambda: safe_textbox_write(self.tb_fim, f"[✓] Baseline created successfully for {len(base)} file(s).\n", "accent"))
            except Exception as e:
                self.after(0, lambda err=str(e): safe_textbox_write(self.tb_fim, f"[!] Error: {err}\n", "danger"))
        threading.Thread(target=task, daemon=True).start()

    def check_fim(self):
        d = self.entry_fim_dir.get().strip()
        safe_textbox_write(self.tb_fim, f"[*] Checking file integrity against baseline for {d}...\n", "warning", clear_first=True)
        def task():
            res = edr_lite_engine.check_fim_integrity(d)
            if "error" in res:
                self.after(0, lambda: safe_textbox_write(self.tb_fim, f"[!] {res['error']}\n", "danger"))
                return
            lines = [
                f"MONITORED DIRECTORY : {res['directory']}",
                f"INTEGRITY BREACHED  : {res['integrity_breached']}",
                f"TOTAL MONITORED     : {res['total_monitored']} files\n",
                f"MODIFIED FILES ({len(res['modified_files'])}):",
                "\n".join(res['modified_files']) or "None",
                f"\nNEWLY CREATED FILES ({len(res['created_files'])}):",
                "\n".join(res['created_files']) or "None",
                f"\nDELETED FILES ({len(res['deleted_files'])}):",
                "\n".join(res['deleted_files']) or "None"
            ]
            tag = "danger" if res['integrity_breached'] else "accent"
            self.after(0, lambda: safe_textbox_write(self.tb_fim, "\n".join(lines) + "\n", tag))
        threading.Thread(target=task, daemon=True).start()

    def run_tasks_audit(self):
        safe_textbox_write(self.tb_tasks, "[*] Reading Scheduled Tasks from schtasks...\n", "warning", clear_first=True)
        def task():
            tasks = edr_lite_engine.audit_scheduled_tasks()
            lines = [f"{'TASK NAME':<45} {'NEXT RUN TIME':<22} {'STATUS'}", "─"*85]
            for t in tasks:
                lines.append(f"{t['task_name'][:43]:<45} {t['next_run']:<22} {t['status']}")
            self.after(0, lambda: safe_textbox_write(self.tb_tasks, "\n".join(lines) + "\n", "normal"))
        threading.Thread(target=task, daemon=True).start()

    def run_binary_diff(self):
        pa = self.entry_diff_a.get().strip()
        pb = self.entry_diff_b.get().strip()
        safe_textbox_write(self.tb_diff, f"[*] Comparing {pa} vs {pb}...\n", "warning", clear_first=True)
        def task():
            try:
                res = binary_diff_engine.compare_binaries(pa, pb)
                lines = [
                    f"VERDICT          : {res['similarity_verdict']}",
                    f"HASHES MATCH     : {res['hashes_match']}\n",
                    f"FILE A           : {res['file_a']['name']} ({res['file_a']['arch']})",
                    f"  ├── SHA-256    : {res['file_a']['sha256']}",
                    f"  └── Size       : {res['file_a']['size']} bytes\n",
                    f"FILE B           : {res['file_b']['name']} ({res['file_b']['arch']})",
                    f"  ├── SHA-256    : {res['file_b']['sha256']}",
                    f"  └── Size       : {res['file_b']['size']} bytes\n",
                    f"NEW SUSPICIOUS APIS IN B: {', '.join(res['api_diff']['new_suspicious_in_b']) or 'None'}",
                    f"SECTIONS ADDED IN B     : {', '.join(res['sections_diff']['added_in_b']) or 'None'}"
                ]
                self.after(0, lambda: safe_textbox_write(self.tb_diff, "\n".join(lines) + "\n", "accent"))
            except Exception as e:
                self.after(0, lambda err=str(e): safe_textbox_write(self.tb_diff, f"[!] Diff Error: {err}\n", "danger"))
        threading.Thread(target=task, daemon=True).start()
