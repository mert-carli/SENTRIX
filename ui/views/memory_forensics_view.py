import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.memory_forensics.volatility_adapter import VolatilityAdapter
from modules.memory_forensics.memory_manager import MemoryManager

class MemoryForensicsWorkspaceView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.vol_adapter = VolatilityAdapter()
        self.mem_manager = MemoryManager()
        self._init_ui()

    def _init_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="MEMORY FORENSICS LAB", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Volatility 3 Integration & Injected Code Analysis", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        bar = ctk.CTkFrame(self, fg_color=COLOR_BG_SECONDARY, border_width=1, border_color=COLOR_BORDER)
        bar.pack(fill="x", padx=20, pady=(0, 10))

        lbl_img = ctk.CTkLabel(bar, text="Memory Image Path:", font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY)
        lbl_img.pack(side="left", padx=(15, 5), pady=10)

        self.entry_img = ctk.CTkEntry(bar, placeholder_text="C:\\Evidence\\memdump.raw", width=340, font=FONT_CODE, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_img.pack(side="left", padx=(0, 15), pady=10)

        self.combo_plugin = ctk.CTkComboBox(
            bar, values=self.vol_adapter.SUPPORTED_PLUGINS,
            width=180, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, font=FONT_CODE
        )
        self.combo_plugin.pack(side="left", padx=(0, 15), pady=10)

        btn_run = ctk.CTkButton(
            bar, text="Run Volatility Plugin", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=170,
            command=self._run_volatility_threaded
        )
        btn_run.pack(side="left", pady=10)

        self.txt_output = ctk.CTkTextbox(self, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_output.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        # Check Volatility installation on load
        stat = self.vol_adapter.check_volatility_installed()
        if stat["available"]:
            self.txt_output.insert("end", f"[+] Volatility 3 detected: {stat['path']}\nReady to analyze memory dumps.\n")
        else:
            self.txt_output.insert("end", f"[-] Volatility 3 Status: {stat['message']}\nInstall Volatility 3 (pip install volatility3) to execute memory plugins.\n")

    def _run_volatility_threaded(self):
        path = self.entry_img.get().strip()
        plugin = self.combo_plugin.get()
        if not path:
            self.txt_output.insert("end", "[!] Specify a memory image path.\n")
            return

        self.txt_output.delete("1.0", "end")
        self.txt_output.insert("end", f"[*] Executing Volatility 3 plugin: {plugin} on {path}...\n")

        def run():
            res = self.vol_adapter.run_plugin(path, plugin)
            self.after(0, lambda: self._render_volatility_output(res))
        threading.Thread(target=run, daemon=True).start()

    def _render_volatility_output(self, res):
        if not res.get("success"):
            self.txt_output.insert("end", f"[-] Plugin Execution Failed: {res.get('error')}\n")
            if res.get("status") == "NOT_INSTALLED":
                self.txt_output.insert("end", "[i] Volatility 3 executable is required for this operation.\n")
            return

        self.txt_output.insert("end", f"[+] Output from {res.get('plugin')}:\n")
        self.txt_output.insert("end", "=" * 70 + "\n")
        self.txt_output.insert("end", res.get("raw_output", "No output returned."))
