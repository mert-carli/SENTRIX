import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
import network_tools
from modules.correlation.engine import central_correlation_engine
from core.database import db

class ThreatHunterView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self.active_hunt_id = None
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "ACTIVE THREAT HUNTER (IDS) & CENTRAL CORRELATION ENGINE")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_hunt = self.tabview.add("Hunt Operations & Mitigation")
        self.tab_correlate = self.tabview.add("Cross-Module Correlation")

        self._build_hunt_tab()
        self._build_correlate_tab()

    def _build_hunt_tab(self):
        tab = self.tab_hunt
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        grid_btn = ctk.CTkFrame(tab, fg_color="transparent")
        grid_btn.grid(row=0, column=0, pady=10, sticky="ew")
        for i in range(4): grid_btn.grid_columnconfigure(i, weight=1)

        create_button(grid_btn, "[ 1. FAILED LOGINS (4625) ]", lambda: self.run_hunt(1), is_danger=True).grid(row=0, column=0, padx=4, sticky="ew")
        create_button(grid_btn, "[ 2. SUSPICIOUS CONNS ]", lambda: self.run_hunt(2), is_danger=True).grid(row=0, column=1, padx=4, sticky="ew")
        create_button(grid_btn, "[ 3. ROGUE DEVICES (ARP) ]", lambda: self.run_hunt(3), is_danger=True).grid(row=0, column=2, padx=4, sticky="ew")
        create_button(grid_btn, "[ 4. PERMISSIVE FIREWALL ]", lambda: self.run_hunt(4), is_danger=True).grid(row=0, column=3, padx=4, sticky="ew")

        mitigate_frame = ctk.CTkFrame(tab, fg_color="transparent")
        mitigate_frame.grid(row=1, column=0, pady=(0, 10), sticky="ew")
        create_button(mitigate_frame, "[ EXECUTE ACTIVE DEFENSE (MITIGATE THREAT) ]", self.run_mitigation, is_accent=True).pack(fill="x")

        self.tb_hunt = create_textbox(tab)
        self.tb_hunt.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_hunt, "Active Threat Hunter (IDS) Ready. Select an operation above to audit kernel/log telemetry.\n", "accent")

    def _build_correlate_tab(self):
        tab = self.tab_correlate
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ RUN CENTRAL CORRELATION RULES ]", self.run_correlation, is_accent=True).pack(side="left", padx=5)
        create_button(ctrl, "[ VIEW RECORDED ALERTS ]", self.view_alerts).pack(side="left", padx=5)

        self.tb_correlate = create_textbox(tab)
        self.tb_correlate.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_correlate, "Central Detection & Correlation Engine Ready.\n", "accent")

    # --- Actions ---
    def run_hunt(self, hunt_id: int):
        self.active_hunt_id = hunt_id
        safe_textbox_write(self.tb_hunt, f"[*] Executing Hunt Operation #{hunt_id}...\n", "warning", clear_first=True)
        def task():
            lines = network_tools.get_real_threat_hunt(hunt_id)
            for l, tag, _ in lines:
                self.after(0, lambda l=l, t=tag: safe_textbox_write(self.tb_hunt, l, t))
        threading.Thread(target=task, daemon=True).start()

    def run_mitigation(self):
        if not self.active_hunt_id:
            safe_textbox_write(self.tb_hunt, "[!] Select and run a hunt operation before executing mitigation.\n", "warning")
            return
        safe_textbox_write(self.tb_hunt, f"\n[*] Executing mitigation protocol for Hunt #{self.active_hunt_id}...\n", "warning")
        def task():
            lines = network_tools.mitigate_threat(self.active_hunt_id)
            for l, tag, _ in lines:
                self.after(0, lambda l=l, t=tag: safe_textbox_write(self.tb_hunt, l, t))
        threading.Thread(target=task, daemon=True).start()

    def run_correlation(self):
        safe_textbox_write(self.tb_correlate, "[*] Running Central Correlation Engine across sockets and logs...\n", "warning", clear_first=True)
        def task():
            alerts = central_correlation_engine.run_all_correlation_checks()
            lines = [f"[+] Correlation Run Complete. Generated {len(alerts)} alert(s):\n", "─"*75]
            for a in alerts:
                lines.append(f"[{a['severity']}] Alert #{a['id']}: {a['title']}")
            self.after(0, lambda: safe_textbox_write(self.tb_correlate, "\n".join(lines) + "\n", "accent" if alerts else "normal"))
        threading.Thread(target=task, daemon=True).start()

    def view_alerts(self):
        alerts = db.get_recent_alerts(limit=30)
        lines = [f"{'ID':<6} {'SEVERITY':<10} {'TITLE':<45} {'SOURCE'}", "─"*80]
        for a in alerts:
            lines.append(f"{a['id']:<6} {a['severity']:<10} {a['title'][:43]:<45} {a['source']}")
        safe_textbox_write(self.tb_correlate, "\n".join(lines) + "\n", "normal", clear_first=True)
