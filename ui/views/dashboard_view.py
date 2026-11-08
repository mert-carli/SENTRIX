"""
SENTRIX v5.0 — Executive Cyber Operations Dashboard (Genel Bakış)
Turkish-first interface, 4 status cards, AI security query bar,
recent events list, and quick operational diagnostics.
"""

import threading
import psutil
import customtkinter as ctk
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_CARD, COLOR_BORDER,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_ACCENT_PRIMARY,
    COLOR_STATE_SUCCESS, COLOR_STATE_WARNING, COLOR_STATE_CRITICAL,
    FONT_TITLE_MD, FONT_BODY_LG, FONT_BODY_MD, FONT_BODY_SM, FONT_CODE_SM,
    create_card_frame, create_header, create_button, create_textbox, safe_textbox_write
)
import network_tools
from core.database import db
from modules.ai_analyst.analyst import ai_security_analyst
from modules.ai_security.context_builder import context_builder
from core.translations import tr

class DashboardView(ctk.CTkFrame):
    """Refined v5.0 Executive Dashboard with modern cards and integrated AI Copilot shortcut."""

    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.grid_rowconfigure(3, weight=1)

        # 1. Header
        header = create_header(self, "GENEL GÜVENLİK VE OPERASYON PANELİ")
        header.grid(row=0, column=0, columnspan=4, padx=16, pady=(14, 8), sticky="w")

        # 2. Metric Cards (4 Cards across top)
        self.card_score = self._create_metric_card("SİSTEM DURUMU", "KORUMA AKTİF", COLOR_STATE_SUCCESS, 0)
        self.card_conns = self._create_metric_card("AKTİF CİHAZLAR", "0 Cihaz", COLOR_TEXT_PRIMARY, 1)
        self.card_ports = self._create_metric_card("AÇIK PORTLAR & ZAFİYET", "0 Port / 0 Açık", COLOR_ACCENT_PRIMARY, 2)
        self.card_alerts = self._create_metric_card("SON UYARILAR", "0 Olay", COLOR_STATE_WARNING, 3)

        # 3. AI Quick Prompt Bar
        ai_bar = create_card_frame(self, corner_radius=8)
        ai_bar.grid(row=1, column=0, columnspan=4, padx=16, pady=8, sticky="ew")
        ai_bar.grid_columnconfigure(0, weight=1)

        self.txt_ai_quick = ctk.CTkEntry(
            ai_bar,
            placeholder_text="Güvenlikle ilgili ne öğrenmek istersiniz? (Örn: Bilgisayarım güvenli mi?, 3389 portu nedir?)",
            height=36,
            font=FONT_BODY_MD,
            fg_color=COLOR_BG_MAIN,
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.txt_ai_quick.grid(row=0, column=0, padx=(10, 8), pady=8, sticky="ew")
        self.txt_ai_quick.bind("<Return>", lambda e: self._on_ai_quick_ask())

        btn_ai_ask = ctk.CTkButton(
            ai_bar,
            text="Asistana Sor",
            width=100,
            height=36,
            font=FONT_BODY_MD,
            fg_color=COLOR_ACCENT_PRIMARY,
            hover_color="#3B7AE0",
            text_color="#FFFFFF",
            corner_radius=6,
            command=self._on_ai_quick_ask
        )
        btn_ai_ask.grid(row=0, column=1, padx=(0, 10), pady=8)

        # 4. Action Bar (Quick diagnostics)
        action_bar = ctk.CTkFrame(self, fg_color=COLOR_BG_SECONDARY, border_width=1, border_color=COLOR_BORDER, corner_radius=6)
        action_bar.grid(row=2, column=0, columnspan=4, padx=16, pady=(0, 8), sticky="ew")
        for i in range(5): action_bar.grid_columnconfigure(i, weight=1)

        create_button(action_bar, "KAPSAMLI DENETİM", self.run_audit, is_danger=True).grid(row=0, column=0, padx=4, pady=6, sticky="ew")
        create_button(action_bar, "DIŞ IP SORGULA", self.show_public_ip).grid(row=0, column=1, padx=4, pady=6, sticky="ew")
        create_button(action_bar, "YEREL AĞ & MAC", self.show_local_ip).grid(row=0, column=2, padx=4, pady=6, sticky="ew")
        create_button(action_bar, "DNS AYARLARI", self.show_dns).grid(row=0, column=3, padx=4, pady=6, sticky="ew")
        create_button(action_bar, "BAĞLANTI TESTİ", self.check_internet, is_accent=True).grid(row=0, column=4, padx=4, pady=6, sticky="ew")

        # 5. Split Content (Left: Output & Recent Events, Right: AI Briefing)
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=3, column=0, columnspan=4, padx=16, pady=(0, 14), sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=3)
        content_frame.grid_columnconfigure(1, weight=2)
        content_frame.grid_rowconfigure(0, weight=1)

        # Left Textbox
        self.output_tb = create_textbox(content_frame)
        self.output_tb.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        safe_textbox_write(self.output_tb, "SENTRIX Siber Operasyon Platformu v5.0 Hazır.\nDenetim başlatmak veya asistanı kullanmak için komutları seçebilirsiniz.\n", "accent")

        # Right Briefing Panel
        briefing_frame = create_card_frame(content_frame, corner_radius=8)
        briefing_frame.grid(row=0, column=1, sticky="nsew")
        briefing_frame.grid_rowconfigure(1, weight=1)
        briefing_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(briefing_frame, text="YÖNETİCİ ÖZETİ VE GÜVENLİK DURUMU", font=("Segoe UI", 11, "bold"), text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=12, pady=(10, 6), sticky="w")
        self.briefing_tb = create_textbox(briefing_frame)
        self.briefing_tb.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        self.refresh_briefing()
        self.refresh_metrics()

    def _create_metric_card(self, title: str, value: str, value_color: str, col: int) -> ctk.CTkLabel:
        card = create_card_frame(self, corner_radius=6)
        card.grid(row=0, column=col, padx=(16 if col==0 else 4, 16 if col==3 else 4), pady=(0, 4), sticky="ew")
        
        lbl_title = ctk.CTkLabel(card, text=title, font=("Segoe UI", 9, "bold"), text_color=COLOR_TEXT_SECONDARY)
        lbl_title.pack(padx=12, pady=(8, 2), anchor="w")
        
        lbl_val = ctk.CTkLabel(card, text=value, font=("Segoe UI", 16, "bold"), text_color=value_color)
        lbl_val.pack(padx=12, pady=(0, 8), anchor="w")
        return lbl_val

    def _on_ai_quick_ask(self):
        query = self.txt_ai_quick.get().strip()
        if not query:
            return
        if hasattr(self.main_app, "navigate_to"):
            self.main_app.navigate_to("ai_copilot")
            copilot_view = self.main_app.views.get("ai_copilot")
            if copilot_view and hasattr(copilot_view, "_on_chip_click"):
                copilot_view._on_chip_click(query)

    def refresh_metrics(self):
        try:
            snapshot = context_builder.build_snapshot()
            summ = snapshot["summary"]
            self.card_conns.configure(text=f"{summ['online_hosts']} Aktif Cihaz")
            self.card_ports.configure(text=f"{summ['total_open_ports']} Port / {summ['critical_vulnerabilities']} Zafiyet")
            self.card_alerts.configure(text=f"{summ['recent_alerts_count']} Olay")
            
            if summ["critical_ports_exposed"] > 0 or summ["critical_vulnerabilities"] > 0:
                self.card_score.configure(text="DİKKAT GEREKİYOR", text_color=COLOR_STATE_WARNING)
            else:
                self.card_score.configure(text="KORUMA AKTİF", text_color=COLOR_STATE_SUCCESS)
        except Exception:
            pass

    def refresh_briefing(self):
        briefing = ai_security_analyst.generate_executive_briefing()
        safe_textbox_write(self.briefing_tb, f"DURUM: {briefing['status']}\n\n{briefing['summary']}\n", "normal", clear_first=True)

    def run_audit(self):
        safe_textbox_write(self.output_tb, "\n[*] Kapsamlı Güvenlik ve Tehdit Denetimi Yürütülüyor...\n", "warning")
        def task():
            threat_data = network_tools.get_threat_scan_data()
            self.after(0, lambda: self._display_audit_results(threat_data))
        threading.Thread(target=task, daemon=True).start()

    def _display_audit_results(self, threat_data):
        for line, tag, _ in threat_data:
            safe_textbox_write(self.output_tb, line, tag)
        self.refresh_briefing()
        self.refresh_metrics()

    def show_public_ip(self):
        def task():
            ip = network_tools.get_public_ip()
            self.after(0, lambda: safe_textbox_write(self.output_tb, f"\n[+] DIŞ (PUBLIC) IP ADRESİ: {ip}\n", "accent"))
        threading.Thread(target=task, daemon=True).start()

    def show_local_ip(self):
        def task():
            info = network_tools.get_local_network_info()
            self.after(0, lambda: safe_textbox_write(self.output_tb, f"\n[+] YEREL AĞ BAĞLANTILARI:\n{info}\n", "normal"))
        threading.Thread(target=task, daemon=True).start()

    def show_dns(self):
        def task():
            dns = network_tools.get_dns_settings()
            self.after(0, lambda: safe_textbox_write(self.output_tb, f"\n[+] DNS SUNUCULARI:\n{dns}\n", "normal"))
        threading.Thread(target=task, daemon=True).start()

    def check_internet(self):
        def task():
            res = network_tools.run_ping("8.8.8.8")
            self.after(0, lambda: safe_textbox_write(self.output_tb, f"\n[+] İNTERNET ERİŞİM TESTİ:\n{res}\n", "accent"))
        threading.Thread(target=task, daemon=True).start()
