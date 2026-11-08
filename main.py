"""
SENTRIX v5.0 — AKILLI SİBER GÜVENLİK VE OPERASYON PLATFORMU
Windows Native | Red Team | Blue Team | DFIR | Threat Intelligence | AI Copilot
"""

import customtkinter as ctk
import threading
import time
import psutil
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_CARD, COLOR_BORDER,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_ACCENT_PRIMARY,
    COLOR_STATE_SUCCESS, COLOR_STATE_WARNING, COLOR_STATE_CRITICAL,
    FONT_TITLE_MD, FONT_BODY_LG, FONT_BODY_MD, FONT_BODY_SM, FONT_CODE_SM,
    BaseWorkspaceView
)

# Core Views
from ui.views.dashboard_view import DashboardView
from ui.views.recon_view import ReconView
from ui.views.network_ops_view import NetworkOpsView
from ui.views.websec_view import WebSecurityView
from ui.views.wireless_view import WirelessView
from ui.views.forensics_view import ForensicsView
from ui.views.threat_view import ThreatHunterView
from ui.views.enterprise_view import EnterpriseView
from ui.views.reporting_view import ReportingTerminalView
from ui.views.offensive_lab_view import OffensiveLabView
from ui.views.endpoint_sec_view import EndpointSecurityView
from ui.views.detection_ir_view import DetectionIncidentView
from ui.views.automation_toolkit_view import AutomationToolkitView

# v4.0 Views
from ui.views.windows_internals_view import WindowsInternalsView
from ui.views.threat_hunting_view import ThreatHuntingWorkspaceView
from ui.views.detection_studio_view import DetectionStudioView
from ui.views.memory_forensics_view import MemoryForensicsWorkspaceView
from ui.views.cloud_infra_view import CloudInfrastructureView
from ui.views.soar_playbook_view import SOARPlaybookView
from ui.views.specialized_labs_view import SpecializedLabsView

# SENTRIX v5.0 Major Pillar Views
from ui.views.ai_copilot_view import AICopilotView
from ui.views.attack_graph_view import AttackGraphView
from ui.views.network_topology_view import NetworkTopologyView

from core.permission import is_admin, get_privilege_status_str
from core.database import db
from core.task_manager import task_manager
from core.translations import tr
import network_tools

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
ctk.set_widget_scaling(1.0)
ctk.set_window_scaling(1.0)

class SentrixCommandCenterApp(ctk.CTk):
    """SENTRIX v5.0 Central Command Window with Turkish-first navigation and dual view modes."""

    def __init__(self):
        super().__init__()

        self.title("SENTRIX v5.0 — AKILLI SİBER GÜVENLİK VE OPERASYON PLATFORMU")
        self.geometry("1500x940")
        self.minsize(1180, 800)
        self.configure(fg_color=COLOR_BG_MAIN)

        self.is_running = True
        self.current_lang = "TR"
        self.current_view_mode = "basic"  # 'basic' or 'advanced'

        # Main Layout
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_status_bar()
        self._build_views()

        # Telemetry
        threading.Thread(target=self._monitor_system_resources, daemon=True).start()

    def _build_header(self):
        self.header_frame = ctk.CTkFrame(
            self,
            fg_color=COLOR_BG_SECONDARY,
            corner_radius=0,
            border_width=1,
            border_color=COLOR_BORDER,
            height=50
        )
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky="ew")

        # Left Logo
        title_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=16, pady=8)

        lbl_logo = ctk.CTkLabel(
            title_box,
            text="SENTRIX v5.0",
            font=("Segoe UI", 16, "bold"),
            text_color=COLOR_ACCENT_PRIMARY
        )
        lbl_logo.pack(side="left")

        lbl_sub = ctk.CTkLabel(
            title_box,
            text=" // SİBER OPERASYON PLATFORMU",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOR_TEXT_SECONDARY
        )
        lbl_sub.pack(side="left", padx=(6, 0))

        # Command Palette / Global Search
        self.search_entry = ctk.CTkEntry(
            self.header_frame,
            placeholder_text="Genel Arama (Asistan, Harita, Port, CVE, Olay, İşlem, Kural)...",
            font=FONT_BODY_MD,
            width=460,
            height=32,
            fg_color=COLOR_BG_MAIN,
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.search_entry.pack(side="left", padx=20, pady=8)
        self.search_entry.bind("<Return>", lambda e: self._handle_global_search())

        # Right Controls: Privilege & View Mode & Lang
        ctrl_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        ctrl_box.pack(side="right", padx=16, pady=8)

        admin_state = is_admin()
        priv_text = "YÖNETİCİ (ADMIN)" if admin_state else "STANDART KULLANICI"
        priv_color = COLOR_STATE_SUCCESS if admin_state else COLOR_STATE_WARNING
        lbl_priv = ctk.CTkLabel(
            ctrl_box,
            text=f"● {priv_text}",
            font=("Segoe UI", 10, "bold"),
            text_color=priv_color
        )
        lbl_priv.pack(side="left", padx=8)

        # Temel / Gelişmiş Görünüm Toggle
        self.btn_view_mode = ctk.CTkButton(
            ctrl_box,
            text="Temel Görünüm",
            width=115,
            height=28,
            font=FONT_BODY_SM,
            fg_color=COLOR_CARD,
            hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_PRIMARY,
            command=self.toggle_view_mode
        )
        self.btn_view_mode.pack(side="left", padx=6)

        self.btn_lang = ctk.CTkButton(
            ctrl_box,
            text="[ DİL: TR ]",
            width=80,
            height=28,
            font=FONT_BODY_SM,
            fg_color=COLOR_BG_MAIN,
            hover_color=COLOR_BORDER,
            border_width=1,
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY,
            command=self.toggle_language
        )
        self.btn_lang.pack(side="left")

    def _build_sidebar(self):
        self.sidebar_frame = ctk.CTkScrollableFrame(
            self,
            width=265,
            corner_radius=0,
            fg_color="#0D1522",
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.sidebar_frame.grid(row=1, column=0, sticky="nsew")

        self.nav_buttons = {}

        # 5 Categorized Workspaces (v5.0 Architecture)
        self.menu_groups = [
            ("GENEL", [
                ("Dashboard", "Genel Bakış"),
                ("AICopilot", "Akıllı Güvenlik Asistanı"),
                ("DetectionIR", "Bildirimler ve Alarmlar")
            ]),
            ("AĞ VE GÜVENLİK", [
                ("NetworkTopology", "Canlı Ağ Haritası"),
                ("AdvancedRecon", "Ağ Taraması & Keşif"),
                ("NetworkOps", "Ağ Analiz Araçları"),
                ("WebSecurity", "Web Güvenliği & API"),
                ("Wireless", "Kablosuz Ağ Analizi")
            ]),
            ("TEHDİT ANALİZİ", [
                ("AttackGraph", "Saldırı ve Olay Haritası"),
                ("ThreatHunting", "Tehdit Araştırması"),
                ("WindowsInternals", "Sistem İşlemleri & ETW"),
                ("Forensics", "Dijital Adli İnceleme"),
                ("ThreatHunter", "Tehdit İstihbaratı")
            ]),
            ("İLERİ ARAÇLAR", [
                ("MemoryForensics", "Bellek Analizi (Memory)"),
                ("CloudInfrastructure", "Bulut & Konteyner"),
                ("DetectionStudio", "Kural Stüdyosu (YARA/Sigma)"),
                ("SOARPlaybooks", "Otomasyon & Müdahale"),
                ("OffensiveLab", "Zafiyet Araştırması (EPSS)"),
                ("Enterprise", "Active Directory Analizi"),
                ("SpecializedLabs", "Bal Küpü (Honeypot)")
            ]),
            ("YÖNETİM", [
                ("ReportsTerminal", "Raporlar & Yetkili Kapsam"),
                ("AutomationToolkit", "Siber Araç Seti & Kripto")
            ])
        ]

        for group_title, items in self.menu_groups:
            lbl_group = ctk.CTkLabel(
                self.sidebar_frame,
                text=f"─ {group_title} ─",
                font=("Segoe UI", 9, "bold"),
                text_color="#64748B",
                anchor="w"
            )
            lbl_group.pack(fill="x", padx=12, pady=(12, 3))

            for key, label in items:
                btn = ctk.CTkButton(
                    self.sidebar_frame,
                    text=label,
                    font=FONT_BODY_MD,
                    fg_color="transparent",
                    text_color=COLOR_TEXT_PRIMARY,
                    hover_color=COLOR_CARD,
                    anchor="w",
                    height=32,
                    corner_radius=4,
                    command=lambda k=key: self.select_view(k)
                )
                btn.pack(fill="x", padx=8, pady=1)
                self.nav_buttons[key] = btn

    def _build_status_bar(self):
        self.status_bar = ctk.CTkFrame(
            self,
            fg_color=COLOR_BG_MAIN,
            corner_radius=0,
            border_width=1,
            border_color=COLOR_BORDER,
            height=28
        )
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")

        self.lbl_status = ctk.CTkLabel(
            self.status_bar,
            text="SENTRIX v5.0 // SİSTEM KORUMASI AKTİF",
            font=("Segoe UI", 10),
            text_color=COLOR_STATE_SUCCESS
        )
        self.lbl_status.pack(side="left", padx=16, pady=2)

        self.lbl_hw = ctk.CTkLabel(
            self.status_bar,
            text="CPU: 00% | RAM: 00%",
            font=FONT_CODE_SM,
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_hw.pack(side="right", padx=16, pady=2)

    def _build_views(self):
        self.views_container = ctk.CTkFrame(self, fg_color=COLOR_BG_MAIN, corner_radius=0)
        self.views_container.grid(row=1, column=1, sticky="nsew")
        self.views_container.grid_rowconfigure(0, weight=1)
        self.views_container.grid_columnconfigure(0, weight=1)

        self.views = {
            "Dashboard": DashboardView(self.views_container, self),
            "AICopilot": AICopilotView(self.views_container, self),
            "NetworkTopology": NetworkTopologyView(self.views_container, self),
            "AttackGraph": AttackGraphView(self.views_container, self),
            "AdvancedRecon": ReconView(self.views_container, self),
            "NetworkOps": NetworkOpsView(self.views_container, self),
            "WebSecurity": WebSecurityView(self.views_container, self),
            "Wireless": WirelessView(self.views_container, self),
            "OffensiveLab": OffensiveLabView(self.views_container, self),
            "Enterprise": EnterpriseView(self.views_container, self),
            "SpecializedLabs": SpecializedLabsView(self.views_container, self),
            "ThreatHunting": ThreatHuntingWorkspaceView(self.views_container, self),
            "DetectionStudio": DetectionStudioView(self.views_container, self),
            "WindowsInternals": WindowsInternalsView(self.views_container, self),
            "ThreatHunter": ThreatHunterView(self.views_container, self),
            "DetectionIR": DetectionIncidentView(self.views_container, self),
            "MemoryForensics": MemoryForensicsWorkspaceView(self.views_container, self),
            "Forensics": ForensicsView(self.views_container, self),
            "EndpointSecurity": EndpointSecurityView(self.views_container, self),
            "CloudInfrastructure": CloudInfrastructureView(self.views_container, self),
            "SOARPlaybooks": SOARPlaybookView(self.views_container, self),
            "AutomationToolkit": AutomationToolkitView(self.views_container, self),
            "ReportsTerminal": ReportingTerminalView(self.views_container, self)
        }

        # Backwards compatible alias for internal calls
        self.views["ai_copilot"] = self.views["AICopilot"]
        self.views["network_topology"] = self.views["NetworkTopology"]
        self.views["attack_graph"] = self.views["AttackGraph"]

        for key, view in self.views.items():
            if key not in ["ai_copilot", "network_topology", "attack_graph"]:
                view.grid(row=0, column=0, sticky="nsew")
                view.grid_remove()

        # Initial View: Dashboard
        self.select_view("Dashboard")

    def select_view(self, view_key: str):
        # Resolve aliases
        if view_key == "ai_copilot":
            view_key = "AICopilot"
        elif view_key == "network_topology":
            view_key = "NetworkTopology"
        elif view_key == "attack_graph":
            view_key = "AttackGraph"

        for k, btn in self.nav_buttons.items():
            if k == view_key:
                btn.configure(fg_color=COLOR_CARD, text_color=COLOR_ACCENT_PRIMARY)
            else:
                btn.configure(fg_color="transparent", text_color=COLOR_TEXT_PRIMARY)

        for k, view in self.views.items():
            if k == view_key:
                view.grid()
            else:
                view.grid_remove()

    def navigate_to(self, view_key: str):
        """Public navigation hook for views to switch screens."""
        self.select_view(view_key)

    def toggle_view_mode(self):
        """Toggles between Temel Görünüm (simple) and Gelişmiş Görünüm (deep technical)."""
        if self.current_view_mode == "basic":
            self.current_view_mode = "advanced"
            self.btn_view_mode.configure(text="Gelişmiş Görünüm", text_color=COLOR_STATE_WARNING)
        else:
            self.current_view_mode = "basic"
            self.btn_view_mode.configure(text="Temel Görünüm", text_color=COLOR_ACCENT_PRIMARY)

        # Notify active view if it supports toggle_view_mode
        for view in self.views.values():
            if hasattr(view, "toggle_view_mode"):
                try:
                    view.toggle_view_mode(self.current_view_mode)
                except Exception:
                    pass

    def _handle_global_search(self):
        query = self.search_entry.get().strip().lower()
        if not query:
            return

        if any(term in query for term in ["asistan", "ai", "sor", "copilot", "danış"]):
            self.select_view("AICopilot")
        elif any(term in query for term in ["topoloji", "ağ haritası", "cihazlar", "gateway"]):
            self.select_view("NetworkTopology")
        elif any(term in query for term in ["saldırı", "grafik", "olay haritası", "nedensellik", "zincir"]):
            self.select_view("AttackGraph")
        elif any(term in query for term in ["etw", "internals", "sysmon", "eventlog", "işlem"]):
            self.select_view("WindowsInternals")
        elif any(term in query for term in ["hunt", "tehdit", "hipotez"]):
            self.select_view("ThreatHunting")
        elif any(term in query for term in ["sigma", "yara", "kural"]):
            self.select_view("DetectionStudio")
        elif any(term in query for term in ["volatility", "bellek", "memory", "dump", "rwx"]):
            self.select_view("MemoryForensics")
        elif any(term in query for term in ["cloud", "bulut", "aws", "docker", "k8s"]):
            self.select_view("CloudInfrastructure")
        elif any(term in query for term in ["soar", "otomasyon", "playbook"]):
            self.select_view("SOARPlaybooks")
        elif any(term in query for term in ["port", "tarama", "recon"]):
            self.select_view("AdvancedRecon")
        elif any(term in query for term in ["web", "http", "api"]):
            self.select_view("WebSecurity")
        elif any(term in query for term in ["wifi", "kablosuz"]):
            self.select_view("Wireless")
        elif any(term in query for term in ["ad", "ldap", "active directory"]):
            self.select_view("Enterprise")
        elif any(term in query for term in ["adli", "forensic", "pcap"]):
            self.select_view("Forensics")
        else:
            self.select_view("Dashboard")

    def toggle_language(self):
        self.current_lang = "TR" if self.current_lang == "EN" else "EN"
        self.btn_lang.configure(text=f"[ DİL: {self.current_lang} ]" if self.current_lang == "TR" else "[ LANG: EN ]")

    def _monitor_system_resources(self):
        while self.is_running:
            try:
                cpu = psutil.cpu_percent(interval=None)
                ram = psutil.virtual_memory().percent
                self.lbl_hw.configure(text=f"CPU: {cpu:02.0f}% | RAM: {ram:02.0f}%")
            except Exception:
                pass
            time.sleep(2)

    def on_closing(self):
        self.is_running = False
        task_manager.shutdown(wait=False)
        self.destroy()

if __name__ == "__main__":
    app = SentrixCommandCenterApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
