"""
SENTRIX v5.0 — Live Network Topology View
Interactive star topology map with gateway centering,
device classification badges, and a 4-tab right inspector: Bilgi, Güvenlik, Geçmiş, Aksiyonlar.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, Any, Optional
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_CARD, COLOR_BORDER,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_ACCENT_PRIMARY,
    COLOR_STATE_SUCCESS, COLOR_STATE_WARNING, COLOR_STATE_CRITICAL,
    FONT_TITLE_MD, FONT_BODY_LG, FONT_BODY_MD, FONT_BODY_SM, FONT_CODE_SM,
    BaseWorkspaceView, create_card_frame, create_term_badge
)
from modules.network_topology.topology_engine import network_topology_engine, DeviceStatus
from modules.network_topology.topology_visualizer import NetworkTopologyCanvas
from modules.ai_security.action_guard import action_guard, ActionType, ActionRisk
from core.translations import tr

class NetworkTopologyView(BaseWorkspaceView):
    """Visualizes live LAN assets in a star topology with interactive device inspection."""

    def __init__(self, parent, main_app):
        super().__init__(parent, main_app, title_tr_key="network_map", subtitle_tr_key="network_map")
        self.selected_device: Optional[Dict[str, Any]] = None
        self._build_layout()
        self.load_topology()

    def _build_layout(self):
        # Action Bar
        self.action_bar = ctk.CTkFrame(self, fg_color="transparent")
        self.action_bar.pack(fill="x", padx=16, pady=(0, 8))

        self.btn_refresh = ctk.CTkButton(
            self.action_bar,
            text="Haritayı Yenile",
            height=28,
            width=110,
            fg_color=COLOR_ACCENT_PRIMARY,
            hover_color="#3B7AE0",
            text_color="#FFFFFF",
            font=FONT_BODY_SM,
            command=self.load_topology
        )
        self.btn_refresh.pack(side="left", padx=(0, 8))

        self.lbl_stats = ctk.CTkLabel(
            self.action_bar,
            text="",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_stats.pack(side="left", padx=8)

        # Split Content Frame
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self.content_frame.grid_columnconfigure(0, weight=3)
        self.content_frame.grid_columnconfigure(1, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Left Canvas
        self.canvas_widget = NetworkTopologyCanvas(self.content_frame, on_device_selected=self._on_device_selected)
        self.canvas_widget.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        # Right Inspector Card
        self.inspector_card = create_card_frame(self.content_frame, corner_radius=8)
        self.inspector_card.grid(row=0, column=1, sticky="nsew")
        self._build_device_inspector()

    def _build_device_inspector(self):
        self.lbl_panel_title = ctk.CTkLabel(
            self.inspector_card,
            text="CİHAZ DETAY PANELİ",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_panel_title.pack(anchor="w", padx=12, pady=(10, 4))

        self.lbl_dev_ip = ctk.CTkLabel(
            self.inspector_card,
            text="Bir cihaz seçin",
            font=FONT_TITLE_MD,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.lbl_dev_ip.pack(anchor="w", padx=12, pady=2)

        self.lbl_dev_sub = ctk.CTkLabel(
            self.inspector_card,
            text="Haritadaki bir cihaza tıklayarak ayrıntılarını görebilirsiniz.",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_dev_sub.pack(anchor="w", padx=12, pady=(0, 6))

        # Tab view for Bilgi, Güvenlik, Geçmiş, Aksiyonlar
        self.tabs = ctk.CTkTabview(
            self.inspector_card,
            fg_color=COLOR_BG_MAIN,
            segmented_button_fg_color=COLOR_CARD,
            segmented_button_selected_color=COLOR_ACCENT_PRIMARY,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabs.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        self.tab_info = self.tabs.add("Bilgi")
        self.tab_sec = self.tabs.add("Güvenlik")
        self.tab_hist = self.tabs.add("Geçmiş")
        self.tab_act = self.tabs.add("Aksiyonlar")

    def load_topology(self):
        def _fetch():
            try:
                data = network_topology_engine.build_topology()
                if self.winfo_exists():
                    self.after(0, lambda: self._apply_topology(data))
            except Exception:
                pass

        threading.Thread(target=_fetch, daemon=True).start()

    def _apply_topology(self, data: Dict[str, Any]):
        gw = data.get("gateway", {})
        total = data.get("total_devices", 0)
        self.lbl_stats.configure(text=f"Ağ Geçidi: {gw.get('ip', 'Bilinmiyor')} | Toplam {total} Cihaz Keşfedildi")
        self.canvas_widget.render(data)

    def _on_device_selected(self, device: Dict[str, Any]):
        self.selected_device = device
        self.lbl_dev_ip.configure(text=device.get("ip", "Cihaz"))
        self.lbl_dev_sub.configure(text=f"{device.get('device_type', '')} • {device.get('hostname', '')}")

        # 1. Update Bilgi Tab
        for c in self.tab_info.winfo_children(): c.destroy()
        info_items = [
            ("IP Adresi", device.get("ip")),
            ("Ana Bilgisayar", device.get("hostname")),
            ("MAC Adresi", device.get("mac")),
            ("Üretici", device.get("vendor")),
            ("İşletim Sistemi", device.get("os")),
            ("Cihaz Türü", device.get("device_type")),
            ("Son Görülme", device.get("last_seen", "")[:19])
        ]
        for k, v in info_items:
            row = ctk.CTkFrame(self.tab_info, fg_color="transparent")
            row.pack(fill="x", padx=6, pady=2)
            ctk.CTkLabel(row, text=f"{k}:", font=("Segoe UI", 10, "bold"), text_color=COLOR_ACCENT_PRIMARY).pack(anchor="w")
            ctk.CTkLabel(row, text=str(v or "Bilinmiyor"), font=FONT_BODY_SM, text_color=COLOR_TEXT_PRIMARY, wraplength=190, justify="left").pack(anchor="w")

        # 2. Update Güvenlik Tab
        for c in self.tab_sec.winfo_children(): c.destroy()
        posture = device.get("posture", DeviceStatus.SECURE)
        post_color = COLOR_STATE_CRITICAL if posture == DeviceStatus.CRITICAL else (COLOR_STATE_WARNING if posture == DeviceStatus.WARNING else COLOR_STATE_SUCCESS)

        badge_box = ctk.CTkFrame(self.tab_sec, fg_color=COLOR_CARD, corner_radius=6)
        badge_box.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(badge_box, text=f"GÜVENLİK DURUMU: {posture}", font=("Segoe UI", 11, "bold"), text_color=post_color).pack(padx=8, pady=6)

        ports = device.get("open_ports", [])
        ctk.CTkLabel(self.tab_sec, text=f"Açık Portlar ({len(ports)}):", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=6, pady=(6, 2))

        port_scroll = ctk.CTkScrollableFrame(self.tab_sec, fg_color="transparent", height=120)
        port_scroll.pack(fill="both", expand=True, padx=4, pady=2)

        if not ports:
            ctk.CTkLabel(port_scroll, text="Açık port kaydı yok.", font=FONT_BODY_SM, text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=4)
        else:
            for p in ports:
                p_num = p.get("port")
                svc = p.get("service", "Bilinmiyor")
                is_crit = p_num in [21, 23, 445, 3389]
                p_lbl = ctk.CTkLabel(
                    port_scroll,
                    text=f"• Port {p_num}/TCP - {svc}" + (" [KRİTİK]" if is_crit else ""),
                    font=FONT_BODY_SM,
                    text_color=COLOR_STATE_CRITICAL if is_crit else COLOR_TEXT_PRIMARY
                )
                p_lbl.pack(anchor="w", padx=4, pady=1)

        # 3. Update Geçmiş Tab
        for c in self.tab_hist.winfo_children(): c.destroy()
        diff = device.get("diff", {})
        ctk.CTkLabel(self.tab_hist, text="Tarama Karşılaştırma Analizi:", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=6, pady=(6, 2))
        if not diff.get("has_diff"):
            ctk.CTkLabel(self.tab_hist, text=diff.get("message", "Önceki tarama ile fark tespit edilmedi."), font=FONT_BODY_SM, text_color=COLOR_TEXT_SECONDARY, wraplength=190, justify="left").pack(anchor="w", padx=6)
        else:
            for np in diff.get("new_ports", []):
                ctk.CTkLabel(self.tab_hist, text=f"+ Yeni Açılan: {np['port']} ({np['service']})", font=FONT_BODY_SM, text_color=COLOR_STATE_WARNING).pack(anchor="w", padx=6)
            for cp in diff.get("closed_ports", []):
                ctk.CTkLabel(self.tab_hist, text=f"- Kapanan Port: {cp['port']} ({cp['service']})", font=FONT_BODY_SM, text_color=COLOR_STATE_SUCCESS).pack(anchor="w", padx=6)

        # 4. Update Aksiyonlar Tab
        for c in self.tab_act.winfo_children(): c.destroy()
        ip_target = device.get("ip", "")

        def block_ip_action():
            prop = action_guard.create_proposal(
                action_type=ActionType.BLOCK_FIREWALL_IP,
                target=ip_target,
                description=f"Cihaz {ip_target} trafiğini Güvenlik Duvarında engelle",
                risk_level=ActionRisk.HIGH
            )
            # Switch to Copilot tab or show status
            self.lbl_dev_sub.configure(text=f"Aksiyon oluşturuldu: {prop['action_id']}")

        btn_block = ctk.CTkButton(
            self.tab_act,
            text="Güvenlik Duvarında Engelle",
            height=30,
            fg_color=COLOR_STATE_CRITICAL,
            hover_color="#C0392B",
            font=FONT_BODY_SM,
            command=block_ip_action
        )
        btn_block.pack(fill="x", padx=8, pady=6)

        lbl_hint = ctk.CTkLabel(
            self.tab_act,
            text="Tüm engelleme ve durdurma eylemleri 'Akıllı Asistan' sekmesinde operatör onayına sunulur.",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY,
            wraplength=190,
            justify="left"
        )
        lbl_hint.pack(anchor="w", padx=8, pady=4)
