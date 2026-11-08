"""
SENTRIX v5.0 — Attack & Incident Graph View
Visualizes correlated event chains with interactive time filtering,
pan-zoom canvas, and an expandable technical details inspector.
"""

import customtkinter as ctk
from typing import Dict, Any, Optional
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_CARD, COLOR_BORDER,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_ACCENT_PRIMARY,
    COLOR_STATE_SUCCESS, COLOR_STATE_WARNING, COLOR_STATE_CRITICAL,
    FONT_TITLE_MD, FONT_BODY_LG, FONT_BODY_MD, FONT_BODY_SM, FONT_CODE_SM,
    BaseWorkspaceView, create_card_frame, create_term_badge
)
from modules.attack_graph.attack_graph_engine import attack_graph_engine
from modules.attack_graph.graph_visualizer import AttackGraphCanvas
from core.translations import tr

class AttackGraphView(BaseWorkspaceView):
    """Incident causality graph view with time-window filtering and deep entity inspector."""

    def __init__(self, parent, main_app):
        super().__init__(parent, main_app, title_tr_key="attack_graph", subtitle_tr_key="attack_graph")
        self.current_time_filter = "24h"
        self.selected_node: Optional[Dict[str, Any]] = None
        self._build_layout()
        self.load_graph()

    def _build_layout(self):
        # Filter chips row
        self.filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.filter_frame.pack(fill="x", padx=16, pady=(0, 8))

        lbl_filter = ctk.CTkLabel(
            self.filter_frame,
            text="Zaman Penceresi:",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY
        )
        lbl_filter.pack(side="left", padx=(0, 8))

        self.time_buttons = {}
        filters = [("1h", "Son 1 saat"), ("24h", "Son 24 saat"), ("7d", "Son 7 gün"), ("all", "Tümü")]
        for key, label in filters:
            btn = ctk.CTkButton(
                self.filter_frame,
                text=label,
                height=26,
                width=80,
                fg_color=COLOR_ACCENT_PRIMARY if key == self.current_time_filter else COLOR_CARD,
                hover_color=COLOR_BORDER,
                font=FONT_BODY_SM,
                corner_radius=13,
                command=lambda k=key: self._on_filter_changed(k)
            )
            btn.pack(side="left", padx=4)
            self.time_buttons[key] = btn

        btn_refresh = ctk.CTkButton(
            self.filter_frame,
            text="Yenile",
            height=26,
            width=70,
            fg_color=COLOR_CARD,
            hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY,
            font=FONT_BODY_SM,
            command=self.load_graph
        )
        btn_refresh.pack(side="right", padx=4)

        # Split Content Frame
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self.content_frame.grid_columnconfigure(0, weight=3)
        self.content_frame.grid_columnconfigure(1, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Left: Visualizer Canvas
        self.canvas_widget = AttackGraphCanvas(self.content_frame, on_node_selected=self._on_node_selected)
        self.canvas_widget.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        # Right: Detail Inspector
        self.inspector_card = create_card_frame(self.content_frame, corner_radius=8)
        self.inspector_card.grid(row=0, column=1, sticky="nsew")
        self._build_inspector()

    def _build_inspector(self):
        lbl_title = ctk.CTkLabel(
            self.inspector_card,
            text="OLAY DETAY PANELİ",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOR_TEXT_SECONDARY
        )
        lbl_title.pack(anchor="w", padx=12, pady=(10, 4))

        self.lbl_node_name = ctk.CTkLabel(
            self.inspector_card,
            text="Bir düğüm seçin",
            font=FONT_TITLE_MD,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.lbl_node_name.pack(anchor="w", padx=12, pady=2)

        self.lbl_node_sub = ctk.CTkLabel(
            self.inspector_card,
            text="Ayrıntıları incelemek için grafikteki bir olaya tıklayın.",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_node_sub.pack(anchor="w", padx=12, pady=(0, 8))

        # Switch for technical details
        self.switch_technical = ctk.CTkSwitch(
            self.inspector_card,
            text="Teknik Ayrıntıları Göster",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY,
            progress_color=COLOR_ACCENT_PRIMARY,
            command=self._update_inspector_details
        )
        self.switch_technical.pack(anchor="w", padx=12, pady=6)

        # Details list frame
        self.details_scroll = ctk.CTkScrollableFrame(self.inspector_card, fg_color=COLOR_BG_MAIN, corner_radius=6)
        self.details_scroll.pack(fill="both", expand=True, padx=10, pady=(6, 10))

    def _on_filter_changed(self, new_filter: str):
        self.current_time_filter = new_filter
        for k, btn in self.time_buttons.items():
            btn.configure(fg_color=COLOR_ACCENT_PRIMARY if k == new_filter else COLOR_CARD)
        self.load_graph()

    def load_graph(self):
        graph_data = attack_graph_engine.build_graph(self.current_time_filter)
        self.canvas_widget.render(graph_data)

    def _on_node_selected(self, node: Dict[str, Any]):
        self.selected_node = node
        self.lbl_node_name.configure(text=node.get("label", "Düğüm"))
        self.lbl_node_sub.configure(text=f"{node.get('type', '')} • {node.get('sublabel', '')}")
        self._update_inspector_details()

    def _update_inspector_details(self):
        # Clear existing
        for child in self.details_scroll.winfo_children():
            child.destroy()

        if not self.selected_node:
            lbl_empty = ctk.CTkLabel(self.details_scroll, text="Seçili olay yok.", font=FONT_BODY_SM, text_color=COLOR_TEXT_SECONDARY)
            lbl_empty.pack(anchor="w", padx=8, pady=8)
            return

        details = self.selected_node.get("details", {})
        show_tech = bool(self.switch_technical.get())

        for k, v in details.items():
            # If not tech mode, filter out raw hashes or commands unless critical
            if not show_tech and k in ["Komut Satırı", "Kanıt", "Ham Veri"]:
                continue

            row = ctk.CTkFrame(self.details_scroll, fg_color="transparent")
            row.pack(fill="x", padx=6, pady=3)

            lbl_k = ctk.CTkLabel(row, text=f"{k}:", font=("Segoe UI", 10, "bold"), text_color=COLOR_ACCENT_PRIMARY)
            lbl_k.pack(anchor="w")

            val_str = str(v)
            lbl_v = ctk.CTkLabel(row, text=val_str, font=FONT_CODE_SM if show_tech else FONT_BODY_SM, text_color=COLOR_TEXT_PRIMARY, wraplength=210, justify="left")
            lbl_v.pack(anchor="w", padx=(6, 0))
