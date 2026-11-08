"""
SENTRIX v5.0 — Network Topology Canvas Visualizer
Interactive 2D star topology visualizer.
Provides fluid pan, zoom, gateway centering, and device selection.
"""

import tkinter as tk
import customtkinter as ctk
from typing import Dict, Any, List, Optional, Callable
from core.logger import log

class NetworkTopologyCanvas(ctk.CTkFrame):
    """Visualizes live network devices connected to the default gateway with interactive inspection."""

    def __init__(self, master, on_device_selected: Optional[Callable[[Dict[str, Any]], None]] = None, **kwargs):
        super().__init__(master, fg_color="#0B111B", corner_radius=8, **kwargs)
        self.on_device_selected = on_device_selected

        self.scale = 1.0
        self.offset_x = 0
        self.offset_y = 0
        self.drag_start_x = 0
        self.drag_start_y = 0
        self.selected_device_id: Optional[str] = None

        self.nodes_data: List[Dict[str, Any]] = []
        self.edges_data: List[Dict[str, Any]] = []

        self._build_ui()

    def _build_ui(self):
        # Header toolbar
        self.toolbar = ctk.CTkFrame(self, fg_color="#111A27", height=38, corner_radius=6)
        self.toolbar.pack(fill="x", padx=6, pady=(6, 2))

        self.lbl_title = ctk.CTkLabel(
            self.toolbar,
            text="CANLI AĞ VE CİHAZ TOPOLOJİSİ",
            font=("Segoe UI", 11, "bold"),
            text_color="#94A3B8"
        )
        self.lbl_title.pack(side="left", padx=12)

        self.lbl_notification = ctk.CTkLabel(
            self.toolbar,
            text="",
            font=("Segoe UI", 10),
            text_color="#31B88A"
        )
        self.lbl_notification.pack(side="left", padx=10)

        self.btn_reset = ctk.CTkButton(
            self.toolbar, text="Ortala", width=60, height=24,
            fg_color="#162131", hover_color="#263447", font=("Segoe UI", 10),
            command=self.reset_view
        )
        self.btn_reset.pack(side="right", padx=6)

        self.btn_zoom_out = ctk.CTkButton(
            self.toolbar, text="-", width=30, height=24,
            fg_color="#162131", hover_color="#263447", font=("Segoe UI", 12, "bold"),
            command=lambda: self._apply_zoom(0.85)
        )
        self.btn_zoom_out.pack(side="right", padx=2)

        self.btn_zoom_in = ctk.CTkButton(
            self.toolbar, text="+", width=30, height=24,
            fg_color="#162131", hover_color="#263447", font=("Segoe UI", 12, "bold"),
            command=lambda: self._apply_zoom(1.15)
        )
        self.btn_zoom_in.pack(side="right", padx=2)

        # Canvas
        self.canvas = tk.Canvas(
            self,
            bg="#0B111B",
            highlightthickness=0,
            cursor="fleur"
        )
        self.canvas.pack(fill="both", expand=True, padx=4, pady=4)

        self.canvas.bind("<ButtonPress-1>", self._on_mouse_down)
        self.canvas.bind("<B1-Motion>", self._on_mouse_drag)
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)

    def render(self, topology_data: Dict[str, Any]):
        """Updates topology elements and redraws."""
        self.nodes_data = topology_data.get("nodes", [])
        self.edges_data = topology_data.get("edges", [])
        notif = topology_data.get("notification_msg", "")
        self.lbl_notification.configure(text=notif)
        self.redraw()

    def reset_view(self):
        self.scale = 1.0
        self.offset_x = 0
        self.offset_y = 0
        self.redraw()

    def _apply_zoom(self, factor: float):
        self.scale = max(0.5, min(2.5, self.scale * factor))
        self.redraw()

    def _on_mouse_wheel(self, event):
        factor = 1.1 if event.delta > 0 else 0.9
        self._apply_zoom(factor)

    def _on_mouse_down(self, event):
        self.drag_start_x = event.x
        self.drag_start_y = event.y

        clicked = self._find_node_at(event.x, event.y)
        if clicked:
            self.selected_device_id = clicked["id"]
            self.redraw()
            if self.on_device_selected:
                self.on_device_selected(clicked)

    def _on_mouse_drag(self, event):
        dx = event.x - self.drag_start_x
        dy = event.y - self.drag_start_y
        self.offset_x += dx
        self.offset_y += dy
        self.drag_start_x = event.x
        self.drag_start_y = event.y
        self.redraw()

    def _find_node_at(self, screen_x: float, screen_y: float) -> Optional[Dict[str, Any]]:
        for node in reversed(self.nodes_data):
            nx = (node.get("x", 0) * self.scale) + self.offset_x
            ny = (node.get("y", 0) * self.scale) + self.offset_y
            nw = node.get("width", 110) * self.scale
            nh = node.get("height", 52) * self.scale
            if nx <= screen_x <= nx + nw and ny <= screen_y <= ny + nh:
                return node
        return None

    def redraw(self):
        self.canvas.delete("all")

        if not self.nodes_data:
            w = self.canvas.winfo_width() or 600
            h = self.canvas.winfo_height() or 400
            self.canvas.create_text(
                w / 2, h / 2,
                text="Ağ topolojisinde henüz keşfedilmiş cihaz bulunmuyor.\n'Ağ Taraması' sekmesinden bir keşif taraması başlatabilirsiniz.",
                fill="#64748B",
                font=("Segoe UI", 12),
                justify="center"
            )
            return

        node_lookup = {n["id"]: n for n in self.nodes_data}

        # 1. Draw Star Lines (from Gateway to endpoints)
        for edge in self.edges_data:
            src = node_lookup.get(edge["from"])
            dst = node_lookup.get(edge["to"])
            if not src or not dst:
                continue

            x1 = (src.get("x", 0) + (src.get("width", 110) / 2)) * self.scale + self.offset_x
            y1 = (src.get("y", 0) + (src.get("height", 52) / 2)) * self.scale + self.offset_y
            x2 = (dst.get("x", 0) + (dst.get("width", 110) / 2)) * self.scale + self.offset_x
            y2 = (dst.get("y", 0) + (dst.get("height", 52) / 2)) * self.scale + self.offset_y

            self.canvas.create_line(
                x1, y1, x2, y2,
                fill=edge.get("color", "#263447"),
                width=max(1, int(1.5 * self.scale)),
                dash=(3, 2)
            )

        # 2. Draw Devices
        for node in self.nodes_data:
            nx = node.get("x", 0) * self.scale + self.offset_x
            ny = node.get("y", 0) * self.scale + self.offset_y
            nw = node.get("width", 110) * self.scale
            nh = node.get("height", 52) * self.scale

            is_selected = (node["id"] == self.selected_device_id)
            is_gw = node.get("is_gateway", False)

            bg_card = "#1B2A3D" if is_gw else ("#1E2B3E" if is_selected else "#162131")
            border_color = "#4F8FF7" if is_selected else ("#4F8FF7" if is_gw else "#263447")
            status_color = node.get("color", "#31B88A")

            # Main Card Box
            self.canvas.create_rectangle(
                nx, ny, nx + nw, ny + nh,
                fill=bg_card,
                outline=border_color,
                width=2 if (is_selected or is_gw) else 1
            )

            # Left Color Bar
            self.canvas.create_rectangle(
                nx, ny, nx + (4 * self.scale), ny + nh,
                fill=status_color,
                outline=""
            )

            # Device Type Tag (e.g. [GW], [PC], [SRV])
            self.canvas.create_text(
                nx + (10 * self.scale), ny + (12 * self.scale),
                text=node.get("icon_tag", "[?]"),
                anchor="w",
                fill=status_color,
                font=("Segoe UI", max(8, int(8 * self.scale)), "bold")
            )

            # IP Address
            self.canvas.create_text(
                nx + (34 * self.scale), ny + (12 * self.scale),
                text=node.get("ip", ""),
                anchor="w",
                fill="#E8EDF4",
                font=("Segoe UI", max(9, int(9.5 * self.scale)), "bold")
            )

            # Hostname / Short Vendor
            host_lbl = node.get("hostname", "")
            if host_lbl == "Bilinmiyor":
                host_lbl = node.get("vendor", "")[:12]
            else:
                host_lbl = host_lbl[:14]

            self.canvas.create_text(
                nx + (10 * self.scale), ny + (28 * self.scale),
                text=host_lbl,
                anchor="w",
                fill="#94A3B8",
                font=("Segoe UI", max(8, int(8.5 * self.scale)))
            )

            # Port / Risk Sublabel
            ports_cnt = node.get("open_ports_count", 0)
            port_text = f"{ports_cnt} port açık" if ports_cnt > 0 else "Port taranmadı"
            self.canvas.create_text(
                nx + (10 * self.scale), ny + (42 * self.scale),
                text=port_text,
                anchor="w",
                fill="#64748B" if ports_cnt == 0 else status_color,
                font=("Segoe UI", max(7, int(8 * self.scale)))
            )
