"""
SENTRIX v5.0 — Attack Graph Visualizer Canvas
Interactive, pan-and-zoom 2D visualizer for the Attack & Incident Graph.
Built directly on Tkinter Canvas within CustomTkinter for high-performance offline rendering.
"""

import tkinter as tk
import customtkinter as ctk
from typing import Dict, Any, List, Optional, Callable
from core.logger import log

class AttackGraphCanvas(ctk.CTkFrame):
    """Interactive visualizer for event causality graphs with pan, zoom, and node inspection."""

    def __init__(self, master, on_node_selected: Optional[Callable[[Dict[str, Any]], None]] = None, **kwargs):
        super().__init__(master, fg_color="#0B111B", corner_radius=8, **kwargs)
        self.on_node_selected = on_node_selected
        
        self.scale = 1.0
        self.offset_x = 0
        self.offset_y = 0
        self.drag_start_x = 0
        self.drag_start_y = 0
        self.selected_node_id: Optional[str] = None

        self.nodes_data: List[Dict[str, Any]] = []
        self.edges_data: List[Dict[str, Any]] = []
        self._node_canvas_items: Dict[str, List[int]] = {}

        self._build_ui()

    def _build_ui(self):
        # Canvas control toolbar (zoom buttons)
        self.toolbar = ctk.CTkFrame(self, fg_color="#111A27", height=36, corner_radius=6)
        self.toolbar.pack(fill="x", padx=6, pady=(6, 2))

        self.lbl_title = ctk.CTkLabel(
            self.toolbar,
            text="SALDIRI VE OLAY İLİŞKİLERİ DİYAGRAMI",
            font=("Segoe UI", 11, "bold"),
            text_color="#94A3B8"
        )
        self.lbl_title.pack(side="left", padx=12)

        self.btn_reset = ctk.CTkButton(
            self.toolbar, text="Sıfırla", width=60, height=24,
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

        # Main TK Canvas
        self.canvas = tk.Canvas(
            self,
            bg="#0B111B",
            highlightthickness=0,
            cursor="fleur"
        )
        self.canvas.pack(fill="both", expand=True, padx=4, pady=4)

        # Mouse event bindings for Pan and Click
        self.canvas.bind("<ButtonPress-1>", self._on_mouse_down)
        self.canvas.bind("<B1-Motion>", self._on_mouse_drag)
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)

    def render(self, graph_data: Dict[str, Any]):
        """Renders nodes and edges on the canvas."""
        self.nodes_data = graph_data.get("nodes", [])
        self.edges_data = graph_data.get("edges", [])
        self.redraw()

    def reset_view(self):
        """Resets zoom and center offset."""
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

        # Check if clicked on a node
        clicked_node = self._find_node_at(event.x, event.y)
        if clicked_node:
            self.selected_node_id = clicked_node["id"]
            self.redraw()
            if self.on_node_selected:
                self.on_node_selected(clicked_node)

    def _on_mouse_drag(self, event):
        dx = event.x - self.drag_start_x
        dy = event.y - self.drag_start_y
        self.offset_x += dx
        self.offset_y += dy
        self.drag_start_x = event.x
        self.drag_start_y = event.y
        self.redraw()

    def _find_node_at(self, screen_x: float, screen_y: float) -> Optional[Dict[str, Any]]:
        """Finds if a screen point lies inside any node card."""
        for node in reversed(self.nodes_data):
            nx = (node.get("x", 0) * self.scale) + self.offset_x
            ny = (node.get("y", 0) * self.scale) + self.offset_y
            nw = node.get("width", 130) * self.scale
            nh = node.get("height", 50) * self.scale
            if nx <= screen_x <= nx + nw and ny <= screen_y <= ny + nh:
                return node
        return None

    def redraw(self):
        """Clears and repaints the entire diagram."""
        self.canvas.delete("all")
        self._node_canvas_items.clear()

        if not self.nodes_data:
            # Draw empty state message
            w = self.canvas.winfo_width() or 600
            h = self.canvas.winfo_height() or 400
            self.canvas.create_text(
                w / 2, h / 2,
                text="Seçilen zaman aralığında aktif saldırı veya olay ilişkisi bulunamadı.\n(Temiz Başlangıç Durumu)",
                fill="#64748B",
                font=("Segoe UI", 12),
                justify="center"
            )
            return

        # 1. Draw Edges (Connecting lines and labels)
        node_lookup = {n["id"]: n for n in self.nodes_data}
        for edge in self.edges_data:
            src = node_lookup.get(edge["from"])
            dst = node_lookup.get(edge["to"])
            if not src or not dst:
                continue

            x1 = (src.get("x", 0) + src.get("width", 130)) * self.scale + self.offset_x
            y1 = (src.get("y", 0) + (src.get("height", 50) / 2)) * self.scale + self.offset_y
            x2 = dst.get("x", 0) * self.scale + self.offset_x
            y2 = (dst.get("y", 0) + (dst.get("height", 50) / 2)) * self.scale + self.offset_y

            edge_color = edge.get("color", "#475569")
            # Connecting arrow
            self.canvas.create_line(
                x1, y1, x2, y2,
                fill=edge_color,
                width=max(1, int(2 * self.scale)),
                arrow=tk.LAST,
                arrowshape=(10 * self.scale, 12 * self.scale, 4 * self.scale)
            )

            # Edge text label
            lbl = edge.get("label", "")
            if lbl:
                mx = (x1 + x2) / 2
                my = (y1 + y2) / 2 - 8
                self.canvas.create_text(
                    mx, my,
                    text=lbl,
                    fill="#94A3B8",
                    font=("Segoe UI", max(8, int(9 * self.scale)))
                )

        # 2. Draw Nodes (Cards)
        for node in self.nodes_data:
            nx = node.get("x", 0) * self.scale + self.offset_x
            ny = node.get("y", 0) * self.scale + self.offset_y
            nw = node.get("width", 130) * self.scale
            nh = node.get("height", 50) * self.scale

            is_selected = (node["id"] == self.selected_node_id)
            bg_card = "#1E2B3E" if is_selected else "#162131"
            border_color = "#4F8FF7" if is_selected else "#263447"
            sev_color = node.get("color", "#94A3B8")

            # Main Card Box
            card = self.canvas.create_rectangle(
                nx, ny, nx + nw, ny + nh,
                fill=bg_card,
                outline=border_color,
                width=2 if is_selected else 1
            )

            # Left color bar indicator for severity
            bar = self.canvas.create_rectangle(
                nx, ny, nx + (4 * self.scale), ny + nh,
                fill=sev_color,
                outline=""
            )

            # Title text
            title_text = self.canvas.create_text(
                nx + (12 * self.scale), ny + (14 * self.scale),
                text=node.get("label", ""),
                anchor="w",
                fill="#E8EDF4",
                font=("Segoe UI", max(9, int(10 * self.scale)), "bold")
            )

            # Sublabel text
            sub_text = self.canvas.create_text(
                nx + (12 * self.scale), ny + (32 * self.scale),
                text=node.get("sublabel", ""),
                anchor="w",
                fill="#94A3B8",
                font=("Segoe UI", max(8, int(9 * self.scale)))
            )

            self._node_canvas_items[node["id"]] = [card, bar, title_text, sub_text]

