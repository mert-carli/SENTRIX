import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
import network_tools

class NetworkOpsView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self.arp_monitor = None
        self.traffic_monitor = None
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "NETWORK OPERATIONS, MONITORING & TOPOLOGY")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        # Tabs
        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_scan = self.tabview.add("Network Scanner")
        self.tab_matrix = self.tabview.add("Connection Matrix")
        self.tab_arp = self.tabview.add("ARP Monitor")
        self.tab_traffic = self.tabview.add("Live Traffic")
        self.tab_topo = self.tabview.add("Network Topology")

        self._build_scan_tab()
        self._build_matrix_tab()
        self._build_arp_tab()
        self._build_traffic_tab()
        self._build_topo_tab()

    def _build_scan_tab(self):
        tab = self.tab_scan
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ RUN LOCAL NETWORK SCAN ]", self.run_net_scan, is_accent=True).pack(side="left", padx=5)

        self.tb_scan = create_textbox(tab)
        self.tb_scan.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_scan, "Network Scanner Loaded. Click above to scan local subnet.\n", "accent")

    def _build_matrix_tab(self):
        tab = self.tab_matrix
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")

        filters = ["ALL", "TCP", "UDP", "ESTABLISHED", "LISTENING", "SUSPICIOUS"]
        for f in filters:
            is_danger = (f == "SUSPICIOUS")
            create_button(ctrl, f"[ {f} ]", lambda flt=f: self.run_matrix(flt), is_danger=is_danger).pack(side="left", padx=4)

        self.tb_matrix = create_textbox(tab)
        self.tb_matrix.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_matrix, "Connection Matrix Ready. Select a filter above.\n", "accent")

    def _build_arp_tab(self):
        tab = self.tab_arp
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        self.btn_arp = create_button(ctrl, "[ START ARP SPOOF MONITOR ]", self.toggle_arp, is_danger=True)
        self.btn_arp.pack(side="left", padx=5)
        create_button(ctrl, "[ DHCP / GATEWAY INFO ]", self.show_dhcp).pack(side="left", padx=5)

        self.tb_arp = create_textbox(tab)
        self.tb_arp.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_arp, "ARP Spoofing Detection Center Ready.\n", "accent")

    def _build_traffic_tab(self):
        tab = self.tab_traffic
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        metrics = ctk.CTkFrame(tab, fg_color=COLOR_BG_MAIN, border_width=1, border_color=COLOR_BORDER)
        metrics.grid(row=0, column=0, pady=10, sticky="ew")
        metrics.grid_columnconfigure((0, 1, 2), weight=1)

        self.lbl_dl = ctk.CTkLabel(metrics, text="DOWNLOAD: 0.00 Mbps", font=FONT_TITLE, text_color=COLOR_ACCENT_TERMINAL)
        self.lbl_dl.grid(row=0, column=0, padx=10, pady=10)
        self.lbl_up = ctk.CTkLabel(metrics, text="UPLOAD: 0.00 Mbps", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        self.lbl_up.grid(row=0, column=1, padx=10, pady=10)
        self.lbl_conns = ctk.CTkLabel(metrics, text="ESTABLISHED: 0", font=FONT_TITLE, text_color=COLOR_STATE_WARNING)
        self.lbl_conns.grid(row=0, column=2, padx=10, pady=10)

        self.btn_traffic = create_button(tab, "[ START TRAFFIC MONITOR ]", self.toggle_traffic, is_accent=True)
        self.btn_traffic.grid(row=1, column=0, pady=5, sticky="ew")

        self.tb_traffic = create_textbox(tab)
        self.tb_traffic.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_traffic, "Traffic Monitor Ready.\n", "accent")

    def _build_topo_tab(self):
        tab = self.tab_topo
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        create_button(tab, "[ MAP LOCAL TOPOLOGY ]", self.run_topology, is_accent=True).grid(row=0, column=0, pady=10, sticky="ew")
        self.tb_topo = create_textbox(tab)
        self.tb_topo.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_topo, "Network Topology Mapper Ready.\n", "accent")

    # --- Actions ---
    def run_net_scan(self):
        safe_textbox_write(self.tb_scan, "[*] Scanning local subnet...\n", "warning", clear_first=True)
        def task():
            def cb(msg):
                self.after(0, lambda m=msg: safe_textbox_write(self.tb_scan, m + "\n", "normal"))
            res = network_tools.scan_local_network(progress_callback=cb)
            self.after(0, lambda r=res: safe_textbox_write(self.tb_scan, r, "accent"))
        threading.Thread(target=task, daemon=True).start()

    def run_matrix(self, filter_val: str):
        lines = network_tools.get_connection_matrix(filter_val)
        safe_textbox_write(self.tb_matrix, "", clear_first=True)
        for l, tag, _ in lines:
            safe_textbox_write(self.tb_matrix, l, tag)

    def toggle_arp(self):
        if self.arp_monitor and self.arp_monitor.is_running:
            self.arp_monitor.stop()
            self.btn_arp.configure(text="[ START ARP SPOOF MONITOR ]")
            safe_textbox_write(self.tb_arp, "\n[*] ARP Monitor stopped.\n", "warning")
        else:
            def cb(msg):
                tag = "danger" if "ANOMALİ" in msg or "Spoofing" in msg else "normal"
                self.after(0, lambda m=msg, t=tag: safe_textbox_write(self.tb_arp, m + "\n", t))
            self.arp_monitor = network_tools.ArpMonitor(cb)
            self.arp_monitor.start()
            self.btn_arp.configure(text="[ STOP ARP MONITOR ]")

    def show_dhcp(self):
        info = network_tools.get_dhcp_and_gateway_info()
        safe_textbox_write(self.tb_arp, f"\n[+] DHCP & GATEWAY DETAILS:\n{info}\n", "accent")

    def toggle_traffic(self):
        if self.traffic_monitor and self.traffic_monitor.is_running:
            self.traffic_monitor.stop()
            self.btn_traffic.configure(text="[ START TRAFFIC MONITOR ]")
            safe_textbox_write(self.tb_traffic, "\n[*] Traffic Monitor stopped.\n", "warning")
        else:
            def cb(data):
                def update():
                    self.lbl_dl.configure(text=f"DOWNLOAD: {data['dl_mbps']} Mbps")
                    self.lbl_up.configure(text=f"UPLOAD: {data['up_mbps']} Mbps")
                    self.lbl_conns.configure(text=f"ESTABLISHED: {data['active_count']}")
                    conns_text = "\n".join(data["connections"][:20])
                    safe_textbox_write(self.tb_traffic, conns_text + "\n", "normal", clear_first=True)
                self.after(0, update)
            self.traffic_monitor = network_tools.TrafficMonitor(cb)
            self.traffic_monitor.start()
            self.btn_traffic.configure(text="[ STOP TRAFFIC MONITOR ]")

    def run_topology(self):
        safe_textbox_write(self.tb_topo, "[*] Generating Horizontal Topology...\n", "warning", clear_first=True)
        def task():
            map_lines = network_tools.get_horizontal_network_map()
            for l, _ in map_lines:
                self.after(0, lambda l=l: safe_textbox_write(self.tb_topo, l, "accent"))
        threading.Thread(target=task, daemon=True).start()
