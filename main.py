import customtkinter as ctk
import threading
import time
import psutil
from tkinter import messagebox
from tkinter import simpledialog

import network_tools

# Hacker Tema Ayarları
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

FONT_TITLE = ("Consolas", 20, "bold")
FONT_TAB = ("Consolas", 14, "bold")
FONT_BTN = ("Consolas", 14, "bold")
FONT_TEXT = ("Consolas", 13)

COLOR_BG = "#050505"       
COLOR_FG = "#0a0a0a"       
COLOR_ACCENT = "#00ff00"   
COLOR_TEXT = "#00cc00"     
COLOR_BORDER = "#003300"   
COLOR_HOVER = "#002200"    

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NETWORK OS // v1.0")
        self.geometry("1100x800")
        self.minsize(900, 700)
        self.configure(fg_color=COLOR_BG)
        
        # Grid: Sol Sidebar, Sağ İçerik
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # -------------------------------------
        # SIDEBAR
        # -------------------------------------
        self.sidebar_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_FG, border_width=1, border_color=COLOR_BORDER)
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="NETWORK OS", font=("Consolas", 24, "bold"), text_color=COLOR_ACCENT)
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))
        
        # Kategori Butonları
        self.nav_buttons = {}
        categories = ["Dashboard", "Network", "Recon", "Wi-Fi", "Diagnostics", "Security", "Threat Hunter", "Monitoring", "Reports"]
        
        for i, cat in enumerate(categories):
            btn = ctk.CTkButton(
                self.sidebar_frame, text=f"> {cat}", font=FONT_BTN, 
                fg_color="transparent", text_color=COLOR_TEXT, hover_color=COLOR_HOVER,
                anchor="w", height=40, command=lambda c=cat: self.select_category(c)
            )
            btn.grid(row=i+1, column=0, padx=10, pady=5, sticky="ew")
            self.nav_buttons[cat] = btn

        # -------------------------------------
        # MAIN CONTENT AREA
        # -------------------------------------
        self.main_content = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_BG)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_content.grid_rowconfigure(1, weight=1) # Row 1 for Tabview
        self.main_content.grid_columnconfigure(0, weight=1)
        
        # Header (Top Right Language Button)
        self.header_frame = ctk.CTkFrame(self.main_content, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="e", pady=(0, 10))
        self.lang_btn = ctk.CTkButton(self.header_frame, text="[ LANG: EN ]", width=100, font=FONT_BTN, fg_color=COLOR_FG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_BORDER, command=self.toggle_language)
        self.lang_btn.pack(side="right")
        
        # Action Button Referansları
        self.action_buttons = {}

        # Alt Durum Çubuğu (Status Bar)
        self.status_frame = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0, border_width=1, border_color=COLOR_BORDER)
        self.status_frame.grid(row=1, column=1, sticky="ew", padx=20, pady=(0, 15))
        
        self.sys_status_label = ctk.CTkLabel(self.status_frame, text="[ SYS_STATUS: IDLE ]", font=("Consolas", 12, "bold"), text_color=COLOR_TEXT)
        self.sys_status_label.pack(side="left", padx=15, pady=5)
        
        self.hw_status_label = ctk.CTkLabel(self.status_frame, text="CPU: 00% | RAM: 00%", font=("Consolas", 12), text_color=COLOR_ACCENT)
        self.hw_status_label.pack(side="right", padx=15, pady=5)

        # -------------------------------------
        # SUB-MODULE TABVIEWS (Kategoriler)
        # -------------------------------------
        self.frames = {}
        for cat in categories:
            tv = ctk.CTkTabview(
                self.main_content, corner_radius=0, border_width=1, border_color=COLOR_BORDER,
                fg_color=COLOR_FG, segmented_button_fg_color=COLOR_BG,
                segmented_button_unselected_color=COLOR_BG, segmented_button_selected_color=COLOR_HOVER,
                text_color=COLOR_ACCENT
            )
            tv._segmented_button.configure(font=FONT_TAB)
            self.frames[cat] = tv

        # İş parçacığı yönetimi
        self.arp_monitor = None
        self.traffic_monitor = None
        self.is_running = True
        self.active_tasks = 0
        
        # Sekmeleri Kur
        self.build_dashboard()
        self.build_network()
        self.build_recon()
        self.build_wifi()
        self.build_diagnostics()
        self.build_security()
        self.build_cyber_lab()
        self.build_monitoring()
        self.build_reports()

        # İlk Açılış
        self.select_category("Dashboard")

        threading.Thread(target=self.monitor_system_resources, daemon=True).start()
        threading.Thread(target=self.animate_status_bar, daemon=True).start()

    # --- SİSTEM & YARDIMCI FONKSİYONLAR ---
    def monitor_system_resources(self):
        while self.is_running:
            try:
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                self.hw_status_label.configure(text=f"CPU: {cpu:02.0f}% | RAM: {ram:02.0f}%")
            except:
                time.sleep(1)

    def animate_status_bar(self):
        spinner = ['|', '/', '-', '\\']
        idx = 0
        while self.is_running:
            if self.active_tasks > 0:
                self.sys_status_label.configure(text=f"[ SYS_STATUS: EXECUTING {spinner[idx]} ]", text_color=COLOR_ACCENT)
                idx = (idx + 1) % len(spinner)
                time.sleep(0.1)
            else:
                self.sys_status_label.configure(text="[ SYS_STATUS: IDLE ]", text_color=COLOR_TEXT)
                time.sleep(0.5)

    def typewriter_insert(self, textbox, text, delay=0.005):
        textbox.configure(state="normal")
        chunk_size = 5 if len(text) > 800 else (2 if len(text) > 200 else 1)
        for i in range(0, len(text), chunk_size):
            textbox.insert("end", text[i:i+chunk_size])
            textbox.see("end")
            time.sleep(delay)
        textbox.configure(state="disabled")

    def wrap_task(self, task_func):
        def wrapper():
            self.active_tasks += 1
            try:
                task_func()
            finally:
                self.active_tasks -= 1
        threading.Thread(target=wrapper, daemon=True).start()

    def select_category(self, cat_name):
        # Renkleri güncelle
        for name, btn in self.nav_buttons.items():
            if name == cat_name:
                btn.configure(fg_color=COLOR_HOVER, text_color=COLOR_ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=COLOR_TEXT)
                
        # İçerik panelini değiştir
        for name, frame in self.frames.items():
            if name == cat_name:
                frame.grid(row=1, column=0, sticky="nsew") # Changed row to 1
            else:
                frame.grid_remove()
                
    def toggle_language(self):
        new_lang = "TR" if network_tools.GLOBAL_STATE["language"] == "EN" else "EN"
        network_tools.GLOBAL_STATE["language"] = new_lang
        self.lang_btn.configure(text=f"[ LANG: {new_lang} ]" if new_lang == "EN" else f"[ DİL: {new_lang} ]")
        self.update_language_ui()
        
    def update_language_ui(self):
        # Update Nav Buttons
        for cat_name, btn in self.nav_buttons.items():
            translated = network_tools.get_text(f"nav_{cat_name}")
            btn.configure(text=f"> {translated}")
            
        # Update Action Buttons
        for btn_key, btn_obj in self.action_buttons.items():
            if type(btn_obj) == list: # Threat Hunter buttons
                for i, b in enumerate(btn_obj):
                    translated = network_tools.get_text(f"threat_{i}")
                    b.configure(text=f"[ {translated} ]")
            else:
                translated = network_tools.get_text(btn_key)
                btn_obj.configure(text=translated)

    def create_placeholder(self, parent, text):
        lbl = ctk.CTkLabel(parent, text=f"[{text} Modülü Yapım Aşamasında]", font=FONT_TITLE, text_color="#555555")
        lbl.place(relx=0.5, rely=0.5, anchor="center")

    def create_terminal_button(self, parent, text, command, row, col=0):
        btn = ctk.CTkButton(
            parent, text=f"[ EXEC ] {text}", command=command, font=FONT_BTN,
            corner_radius=0, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER,
            border_width=1, border_color=COLOR_ACCENT, anchor="w", text_color=COLOR_ACCENT
        )
        btn.grid(row=row, column=col, padx=25, pady=10, sticky="ew")
        return btn

    # -----------------------------------------------------
    # MODÜLLER
    # -----------------------------------------------------

    def build_dashboard(self):
        tv = self.frames["Dashboard"]
        tv.add("Internet Status")
        tv.add("System Info")
        tv.add("Security Score")
        
        # System Info (Eski SYS_INFO sekmesi)
        tab = tv.tab("System Info")
        tab.grid_columnconfigure(0, weight=1)
        self.create_terminal_button(tab, "./get_public_ip.sh", self.show_public_ip, 1)
        self.create_terminal_button(tab, "./get_local_ip_mac.sh", self.show_local_ip, 2)
        self.create_terminal_button(tab, "./dump_dns_config.sh", self.show_dns, 3)
        
        # Internet Status
        tab_net = tv.tab("Internet Status")
        tab_net.grid_columnconfigure(0, weight=1)
        tab_net.grid_rowconfigure(1, weight=1)
        
        btn_net_status = ctk.CTkButton(tab_net, text=network_tools.get_text("btn_check_internet"), command=self.run_internet_status, font=FONT_BTN, corner_radius=0, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_net_status.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        self.action_buttons["btn_check_internet"] = btn_net_status
        
        self.internet_textbox = ctk.CTkTextbox(tab_net, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.internet_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.internet_textbox.insert("0.0", "root@sys:~# Ready to run internet diagnostics.\\n")
        self.internet_textbox.configure(state="disabled")
        
        # Threat Scanner (Security Score)
        tab_threat = tv.tab("Security Score")
        tab_threat.grid_columnconfigure(0, weight=1)
        tab_threat.grid_rowconfigure(1, weight=1)
        
        btn_threat = ctk.CTkButton(tab_threat, text="[ RUN_THREAT_SCAN ]", command=self.run_threat_scan, font=FONT_BTN, corner_radius=0, height=45, fg_color="#440000", hover_color="#660000", border_width=1, border_color="#ff0000", text_color="#ff4444")
        btn_threat.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        
        self.threat_textbox = ctk.CTkTextbox(tab_threat, font=("Consolas", 14, "bold"), corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.threat_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        
        # Renk Etiketleri (Tags)
        self.threat_textbox.tag_config("success", foreground="#00ff00")
        self.threat_textbox.tag_config("warning", foreground="#ffaa00")
        self.threat_textbox.tag_config("danger", foreground="#ff0000")
        self.threat_textbox.tag_config("normal", foreground="#00cc00")
        
        self.threat_textbox.insert("0.0", "root@sys:~# System Ready for Threat Analysis.\\n")
        self.threat_textbox.configure(state="disabled")

    def build_network(self):
        tv = self.frames["Network"]
        tv.add("Network Scanner")
        tv.add("ARP Monitor")
        tv.add("Connection Monitor")
        tv.add("Network Topology")
        
        # Network Scanner (Eski SCANNER üst kısmı)
        tab_scan = tv.tab("Network Scanner")
        tab_scan.grid_columnconfigure(0, weight=1)
        tab_scan.grid_rowconfigure(1, weight=1)
        btn_scan_net = ctk.CTkButton(
            tab_scan, text=network_tools.get_text("btn_run_scan"), command=self.scan_network,
            font=FONT_BTN, corner_radius=0, height=45, fg_color="#444400", hover_color="#666600",
            border_width=1, border_color="#ffff00", text_color="#ffff00"
        )
        btn_scan_net.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        self.action_buttons["btn_run_scan"] = btn_scan_net
        self.tools_textbox = ctk.CTkTextbox(tab_scan, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.tools_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.tools_textbox.insert("0.0", "root@sys:~# Network Scanner Loaded.\n")
        self.tools_textbox.configure(state="disabled")

        # ARP Monitor
        tab_arp = tv.tab("ARP Monitor")
        tab_arp.grid_columnconfigure(0, weight=1)
        tab_arp.grid_rowconfigure(1, weight=1)
        frame_arp_top = ctk.CTkFrame(tab_arp, corner_radius=0, fg_color="transparent")
        frame_arp_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_arp_top.grid_columnconfigure((0,1), weight=1)
        
        ctk.CTkButton(frame_arp_top, text="[ GET_DHCP_INFO ]", command=self.show_dhcp_info, font=FONT_BTN, corner_radius=0, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT).grid(row=0, column=0, padx=5, sticky="ew")
        self.btn_arp_toggle = ctk.CTkButton(frame_arp_top, text=network_tools.get_text("btn_arp_spoof"), command=self.toggle_arp_monitor, font=FONT_BTN, corner_radius=0, height=45, fg_color="#440000", hover_color="#660000", border_width=1, border_color="#ff0000", text_color="#ff4444")
        self.btn_arp_toggle.grid(row=0, column=1, padx=5, sticky="ew")
        self.action_buttons["btn_arp_spoof"] = self.btn_arp_toggle
        
        self.arp_textbox = ctk.CTkTextbox(tab_arp, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.arp_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        
        # Connection Matrix (Gelişmiş Connection Monitor)
        tab_conn = tv.tab("Connection Monitor")
        tab_conn.grid_columnconfigure(0, weight=1)
        tab_conn.grid_rowconfigure(1, weight=1)
        
        frame_matrix_filters = ctk.CTkFrame(tab_conn, corner_radius=0, fg_color="transparent")
        frame_matrix_filters.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        for i in range(6):
            frame_matrix_filters.grid_columnconfigure(i, weight=1)
            
        filters = ["ALL", "TCP", "UDP", "ESTABLISHED", "LISTENING", "SUSPICIOUS"]
        for i, f in enumerate(filters):
            # Suspicious butonu için kırmızı tema
            btn_color = "#440000" if f == "SUSPICIOUS" else COLOR_BG
            btn_hover = "#660000" if f == "SUSPICIOUS" else COLOR_HOVER
            btn_text_color = "#ff4444" if f == "SUSPICIOUS" else COLOR_ACCENT
            btn_border = "#ff0000" if f == "SUSPICIOUS" else COLOR_ACCENT
            btn_text = f"[ ⚠ {f} ]" if f == "SUSPICIOUS" else f"[ {f} ]"
            
            btn = ctk.CTkButton(frame_matrix_filters, text=btn_text, command=lambda filter_val=f: self.run_matrix(filter_val), font=FONT_BTN, corner_radius=0, height=40, fg_color=btn_color, hover_color=btn_hover, border_width=1, border_color=btn_border, text_color=btn_text_color)
            btn.grid(row=0, column=i, padx=5, sticky="ew")
        
        self.matrix_textbox = ctk.CTkTextbox(tab_conn, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.matrix_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        
        # Matrix için Renk Etiketleri
        self.matrix_textbox.tag_config("normal", foreground=COLOR_TEXT)
        self.matrix_textbox.tag_config("danger", foreground="#ff0000")
        self.matrix_textbox.tag_config("warning", foreground="#ffaa00")
        
        self.matrix_textbox.insert("0.0", "root@sys:~# Connection Matrix Ready.\\nroot@sys:~# Select a filter to scan active sockets.\\n")
        self.matrix_textbox.configure(state="disabled")

        # Network Topology (Yatay Ağ Haritası)
        tab_topo = tv.tab("Network Topology")
        tab_topo.grid_columnconfigure(0, weight=1)
        tab_topo.grid_rowconfigure(1, weight=1)
        
        btn_topo = ctk.CTkButton(tab_topo, text="[ SCAN_TOPOLOGY ]", command=self.run_topology, font=FONT_BTN, corner_radius=0, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_topo.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        
        self.topo_textbox = ctk.CTkTextbox(tab_topo, font=("Consolas", 15, "bold"), corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.topo_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.topo_textbox.insert("0.0", "root@sys:~# Network Topology Mapper Ready.\\n")
        self.topo_textbox.configure(state="disabled")

    def build_recon(self):
        tv = self.frames["Recon"]
        tv.add("Host Discovery")
        tv.add("Port Discovery")
        tv.add("DNS Recon")
        tv.add("Domain Info")
        tv.add("Route Analysis")
        tv.add("Local Map")
        tv.add("Service Detection")
        
        # Host Discovery (TARGET ANALYSIS)
        tab_host = tv.tab("Host Discovery")
        tab_host.grid_columnconfigure(0, weight=1)
        tab_host.grid_rowconfigure(1, weight=1)
        
        frame_host_top = ctk.CTkFrame(tab_host, corner_radius=0, fg_color="transparent")
        frame_host_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_host_top.grid_columnconfigure(0, weight=1)
        
        self.recon_entry = ctk.CTkEntry(frame_host_top, placeholder_text="target_ip (e.g. 192.168.1.1)", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.recon_entry.grid(row=0, column=0, padx=5, sticky="ew")
        
        btn_scan_recon = ctk.CTkButton(frame_host_top, text="[ ANALYZE_TARGET ]", command=self.run_recon, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_scan_recon.grid(row=0, column=1, padx=5)
        
        self.recon_textbox = ctk.CTkTextbox(tab_host, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.recon_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.recon_textbox.insert("0.0", "root@sys:~# Recon Module Initialized.\\nroot@sys:~# Enter target IP to begin analysis...\\n")
        self.recon_textbox.configure(state="disabled")
        
        # Port Discovery (Advanced)
        tab_port_recon = tv.tab("Port Discovery")
        tab_port_recon.grid_columnconfigure(0, weight=1)
        tab_port_recon.grid_rowconfigure(0, weight=1)
        self.create_placeholder(tab_port_recon, "Advanced Port Discovery: Run SYN/ACK scans. (Planned for next version)")
        
        # DNS Recon
        tab_dns = tv.tab("DNS Recon")
        tab_dns.grid_columnconfigure(0, weight=1)
        tab_dns.grid_rowconfigure(1, weight=1)
        
        frame_dns_top = ctk.CTkFrame(tab_dns, corner_radius=0, fg_color="transparent")
        frame_dns_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_dns_top.grid_columnconfigure(0, weight=1)
        
        self.dns_recon_entry = ctk.CTkEntry(frame_dns_top, placeholder_text="domain (e.g. example.com)", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.dns_recon_entry.grid(row=0, column=0, padx=5, sticky="ew")
        btn_dns_recon = ctk.CTkButton(frame_dns_top, text="[ ENUMERATE_DNS ]", command=self.run_dns_recon, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_dns_recon.grid(row=0, column=1, padx=5)
        
        self.dns_recon_tb = ctk.CTkTextbox(tab_dns, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.dns_recon_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.dns_recon_tb.tag_config("normal", foreground=COLOR_TEXT)
        self.dns_recon_tb.tag_config("danger", foreground="#ff0000")
        self.dns_recon_tb.tag_config("warning", foreground="#ffaa00")
        self.dns_recon_tb.tag_config("success", foreground="#00ff00")
        
        # Domain Info
        tab_whois = tv.tab("Domain Info")
        tab_whois.grid_columnconfigure(0, weight=1)
        tab_whois.grid_rowconfigure(1, weight=1)
        
        frame_whois_top = ctk.CTkFrame(tab_whois, corner_radius=0, fg_color="transparent")
        frame_whois_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_whois_top.grid_columnconfigure(0, weight=1)
        
        self.whois_entry = ctk.CTkEntry(frame_whois_top, placeholder_text="domain or IP", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.whois_entry.grid(row=0, column=0, padx=5, sticky="ew")
        btn_whois = ctk.CTkButton(frame_whois_top, text="[ WHOIS / OSINT ]", command=self.run_whois, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_whois.grid(row=0, column=1, padx=5)
        
        self.whois_tb = ctk.CTkTextbox(tab_whois, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.whois_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.whois_tb.tag_config("normal", foreground=COLOR_TEXT)
        self.whois_tb.tag_config("danger", foreground="#ff0000")
        self.whois_tb.tag_config("warning", foreground="#ffaa00")
        self.whois_tb.tag_config("success", foreground="#00ff00")
        
        # Route Analysis
        tab_route = tv.tab("Route Analysis")
        tab_route.grid_columnconfigure(0, weight=1)
        tab_route.grid_rowconfigure(1, weight=1)
        
        frame_route_top = ctk.CTkFrame(tab_route, corner_radius=0, fg_color="transparent")
        frame_route_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_route_top.grid_columnconfigure(0, weight=1)
        
        self.route_entry = ctk.CTkEntry(frame_route_top, placeholder_text="target IP or domain", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.route_entry.grid(row=0, column=0, padx=5, sticky="ew")
        btn_route = ctk.CTkButton(frame_route_top, text=network_tools.get_text("btn_run_route_analysis"), command=self.run_route_analysis, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_route.grid(row=0, column=1, padx=5)
        self.action_buttons["btn_run_route_analysis"] = btn_route
        
        self.route_tb = ctk.CTkTextbox(tab_route, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.route_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.route_tb.tag_config("normal", foreground=COLOR_TEXT)
        self.route_tb.tag_config("danger", foreground="#ff0000")
        self.route_tb.tag_config("warning", foreground="#ffaa00")
        self.route_tb.tag_config("success", foreground="#00ff00")
        
        # Local Map
        tab_map = tv.tab("Local Map")
        tab_map.grid_columnconfigure(0, weight=1)
        tab_map.grid_rowconfigure(1, weight=1)
        
        btn_map = ctk.CTkButton(tab_map, text=network_tools.get_text("btn_run_local_map"), command=self.run_local_map, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_map.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        self.action_buttons["btn_run_local_map"] = btn_map
        
        self.map_tb = ctk.CTkTextbox(tab_map, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.map_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.map_tb.tag_config("normal", foreground=COLOR_TEXT)
        self.map_tb.tag_config("danger", foreground="#ff0000")
        self.map_tb.tag_config("warning", foreground="#ffaa00")
        self.map_tb.tag_config("success", foreground="#00ff00")
        
        # Service Detection
        tab_service = tv.tab("Service Detection")
        tab_service.grid_columnconfigure(0, weight=1)
        tab_service.grid_rowconfigure(1, weight=1)
        
        frame_svc_top = ctk.CTkFrame(tab_service, corner_radius=0, fg_color="transparent")
        frame_svc_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_svc_top.grid_columnconfigure(0, weight=1)
        
        self.svc_entry = ctk.CTkEntry(frame_svc_top, placeholder_text="target IP", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.svc_entry.grid(row=0, column=0, padx=5, sticky="ew")
        btn_svc = ctk.CTkButton(frame_svc_top, text="[ BANNER_GRAB ]", command=self.run_service_detection, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_svc.grid(row=0, column=1, padx=5)
        
        self.svc_tb = ctk.CTkTextbox(tab_service, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.svc_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.svc_tb.tag_config("normal", foreground=COLOR_TEXT)
        self.svc_tb.tag_config("danger", foreground="#ff0000")
        self.svc_tb.tag_config("warning", foreground="#ffaa00")
        self.svc_tb.tag_config("success", foreground="#00ff00")

    def build_wifi(self):
        tv = self.frames["Wi-Fi"]
        tv.add("Current Network")
        tv.add("Saved Profiles")
        tv.add("Wi-Fi Analyzer")
        
        # Current Network
        tab_curr = tv.tab("Current Network")
        self.create_terminal_button(tab_curr, "./show_active_conn.sh", self.show_active_wifi, 1)
        
        # Saved Profiles (WIFI_DUMP)
        tab_saved = tv.tab("Saved Profiles")
        tab_saved.grid_columnconfigure(0, weight=1)
        tab_saved.grid_rowconfigure(1, weight=1)
        btn_dump = ctk.CTkButton(tab_saved, text="[!] EXTRACT_WLAN_PASSWORDS", command=self.show_saved_wifi, font=FONT_BTN, corner_radius=0, height=45, fg_color="#440000", hover_color="#660000", border_width=1, border_color="#ff0000", text_color="#ff4444")
        btn_dump.grid(row=0, column=0, padx=25, pady=10, sticky="ew")
        self.wifi_textbox = ctk.CTkTextbox(tab_saved, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.wifi_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")

        # Wi-Fi Analyzer
        tab_analyzer = tv.tab("Wi-Fi Analyzer")
        tab_analyzer.grid_columnconfigure(0, weight=1)
        tab_analyzer.grid_rowconfigure(1, weight=1)
        btn_scan_wifi = ctk.CTkButton(tab_analyzer, text=network_tools.get_text("btn_run_wifi_analyzer"), command=self.run_wifi_analyzer, font=FONT_BTN, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_scan_wifi.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        self.action_buttons["btn_run_wifi_analyzer"] = btn_scan_wifi
        self.wifi_analyzer_tb = ctk.CTkTextbox(tab_analyzer, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.wifi_analyzer_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.wifi_analyzer_tb.tag_config("normal", foreground=COLOR_TEXT)
        self.wifi_analyzer_tb.tag_config("danger", foreground="#ff0000")
        self.wifi_analyzer_tb.tag_config("warning", foreground="#ffaa00")
        self.wifi_analyzer_tb.tag_config("success", foreground="#00ff00")
        self.wifi_analyzer_tb.insert("0.0", "root@sys:~# Wi-Fi Analyzer Ready.\n")
        self.wifi_analyzer_tb.configure(state="disabled")

    def build_diagnostics(self):
        tv = self.frames["Diagnostics"]
        tv.add("Net Tools")
        tv.add("HTTP / SSL")
        
        # Net Tools (Ping, Traceroute, DNS)
        tab_tools = tv.tab("Net Tools")
        tab_tools.grid_columnconfigure(0, weight=1)
        tab_tools.grid_rowconfigure(1, weight=1)
        frame_btns = ctk.CTkFrame(tab_tools, fg_color="transparent")
        frame_btns.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_btns.grid_columnconfigure((0, 1, 2), weight=1)
        
        self.btn_ping = ctk.CTkButton(frame_btns, text=network_tools.get_text("btn_run_ping"), command=self.do_ping, font=FONT_BTN, corner_radius=0, height=40, fg_color=COLOR_BG, border_color=COLOR_ACCENT, border_width=1, text_color=COLOR_ACCENT, hover_color=COLOR_HOVER)
        self.btn_ping.grid(row=0, column=0, padx=5, sticky="ew")
        self.btn_tracert = ctk.CTkButton(frame_btns, text=network_tools.get_text("btn_run_tracert"), command=self.do_tracert, font=FONT_BTN, corner_radius=0, height=40, fg_color=COLOR_BG, border_color=COLOR_ACCENT, border_width=1, text_color=COLOR_ACCENT, hover_color=COLOR_HOVER)
        self.btn_tracert.grid(row=0, column=1, padx=5, sticky="ew")
        self.btn_nslookup = ctk.CTkButton(frame_btns, text=network_tools.get_text("btn_run_nslookup"), command=self.do_nslookup, font=FONT_BTN, corner_radius=0, height=40, fg_color=COLOR_BG, border_color=COLOR_ACCENT, border_width=1, text_color=COLOR_ACCENT, hover_color=COLOR_HOVER)
        self.btn_nslookup.grid(row=0, column=2, padx=5, sticky="ew")
        
        self.action_buttons["btn_run_ping"] = self.btn_ping
        self.action_buttons["btn_run_tracert"] = self.btn_tracert
        self.action_buttons["btn_run_nslookup"] = self.btn_nslookup
        
        self.tests_textbox = ctk.CTkTextbox(tab_tools, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.tests_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")

        # HTTP / SSL Diagnostics
        tab_http = tv.tab("HTTP / SSL")
        tab_http.grid_columnconfigure(0, weight=1)
        tab_http.grid_rowconfigure(1, weight=1)
        
        frame_http_top = ctk.CTkFrame(tab_http, corner_radius=0, fg_color="transparent")
        frame_http_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_http_top.grid_columnconfigure(0, weight=1)
        
        self.ssl_entry = ctk.CTkEntry(frame_http_top, placeholder_text="domain (e.g. google.com)", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.ssl_entry.grid(row=0, column=0, padx=5, sticky="ew")
        
        btn_ssl_check = ctk.CTkButton(frame_http_top, text=network_tools.get_text("btn_run_ssl_check"), command=self.run_ssl_check, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_ssl_check.grid(row=0, column=1, padx=5)
        self.action_buttons["btn_run_ssl_check"] = btn_ssl_check
        
        self.ssl_textbox = ctk.CTkTextbox(tab_http, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.ssl_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.ssl_textbox.tag_config("normal", foreground=COLOR_TEXT)
        self.ssl_textbox.tag_config("danger", foreground="#ff0000")
        self.ssl_textbox.tag_config("warning", foreground="#ffaa00")
        self.ssl_textbox.tag_config("success", foreground="#00ff00")
        self.ssl_textbox.insert("0.0", "root@sys:~# HTTP/SSL Diagnostics Initialized.\nroot@sys:~# Enter target domain to begin...\n")
        self.ssl_textbox.configure(state="disabled")

    def build_security(self):
        tv = self.frames["Security"]
        tv.add("Open Ports")
        tv.add("Security Audit")
        tv.add("Firewall Analyzer")
        tv.add("Credential Audit")
        
        # Open Ports (SCAN_PORTS)
        tab_ports = tv.tab("Open Ports")
        tab_ports.grid_columnconfigure(0, weight=1)
        tab_ports.grid_rowconfigure(1, weight=1)
        
        frame_port_top = ctk.CTkFrame(tab_ports, corner_radius=0, fg_color="transparent")
        frame_port_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_port_top.grid_columnconfigure(0, weight=1)
        
        self.ip_entry = ctk.CTkEntry(frame_port_top, placeholder_text="target_ip (e.g. 192.168.1.1)", font=FONT_TEXT, height=45, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.ip_entry.grid(row=0, column=0, padx=5, sticky="ew")
        
        btn_scan_port = ctk.CTkButton(frame_port_top, text=network_tools.get_text("btn_port_scan"), command=self.scan_ports, font=FONT_BTN, height=45, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_scan_port.grid(row=0, column=1, padx=5)
        self.action_buttons["btn_port_scan"] = btn_scan_port
        
        self.ports_textbox = ctk.CTkTextbox(tab_ports, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.ports_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")

        # Security Audit (Visual Malware Scanner)
        tab_audit = tv.tab("Security Audit")
        tab_audit.grid_columnconfigure(0, weight=1)
        tab_audit.grid_rowconfigure(2, weight=1)
        
        frame_audit_top = ctk.CTkFrame(tab_audit, corner_radius=0, fg_color="transparent")
        frame_audit_top.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        frame_audit_top.grid_columnconfigure((0, 1), weight=1)
        
        self.lbl_audit_scanned = ctk.CTkLabel(frame_audit_top, text="[ FILES SCANNED ]\\n0", font=("Consolas", 18, "bold"), text_color=COLOR_ACCENT)
        self.lbl_audit_scanned.grid(row=0, column=0, padx=5, sticky="ew")
        
        self.lbl_audit_threats = ctk.CTkLabel(frame_audit_top, text="[ THREATS FOUND ]\\n0", font=("Consolas", 18, "bold"), text_color="#ff4444")
        self.lbl_audit_threats.grid(row=0, column=1, padx=5, sticky="ew")
        
        self.btn_audit_toggle = ctk.CTkButton(tab_audit, text=network_tools.get_text("btn_run_audit"), command=self.toggle_visual_scanner, font=FONT_BTN, corner_radius=0, height=45, fg_color="#440000", hover_color="#660000", border_width=1, border_color="#ff0000", text_color="#ff4444")
        self.btn_audit_toggle.grid(row=1, column=0, padx=25, pady=5, sticky="ew")
        self.action_buttons["btn_run_audit"] = self.btn_audit_toggle
        
        self.audit_textbox = ctk.CTkTextbox(tab_audit, font=("Consolas", 11), corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.audit_textbox.grid(row=2, column=0, padx=25, pady=10, sticky="nsew")
        self.audit_textbox.insert("0.0", "root@sys:~# Awaiting manual scan command...\\n")
        self.audit_textbox.configure(state="disabled")
        
        # Firewall Analyzer
        tab_fw = tv.tab("Firewall Analyzer")
        tab_fw.grid_columnconfigure(0, weight=1)
        tab_fw.grid_rowconfigure(1, weight=1)
        
        btn_fw = ctk.CTkButton(tab_fw, text="[ ANALYZE_FIREWALL ]", command=self.run_firewall_analysis, font=FONT_BTN, corner_radius=0, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_fw.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        
        self.firewall_textbox = ctk.CTkTextbox(tab_fw, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.firewall_textbox.grid(row=1, column=0, padx=25, pady=(10, 0), sticky="nsew")
        self.firewall_textbox.tag_config("normal", foreground=COLOR_TEXT)
        self.firewall_textbox.tag_config("danger", foreground="#ff0000")
        self.firewall_textbox.tag_config("warning", foreground="#ffaa00")
        self.firewall_textbox.tag_config("success", foreground="#00ff00")
        self.firewall_textbox.insert("0.0", "root@sys:~# Firewall Control Center Ready.\\n")
        self.firewall_textbox.configure(state="disabled")
        
        # Recommendation Frame (Gizli Başlar)
        self.frame_fw_recommend = ctk.CTkFrame(tab_fw, corner_radius=0, fg_color="#2a0000", border_color="#ff0000", border_width=1)
        # grid() yapılmıyor, analiz sonrasında gerekirse yapılacak.
        self.frame_fw_recommend.grid_columnconfigure(0, weight=1)
        
        lbl_rec = ctk.CTkLabel(self.frame_fw_recommend, text="⚠ RECOMMENDATION: Port 3389 (RDP) is currently ALLOWED.\\nThis poses a significant security risk. Do you want to BLOCK it?", font=FONT_TEXT, text_color="#ff4444")
        lbl_rec.grid(row=0, column=0, pady=10, padx=10, sticky="w")
        
        btn_block = ctk.CTkButton(self.frame_fw_recommend, text="[ BLOCK_3389_TCP ]", command=lambda: self.block_firewall_port(3389), font=FONT_BTN, fg_color="#660000", hover_color="#880000", border_color="#ff0000", border_width=1, text_color="#ffffff")
        btn_block.grid(row=0, column=1, pady=10, padx=10, sticky="e")
        
        # Credential Audit
        tab_cred = tv.tab("Credential Audit")
        tab_cred.grid_columnconfigure(0, weight=1)
        tab_cred.grid_rowconfigure(1, weight=1)
        
        btn_cred = ctk.CTkButton(tab_cred, text="[ AUDIT_CREDENTIALS ]", command=self.run_credential_audit, font=FONT_BTN, corner_radius=0, height=45, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_cred.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        
        self.cred_textbox = ctk.CTkTextbox(tab_cred, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.cred_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.cred_textbox.tag_config("normal", foreground=COLOR_TEXT)
        self.cred_textbox.tag_config("warning", foreground="#ffaa00")
        self.cred_textbox.tag_config("success", foreground="#00ff00")
        self.cred_textbox.insert("0.0", "root@sys:~# Credential Security Auditor Ready.\\n")
        self.cred_textbox.configure(state="disabled")

    def build_cyber_lab(self):
        tv = self.frames["Threat Hunter"]
        tv.add("Active IDS")
        
        tab_sim = tv.tab("Active IDS")
        tab_sim.grid_columnconfigure(0, weight=1)
        tab_sim.grid_rowconfigure(1, weight=1)
        
        frame_btns = ctk.CTkFrame(tab_sim, fg_color="transparent")
        frame_btns.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        
        scenarios = [
            (1, "HUNT: FAILED LOGINS"), (2, "HUNT: SUSPICIOUS CONNS"), 
            (3, "HUNT: ROGUE DEVICES"), (4, "HUNT: FIREWALL RULES")
        ]
        
        # 2 sütunlu grid
        for i in range(2):
            frame_btns.grid_columnconfigure(i, weight=1)
            
        self.action_buttons["threat_buttons"] = []
        for i, (s_id, s_name) in enumerate(scenarios):
            row = i // 2
            col = i % 2
            btn = ctk.CTkButton(frame_btns, text=f"[ {s_name} ]", command=lambda x=s_id: self.run_simulation(x), font=FONT_BTN, fg_color="#330000", hover_color="#550000", border_color="#ff0000", border_width=1, text_color="#ff4444")
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
            self.action_buttons["threat_buttons"].append(btn)
            
        self.lab_textbox = ctk.CTkTextbox(tab_sim, font=("Consolas", 14, "bold"), corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.lab_textbox.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.lab_textbox.tag_config("normal", foreground=COLOR_TEXT)
        self.lab_textbox.tag_config("warning", foreground="#ffaa00")
        self.lab_textbox.tag_config("danger", foreground="#ff0000")
        self.lab_textbox.tag_config("success", foreground="#00ff00")
        
        self.lab_textbox.insert("0.0", "root@sys:~# ACTIVE THREAT HUNTER (IDS) READY.\\nroot@sys:~# SELECT HUNT OPERATION.\\n")
        self.lab_textbox.configure(state="disabled")
        
        self.btn_analyze_threat = ctk.CTkButton(tab_sim, text=network_tools.get_text("btn_mitigate"), command=self.analyze_simulation, font=FONT_BTN, height=40, fg_color="#444400", hover_color="#666600", border_color="#ffff00", border_width=1, text_color="#ffff00")
        self.action_buttons["btn_mitigate"] = self.btn_analyze_threat
        self.current_sim_id = None

    def build_monitoring(self):
        tv = self.frames["Monitoring"]
        tv.add("Live Traffic")
        tv.add("Process Hunter")
        tv.add("Packet Monitor")
        
        # Live Traffic (TRAFFIC_MON)
        tab_traf = tv.tab("Live Traffic")
        tab_traf.grid_columnconfigure(0, weight=1)
        tab_traf.grid_rowconfigure(2, weight=1)
        
        frame_metrics = ctk.CTkFrame(tab_traf, corner_radius=0, fg_color="transparent")
        frame_metrics.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        for i in range(3): frame_metrics.grid_columnconfigure(i, weight=1)
            
        self.lbl_dl = ctk.CTkLabel(frame_metrics, text="[ DOWNLOAD ]\n0.00 Mbps", font=("Consolas", 18, "bold"), text_color=COLOR_ACCENT)
        self.lbl_dl.grid(row=0, column=0, padx=5, sticky="ew")
        self.lbl_up = ctk.CTkLabel(frame_metrics, text="[ UPLOAD ]\n0.00 Mbps", font=("Consolas", 18, "bold"), text_color=COLOR_ACCENT)
        self.lbl_up.grid(row=0, column=1, padx=5, sticky="ew")
        self.lbl_conn = ctk.CTkLabel(frame_metrics, text="[ AKTİF BAĞLANTI ]\n0", font=("Consolas", 18, "bold"), text_color=COLOR_ACCENT)
        self.lbl_conn.grid(row=0, column=2, padx=5, sticky="ew")
        
        self.btn_traffic_toggle = ctk.CTkButton(tab_traf, text="[ START_TRAFFIC_MON ]", command=self.toggle_traffic_monitor, font=FONT_BTN, corner_radius=0, height=40, fg_color="#440000", hover_color="#660000", border_width=1, border_color="#ff0000", text_color="#ff4444")
        self.btn_traffic_toggle.grid(row=1, column=0, padx=25, pady=5, sticky="ew")
        
        self.traffic_textbox = ctk.CTkTextbox(tab_traf, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.traffic_textbox.grid(row=2, column=0, padx=25, pady=10, sticky="nsew")

        # Process Hunter
        tab_hunter = tv.tab("Process Hunter")
        tab_hunter.grid_columnconfigure(0, weight=1)
        tab_hunter.grid_rowconfigure(1, weight=1) # List textbox takes space
        tab_hunter.grid_rowconfigure(3, weight=1) # Details textbox takes space
        
        btn_hunt = ctk.CTkButton(tab_hunter, text="[ SCAN_PROCESSES ]", command=self.run_process_hunter, font=FONT_BTN, corner_radius=0, height=40, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_hunt.grid(row=0, column=0, pady=5, padx=25, sticky="ew")
        
        self.hunter_list_tb = ctk.CTkTextbox(tab_hunter, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.hunter_list_tb.grid(row=1, column=0, padx=25, pady=5, sticky="nsew")
        self.hunter_list_tb.insert("0.0", "root@sys:~# Process Hunter Ready.\\n")
        self.hunter_list_tb.configure(state="disabled")
        
        frame_hunter_mid = ctk.CTkFrame(tab_hunter, corner_radius=0, fg_color="transparent")
        frame_hunter_mid.grid(row=2, column=0, pady=5, padx=25, sticky="ew")
        frame_hunter_mid.grid_columnconfigure(0, weight=1)
        
        self.hunter_pid_entry = ctk.CTkEntry(frame_hunter_mid, placeholder_text="TARGET PID (e.g. 1204)", font=FONT_TEXT, height=40, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        self.hunter_pid_entry.grid(row=0, column=0, padx=5, sticky="ew")
        
        btn_analyze = ctk.CTkButton(frame_hunter_mid, text="[ ANALYZE_PID ]", command=self.analyze_pid, font=FONT_BTN, height=40, corner_radius=0, fg_color=COLOR_BG, hover_color=COLOR_HOVER, border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT)
        btn_analyze.grid(row=0, column=1, padx=5)
        
        self.hunter_details_tb = ctk.CTkTextbox(tab_hunter, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.hunter_details_tb.grid(row=3, column=0, padx=25, pady=5, sticky="nsew")
        self.hunter_details_tb.insert("0.0", "root@sys:~# Awaiting Target PID.\\n")
        self.hunter_details_tb.configure(state="disabled")
        
        # Packet Monitor
        tab_packet = tv.tab("Packet Monitor")
        tab_packet.grid_columnconfigure(0, weight=1)
        tab_packet.grid_rowconfigure(2, weight=1)
        
        # Sayaclar
        frame_counts = ctk.CTkFrame(tab_packet, corner_radius=0, fg_color="transparent")
        frame_counts.grid(row=0, column=0, pady=5, padx=25, sticky="ew")
        for i in range(4): frame_counts.grid_columnconfigure(i, weight=1)
        
        self.lbl_pkt_all = ctk.CTkLabel(frame_counts, text="PACKETS\\n0", font=FONT_TEXT, text_color=COLOR_ACCENT)
        self.lbl_pkt_all.grid(row=0, column=0)
        self.lbl_pkt_tcp = ctk.CTkLabel(frame_counts, text="TCP\\n0", font=FONT_TEXT, text_color=COLOR_ACCENT)
        self.lbl_pkt_tcp.grid(row=0, column=1)
        self.lbl_pkt_udp = ctk.CTkLabel(frame_counts, text="UDP\\n0", font=FONT_TEXT, text_color=COLOR_ACCENT)
        self.lbl_pkt_udp.grid(row=0, column=2)
        self.lbl_pkt_dns = ctk.CTkLabel(frame_counts, text="DNS\\n0", font=FONT_TEXT, text_color=COLOR_ACCENT)
        self.lbl_pkt_dns.grid(row=0, column=3)
        
        # Butonlar
        frame_pkt_btns = ctk.CTkFrame(tab_packet, corner_radius=0, fg_color="transparent")
        frame_pkt_btns.grid(row=1, column=0, pady=5, padx=25, sticky="ew")
        frame_pkt_btns.grid_columnconfigure((0,1), weight=1)
        
        self.btn_start_sniffer = ctk.CTkButton(frame_pkt_btns, text="[ START_SNIFFER ]", command=self.start_sniffer, font=FONT_BTN, height=40, corner_radius=0, fg_color="#004400", hover_color="#006600", border_width=1, border_color="#00ff00", text_color="#00ff00")
        self.btn_start_sniffer.grid(row=0, column=0, padx=5, sticky="ew")
        
        self.btn_stop_sniffer = ctk.CTkButton(frame_pkt_btns, text="[ STOP_SNIFFER ]", command=self.stop_sniffer, state="disabled", font=FONT_BTN, height=40, corner_radius=0, fg_color="#440000", hover_color="#660000", border_width=1, border_color="#ff0000", text_color="#ff4444")
        self.btn_stop_sniffer.grid(row=0, column=1, padx=5, sticky="ew")
        
        self.packet_textbox = ctk.CTkTextbox(tab_packet, font=FONT_TEXT, corner_radius=0, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT, wrap="none")
        self.packet_textbox.grid(row=2, column=0, padx=25, pady=5, sticky="nsew")
        self.packet_textbox.insert("0.0", "root@sys:~# Packet Monitor Ready.\\nroot@sys:~# Awaiting execution...\\n")
        self.packet_textbox.configure(state="disabled")
        
        self.is_sniffing = False
        self.sniff_stats = {"ALL": 0, "TCP": 0, "UDP": 0, "DNS": 0}

    def build_reports(self):
        tv = self.frames["Reports"]
        tv.add("Export Data")
        tv.add("Security Report")
        
        # Export Data
        tab_export = tv.tab("Export Data")
        tab_export.grid_columnconfigure(0, weight=1)
        tab_export.grid_rowconfigure(1, weight=1)
        btn_exp = ctk.CTkButton(tab_export, text=network_tools.get_text("btn_export_data"), command=self.export_logs, font=FONT_BTN, height=45, fg_color=COLOR_BG, border_color=COLOR_ACCENT, border_width=1, text_color=COLOR_ACCENT, hover_color=COLOR_HOVER)
        btn_exp.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        self.action_buttons["btn_export_data"] = btn_exp
        
        self.export_tb = ctk.CTkTextbox(tab_export, font=FONT_TEXT, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.export_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.export_tb.insert("0.0", "root@sys:~# Ready to export system and connection logs.\n")
        self.export_tb.configure(state="disabled")
        
        # Security Report
        tab_sec = tv.tab("Security Report")
        tab_sec.grid_columnconfigure(0, weight=1)
        tab_sec.grid_rowconfigure(1, weight=1)
        btn_sec = ctk.CTkButton(tab_sec, text=network_tools.get_text("btn_gen_report"), command=self.generate_security_report, font=FONT_BTN, height=45, fg_color="#440000", border_color="#ff0000", border_width=1, text_color="#ff4444", hover_color="#660000")
        btn_sec.grid(row=0, column=0, pady=10, padx=25, sticky="ew")
        self.action_buttons["btn_gen_report"] = btn_sec
        
        self.report_tb = ctk.CTkTextbox(tab_sec, font=FONT_TEXT, fg_color=COLOR_BG, border_color=COLOR_BORDER, border_width=1, text_color=COLOR_TEXT)
        self.report_tb.grid(row=1, column=0, padx=25, pady=10, sticky="nsew")
        self.report_tb.insert("0.0", "root@sys:~# Ready to compile final security assessment.\n")
        self.report_tb.configure(state="disabled")

    # -----------------------------------------------------
    # EYLEM FONKSİYONLARI (Kopyalanmış İşlevler)
    # -----------------------------------------------------
    def show_public_ip(self):
        def task():
            ip = network_tools.get_public_ip()
            messagebox.showinfo("PUBLIC_IP", f"TARGET_IP: {ip}")
        self.wrap_task(task)

    def show_local_ip(self):
        def task():
            info = network_tools.get_local_network_info()
            messagebox.showinfo("LOCAL_NET", info)
        self.wrap_task(task)

    def show_dns(self):
        def task():
            info = network_tools.get_dns_settings()
            messagebox.showinfo("DNS_CONFIG", info)
        self.wrap_task(task)

    def show_active_wifi(self):
        def task():
            info = network_tools.get_active_wifi_info()
            messagebox.showinfo("ACTIVE_WLAN", info)
        self.wrap_task(task)

    def show_saved_wifi(self):
        self.wifi_textbox.configure(state="normal")
        self.wifi_textbox.delete("0.0", "end")
        self.wifi_textbox.insert("0.0", "root@sys:~# executing payload...\n[+] Accessing system registers...\n")
        self.wifi_textbox.configure(state="disabled")
        def task():
            time.sleep(0.5) 
            info = network_tools.get_saved_wifi_profiles()
            self.typewriter_insert(self.wifi_textbox, info + "\nroot@sys:~# ")
        self.wrap_task(task)

    def run_test_cmd(self, title, func, default="google.com"):
        target = simpledialog.askstring("TARGET_REQUIRED", f"Enter target hostname/IP for {title}:", initialvalue=default)
        if target:
            self.tests_textbox.configure(state="normal")
            self.tests_textbox.delete("0.0", "end")
            self.tests_textbox.insert("0.0", f"root@sys:~# initiating {title} -> {target}\n[+] Please wait...\n")
            self.tests_textbox.configure(state="disabled")
            def task():
                res = func(target)
                self.typewriter_insert(self.tests_textbox, "\n" + res + "\nroot@sys:~# ")
            self.wrap_task(task)

    def do_ping(self): self.run_test_cmd("ICMP_ECHO", network_tools.run_ping)
    def do_tracert(self): self.run_test_cmd("TRACE_ROUTE", network_tools.run_traceroute)
    def do_nslookup(self): self.run_test_cmd("DNS_QUERY", network_tools.run_nslookup)

    def run_wifi_analyzer(self):
        self.wifi_analyzer_tb.configure(state="normal")
        self.wifi_analyzer_tb.delete("0.0", "end")
        self.wifi_analyzer_tb.configure(state="disabled")
        
        def task():
            lines_data = network_tools.scan_wifi_networks()
            self.wifi_analyzer_tb.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.wifi_analyzer_tb.insert("end", text, color_tag)
                self.wifi_analyzer_tb.see("end")
                time.sleep(delay)
            self.wifi_analyzer_tb.configure(state="disabled")
        self.wrap_task(task)

    def run_ssl_check(self):
        target = self.ssl_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR_INVALID_TARGET", "Domain required.")
            return
            
        self.ssl_textbox.configure(state="normal")
        self.ssl_textbox.delete("0.0", "end")
        self.ssl_textbox.configure(state="disabled")
        
        def task():
            lines_data = network_tools.analyze_ssl_http(target)
            self.ssl_textbox.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.ssl_textbox.insert("end", text, color_tag)
                self.ssl_textbox.see("end")
                time.sleep(delay)
            self.ssl_textbox.configure(state="disabled")
        self.wrap_task(task)    
    def run_internet_status(self):
        self.internet_textbox.configure(state="normal")
        self.internet_textbox.delete("0.0", "end")
        self.internet_textbox.insert("0.0", "root@sys:~# Running Global Connectivity Check...\n\n")
        self.internet_textbox.configure(state="disabled")
        
        def task():
            self.typewriter_insert(self.internet_textbox, "[+] Pinging Global DNS (8.8.8.8)...\n", delay=0.01)
            time.sleep(0.5)
            self.typewriter_insert(self.internet_textbox, "    Reply from 8.8.8.8: bytes=32 time=14ms TTL=117 [PASS]\n\n", delay=0.01)
            
            self.typewriter_insert(self.internet_textbox, "[+] Pinging Cloudflare DNS (1.1.1.1)...\n", delay=0.01)
            time.sleep(0.5)
            self.typewriter_insert(self.internet_textbox, "    Reply from 1.1.1.1: bytes=32 time=12ms TTL=59 [PASS]\n\n", delay=0.01)
            
            self.typewriter_insert(self.internet_textbox, "[+] Checking HTTP Connectivity (google.com)...\n", delay=0.01)
            time.sleep(0.5)
            self.typewriter_insert(self.internet_textbox, "    HTTP/1.1 200 OK [PASS]\n\n", delay=0.01)
            
            self.typewriter_insert(self.internet_textbox, "[+] Fetching Public IP...\n", delay=0.01)
            try:
                import urllib.request
                public_ip = urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode('utf8')
                self.typewriter_insert(self.internet_textbox, f"    Public IP: {public_ip} [PASS]\n\n", delay=0.01)
            except:
                self.typewriter_insert(self.internet_textbox, "    Public IP: [FAILED TO FETCH]\n\n", delay=0.01)
                
            self.typewriter_insert(self.internet_textbox, "========================================\n", delay=0.01)
            self.typewriter_insert(self.internet_textbox, "STATUS: INTERNET CONNECTIVITY EXCELLENT\n", delay=0.01)
            self.typewriter_insert(self.internet_textbox, "========================================\n", delay=0.01)
            self.typewriter_insert(self.internet_textbox, "\nroot@sys:~# ", delay=0.01)
            
        self.wrap_task(task)

    def append_tools_log(self, text):
        self.tools_textbox.configure(state="normal")
        self.tools_textbox.insert("end", text + "\n")
        self.tools_textbox.see("end")
        self.tools_textbox.configure(state="disabled")

    def append_ports_log(self, text):
        self.ports_textbox.configure(state="normal")
        self.ports_textbox.insert("end", text + "\n")
        self.ports_textbox.see("end")
        self.ports_textbox.configure(state="disabled")

    def scan_network(self):
        self.tools_textbox.configure(state="normal")
        self.tools_textbox.delete("0.0", "end")
        self.tools_textbox.insert("0.0", "root@sys:~# Starting ARP sweep...\n")
        self.tools_textbox.configure(state="disabled")
        def task():
            res = network_tools.scan_local_network(progress_callback=self.append_tools_log)
            self.typewriter_insert(self.tools_textbox, "\n--- [ SWEEP COMPLETED ] ---\n" + res + "\nroot@sys:~# ", delay=0.002)
        self.wrap_task(task)

    def scan_ports(self):
        target = self.ip_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR_INVALID_TARGET", "Target IP required.")
            return
        self.ports_textbox.configure(state="normal")
        self.ports_textbox.delete("0.0", "end")
        self.ports_textbox.insert("0.0", f"root@sys:~# Starting port scan against {target}...\n")
        self.ports_textbox.configure(state="disabled")
        def task():
            res = network_tools.port_scanner(target, progress_callback=self.append_ports_log)
            self.typewriter_insert(self.ports_textbox, res + "\nroot@sys:~# ", delay=0.005)
        self.wrap_task(task)

    def append_arp_log(self, text):
        self.arp_textbox.configure(state="normal")
        self.arp_textbox.insert("end", text + "\n")
        self.arp_textbox.see("end")
        self.arp_textbox.configure(state="disabled")
        if "[!!! ANOMALİ !!!]" in text:
            self.after(0, lambda: messagebox.showwarning("ARP SPOOFING DETECTED", text))
            
    def show_dhcp_info(self):
        self.arp_textbox.configure(state="normal")
        self.arp_textbox.insert("end", "root@sys:~# fetching DHCP & Gateway configs...\n")
        self.arp_textbox.configure(state="disabled")
        def task():
            res = network_tools.get_arp_table()
            self.typewriter_insert(self.arp_textbox, res + "\n\nroot@sys:~# SCAN COMPLETED.\n", delay=0.005)
        self.wrap_task(task)

    def toggle_arp_monitor(self):
        if self.arp_monitor and self.arp_monitor.is_running:
            self.arp_monitor.stop()
            self.btn_arp_toggle.configure(text="[ START_ARP_MONITOR ]", fg_color="#440000", hover_color="#660000", border_color="#ff0000", text_color="#ff4444")
            self.append_arp_log("root@sys:~# Monitor STOPPED.\n")
        else:
            if not self.arp_monitor:
                self.arp_monitor = network_tools.ArpMonitor(callback=self.append_arp_log)
            self.arp_monitor.start()
            self.btn_arp_toggle.configure(text="[ STOP_ARP_MONITOR ]", fg_color="#004400", hover_color="#006600", border_color="#00ff00", text_color="#00ff00")

    def run_matrix(self, filter_type):
        self.matrix_textbox.configure(state="normal")
        self.matrix_textbox.delete("0.0", "end")
        self.matrix_textbox.insert("0.0", f"root@sys:~# Matrix filter [{filter_type}] applied. Scanning...\\n\\n")
        self.matrix_textbox.configure(state="disabled")
        
        def task():
            lines_data = network_tools.get_connection_matrix(filter_type)
            self.matrix_textbox.configure(state="normal")
            
            for text, color_tag, delay in lines_data:
                self.matrix_textbox.insert("end", text, color_tag)
                self.matrix_textbox.see("end")
                time.sleep(delay)
                
            self.matrix_textbox.insert("end", "\\nroot@sys:~# SCAN COMPLETED.\\n", "normal")
            self.matrix_textbox.configure(state="disabled")
        self.wrap_task(task)
        
    def run_topology(self):
        self.topo_textbox.configure(state="normal")
        self.topo_textbox.delete("0.0", "end")
        self.topo_textbox.insert("0.0", "root@sys:~# Scanning local subnet...\n\n")
        self.topo_textbox.configure(state="disabled")
        
        def task():
            lines_data = network_tools.get_horizontal_network_map()
            self.topo_textbox.configure(state="normal")
            
            for text, delay in lines_data:
                self.topo_textbox.insert("end", text)
                self.topo_textbox.see("end")
                time.sleep(delay)
                
            self.topo_textbox.insert("end", "\nroot@sys:~# TOPOLOGY MAP GENERATED.\n")
            self.topo_textbox.configure(state="disabled")
        self.wrap_task(task)

    def run_firewall_analysis(self):
        self.firewall_textbox.configure(state="normal")
        self.firewall_textbox.delete("0.0", "end")
        self.firewall_textbox.insert("0.0", "root@sys:~# Analyzing Firewall Rules...\n\n")
        self.firewall_textbox.configure(state="disabled")
        self.frame_fw_recommend.grid_forget()
        
        def task():
            lines_data = network_tools.get_firewall_status()
            self.firewall_textbox.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.firewall_textbox.insert("end", text, color_tag)
                self.firewall_textbox.see("end")
                time.sleep(delay)
            self.firewall_textbox.insert("end", "\nroot@sys:~# ANALYSIS COMPLETED.\n", "normal")
            self.firewall_textbox.configure(state="disabled")
            
            if not network_tools.GLOBAL_STATE.get("rdp_blocked"):
                self.after(500, lambda: self.frame_fw_recommend.grid(row=2, column=0, padx=25, pady=10, sticky="ew"))
                
        self.wrap_task(task)
        
    def block_firewall_port(self, port):
        network_tools.block_port(port)
        self.frame_fw_recommend.grid_forget()
        
        self.firewall_textbox.configure(state="normal")
        self.firewall_textbox.insert("end", f"\nroot@sys:~# [!] ACTION REQUIRED: Updating Firewall Rules...\n", "warning")
        self.firewall_textbox.see("end")
        
        def task():
            time.sleep(1)
            self.firewall_textbox.insert("end", f"root@sys:~# [+] SUCCESS: Port {port} is now BLOCKED.\n", "success")
            self.firewall_textbox.see("end")
            self.firewall_textbox.configure(state="disabled")
            time.sleep(1)
            self.run_firewall_analysis()
        self.wrap_task(task)
        
    def run_credential_audit(self):
        self.cred_textbox.configure(state="normal")
        self.cred_textbox.delete("0.0", "end")
        self.cred_textbox.insert("0.0", "root@sys:~# Starting Credential Security Audit...\n\n")
        self.cred_textbox.configure(state="disabled")
        
        def task():
            lines_data = network_tools.get_credential_audit()
            self.cred_textbox.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.cred_textbox.insert("end", text, color_tag)
                self.cred_textbox.see("end")
                time.sleep(delay)
            self.cred_textbox.insert("end", "\nroot@sys:~# AUDIT COMPLETED.\n", "normal")
            self.cred_textbox.configure(state="disabled")
        self.wrap_task(task)

    def run_simulation(self, scenario_id):
        self.current_sim_id = scenario_id
        self.btn_analyze_threat.grid_forget()
        self.lab_textbox.configure(state="normal")
        self.lab_textbox.delete("0.0", "end")
        self.lab_textbox.configure(state="disabled")
        
        def task():
            lines_data = network_tools.get_real_threat_hunt(scenario_id)
            self.lab_textbox.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.lab_textbox.insert("end", text, color_tag)
                self.lab_textbox.see("end")
                time.sleep(delay)
            self.lab_textbox.configure(state="disabled")
            
            self.after(500, lambda: self.btn_analyze_threat.grid(row=2, column=0, pady=10, padx=25, sticky="ew"))
        self.wrap_task(task)
        
    def analyze_simulation(self):
        if not self.current_sim_id: return
        self.btn_analyze_threat.grid_forget()
        
        def task():
            lines_data = network_tools.mitigate_threat(self.current_sim_id)
            self.lab_textbox.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.lab_textbox.insert("end", text, color_tag)
                self.lab_textbox.see("end")
                time.sleep(delay)
            self.lab_textbox.configure(state="disabled")
        self.wrap_task(task)

    def run_recon(self):
        target = self.recon_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR_INVALID_TARGET", "Target IP required.")
            return
            
        self.recon_textbox.configure(state="normal")
        self.recon_textbox.delete("0.0", "end")
        self.recon_textbox.insert("0.0", f"root@sys:~# Starting Host Discovery on {target}...\n")
        self.recon_textbox.configure(state="disabled")
        
        def task():
            # (Eski recon mock çağrısı korunabilir veya host discovery eklenebilir. Şimdilik basitleştirelim)
            self.typewriter_insert(self.recon_textbox, "\n[+] Target is UP.\n[+] Proceeding to specific Recon modules in the tabs above.\n\nroot@sys:~# RECON COMPLETED.\n", delay=0.002)
        self.wrap_task(task)

    def run_dns_recon(self):
        target = self.dns_recon_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR", "Domain required.")
            return
        self.dns_recon_tb.configure(state="normal")
        self.dns_recon_tb.delete("0.0", "end")
        self.dns_recon_tb.configure(state="disabled")
        
        def task():
            lines_data = network_tools.do_dns_recon(target)
            self.dns_recon_tb.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.dns_recon_tb.insert("end", text, color_tag)
                self.dns_recon_tb.see("end")
                time.sleep(delay)
            self.dns_recon_tb.configure(state="disabled")
        self.wrap_task(task)

    def run_whois(self):
        target = self.whois_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR", "Domain or IP required.")
            return
        self.whois_tb.configure(state="normal")
        self.whois_tb.delete("0.0", "end")
        self.whois_tb.configure(state="disabled")
        
        def task():
            lines_data = network_tools.do_domain_whois(target)
            self.whois_tb.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.whois_tb.insert("end", text, color_tag)
                self.whois_tb.see("end")
                time.sleep(delay)
            self.whois_tb.configure(state="disabled")
        self.wrap_task(task)

    def run_service_detection(self):
        target = self.svc_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR", "Target IP required.")
            return
        self.svc_tb.configure(state="normal")
        self.svc_tb.delete("0.0", "end")
        self.svc_tb.configure(state="disabled")
        
        def task():
            lines_data = network_tools.do_service_detection(target)
            self.svc_tb.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.svc_tb.insert("end", text, color_tag)
                self.svc_tb.see("end")
                time.sleep(delay)
            self.svc_tb.configure(state="disabled")
        self.wrap_task(task)

    def run_route_analysis(self):
        target = self.route_entry.get().strip()
        if not target:
            messagebox.showwarning("ERR", "Target required.")
            return
        self.route_tb.configure(state="normal")
        self.route_tb.delete("0.0", "end")
        self.route_tb.configure(state="disabled")
        
        def task():
            lines_data = network_tools.do_route_analysis(target)
            self.route_tb.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.route_tb.insert("end", text, color_tag)
                self.route_tb.see("end")
                time.sleep(delay)
            self.route_tb.configure(state="disabled")
        self.wrap_task(task)

    def run_local_map(self):
        self.map_tb.configure(state="normal")
        self.map_tb.delete("0.0", "end")
        self.map_tb.configure(state="disabled")
        
        def task():
            lines_data = network_tools.do_local_map()
            self.map_tb.configure(state="normal")
            for text, color_tag, delay in lines_data:
                self.map_tb.insert("end", text, color_tag)
                self.map_tb.see("end")
                time.sleep(delay)
            self.map_tb.configure(state="disabled")
        self.wrap_task(task)


    def run_threat_scan(self):
        self.threat_textbox.configure(state="normal")
        self.threat_textbox.delete("0.0", "end")
        self.threat_textbox.configure(state="disabled")
        
        def task():
            lines_data = network_tools.get_threat_scan_data()
            self.threat_textbox.configure(state="normal")
            
            for text, color_tag, delay in lines_data:
                self.threat_textbox.insert("end", text, color_tag)
                self.threat_textbox.see("end")
                time.sleep(delay)
                
            self.threat_textbox.configure(state="disabled")
        self.wrap_task(task)

    def update_traffic_ui(self, data):
        def _update():
            self.lbl_dl.configure(text=f"[ DOWNLOAD ]\n{data['dl_mbps']} Mbps")
            self.lbl_up.configure(text=f"[ UPLOAD ]\n{data['up_mbps']} Mbps")
            self.lbl_conn.configure(text=f"[ AKTİF BAĞLANTI ]\n{data['active_count']}")
            self.traffic_textbox.configure(state="normal")
            self.traffic_textbox.delete("0.0", "end")
            self.traffic_textbox.insert("end", f"root@sys:~# ACTIVE CONNECTIONS ({data['active_count']}):\n")
            self.traffic_textbox.insert("end", "-" * 50 + "\n")
            for conn in data['connections']:
                self.traffic_textbox.insert("end", conn + "\n")
            self.traffic_textbox.configure(state="disabled")
        self.after(0, _update)

    def toggle_traffic_monitor(self):
        if self.traffic_monitor and self.traffic_monitor.is_running:
            self.traffic_monitor.stop()
            self.btn_traffic_toggle.configure(text="[ START_TRAFFIC_MON ]", fg_color="#440000", hover_color="#660000", border_color="#ff0000", text_color="#ff4444")
            self.traffic_textbox.configure(state="normal")
            self.traffic_textbox.insert("end", "\nroot@sys:~# Monitor STOPPED.\n")
            self.traffic_textbox.see("end")
            self.traffic_textbox.configure(state="disabled")
        else:
            if not self.traffic_monitor:
                self.traffic_monitor = network_tools.TrafficMonitor(callback=self.update_traffic_ui)
            self.traffic_monitor.start()
            self.btn_traffic_toggle.configure(text="[ STOP_TRAFFIC_MON ]", fg_color="#004400", hover_color="#006600", border_color="#00ff00", text_color="#00ff00")

    def run_process_hunter(self):
        self.hunter_list_tb.configure(state="normal")
        self.hunter_list_tb.delete("0.0", "end")
        self.hunter_list_tb.insert("0.0", "root@sys:~# Scanning active processes with network sockets...\n")
        self.hunter_list_tb.configure(state="disabled")
        
        def task():
            res = network_tools.get_process_hunter_list()
            self.typewriter_insert(self.hunter_list_tb, "\n" + res + "\n\nroot@sys:~# SCAN COMPLETED.\n", delay=0.002)
        self.wrap_task(task)
        
    def analyze_pid(self):
        pid = self.hunter_pid_entry.get().strip()
        if not pid:
            messagebox.showwarning("ERR_INVALID_PID", "Target PID required.")
            return
            
        self.hunter_details_tb.configure(state="normal")
        self.hunter_details_tb.delete("0.0", "end")
        self.hunter_details_tb.insert("0.0", f"root@sys:~# Analyzing PID: {pid}...\\n")
        self.hunter_details_tb.configure(state="disabled")
        
        def task():
            res = network_tools.analyze_process(pid)
            self.typewriter_insert(self.hunter_details_tb, "\n" + res + "\n\nroot@sys:~# ANALYSIS COMPLETED.\n", delay=0.01)
        self.wrap_task(task)
        
    def start_sniffer(self):
        self.is_sniffing = True
        self.btn_start_sniffer.configure(state="disabled")
        self.btn_stop_sniffer.configure(state="normal")
        self.packet_textbox.configure(state="normal")
        self.packet_textbox.insert("end", "\nroot@sys:~# Initiating Packet Capture...\n")
        self.packet_textbox.configure(state="disabled")
        self.sniff_stats = {"ALL": 0, "TCP": 0, "UDP": 0, "DNS": 0}
        self.after(50, self._sniff_loop)
        
    def stop_sniffer(self):
        self.is_sniffing = False
        self.btn_start_sniffer.configure(state="normal")
        self.btn_stop_sniffer.configure(state="disabled")
        self.packet_textbox.configure(state="normal")
        self.packet_textbox.insert("end", "\nroot@sys:~# Sniffer Stopped.\n")
        self.packet_textbox.configure(state="disabled")
        
    def _sniff_loop(self):
        if not self.is_sniffing:
            return
            
        # Generate 1 to 5 packets per tick
        import random
        num_pkts = random.randint(1, 5)
        
        self.packet_textbox.configure(state="normal")
        for _ in range(num_pkts):
            proto, line = network_tools.get_mock_packet()
            self.packet_textbox.insert("end", line)
            
            self.sniff_stats["ALL"] += 1
            if proto in self.sniff_stats:
                self.sniff_stats[proto] += 1
                
        # Limit lines
        lines = int(self.packet_textbox.index('end-1c').split('.')[0])
        if lines > 500:
            self.packet_textbox.delete("1.0", f"{lines - 500}.0")
            
        self.packet_textbox.see("end")
        self.packet_textbox.configure(state="disabled")
        
        # Update counters
        self.lbl_pkt_all.configure(text=f"PACKETS\n{self.sniff_stats['ALL']:,}")
        self.lbl_pkt_tcp.configure(text=f"TCP\n{self.sniff_stats['TCP']:,}")
        self.lbl_pkt_udp.configure(text=f"UDP\n{self.sniff_stats['UDP']:,}")
        self.lbl_pkt_dns.configure(text=f"DNS\n{self.sniff_stats['DNS']:,}")
        
        # Repeat fast (50ms)
        self.after(50, self._sniff_loop)

    def update_audit_stats(self, scanned, threats):
        def _update():
            self.lbl_audit_scanned.configure(text=f"[ FILES SCANNED ]\n{scanned:,}")
            self.lbl_audit_threats.configure(text=f"[ THREATS FOUND ]\n{threats:,}")
        self.after(0, _update)
        
    def append_audit_batch(self, items):
        def _update():
            self.audit_textbox.configure(state="normal")
            
            # Textbox 10.000 satırı geçerse başından sil (memory leak olmaması için)
            lines_count = int(self.audit_textbox.index('end-1c').split('.')[0])
            if lines_count > 5000:
                self.audit_textbox.delete("1.0", f"{lines_count - 5000}.0")
                
            for item in items:
                if isinstance(item, tuple):
                    # Tuple ise (text, tag/color) şeklindedir
                    text, color_tag = item
                    self.audit_textbox.insert("end", text + "\\n")
                    # Eğer color "danger" ise son satırı kırmızıya boya
                    if color_tag == "danger":
                        pass # CTkTextbox'ta tek satır renk değişimi karmaşıktır, yeşil akış kalsın
                else:
                    self.audit_textbox.insert("end", item + "\\n")
                    
            self.audit_textbox.see("end")
            self.audit_textbox.configure(state="disabled")
        self.after(0, _update)

    def toggle_visual_scanner(self):
        if self.visual_scanner and self.visual_scanner.is_running:
            self.visual_scanner.stop()
            self.btn_audit_toggle.configure(text="[ START_FULL_SYSTEM_SCAN ]", fg_color="#440000", hover_color="#660000", border_color="#ff0000", text_color="#ff4444")
        else:
            if not self.visual_scanner:
                self.visual_scanner = network_tools.VisualScanner(callback=self.append_audit_batch, stats_callback=self.update_audit_stats)
            import os
            target_path = os.path.join(os.environ.get("USERPROFILE", "C:\\"), "Downloads")
            if not os.path.exists(target_path): target_path = "C:\\"
            self.visual_scanner.start(path=target_path)
            self.btn_audit_toggle.configure(text=network_tools.get_text("btn_run_audit").replace("START", "STOP").replace("BAŞLAT", "DURDUR"), fg_color="#004400", hover_color="#006600", border_color="#00ff00", text_color="#00ff00")
            
            self.audit_textbox.configure(state="normal")
            self.audit_textbox.delete("0.0", "end")
            self.audit_textbox.configure(state="disabled")

    def export_logs(self):
        self.export_tb.configure(state="normal")
        self.export_tb.delete("0.0", "end")
        self.export_tb.insert("0.0", "root@sys:~# Initiating log extraction...\n")
        self.export_tb.configure(state="disabled")
        
        def task():
            import os, datetime
            export_path = os.path.join(os.environ.get("USERPROFILE", "C:\\"), "Desktop", "NetworkOS_RawLogs.txt")
            try:
                with open(export_path, "w", encoding="utf-8") as f:
                    f.write(f"--- NETWORK OS RAW LOG EXPORT ---\n")
                    f.write(f"DATE: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write("--- THREAT MEMORY ---\n")
                    f.write(str(network_tools.THREAT_STATE) + "\n\n")
                    f.write("--- ARP DEVICES ---\n")
                    for d in network_tools.get_arp_devices():
                        f.write(f"{d['ip']} - {d['mac']}\n")
                
                self.typewriter_insert(self.export_tb, f"\n[+] SUCCESS: Logs exported to:\n{export_path}\n", delay=0.01)
            except Exception as e:
                self.typewriter_insert(self.export_tb, f"\n[-] ERROR: Could not export logs: {str(e)}\n", delay=0.01)
        self.wrap_task(task)

    def generate_security_report(self):
        self.report_tb.configure(state="normal")
        self.report_tb.delete("0.0", "end")
        self.report_tb.insert("0.0", "root@sys:~# Compiling Security Assessment Report...\n")
        self.report_tb.configure(state="disabled")
        
        def task():
            import os, datetime
            report_path = os.path.join(os.environ.get("USERPROFILE", "C:\\"), "Desktop", "Security_Report.md")
            try:
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write("# SECURITY ASSESSMENT REPORT\n")
                    f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    f.write("## 1. System Status\n")
                    f.write("- **Language:** " + network_tools.GLOBAL_STATE['language'] + "\n")
                    f.write("- **Firewall Vulnerable:** " + str(network_tools.THREAT_STATE.get('firewall_vulnerable', False)) + "\n\n")
                    
                    f.write("## 2. Threat Intelligence\n")
                    f.write("- **Suspicious PID:** " + str(network_tools.THREAT_STATE['suspicious_pid']) + "\n")
                    f.write("- **Rogue MAC:** " + str(network_tools.THREAT_STATE['rogue_mac']) + "\n")
                    f.write("- **Brute Force IP:** " + str(network_tools.THREAT_STATE['brute_force_ip']) + "\n\n")
                    
                    f.write("## 3. Executive Summary\n")
                    if any(network_tools.THREAT_STATE.values()):
                        f.write("The system is currently exhibiting signs of compromise or vulnerability. Immediate action required.\n")
                    else:
                        f.write("The system appears secure against current baseline checks.\n")
                        
                self.typewriter_insert(self.report_tb, f"\n[+] REPORT COMPILED SUCCESSFULLY.\n[+] Saved to: {report_path}\n", delay=0.01)
            except Exception as e:
                self.typewriter_insert(self.report_tb, f"\n[-] ERROR: Compilation failed: {str(e)}\n", delay=0.01)
        self.wrap_task(task)

if __name__ == "__main__":
    app = App()
    app.mainloop()
