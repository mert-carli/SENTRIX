import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.recon.scanner import port_scanner_engine, PortScanResult
from modules.recon.osint import osint_engine
import network_tools

class ReconView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "ADVANCED RECONNAISSANCE & ATTACK SURFACE MAPPING")
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

        self.tab_port_scan = self.tabview.add("Port & Service Scanner")
        self.tab_osint = self.tabview.add("OSINT & Attack Surface")
        self.tab_service = self.tabview.add("Banner Grabbing")
        self.tab_route = self.tabview.add("Route Analysis")

        self._build_port_scanner_tab()
        self._build_osint_tab()
        self._build_service_tab()
        self._build_route_tab()

    def _build_port_scanner_tab(self):
        tab = self.tab_port_scan
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        # Controls
        ctrl_frame = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl_frame, text="TARGET HOST:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_port_target = ctk.CTkEntry(ctrl_frame, placeholder_text="127.0.0.1 or domain", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_port_target.insert(0, "127.0.0.1")
        self.entry_port_target.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        ctk.CTkLabel(ctrl_frame, text="PORTS:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=2, padx=(0, 10))
        self.entry_ports = ctk.CTkEntry(ctrl_frame, placeholder_text="21,22,80,443,445,3389", font=FONT_CODE, height=36, width=180, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_ports.insert(0, "21,22,23,25,53,80,135,139,443,445,1433,3306,3389,8080")
        self.entry_ports.grid(row=0, column=3, padx=(0, 10), sticky="ew")

        create_button(ctrl_frame, "[ EXECUTE PORT SCAN ]", self.run_port_scan, is_accent=True).grid(row=0, column=4, padx=5)

        # Export row
        exp_frame = ctk.CTkFrame(tab, fg_color="transparent")
        exp_frame.grid(row=1, column=0, pady=(0, 5), sticky="e")
        create_button(exp_frame, "EXPORT JSON", lambda: self.export_ports("json"), height=28).pack(side="left", padx=5)
        create_button(exp_frame, "EXPORT CSV", lambda: self.export_ports("csv"), height=28).pack(side="left", padx=5)
        create_button(exp_frame, "EXPORT HTML", lambda: self.export_ports("html"), height=28).pack(side="left", padx=5)

        self.tb_ports = create_textbox(tab)
        self.tb_ports.grid(row=2, column=0, sticky="nsew")
        safe_textbox_write(self.tb_ports, "Advanced Port & Service Scanner Ready.\nEnter target host and ports above.\n", "accent")
        self.last_port_results = []

    def _build_osint_tab(self):
        tab = self.tab_osint
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl_frame = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl_frame, text="DOMAIN / IP:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_osint_target = ctk.CTkEntry(ctrl_frame, placeholder_text="example.com", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_osint_target.insert(0, "google.com")
        self.entry_osint_target.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl_frame, "[ ATTACK SURFACE MAP ]", self.run_attack_surface, is_accent=True).grid(row=0, column=2, padx=5)
        create_button(ctrl_frame, "[ WHOIS / RDAP ]", self.run_whois).grid(row=0, column=3, padx=5)
        create_button(ctrl_frame, "[ CERT TRANSPARENCY ]", self.run_cert_transparency).grid(row=0, column=4, padx=5)

        self.tb_osint = create_textbox(tab)
        self.tb_osint.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_osint, "OSINT & Attack Surface Mapper Ready.\n", "accent")

    def _build_service_tab(self):
        tab = self.tab_service
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl_frame = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl_frame, text="TARGET IP:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_svc_target = ctk.CTkEntry(ctrl_frame, placeholder_text="127.0.0.1", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_svc_target.insert(0, "127.0.0.1")
        self.entry_svc_target.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl_frame, "[ BANNER GRAB ]", self.run_banner_grab, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_svc = create_textbox(tab)
        self.tb_svc.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_svc, "Service Detection & Banner Grabbing Ready.\n", "accent")

    def _build_route_tab(self):
        tab = self.tab_route
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl_frame = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, pady=10, sticky="ew")
        ctrl_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl_frame, text="TARGET HOST:", font=FONT_BTN, text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=0, padx=(0, 10))
        self.entry_route_target = ctk.CTkEntry(ctrl_frame, placeholder_text="8.8.8.8", font=FONT_CODE, height=36, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_route_target.insert(0, "8.8.8.8")
        self.entry_route_target.grid(row=0, column=1, padx=(0, 10), sticky="ew")

        create_button(ctrl_frame, "[ TRACE ROUTE ]", self.run_traceroute, is_accent=True).grid(row=0, column=2, padx=5)

        self.tb_route = create_textbox(tab)
        self.tb_route.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_route, "Visual Route Analysis Ready.\n", "accent")

    # --- Actions ---
    def run_port_scan(self):
        target = self.entry_port_target.get().strip()
        ports_str = self.entry_ports.get().strip()
        try:
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        except ValueError:
            safe_textbox_write(self.tb_ports, "[!] Error: Invalid port numbers.\n", "danger")
            return

        safe_textbox_write(self.tb_ports, f"[*] Initiating Port Scan on {target} ({len(ports)} ports)...\n", "warning", clear_first=True)

        def task():
            try:
                results = port_scanner_engine.scan_target(target, ports)
                self.last_port_results = results
                
                header = f"\nPORT     PROTO  STATE       SERVICE          LATENCY    BANNER / VULNERABILITIES\n" + ("─"*85) + "\n"
                self.after(0, lambda: safe_textbox_write(self.tb_ports, header, "accent"))

                for r in results:
                    cve_desc = f" | CVEs: {len(r.cves)}" if r.cves else ""
                    line = f"{r.port:<8} {r.protocol:<6} {r.state:<11} {r.service:<16} {r.latency_ms:>6.1f}ms  {r.banner[:25]}{cve_desc}\n"
                    tag = "accent" if r.state == "OPEN" else ("warning" if r.state == "FILTERED" else "muted")
                    self.after(0, lambda l=line, t=tag: safe_textbox_write(self.tb_ports, l, t))

                self.after(0, lambda: safe_textbox_write(self.tb_ports, f"\n[+] Scan Completed. Found {sum(1 for r in results if r.state=='OPEN')} open ports.\n", "accent"))
            except Exception as e:
                self.after(0, lambda err=str(e): safe_textbox_write(self.tb_ports, f"\n[!] Scan Error: {err}\n", "danger"))

        threading.Thread(target=task, daemon=True).start()

    def export_ports(self, fmt: str):
        if not self.last_port_results:
            safe_textbox_write(self.tb_ports, "[!] No scan results to export. Run a scan first.\n", "warning")
            return
        out = port_scanner_engine.export_results(self.last_port_results, fmt)
        safe_textbox_write(self.tb_ports, f"\n[+] Exported Results ({fmt.upper()}):\n\n{out}\n", "normal")

    def run_attack_surface(self):
        target = self.entry_osint_target.get().strip()
        safe_textbox_write(self.tb_osint, f"[*] Generating Attack Surface Map for {target}...\n", "warning", clear_first=True)
        def task():
            tree = osint_engine.build_attack_surface_tree(target)
            self.after(0, lambda: safe_textbox_write(self.tb_osint, f"\n{tree}\n", "normal"))
        threading.Thread(target=task, daemon=True).start()

    def run_whois(self):
        target = self.entry_osint_target.get().strip()
        safe_textbox_write(self.tb_osint, f"[*] Querying WHOIS/RDAP for {target}...\n", "warning", clear_first=True)
        def task():
            res = osint_engine.whois_rdap(target)
            import json
            pretty = json.dumps(res, indent=2)
            self.after(0, lambda: safe_textbox_write(self.tb_osint, f"\n{pretty}\n", "accent"))
        threading.Thread(target=task, daemon=True).start()

    def run_cert_transparency(self):
        target = self.entry_osint_target.get().strip()
        safe_textbox_write(self.tb_osint, f"[*] Querying Certificate Transparency Logs for *.{target}...\n", "warning", clear_first=True)
        def task():
            subdomains = osint_engine.certificate_transparency(target)
            if subdomains:
                out = f"[+] Discovered {len(subdomains)} Subdomains via Certificate Logs:\n\n" + "\n".join(f"  └── {s}" for s in subdomains)
            else:
                out = "[-] No subdomains retrieved or rate limit encountered."
            self.after(0, lambda: safe_textbox_write(self.tb_osint, f"\n{out}\n", "accent" if subdomains else "warning"))
        threading.Thread(target=task, daemon=True).start()

    def run_banner_grab(self):
        target = self.entry_svc_target.get().strip()
        safe_textbox_write(self.tb_svc, f"[*] Grabbing service banners from {target}...\n", "warning", clear_first=True)
        def task():
            lines = network_tools.do_service_detection(target)
            for l, tag, _ in lines:
                self.after(0, lambda l=l, t=tag: safe_textbox_write(self.tb_svc, l, t))
        threading.Thread(target=task, daemon=True).start()

    def run_traceroute(self):
        target = self.entry_route_target.get().strip()
        safe_textbox_write(self.tb_route, f"[*] Running traceroute to {target}...\n", "warning", clear_first=True)
        def task():
            lines = network_tools.do_route_analysis(target)
            for l, tag, _ in lines:
                self.after(0, lambda l=l, t=tag: safe_textbox_write(self.tb_route, l, t))
        threading.Thread(target=task, daemon=True).start()
