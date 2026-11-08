import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.windows_internals.eventlog_collector import EventLogCollector
from modules.windows_internals.sysmon_collector import SysmonCollector
from modules.windows_internals.etw_collector import ETWCollector
from modules.windows_internals.process_monitor import ProcessMonitor
from modules.windows_internals.service_monitor import ServiceMonitor

class WindowsInternalsView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.event_collector = EventLogCollector()
        self.sysmon_collector = SysmonCollector()
        self.etw_collector = ETWCollector()
        self.process_monitor = ProcessMonitor()
        self.service_monitor = ServiceMonitor()
        self._init_ui()

    def _init_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="WINDOWS INTERNALS & ETW MONITOR", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Live Event Tracing, Sysmon Telemetry & Kernel Internals", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        # Tabview
        self.tabview = ctk.CTkTabview(
            self, fg_color=COLOR_BG_SECONDARY,
            segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_HOVER,
            segmented_button_selected_hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        self.tab_events = self.tabview.add("Event Logs")
        self.tab_sysmon = self.tabview.add("Sysmon Monitor")
        self.tab_etw = self.tabview.add("ETW Sessions & Providers")
        self.tab_processes = self.tabview.add("Process & Service Audits")

        self._setup_eventlog_tab()
        self._setup_sysmon_tab()
        self._setup_etw_tab()
        self._setup_processes_tab()

    def _setup_eventlog_tab(self):
        bar = ctk.CTkFrame(self.tab_events, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        lbl_chan = ctk.CTkLabel(bar, text="Channel:", font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY)
        lbl_chan.pack(side="left", padx=(0, 5))

        self.combo_channel = ctk.CTkComboBox(
            bar, values=self.event_collector.get_supported_channels(),
            width=260, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, font=FONT_CODE
        )
        self.combo_channel.pack(side="left", padx=(0, 15))

        btn_fetch = ctk.CTkButton(
            bar, text="Fetch Recent Events", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=160,
            command=self._fetch_eventlog_threaded
        )
        btn_fetch.pack(side="left")

        self.txt_events = ctk.CTkTextbox(self.tab_events, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_events.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_sysmon_tab(self):
        top = ctk.CTkFrame(self.tab_sysmon, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=10)

        self.lbl_sysmon_status = ctk.CTkLabel(top, text="Checking Sysmon status...", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        self.lbl_sysmon_status.pack(side="left")

        btn_check = ctk.CTkButton(
            top, text="Inspect Sysmon Channel", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=180,
            command=self._check_sysmon_threaded
        )
        btn_check.pack(side="right")

        self.txt_sysmon = ctk.CTkTextbox(self.tab_sysmon, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_sysmon.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_etw_tab(self):
        top = ctk.CTkFrame(self.tab_etw, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=10)

        btn_etw = ctk.CTkButton(
            top, text="List Active Trace Sessions (-ets)", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=220,
            command=self._list_etw_threaded
        )
        btn_etw.pack(side="left")

        self.txt_etw = ctk.CTkTextbox(self.tab_etw, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_etw.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_processes_tab(self):
        top = ctk.CTkFrame(self.tab_processes, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=10)

        btn_procs = ctk.CTkButton(
            top, text="Scan Suspicious Processes (LOLBins)", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=220,
            command=self._scan_procs_threaded
        )
        btn_procs.pack(side="left", padx=(0, 10))

        btn_svc = ctk.CTkButton(
            top, text="Audit Services (Unquoted Paths)", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=220,
            command=self._scan_services_threaded
        )
        btn_svc.pack(side="left")

        self.txt_procs = ctk.CTkTextbox(self.tab_processes, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_procs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _fetch_eventlog_threaded(self):
        chan = self.combo_channel.get()
        self.txt_events.delete("1.0", "end")
        self.txt_events.insert("end", f"[*] Querying recent records from {chan} channel...\n")
        def run():
            events = self.event_collector.query_recent_events(channel=chan, max_events=25)
            self.after(0, lambda: self._render_events(events))
        threading.Thread(target=run, daemon=True).start()

    def _render_events(self, events):
        self.txt_events.delete("1.0", "end")
        if not events:
            self.txt_events.insert("end", "[-] No events returned or channel empty.\n")
            return
        for ev in events:
            ev_id = ev.get("event_id")
            prov = ev.get("provider")
            ts = ev.get("timestamp")
            sev = ev.get("severity")
            self.txt_events.insert("end", f"[{ts}] [{sev}] EventID: {ev_id} | Provider: {prov}\n")
            fields = ev.get("fields", {})
            for k, v in list(fields.items())[:6]:
                if k not in ["EventID", "Provider", "TimeCreated"]:
                    self.txt_events.insert("end", f"   > {k}: {v}\n")
            self.txt_events.insert("end", "-" * 80 + "\n")

    def _check_sysmon_threaded(self):
        self.txt_sysmon.delete("1.0", "end")
        self.txt_sysmon.insert("end", "[*] Inspecting Sysmon driver & event log status...\n")
        def run():
            stat = self.sysmon_collector.check_availability()
            events = self.sysmon_collector.get_recent_sysmon_events(max_events=20)
            self.after(0, lambda: self._render_sysmon(stat, events))
        threading.Thread(target=run, daemon=True).start()

    def _render_sysmon(self, stat, events):
        self.lbl_sysmon_status.configure(text=f"Status: {stat.get('status')} - {stat.get('message')}")
        self.txt_sysmon.delete("1.0", "end")
        self.txt_sysmon.insert("end", f"Sysmon Operational Status: {stat.get('status')}\n")
        self.txt_sysmon.insert("end", f"Channel: {stat.get('channel')}\n")
        self.txt_sysmon.insert("end", f"Notes: {stat.get('message')}\n\n")
        if events:
            self.txt_sysmon.insert("end", f"[+] Retrieved {len(events)} recent Sysmon events:\n")
            for ev in events:
                self.txt_sysmon.insert("end", f"[{ev.get('timestamp')}] Event ID {ev.get('event_id')} - {ev.get('fields', {})}\n")
        else:
            self.txt_sysmon.insert("end", "[i] No operational Sysmon events captured or Sysmon not installed.\n")

    def _list_etw_threaded(self):
        self.txt_etw.delete("1.0", "end")
        self.txt_etw.insert("end", "[*] Querying active ETW trace sessions via logman...\n")
        def run():
            sessions = self.etw_collector.query_active_sessions()
            providers = self.etw_collector.query_security_providers()
            self.after(0, lambda: self._render_etw(sessions, providers))
        threading.Thread(target=run, daemon=True).start()

    def _render_etw(self, sessions, providers):
        self.txt_etw.delete("1.0", "end")
        self.txt_etw.insert("end", f"[+] Active Kernel & Event Trace Sessions ({len(sessions)}):\n")
        self.txt_etw.insert("end", f"{'SESSION NAME':<40} {'TYPE':<20} {'STATUS'}\n")
        self.txt_etw.insert("end", "=" * 70 + "\n")
        for s in sessions:
            self.txt_etw.insert("end", f"{s['session_name']:<40} {s['type']:<20} {s['status']}\n")

        self.txt_etw.insert("end", f"\n[+] Monitored Security ETW Providers ({len(providers)}):\n")
        for p in providers:
            self.txt_etw.insert("end", f" - {p['provider_name']} ({p['guid']})\n")

    def _scan_procs_threaded(self):
        self.txt_procs.delete("1.0", "end")
        self.txt_procs.insert("end", "[*] Inspecting running processes for suspicious LOLBin arguments...\n")
        def run():
            procs = self.process_monitor.get_process_snapshot()
            self.after(0, lambda: self._render_procs(procs))
        threading.Thread(target=run, daemon=True).start()

    def _render_procs(self, procs):
        self.txt_procs.delete("1.0", "end")
        suspicious = [p for p in procs if p.get("is_suspicious")]
        self.txt_procs.insert("end", f"[+] Audited {len(procs)} processes. Found {len(suspicious)} suspicious executions.\n\n")
        for p in (suspicious if suspicious else procs[:25]):
            prefix = "[!] SUSPICIOUS" if p.get("is_suspicious") else "[*] BENIGN"
            self.txt_procs.insert("end", f"{prefix} PID: {p['pid']} | {p['name']} (PPID: {p['ppid']})\n")
            self.txt_procs.insert("end", f"    Path: {p['executable_path']}\n")
            if p['command_line']:
                self.txt_procs.insert("end", f"    Cmd:  {p['command_line'][:120]}\n")
            if p.get("flag_reason"):
                self.txt_procs.insert("end", f"    Flag: {p['flag_reason']}\n")
            self.txt_procs.insert("end", "-" * 60 + "\n")

    def _scan_services_threaded(self):
        self.txt_procs.delete("1.0", "end")
        self.txt_procs.insert("end", "[*] Auditing Windows Services for Unquoted Service Paths...\n")
        def run():
            services = self.service_monitor.get_service_inventory(limit=100)
            self.after(0, lambda: self._render_services(services))
        threading.Thread(target=run, daemon=True).start()

    def _render_services(self, services):
        self.txt_procs.delete("1.0", "end")
        vuln = [s for s in services if s.get("unquoted_path_vulnerability")]
        self.txt_procs.insert("end", f"[+] Audited {len(services)} services. Found {len(vuln)} with unquoted service paths.\n\n")
        for s in vuln:
            self.txt_procs.insert("end", f"[!] VULNERABLE: {s['name']} ({s['display_name']})\n")
            self.txt_procs.insert("end", f"    Path:    {s['path_name']}\n")
            self.txt_procs.insert("end", f"    Account: {s['account']}\n")
            self.txt_procs.insert("end", "-" * 60 + "\n")
