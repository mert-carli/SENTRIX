import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, FONT_TITLE, FONT_SUBTITLE, FONT_BTN, FONT_TEXT,
    FONT_CODE, create_header, create_button, create_textbox, safe_textbox_write
)
from modules.wireless.wifi_lab import wireless_lab

class WirelessView(ctk.CTkFrame):
    def __init__(self, parent, main_app):
        super().__init__(parent, fg_color=COLOR_BG_MAIN)
        self.main_app = main_app
        self.mask_passwords = True
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = create_header(self, "WIRELESS SECURITY LAB & 802.11 SPECTRUM ANALYZER")
        header.grid(row=0, column=0, padx=15, pady=(15, 10), sticky="w")

        self.tabview = ctk.CTkTabview(
            self, corner_radius=4, border_width=1, border_color=COLOR_BORDER,
            fg_color=COLOR_BG_SECONDARY, segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_BORDER,
            segmented_button_unselected_color=COLOR_BG_MAIN,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self.tab_active = self.tabview.add("Active Interface")
        self.tab_saved = self.tabview.add("Saved Profiles")
        self.tab_aps = self.tabview.add("AP Spectrum & Rogue Detection")

        self._build_active_tab()
        self._build_saved_tab()
        self._build_aps_tab()

    def _build_active_tab(self):
        tab = self.tab_active
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ QUERY ACTIVE WI-FI INTERFACE ]", self.query_active_wifi, is_accent=True).pack(side="left", padx=5)

        self.tb_active = create_textbox(tab)
        self.tb_active.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_active, "Active Wi-Fi Interface Monitor Ready.\n", "accent")

    def _build_saved_tab(self):
        tab = self.tab_saved
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ DUMP SAVED PROFILES (MASKED) ]", lambda: self.dump_profiles(True)).pack(side="left", padx=5)
        create_button(ctrl, "[ UNMASK PASSWORDS (CONFIRM) ]", lambda: self.dump_profiles(False), is_danger=True).pack(side="left", padx=5)

        self.tb_saved = create_textbox(tab)
        self.tb_saved.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_saved, "WLAN Profile Vault Ready. Passwords are masked by default according to security policy.\n", "accent")

    def _build_aps_tab(self):
        tab = self.tab_aps
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, pady=10, sticky="ew")
        create_button(ctrl, "[ SCAN 802.11 ACCESS POINTS & ROGUE DETECTION ]", self.scan_aps, is_accent=True).pack(side="left", padx=5)

        self.tb_aps = create_textbox(tab)
        self.tb_aps.grid(row=1, column=0, sticky="nsew")
        safe_textbox_write(self.tb_aps, "Access Point Spectrum Analyzer Ready.\n", "accent")

    # --- Actions ---
    def query_active_wifi(self):
        info = wireless_lab.get_active_connection()
        score, notes = wireless_lab.calculate_security_score(info)
        lines = [
            "ACTIVE WI-FI INTERFACE METRICS",
            "──────────────────────────────────────────",
            f"SSID            : {info.get('ssid') or 'Not connected'}",
            f"BSSID           : {info.get('bssid') or 'N/A'}",
            f"Radio Type      : {info.get('radio_type') or 'N/A'}",
            f"Channel         : {info.get('channel') or 'N/A'}",
            f"Authentication  : {info.get('auth') or 'N/A'}",
            f"Signal Strength : {info.get('signal') or 'N/A'}",
            f"Rx / Tx Rate    : {info.get('rx_rate')} / {info.get('tx_rate')}\n",
            f"SECURITY SCORE  : {score} / 100"
        ]
        lines.extend(notes)
        safe_textbox_write(self.tb_active, "\n".join(lines) + "\n", "normal", clear_first=True)

    def dump_profiles(self, mask: bool):
        safe_textbox_write(self.tb_saved, f"[*] Reading saved Wi-Fi profiles (Masking={mask})...\n", "warning", clear_first=True)
        def task():
            profiles = wireless_lab.get_saved_profiles(mask_passwords=mask)
            lines = [f"{'PROFILE NAME':<35} {'KEY CONTENT / PASSWORD':<30}", "─"*65]
            for p in profiles:
                lines.append(f"{p['profile']:<35} {p['password']:<30}")
            self.after(0, lambda: safe_textbox_write(self.tb_saved, "\n".join(lines) + "\n", "accent"))
        threading.Thread(target=task, daemon=True).start()

    def scan_aps(self):
        safe_textbox_write(self.tb_aps, "[*] Scanning nearby 802.11 spectrum...\n", "warning", clear_first=True)
        def task():
            aps = wireless_lab.scan_nearby_aps()
            if not aps:
                self.after(0, lambda: safe_textbox_write(self.tb_aps, "[-] No wireless networks detected or Wi-Fi radio is disabled.\n", "warning"))
                return
            lines = [f"{'SSID':<25} {'BSSID':<20} {'CH':<5} {'SIG':<6} {'AUTH':<16} {'ANOMALY STATUS'}", "─"*95]
            for a in aps:
                lines.append(f"{a['ssid'][:24]:<25} {a['bssid']:<20} {a['channel']:<5} {a['signal']:<6} {a['auth'][:15]:<16} {a['anomaly']}")
            self.after(0, lambda: safe_textbox_write(self.tb_aps, "\n".join(lines) + "\n", "normal"))
        threading.Thread(target=task, daemon=True).start()
