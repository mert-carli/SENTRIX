import subprocess
import re
from typing import List, Dict, Any, Tuple
from core.logger import audit_logger

class WirelessSecurityLab:
    def __init__(self):
        pass

    def get_active_connection(self) -> Dict[str, Any]:
        """Retrieves active Wi-Fi connection info via netsh."""
        info = {
            "connected": False,
            "ssid": "",
            "bssid": "",
            "radio_type": "",
            "channel": "",
            "signal": "",
            "rx_rate": "",
            "tx_rate": "",
            "auth": ""
        }
        try:
            cmd = 'netsh wlan show interfaces'
            output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("SSID") and not line.startswith("BSSID"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        info["ssid"] = parts[1].strip()
                        info["connected"] = bool(info["ssid"])
                elif line.startswith("BSSID"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["bssid"] = parts[1].strip()
                elif line.startswith("Radio type") or line.startswith("Radyo türü"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["radio_type"] = parts[1].strip()
                elif line.startswith("Channel") or line.startswith("Kanal"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["channel"] = parts[1].strip()
                elif line.startswith("Authentication") or line.startswith("Kimlik"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["auth"] = parts[1].strip()
                elif line.startswith("Signal") or line.startswith("Sinyal"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["signal"] = parts[1].strip()
                elif line.startswith("Receive rate") or line.startswith("Alma oranı"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["rx_rate"] = parts[1].strip()
                elif line.startswith("Transmit rate") or line.startswith("İletim oranı"):
                    parts = line.split(":", 1)
                    if len(parts) > 1: info["tx_rate"] = parts[1].strip()
        except Exception as e:
            info["error"] = str(e)
        return info

    def get_saved_profiles(self, mask_passwords: bool = True) -> List[Dict[str, str]]:
        """Extracts saved Wi-Fi profiles with optional password masking."""
        profiles = []
        try:
            output = subprocess.check_output('netsh wlan show profiles', shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
            profile_names = []
            for line in output.splitlines():
                if "All User Profile" in line or "Tüm Kullanıcı Profili" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        profile_names.append(parts[1].strip())

            for name in profile_names:
                pwd = "None/Open"
                try:
                    cmd = f'netsh wlan show profile name="{name}" key=clear'
                    out_prof = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
                    for pline in out_prof.splitlines():
                        if "Key Content" in pline or "Key İçeriği" in pline:
                            pwd_parts = pline.split(":", 1)
                            if len(pwd_parts) > 1:
                                raw_pwd = pwd_parts[1].strip()
                                pwd = "●●●●●●●● (Masked)" if mask_passwords else raw_pwd
                                break
                except Exception:
                    pwd = "(Access Denied)"

                profiles.append({"profile": name, "password": pwd})
        except Exception as e:
            profiles.append({"profile": "Error", "password": str(e)})
        return profiles

    def scan_nearby_aps(self) -> List[Dict[str, Any]]:
        """Scans nearby 802.11 access points and checks for rogue/evil twin anomalies."""
        aps = []
        try:
            output = subprocess.check_output('netsh wlan show networks mode=bssid', shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
            current_ap = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("SSID") and not line.startswith("BSSID"):
                    parts = line.split(":", 1)
                    if parts and len(parts) > 1:
                        if current_ap and "bssid" in current_ap:
                            aps.append(current_ap)
                        current_ap = {
                            "ssid": parts[1].strip() or "[Hidden Network]",
                            "auth": "",
                            "cipher": "",
                            "bssid": "",
                            "signal": "0%",
                            "channel": ""
                        }
                elif line.startswith("Authentication") or line.startswith("Kimlik"):
                    if current_ap:
                        current_ap["auth"] = line.split(":", 1)[1].strip()
                elif line.startswith("Encryption") or line.startswith("Şifreleme"):
                    if current_ap:
                        current_ap["cipher"] = line.split(":", 1)[1].strip()
                elif line.startswith("BSSID"):
                    if current_ap:
                        current_ap["bssid"] = line.split(":", 1)[1].strip().upper()
                elif line.startswith("Signal") or line.startswith("Sinyal"):
                    if current_ap:
                        current_ap["signal"] = line.split(":", 1)[1].strip()
                elif line.startswith("Channel") or line.startswith("Kanal"):
                    if current_ap:
                        current_ap["channel"] = line.split(":", 1)[1].strip()

            if current_ap and "bssid" in current_ap:
                aps.append(current_ap)
        except Exception:
            pass

        # Evil Twin & Rogue AP Detection
        ssid_map = {}
        for ap in aps:
            ssid = ap["ssid"]
            if ssid not in ssid_map:
                ssid_map[ssid] = []
            ssid_map[ssid].append(ap)

        for ssid, ap_list in ssid_map.items():
            if len(ap_list) > 1 and ssid != "[Hidden Network]":
                # Multiple APs broadcasting identical SSID
                auth_types = set(a["auth"] for a in ap_list)
                for a in ap_list:
                    if len(auth_types) > 1:
                        a["anomaly"] = "POTENTIAL EVIL TWIN: Mismatched authentication encryption for same SSID!"
                    else:
                        a["anomaly"] = f"Multi-BSSID Mesh/Roam ({len(ap_list)} APs)"
            else:
                for a in ap_list:
                    if a.get("auth") in ["Open", "Açık", "None"]:
                        a["anomaly"] = "UNENCRYPTED (Open Wi-Fi Network)"
                    else:
                        a["anomaly"] = "NORMAL"

        return aps

    def calculate_security_score(self, current_info: Dict[str, Any]) -> Tuple[int, List[str]]:
        score = 100
        notes = []
        if not current_info.get("connected"):
            return 0, ["No active Wi-Fi connection."]

        auth = current_info.get("auth", "").upper()
        if "WPA3" in auth:
            notes.append("[+] WPA3 Modern Encryption (+0)")
        elif "WPA2" in auth:
            notes.append("[+] WPA2 Standard Encryption (-5)")
            score -= 5
        elif "WEP" in auth:
            notes.append("[-] WEP Deprecated and Compromised Encryption (-60)")
            score -= 60
        elif "OPEN" in auth or "NONE" in auth:
            notes.append("[-] Unencrypted Open Wi-Fi Network (-80)")
            score -= 80

        return max(0, score), notes

wireless_lab = WirelessSecurityLab()
