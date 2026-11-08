import winreg
from typing import List, Dict, Any
from core.logger import logger

class RegistryMonitor:
    """Audits critical Windows Registry autostart locations and security configuration keys."""

    MONITORED_LOCATIONS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon Shell")
    ]

    def audit_autostart_entries(self) -> List[Dict[str, Any]]:
        findings = []
        for root, subkey, label in self.MONITORED_LOCATIONS:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        findings.append({
                            "location": label,
                            "key_path": subkey,
                            "value_name": val_name,
                            "value_data": str(val_data),
                            "is_suspicious": False
                        })
            except FileNotFoundError:
                continue
            except PermissionError:
                findings.append({
                    "location": label,
                    "key_path": subkey,
                    "value_name": "ACCESS_DENIED",
                    "value_data": "Requires elevated privileges",
                    "is_suspicious": False
                })
            except Exception as e:
                logger.error(f"[RegistryMonitor] Error auditing {subkey}: {e}")
        return findings
