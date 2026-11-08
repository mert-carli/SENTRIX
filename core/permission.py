import ctypes
import os
import sys

def is_admin() -> bool:
    """Checks whether the current process is running with elevated Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def check_permission(required_feature_name: str) -> bool:
    """
    Checks if administrator rights are available for a sensitive feature.
    Returns True if permitted, False otherwise.
    """
    if is_admin():
        return True
    return False

def get_privilege_status_str() -> str:
    return "ELEVATED (Administrator)" if is_admin() else "STANDARD (Limited Privileges)"
