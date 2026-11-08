import os
from core.database import db

THEME_COLORS = {
    "bg_main": "#0B111B",       # Deep Charcoal / Navy Dark
    "bg_secondary": "#151F2D",  # Secondary Panel Surface
    "border": "#29394B",        # Subtle slate borders
    "text_primary": "#E9F1FA",  # Crisp off-white primary text
    "text_secondary": "#AAB7C7",# Muted secondary text
    "accent_terminal": "#53E6A5",# Clean cyan/mint terminal accent
    "state_critical": "#EF5350", # Red warning/critical state
    "state_warning": "#F4B860",  # Amber/yellow warning state
    "state_success": "#53E6A5"   # Green/cyan success
}

FONTS = {
    "title": ("Consolas", 18, "bold"),
    "subtitle": ("Consolas", 14, "bold"),
    "body": ("Consolas", 12),
    "code": ("Consolas", 11),
    "button": ("Consolas", 12, "bold")
}

DEFAULT_CONFIG = {
    "language": "EN",
    "theme": "dark",
    "max_scan_workers": 25,
    "request_timeout": 5.0,
    "packet_buffer_size": 2000,
    "anonymize_logs": True
}

def get_config(key: str, default=None):
    db_val = db.get_setting(key)
    if db_val != "":
        return db_val
    return DEFAULT_CONFIG.get(key, default)

def set_config(key: str, value: str):
    db.set_setting(key, str(value))
