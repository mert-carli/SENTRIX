import re
import logging
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "sentrix_audit.log")

SENSITIVE_PATTERNS = [
    re.compile(r'(password|passwd|pwd|secret|api_key|token|bearer|auth)\s*[:=]\s*([^\s,;]+)', re.IGNORECASE),
    re.compile(r'(Key Content|Key İçeriği)\s*:\s*(.+)', re.IGNORECASE)
]

def sanitize_message(msg: str) -> str:
    """Masks credentials, passwords, and sensitive keys from logs."""
    sanitized = msg
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r'\1: [REDACTED_BY_SECURITY_POLICY]', sanitized)
    return sanitized

class SecurityAuditLogger:
    def __init__(self, log_path: str = LOG_FILE):
        self.logger = logging.getLogger("SentrixAudit")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(log_path, encoding='utf-8')
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_action(self, action: str, details: str = "", level: str = "INFO"):
        clean_details = sanitize_message(details)
        msg = f"ACTION={action} | DETAILS={clean_details}"
        if level == "WARNING":
            self.logger.warning(msg)
        elif level == "ERROR":
            self.logger.error(msg)
        else:
            self.logger.info(msg)

audit_logger = SecurityAuditLogger()
logger = logging.getLogger("Sentrix")
log = logger
