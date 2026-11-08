from typing import Dict, Any

class MASVSMapper:
    """Maps mobile security findings to OWASP Mobile Application Security Verification Standard (MASVS)."""

    CATEGORIES = {
        "MASVS-STORAGE": "Secure Storage and Data Protection",
        "MASVS-CRYPTO": "Cryptographic Architecture & Key Management",
        "MASVS-AUTH": "Authentication & Session Management",
        "MASVS-NETWORK": "Network Communication Security",
        "MASVS-PLATFORM": "Platform Interaction & IPC Security",
        "MASVS-CODE": "Code Quality & Build Hardening",
        "MASVS-RESILIENCE": "Reverse Engineering & Anti-Tampering Resilience"
    }

    @classmethod
    def get_category_name(cls, code: str) -> str:
        return cls.CATEGORIES.get(code, "General Mobile Security")
