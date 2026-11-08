import ssl
import socket
from datetime import datetime
from typing import Dict, Any

class CertificateAnalyzer:
    """Inspects X.509 SSL/TLS certificates, expiry dates, SANs, and signature algorithms."""

    @staticmethod
    def get_certificate_details(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"success": False, "error": "No certificate presented."}

                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")

                    # Parse expiry date
                    expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z") if not_after_str else None
                    is_expired = expires_at < datetime.utcnow() if expires_at else False

                    sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                    return {
                        "success": True,
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": not_before_str,
                        "not_after": not_after_str,
                        "is_expired": is_expired,
                        "subject_alt_names": sans
                    }
        except Exception as e:
            return {"success": False, "error": str(e)}
