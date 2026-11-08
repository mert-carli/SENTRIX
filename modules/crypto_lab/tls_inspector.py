import ssl
import socket
from typing import Dict, Any, List

class TLSInspector:
    """Probes remote TLS endpoints for supported TLS versions, negotiated cipher suites, and protocol weaknesses."""

    DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

    @classmethod
    def inspect_endpoint(cls, host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert(binary_form=True)

                    is_weak = version in cls.DEPRECATED_PROTOCOLS
                    return {
                        "host": host,
                        "port": port,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "ssl_protocol": cipher[1] if cipher else "Unknown",
                        "bits": cipher[2] if cipher else 0,
                        "is_deprecated_protocol": is_weak,
                        "status": "SECURE" if not is_weak and version in ["TLSv1.2", "TLSv1.3"] else "VULNERABLE"
                    }
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "error": str(e),
                "status": "CONNECTION_FAILED"
            }
