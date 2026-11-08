import socket
import threading
from typing import Dict, Any, Optional
from core.logger import logger
from modules.deception_lab.session_tracker import DeceptionSessionTracker

class HoneypotService:
    """Emulates low-interaction decoy services (HTTP, SSH banner) strictly isolated to localhost/specified interface."""

    def __init__(self, service_type: str = "HTTP", host: str = "127.0.0.1", port: int = 8088):
        self.service_type = service_type.upper()
        self.host = host
        self.port = port
        self.tracker = DeceptionSessionTracker()
        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> Dict[str, Any]:
        if self._running:
            return {"status": "ALREADY_RUNNING", "port": self.port}

        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(5)
            self._running = True

            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()

            return {
                "status": "RUNNING",
                "service": self.service_type,
                "endpoint": f"{self.host}:{self.port}",
                "message": f"Honeypot {self.service_type} listening securely on {self.host}:{self.port}"
            }
        except Exception as e:
            self._running = False
            return {"status": "ERROR", "error": str(e)}

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def _listen_loop(self):
        while self._running:
            try:
                self._server_sock.settimeout(1.0)
                client, addr = self._server_sock.accept()
                src_ip, src_port = addr[0], addr[1]

                client.settimeout(2.0)
                data = b""
                try:
                    if self.service_type == "SSH":
                        client.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
                    data = client.recv(1024)
                    if self.service_type == "HTTP":
                        client.sendall(b"HTTP/1.1 401 Unauthorized\r\nServer: SentinelDecoy/4.0\r\nContent-Type: text/plain\r\n\r\nAccess Denied.\r\n")
                except Exception:
                    pass
                finally:
                    client.close()

                self.tracker.record_interaction(
                    service=self.service_type,
                    src_ip=src_ip,
                    src_port=src_port,
                    payload_preview=data.decode("utf-8", errors="replace")
                )
            except socket.timeout:
                continue
            except Exception:
                break
