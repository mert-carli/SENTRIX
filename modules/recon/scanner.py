import socket
import time
import json
import csv
import io
from typing import List, Dict, Any, Optional, Callable
from core.database import db
from core.scope import scope_manager, ScopeViolationError
from core.logger import audit_logger

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

CVE_DATABASE = {
    "FTP": [("CVE-2020-11100", "FTP cleartext credentials exposure"), ("CVE-2015-3306", "ProFTPD copy vulnerability")],
    "SSH": [("CVE-2023-38408", "OpenSSH PKCS#11 provider RCE"), ("CVE-2024-6387", "regreSSHion OpenSSH race condition")],
    "Telnet": [("CVE-2020-10188", "Telnetd unauthenticated buffer overflow / cleartext protocol")],
    "SMB": [("CVE-2017-0144", "EternalBlue SMBv1 Remote Code Execution"), ("CVE-2020-0796", "SMBGhost RCE")],
    "RDP": [("CVE-2019-0708", "BlueKeep RDP pre-auth Remote Code Execution"), ("CVE-2012-0002", "MS12-020 RDP Denial of Service")],
    "MSSQL": [("CVE-2020-0618", "SQL Server Reporting Services RCE")],
    "MySQL": [("CVE-2012-2122", "MySQL Authentication Bypass")],
    "HTTP": [("CVE-2021-41773", "Apache Path Traversal and RCE"), ("CVE-2021-44228", "Log4j Log4Shell JNDI RCE")]
}

class PortScanResult:
    def __init__(self, port: int, protocol: str, state: str, service: str, banner: str = "", latency_ms: float = 0.0):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.banner = banner
        self.latency_ms = latency_ms
        self.cves = CVE_DATABASE.get(service, [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "latency_ms": round(self.latency_ms, 2),
            "cves": [{"id": c[0], "desc": c[1]} for c in self.cves]
        }

class AdvancedPortScanner:
    def __init__(self):
        pass

    def grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                if port in [80, 8080]:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443:
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        ss.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        raw = ss.recv(512)
                        return raw.decode('latin1', errors='ignore').split('\r\n')[0]
                raw = s.recv(512)
                banner = raw.decode('latin1', errors='ignore').strip()
        except Exception:
            pass
        return banner[:120]

    def scan_tcp_port(self, ip: str, port: int, timeout: float = 0.8) -> PortScanResult:
        t0 = time.time()
        state = "CLOSED"
        service = COMMON_SERVICES.get(port, "UNKNOWN")
        banner = ""
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((ip, port))
                latency = (time.time() - t0) * 1000
                if res == 0:
                    state = "OPEN"
                    banner = self.grab_banner(ip, port, timeout=1.0)
                elif res in [10060, 10035, 11]: # ETIMEDOUT / WSAETIMEDOUT
                    state = "FILTERED"
        except socket.timeout:
            state = "FILTERED"
            latency = timeout * 1000
        except Exception:
            state = "UNKNOWN"
            latency = 0.0

        return PortScanResult(port, "TCP", state, service, banner, latency)

    def scan_target(self, target: str, ports: List[int], project_id: int = 1, progress_callback: Optional[Callable[[int, int, PortScanResult], None]] = None, cancel_check: Optional[Callable[[], bool]] = None) -> List[PortScanResult]:
        # Enforce authorized scope
        scope_manager.enforce_scope(target, project_id)
        audit_logger.log_action("PORT_SCAN_STARTED", f"Target={target}, PortsCount={len(ports)}")

        # Resolve IP
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            raise ValueError(f"Could not resolve target '{target}': {e}")

        host_id = db.upsert_host(ip=ip, hostname=target if target != ip else "", project_id=project_id)
        results = []
        total = len(ports)

        for idx, port in enumerate(ports):
            if cancel_check and cancel_check():
                break

            res = self.scan_tcp_port(ip, port)
            results.append(res)

            if res.state == "OPEN":
                cve_json = json.dumps([c[0] for c in res.cves])
                db.upsert_port(
                    host_id=host_id,
                    port=res.port,
                    protocol=res.protocol,
                    service=res.service,
                    version=res.banner,
                    state=res.state,
                    cve_references=cve_json
                )

            if progress_callback:
                progress_callback(idx + 1, total, res)

        audit_logger.log_action("PORT_SCAN_COMPLETED", f"Target={target}, Scanned={len(results)}")
        return results

    def export_results(self, results: List[PortScanResult], fmt: str = "json") -> str:
        data = [r.to_dict() for r in results]
        if fmt.lower() == "json":
            return json.dumps(data, indent=2)
        elif fmt.lower() == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["port", "protocol", "state", "service", "banner", "latency_ms", "cves"])
            writer.writeheader()
            for row in data:
                row_copy = dict(row)
                row_copy["cves"] = "; ".join([c["id"] for c in row["cves"]])
                writer.writerow(row_copy)
            return output.getvalue()
        elif fmt.lower() == "html":
            rows = ""
            for r in data:
                cves_str = ", ".join([f"<span style='color:#ef5350'>{c['id']}</span>" for c in r["cves"]]) or "None"
                color = "#53e6a5" if r["state"] == "OPEN" else ("#f4b860" if r["state"] == "FILTERED" else "#aab7c7")
                rows += f"<tr><td>{r['port']}</td><td>{r['protocol']}</td><td style='color:{color}'>{r['state']}</td><td>{r['service']}</td><td>{r['banner']}</td><td>{r['latency_ms']} ms</td><td>{cves_str}</td></tr>"
            return f"""<!DOCTYPE html>
<html>
<head><title>Sentrix Port Scan Report</title>
<style>
body {{ background:#0B111B; color:#E9F1FA; font-family:Consolas, monospace; padding:20px; }}
table {{ border-collapse: collapse; width: 100%; border: 1px solid #29394B; }}
th, td {{ border: 1px solid #29394B; padding: 8px 12px; text-align: left; }}
th {{ background: #151F2D; color: #53E6A5; }}
tr:nth-child(even) {{ background: #101824; }}
</style>
</head>
<body>
<h2>SENTRIX // Port & Service Scan Report</h2>
<table>
<tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner</th><th>Latency</th><th>CVE References</th></tr>
{rows}
</table>
</body>
</html>"""
        return json.dumps(data)

port_scanner_engine = AdvancedPortScanner()
