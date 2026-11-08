"""
SENTRIX v5.0 — Live Network Topology & Device Discovery Engine
Maps live devices relative to the active default gateway in a star/hierarchical topology.
Automatically classifies device types (Computer, Server, Router, Printer, Unknown),
evaluates risk posture, checks scope, and detects newly joined network devices.
"""

import math
import socket
import subprocess
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.database import db
from core.scope import scope_manager
from core.logger import log
from modules.recon.diff_engine import scan_diff_engine

class DeviceType:
    ROUTER = "Yönlendirici / Ağ Geçidi"
    SERVER = "Sunucu"
    COMPUTER = "Bilgisayar"
    PRINTER = "Ağ Yazıcısı"
    UNKNOWN = "Bilinmeyen Cihaz"

class DeviceStatus:
    SECURE = "GÜVENLİ"
    WARNING = "DİKKAT"
    CRITICAL = "KRİTİK"

class NetworkTopologyEngine:
    """Discovers, correlates, and arranges network assets into an interactive topology model."""

    def __init__(self):
        self._known_ips_baseline = set()
        self._new_devices_cache: List[Dict[str, Any]] = []
        self._cached_gateway: Optional[str] = None

    def get_default_gateway(self) -> str:
        """Finds the default gateway IP on Windows via route print or ipconfig fallback."""
        if self._cached_gateway:
            return self._cached_gateway
        try:
            # Run netstat -rn or route print
            res = subprocess.run("route print 0.0.0.0", shell=True, capture_output=True, text=True, timeout=4)
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway = parts[2]
                    if gateway != "On-link" and not gateway.startswith("127."):
                        self._cached_gateway = gateway
                        return gateway
        except Exception as e:
            log.debug(f"TopologyEngine: Ağ geçidi route tablosundan okunamadı: {e}")

        # Fallback heuristic: query local socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            self._cached_gateway = gw
            return gw
        except Exception:
            self._cached_gateway = "192.168.1.1"
            return "192.168.1.1"

    def build_topology(self, project_id: int = 1) -> Dict[str, Any]:
        """Gathers hosts, classifies devices, and formats node coordinates for star layout."""
        gateway_ip = self.get_default_gateway()
        all_hosts = db.get_all_hosts(project_id=project_id)
        
        # Verify scope boundaries
        valid_hosts = []
        for h in all_hosts:
            ip = h.get("ip", "")
            is_auth, _ = scope_manager.is_target_authorized(ip, project_id=project_id)
            if is_auth or ip == gateway_ip or ip.startswith("127."):
                valid_hosts.append(h)

        devices = []
        new_devices = []
        gateway_device = None

        # Process each host
        for h in valid_hosts:
            ip = h.get("ip", "")
            host_id = h.get("id")
            ports = db.get_open_ports_for_host(host_id) if host_id else []
            
            dev_type, icon_tag = self._classify_device(h, ports, gateway_ip)
            posture = self._evaluate_posture(ports)
            diff_res = scan_diff_engine.compare_target_scans(ip, project_id=project_id)

            device_info = {
                "id": f"dev_{host_id}_{ip}",
                "host_id": host_id,
                "ip": ip,
                "hostname": h.get("hostname") or "Bilinmiyor",
                "mac": h.get("mac") or "Bilinmiyor",
                "vendor": h.get("vendor") or "Bilinmeyen Üretici",
                "os": h.get("os_guess") or "Bilinmiyor",
                "device_type": dev_type,
                "icon_tag": icon_tag,
                "open_ports": ports,
                "open_ports_count": len(ports),
                "posture": posture,
                "diff": diff_res,
                "last_seen": h.get("last_seen") or datetime.now().isoformat(),
                "is_gateway": (ip == gateway_ip)
            }

            if ip == gateway_ip:
                gateway_device = device_info
            else:
                devices.append(device_info)

            # Check new device baseline
            if self._known_ips_baseline and ip not in self._known_ips_baseline and ip != gateway_ip:
                new_devices.append(device_info)

        # If gateway was not in db, create a default gateway node
        if not gateway_device:
            gateway_device = {
                "id": f"dev_gw_{gateway_ip}",
                "host_id": None,
                "ip": gateway_ip,
                "hostname": "Yerel Ağ Geçidi (Gateway)",
                "mac": "Bilinmiyor",
                "vendor": "Yönlendirici Donanımı",
                "os": "Embedded Router OS",
                "device_type": DeviceType.ROUTER,
                "icon_tag": "[GW]",
                "open_ports": [],
                "open_ports_count": 0,
                "posture": DeviceStatus.SECURE,
                "diff": {"has_diff": False},
                "last_seen": datetime.now().isoformat(),
                "is_gateway": True
            }

        # Update baseline
        for h in valid_hosts:
            self._known_ips_baseline.add(h.get("ip"))

        # Calculate circular/star coordinates around the gateway
        nodes, edges = self._layout_star_topology(gateway_device, devices)

        notification_msg = ""
        if new_devices:
            first_new = new_devices[0]
            notification_msg = f"Ağda yeni cihaz tespit edildi: {first_new['ip']} ({first_new['vendor']})"

        return {
            "gateway": gateway_device,
            "total_devices": len(nodes),
            "new_devices_detected": new_devices,
            "notification_msg": notification_msg,
            "nodes": nodes,
            "edges": edges
        }

    def _classify_device(self, host: Dict[str, Any], ports: List[Dict[str, Any]], gateway_ip: str) -> tuple[str, str]:
        """Infers device type and abbreviation tag from vendor, hostname, and open port signatures."""
        ip = host.get("ip", "")
        hostname = (host.get("hostname") or "").lower()
        vendor = (host.get("vendor") or "").lower()
        port_nums = {p.get("port") for p in ports}

        if ip == gateway_ip or "router" in hostname or "gateway" in hostname:
            return DeviceType.ROUTER, "[GW]"

        # Printer signatures: 515 (LPD), 631 (IPP), 9100 (RAW) or printer vendors
        if any(p in port_nums for p in [515, 631, 9100]) or any(v in vendor for v in ["hp", "canon", "epson", "xerox", "brother"]):
            return DeviceType.PRINTER, "[PRN]"

        # Server signatures: domain controller (88, 389), databases (1433, 3306, 5432), server in hostname
        if any(p in port_nums for p in [88, 389, 1433, 3306, 5432]) or any(s in hostname for s in ["srv", "server", "dc0", "sql", "nas"]):
            return DeviceType.SERVER, "[SRV]"

        # Computer / Workstation signatures
        if "pc" in hostname or "desktop" in hostname or "laptop" in hostname or "win" in hostname:
            return DeviceType.COMPUTER, "[PC]"

        if len(ports) > 0 or host.get("hostname"):
            return DeviceType.COMPUTER, "[PC]"

        return DeviceType.UNKNOWN, "[?]"

    def _evaluate_posture(self, ports: List[Dict[str, Any]]) -> str:
        """Determines device security posture badge."""
        port_nums = {p.get("port") for p in ports}
        # Critical exposure: RDP, SMB, Telnet, FTP
        if any(p in port_nums for p in [21, 23, 445, 3389]):
            return DeviceStatus.CRITICAL
        # Warning exposure: HTTP, HTTPS, SSH, unusual ports
        if any(p in port_nums for p in [22, 80, 8080, 8443]) or len(ports) > 3:
            return DeviceStatus.WARNING
        return DeviceStatus.SECURE

    def _layout_star_topology(self, gateway: Dict[str, Any], devices: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Calculates 2D positions placing the Gateway in the center and devices in concentric rings."""
        nodes = []
        edges = []

        center_x = 380
        center_y = 260

        # Central Gateway Node
        gateway["x"] = center_x - 45
        gateway["y"] = center_y - 25
        gateway["width"] = 110
        gateway["height"] = 55
        gateway["color"] = "#4F8FF7"
        nodes.append(gateway)

        total_devices = len(devices)
        if total_devices == 0:
            return nodes, edges

        radius = 175 if total_devices <= 8 else 210
        angle_step = (2 * math.pi) / total_devices

        for i, dev in enumerate(devices):
            angle = i * angle_step
            dx = center_x + (radius * math.cos(angle)) - 45
            dy = center_y + (radius * math.sin(angle)) - 25

            dev["x"] = dx
            dev["y"] = dy
            dev["width"] = 110
            dev["height"] = 52

            # Posture color
            if dev["posture"] == DeviceStatus.CRITICAL:
                dev["color"] = "#E56767"
            elif dev["posture"] == DeviceStatus.WARNING:
                dev["color"] = "#E9AD48"
            else:
                dev["color"] = "#31B88A"

            nodes.append(dev)

            # Connecting star edge from gateway to device
            edges.append({
                "from": gateway["id"],
                "to": dev["id"],
                "color": "#263447" if dev["posture"] == DeviceStatus.SECURE else dev["color"]
            })

        return nodes, edges

network_topology_engine = NetworkTopologyEngine()
