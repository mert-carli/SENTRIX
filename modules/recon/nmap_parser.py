import xml.etree.ElementTree as ET
import os
from typing import Dict, List, Any
from core.database import db

class NmapXMLParser:
    def __init__(self):
        pass

    def parse_file(self, xml_path: str, project_id: int = 1) -> Dict[str, Any]:
        """Parses an Nmap XML output file and persists discovered hosts and ports into SQLite."""
        if not os.path.exists(xml_path):
            raise FileNotFoundError(f"XML file not found: {xml_path}")

        tree = ET.parse(xml_path)
        root = tree.getroot()

        parsed_hosts = []
        total_ports_found = 0

        for host_elem in root.findall('host'):
            # Status check
            status_elem = host_elem.find('status')
            if status_elem is not None and status_elem.get('state') != 'up':
                continue

            # Addresses
            ipv4 = ""
            mac = ""
            vendor = ""
            for addr in host_elem.findall('address'):
                addr_type = addr.get('addrtype')
                if addr_type == 'ipv4':
                    ipv4 = addr.get('addr')
                elif addr_type == 'mac':
                    mac = addr.get('addr')
                    vendor = addr.get('vendor', '')

            if not ipv4:
                continue

            # Hostnames
            hostname = ""
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                first_name = hostnames_elem.find('hostname')
                if first_name is not None:
                    hostname = first_name.get('name', '')

            # OS guess
            os_guess = "Unknown"
            os_elem = host_elem.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    os_guess = osmatch.get('name', 'Unknown')

            host_id = db.upsert_host(
                ip=ipv4, mac=mac, hostname=hostname,
                os_guess=os_guess, vendor=vendor,
                project_id=project_id
            )

            # Ports
            ports_elem = host_elem.find('ports')
            host_ports = []
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    state_elem = port_elem.find('state')
                    if state_elem is None or state_elem.get('state') != 'open':
                        continue

                    port_num = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol', 'tcp').upper()
                    
                    service_name = "unknown"
                    version_str = ""
                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        service_name = service_elem.get('name', 'unknown')
                        product = service_elem.get('product', '')
                        version = service_elem.get('version', '')
                        version_str = f"{product} {version}".strip()

                    db.upsert_port(
                        host_id=host_id,
                        port=port_num,
                        protocol=protocol,
                        service=service_name,
                        version=version_str,
                        state="OPEN",
                        detection_method="NMAP_XML_IMPORT"
                    )
                    host_ports.append({"port": port_num, "protocol": protocol, "service": service_name, "version": version_str})
                    total_ports_found += 1

            parsed_hosts.append({
                "ip": ipv4,
                "hostname": hostname,
                "os": os_guess,
                "ports": host_ports
            })

        db.record_scan_session("NMAP_XML_IMPORT", xml_path, total_ports_found, project_id=project_id)

        return {
            "total_hosts": len(parsed_hosts),
            "total_open_ports": total_ports_found,
            "hosts": parsed_hosts
        }

nmap_parser = NmapXMLParser()
