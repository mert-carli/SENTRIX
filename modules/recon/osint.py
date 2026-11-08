import socket
import ssl
import json
import urllib.request
import subprocess
from typing import Dict, List, Any, Optional
from core.scope import scope_manager
from core.logger import audit_logger

class OSINTMapper:
    def __init__(self):
        pass

    def dns_enumeration(self, domain: str) -> Dict[str, List[str]]:
        domain = domain.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}
        
        for qtype in records.keys():
            try:
                cmd = f"nslookup -type={qtype} {domain}"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                out = proc.stdout
                for line in out.splitlines():
                    line = line.strip()
                    if not line or "Server:" in line or "Address:" in line and "Non-authoritative" not in out:
                        continue
                    if qtype == "A" and ("internet address" in line or (domain in line and "address" in line)):
                        parts = line.split("=") if "=" in line else line.split()
                        records["A"].append(parts[-1].strip())
                    elif qtype == "AAAA" and "AAAA" in line:
                        records["AAAA"].append(line.split()[-1].strip())
                    elif qtype == "MX" and "mail exchanger" in line:
                        records["MX"].append(line.split()[-1].strip())
                    elif qtype == "TXT" and "text =" in line:
                        records["TXT"].append(line.split("text =")[-1].strip().strip('"'))
                    elif qtype == "NS" and "nameserver" in line:
                        records["NS"].append(line.split()[-1].strip())
                    elif qtype == "CNAME" and "canonical name" in line:
                        records["CNAME"].append(line.split()[-1].strip())
            except Exception:
                pass
        return records

    def reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "No PTR record found"

    def certificate_transparency(self, domain: str) -> List[str]:
        """Queries crt.sh Certificate Transparency logs for subdomains."""
        domain = domain.strip().replace("http://", "").replace("https://", "").split("/")[0]
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                for entry in data:
                    name_val = entry.get('name_value', '')
                    for sub in name_val.split('\n'):
                        sub = sub.strip().lower()
                        if '*' not in sub and sub.endswith(domain):
                            subdomains.add(sub)
        except Exception:
            pass
        return sorted(list(subdomains))[:50]

    def whois_rdap(self, target: str) -> Dict[str, Any]:
        target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
        is_ip = False
        try:
            socket.inet_aton(target)
            is_ip = True
        except Exception:
            pass

        try:
            if is_ip:
                url = f"https://rdap.arin.net/registry/ip/{target}"
            else:
                ip = socket.gethostbyname(target)
                url = f"http://ip-api.com/json/{ip}"

            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def technology_fingerprint(self, domain: str) -> Dict[str, Any]:
        domain = domain.strip().replace("http://", "").replace("https://", "").split("/")[0]
        info: Dict[str, Any] = {"server": "Unknown", "x_powered_by": "Unknown", "technologies": [], "security_headers": {}}
        try:
            import http.client
            conn = http.client.HTTPSConnection(domain, timeout=5)
            conn.request("HEAD", "/")
            res = conn.getresponse()
            headers = {k.lower(): v for k, v in res.getheaders()}

            info["server"] = headers.get("server", "Hidden/Not Provided")
            info["x_powered_by"] = headers.get("x-powered-by", "None")

            # Check common technology headers
            if "x-aspnet-version" in headers or "asp.net" in info["x_powered_by"].lower():
                info["technologies"].append("Microsoft ASP.NET")
            if "php" in info["x_powered_by"].lower():
                info["technologies"].append("PHP")
            if "cloudflare" in info["server"].lower():
                info["technologies"].append("Cloudflare CDN/WAF")
            if "nginx" in info["server"].lower():
                info["technologies"].append("Nginx Web Server")
            if "apache" in info["server"].lower():
                info["technologies"].append("Apache HTTP Server")

            # Security Headers Evaluation
            for h in ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]:
                info["security_headers"][h] = "Present" if h in headers else "Missing"
        except Exception as e:
            info["error"] = str(e)
        return info

    def build_attack_surface_tree(self, domain: str) -> str:
        """Generates an ASCII Attack Surface Hierarchy."""
        dns_data = self.dns_enumeration(domain)
        tech_data = self.technology_fingerprint(domain)
        
        lines = []
        lines.append(f"TARGET DOMAIN: {domain}")
        lines.append(f"  ├── Technologies : {', '.join(tech_data.get('technologies', [])) or 'Standard Web'}")
        lines.append(f"  ├── Server       : {tech_data.get('server', 'Unknown')}")
        
        ips = dns_data.get("A", [])
        if ips:
            lines.append("  ├── Resolved IPs :")
            for ip in ips:
                ptr = self.reverse_dns(ip)
                lines.append(f"  │     └── IP: {ip} (PTR: {ptr})")
        
        mx = dns_data.get("MX", [])
        if mx:
            lines.append("  ├── Mail Exchanges (MX):")
            for m in mx:
                lines.append(f"  │     └── {m}")

        txt = dns_data.get("TXT", [])
        if txt:
            lines.append("  ├── TXT Records (SPF/DKIM/Verifications):")
            for t in txt[:5]:
                lines.append(f"  │     └── {t[:70]}...")

        lines.append("  └── Security Headers:")
        for h, status in tech_data.get("security_headers", {}).items():
            lines.append(f"        └── {h:<28}: {status}")

        return "\n".join(lines)

osint_engine = OSINTMapper()
