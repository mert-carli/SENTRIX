import base64
import urllib.parse
import html
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any

class SecurityToolkit:
    def __init__(self):
        pass

    # --- Encoding / Decoding ---
    def encode_base64(self, text: str) -> str:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    def decode_base64(self, b64_str: str) -> str:
        rem = len(b64_str) % 4
        if rem > 0: b64_str += "=" * (4 - rem)
        return base64.b64decode(b64_str.encode('utf-8')).decode('utf-8', errors='ignore')

    def encode_hex(self, text: str) -> str:
        return text.encode('utf-8').hex()

    def decode_hex(self, hex_str: str) -> str:
        clean = hex_str.replace(" ", "").replace("0x", "")
        return bytes.fromhex(clean).decode('utf-8', errors='ignore')

    def encode_url(self, text: str) -> str:
        return urllib.parse.quote(text)

    def decode_url(self, text: str) -> str:
        return urllib.parse.unquote(text)

    # --- Network & Subnet Utilities ---
    def calculate_cidr(self, cidr_str: str) -> Dict[str, Any]:
        """Calculates subnet metrics: Network address, broadcast, netmask, wildcard, usable host range."""
        try:
            net = ipaddress.ip_network(cidr_str.strip(), strict=False)
            hosts = list(net.hosts())
            first_host = str(hosts[0]) if hosts else str(net.network_address)
            last_host = str(hosts[-1]) if hosts else str(net.broadcast_address)
            return {
                "cidr": str(net),
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "wildcard_mask": str(net.hostmask),
                "total_addresses": net.num_addresses,
                "usable_hosts": len(hosts),
                "usable_range": f"{first_host} - {last_host}",
                "is_private": net.is_private
            }
        except Exception as e:
            return {"error": str(e)}

    # --- Forensic Timestamp Utilities ---
    def convert_timestamp(self, ts_input: str) -> Dict[str, str]:
        """Converts between Unix Epoch, Windows FILETIME, and ISO 8601 UTC."""
        results = {}
        ts_clean = ts_input.strip()

        try:
            # Try Unix epoch (10 digits)
            epoch_val = float(ts_clean)
            if epoch_val > 1000000000000: # Milliseconds
                epoch_val /= 1000.0

            dt = datetime.fromtimestamp(epoch_val, tz=timezone.utc)
            results["ISO_8601_UTC"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            results["Unix_Epoch_Seconds"] = str(int(epoch_val))
            
            # Windows FILETIME: 100-ns intervals since Jan 1, 1601
            filetime = int((epoch_val + 11644473600) * 10000000)
            results["Windows_FILETIME"] = str(filetime)
        except Exception:
            results["error"] = "Invalid numeric timestamp format. Enter Unix timestamp (e.g. 1730832000)."
        return results

security_toolkit = SecurityToolkit()
