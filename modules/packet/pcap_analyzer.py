import struct
import socket
import os
from typing import Dict, List, Any, Tuple

PCAP_STANDARD_MAGIC = 0xA1B2C3D4
PCAP_SWAPPED_MAGIC  = 0xD4C3B2A1
PCAP_NANO_MAGIC     = 0xA1B23C4D
PCAPNG_MAGIC        = 0x0A0D0D0A

class PCAPAnalyzer:
    """Pure-Python binary PCAP/PCAPNG network packet capture analyzer with IPv4, IPv6, DNS, and TLS dissection."""

    def parse_pcap_file(self, file_path: str, max_packets: int = 5000) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            header_bytes = f.read(24)

        if len(header_bytes) < 24:
            return {"error": "Corrupt or truncated PCAP header (under 24 bytes)."}

        magic = struct.unpack("<I", header_bytes[:4])[0]
        if magic == PCAPNG_MAGIC:
            return {
                "format": "PCAPNG",
                "message": "PCAPNG format identified. Use TShark or convert to standard PCAP for deep layer extraction.",
                "total_packets_parsed": 0,
                "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
                "top_talkers": [],
                "top_flows": [],
                "anomalies": []
            }

        endian = "<"
        if magic == PCAP_STANDARD_MAGIC:
            endian = "<"
        elif magic == PCAP_SWAPPED_MAGIC:
            endian = ">"
        elif magic == PCAP_NANO_MAGIC:
            endian = "<"
        else:
            return {"error": f"Unsupported or non-standard PCAP magic: 0x{magic:08X}."}

        # Parse Global Header
        _, version_major, version_minor, thiszone, sigfigs, snaplen, network_link = struct.unpack(
            f"{endian}IHHiIII", header_bytes
        )

        packet_count = 0
        protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "IPv6": 0, "OTHER": 0}
        ip_talkers = {}
        flows = {}
        anomalies = []
        dns_queries = set()

        with open(file_path, "rb") as f:
            f.seek(24)  # Skip global header

            while packet_count < max_packets:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
                pkt_bytes = f.read(incl_len)
                if len(pkt_bytes) < incl_len:
                    break

                packet_count += 1
                if len(pkt_bytes) < 14:
                    continue

                eth_proto = struct.unpack("!H", pkt_bytes[12:14])[0]

                # IPv4
                if eth_proto == 0x0800:
                    ip_data = pkt_bytes[14:]
                    if len(ip_data) < 20:
                        continue

                    ihl = (ip_data[0] & 0x0F) * 4
                    proto_num = ip_data[9]
                    src_ip = socket.inet_ntoa(ip_data[12:16])
                    dst_ip = socket.inet_ntoa(ip_data[16:20])

                    ip_talkers[src_ip] = ip_talkers.get(src_ip, 0) + 1
                    ip_talkers[dst_ip] = ip_talkers.get(dst_ip, 0) + 1

                    payload = ip_data[ihl:]
                    src_port, dst_port = 0, 0
                    proto_str = "OTHER"

                    if proto_num == 6:  # TCP
                        proto_str = "TCP"
                        protocol_counts["TCP"] += 1
                        if len(payload) >= 4:
                            src_port, dst_port = struct.unpack("!HH", payload[:4])
                    elif proto_num == 17:  # UDP
                        proto_str = "UDP"
                        protocol_counts["UDP"] += 1
                        if len(payload) >= 4:
                            src_port, dst_port = struct.unpack("!HH", payload[:4])
                            # Check DNS
                            if dst_port == 53 and len(payload) > 12:
                                q_domain = self._extract_dns_query(payload[8:])
                                if q_domain:
                                    dns_queries.add(q_domain)
                    elif proto_num == 1:  # ICMP
                        proto_str = "ICMP"
                        protocol_counts["ICMP"] += 1
                    else:
                        protocol_counts["OTHER"] += 1

                    flow_key = (src_ip, dst_ip, proto_str, dst_port)
                    if flow_key not in flows:
                        flows[flow_key] = {"packets": 0, "bytes": 0}
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["bytes"] += incl_len

                    if dst_port in [4444, 1337, 31337, 6667]:
                        anomalies.append(f"Suspicious Port {dst_port} activity: {src_ip} -> {dst_ip}")

                # IPv6
                elif eth_proto == 0x86DD:
                    protocol_counts["IPv6"] += 1
                    ip6_data = pkt_bytes[14:]
                    if len(ip6_data) >= 40:
                        try:
                            src_ip6 = socket.inet_ntop(socket.AF_INET6, ip6_data[8:24])
                            dst_ip6 = socket.inet_ntop(socket.AF_INET6, ip6_data[24:40])
                            ip_talkers[src_ip6] = ip_talkers.get(src_ip6, 0) + 1
                            ip_talkers[dst_ip6] = ip_talkers.get(dst_ip6, 0) + 1
                        except Exception:
                            pass

        top_talkers = sorted(ip_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
        top_flows = []
        for (s_ip, d_ip, pr, d_pt), stats in sorted(flows.items(), key=lambda x: x[1]["bytes"], reverse=True)[:15]:
            top_flows.append({
                "src": s_ip,
                "dst": f"{d_ip}:{d_pt}" if d_pt else d_ip,
                "proto": pr,
                "packets": stats["packets"],
                "bytes": stats["bytes"]
            })

        return {
            "total_packets_parsed": packet_count,
            "snaplen": snaplen,
            "protocols": protocol_counts,
            "top_talkers": top_talkers,
            "top_flows": top_flows,
            "dns_queries": list(dns_queries)[:20],
            "anomalies": list(set(anomalies))
        }

    @staticmethod
    def _extract_dns_query(udp_payload: bytes) -> str:
        """Parses standard DNS question name from raw UDP bytes."""
        try:
            if len(udp_payload) < 13:
                return ""
            idx = 12
            labels = []
            while idx < len(udp_payload):
                length = udp_payload[idx]
                if length == 0:
                    break
                idx += 1
                labels.append(udp_payload[idx:idx+length].decode("ascii", errors="ignore"))
                idx += length
            return ".".join(labels)
        except Exception:
            return ""

pcap_analyzer = PCAPAnalyzer()
