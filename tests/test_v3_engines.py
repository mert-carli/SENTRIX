import unittest
import os
import sys
import tempfile
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import db
from modules.recon.diff_engine import scan_diff_engine
from modules.recon.nmap_parser import nmap_parser
from modules.packet.pcap_analyzer import pcap_analyzer
from modules.websec.workbench import web_workbench
from modules.active_directory.attack_path import ad_attack_path_analyzer
from modules.vuln_research.epss_engine import epss_engine
from modules.reverse_eng.binary_diff import binary_diff_engine
from modules.redteam.atomic_framework import atomic_test_runner
from modules.endpoint.edr_lite import edr_lite_engine
from modules.correlation.sigma_engine import sigma_detection_engine
from modules.automation.workflow_engine import workflow_engine
from modules.security_tools.toolkit import security_toolkit

class TestSentrixV3Engines(unittest.TestCase):
    def test_security_toolkit_encoding_and_cidr(self):
        # Base64 & Hex
        sample = "SENTRIX_V3_RESEARCH"
        b64 = security_toolkit.encode_base64(sample)
        self.assertEqual(security_toolkit.decode_base64(b64), sample)

        h = security_toolkit.encode_hex(sample)
        self.assertEqual(security_toolkit.decode_hex(h), sample)

        # CIDR
        cidr_res = security_toolkit.calculate_cidr("192.168.1.0/24")
        self.assertEqual(cidr_res["netmask"], "255.255.255.0")
        self.assertEqual(cidr_res["usable_hosts"], 254)
        self.assertTrue(cidr_res["is_private"])

        # Timestamp
        ts_res = security_toolkit.convert_timestamp("1700000000")
        self.assertIn("UTC", ts_res["ISO_8601_UTC"])

    def test_epss_and_risk_priority(self):
        epss = epss_engine.get_epss_score("CVE-2017-0144")
        self.assertGreater(epss["epss_score"], 0.5)

        priority = epss_engine.compute_risk_priority(cvss=9.8, epss=0.97, is_cisa_kev=True)
        self.assertIn("P1 - CRITICAL", priority)

    def test_ad_attack_paths(self):
        res = ad_attack_path_analyzer.build_sample_attack_paths("corp.local", ["sec_admin", "svc_backup"])
        self.assertEqual(len(res["attack_paths"]), 2)
        self.assertLessEqual(res["identity_security_score"], 100)

    def test_response_diff_and_har(self):
        diff = web_workbench.compute_response_diff("HTTP/1.1 200 OK\nServer: Apache\n", "HTTP/1.1 200 OK\nServer: Nginx\n")
        self.assertIn("+Server: Nginx", diff)

        har = web_workbench.export_to_har(
            {"method": "GET", "url": "https://example.com", "headers": {"User-Agent": "Sentrix"}},
            {"status_code": 200, "reason": "OK", "body": "test", "body_len": 4}
        )
        self.assertIn('"name": "SENTRIX Cyber Operations Platform"', har)

    def test_pcap_binary_parsing(self):
        # Construct synthetic valid PCAP binary buffer (global header + 1 synthetic packet)
        # Global header: magic (0xa1b2c3d4), ver 2.4, zone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
        global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        
        # Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
        # Ethernet: dst(6), src(6), ethertype 0x0800
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        # IPv4: ver/ihl 0x45, tos 0, len 40, id 1, flags 0, ttl 64, proto 6 (TCP), cksum 0, src 192.168.1.10, dst 10.0.0.1
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\xc0\xa8\x01\x0a", b"\x0a\x00\x00\x01")
        # TCP: src 4444 (suspicious port), dst 80, seq 1, ack 0, offset 5, flags 2 (SYN), win 1024, cksum 0, urp 0
        tcp_hdr = struct.pack("!HHIIBBHHH", 4444, 80, 1, 0, 0x50, 2, 1024, 0, 0)
        pkt_data = eth + ip_hdr + tcp_hdr

        pkt_hdr = struct.pack("<IIII", 1700000000, 0, len(pkt_data), len(pkt_data))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tf:
            tf.write(global_hdr + pkt_hdr + pkt_data)
            pcap_path = tf.name

        try:
            res = pcap_analyzer.parse_pcap_file(pcap_path)
            self.assertEqual(res["total_packets_parsed"], 1)
            self.assertEqual(res["protocols"]["TCP"], 1)
            self.assertTrue(any("192.168.1.10" in t[0] for t in res["top_talkers"]))
            self.assertTrue(any(f["src"] == "192.168.1.10" for f in res["top_flows"]))
        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)

    def test_nmap_xml_parser(self):
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
    <status state="up"/>
    <address addr="192.168.10.55" addrtype="ipv4"/>
    <hostnames><hostname name="testserver.local"/></hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
        </port>
    </ports>
</host>
</nmaprun>"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml", mode="w", encoding="utf-8") as tf:
            tf.write(sample_xml)
            xml_path = tf.name

        try:
            res = nmap_parser.parse_file(xml_path, project_id=1)
            self.assertEqual(res["total_hosts"], 1)
            self.assertEqual(res["total_open_ports"], 1)
            self.assertEqual(res["hosts"][0]["ip"], "192.168.10.55")
        finally:
            if os.path.exists(xml_path):
                os.remove(xml_path)

    def test_sigma_detection_engine(self):
        matched = sigma_detection_engine.evaluate_process_event("powershell.exe -NoProfile -enc SQBFAFgA...", "powershell.exe")
        self.assertTrue(any(r["id"] == "SIGMA-WIN-001" for r in matched))

        matched_sock = sigma_detection_engine.evaluate_socket_event(4444, "192.168.1.200")
        self.assertTrue(any(r["id"] == "SIGMA-WIN-003" for r in matched_sock))

    def test_edr_lite_fim_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            test_file = os.path.join(td, "config.ini")
            with open(test_file, "w") as f: f.write("version=1.0\n")

            edr_lite_engine.create_fim_baseline(td)
            
            # Unmodified check
            res_clean = edr_lite_engine.check_fim_integrity(td)
            self.assertFalse(res_clean["integrity_breached"])

            # Tamper file
            with open(test_file, "a") as f: f.write("backdoor=active\n")

            res_tampered = edr_lite_engine.check_fim_integrity(td)
            self.assertTrue(res_tampered["integrity_breached"])
            self.assertIn(test_file, res_tampered["modified_files"])

    def test_atomic_framework_catalog(self):
        matrix = atomic_test_runner.get_coverage_matrix()
        self.assertGreater(len(matrix), 2)
        res = atomic_test_runner.run_atomic_test("T1059.001-TEST1")
        self.assertIn(res["status"], ["COMPLETED", "FAILED"])

    def test_automation_workflow_engine(self):
        res = workflow_engine.run_automated_audit_workflow("127.0.0.1", project_id=1)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertGreater(len(res["logs"]), 3)

if __name__ == "__main__":
    unittest.main()
