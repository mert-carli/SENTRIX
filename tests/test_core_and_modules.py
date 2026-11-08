import unittest
import os
import sys
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import db
from core.scope import scope_manager, ScopeViolationError
from core.event_bus import event_bus
from core.task_manager import task_manager, TaskStatus
from core.permission import is_admin, get_privilege_status_str
from modules.password_lab.pwd_tool import password_lab
from modules.forensics.dfir import forensics_toolkit
from modules.api_sec.api_tester import api_security_tester
from modules.vuln_research.cve_engine import vulnerability_engine
from modules.reporting.report_generator import report_generator
from modules.recon.scanner import port_scanner_engine

class TestSentrixCore(unittest.TestCase):
    def test_database_operations(self):
        host_id = db.upsert_host("127.0.0.1", hostname="localhost", os_guess="Windows")
        self.assertGreater(host_id, 0)
        
        db.upsert_port(host_id, 443, "TCP", "HTTPS", "OpenSSL", "OPEN")
        ports = db.get_open_ports_for_host(host_id)
        self.assertTrue(any(p["port"] == 443 for p in ports))
        
        alert_id = db.add_alert("HIGH", "UnitTest", "Test Alert")
        self.assertGreater(alert_id, 0)
        recent = db.get_recent_alerts(5)
        self.assertTrue(any(a["id"] == alert_id for a in recent))

    def test_scope_manager(self):
        # 127.0.0.1 and localhost should be authorized by default
        auth, _ = scope_manager.is_target_authorized("127.0.0.1")
        self.assertTrue(auth)

        auth_local, _ = scope_manager.is_target_authorized("localhost")
        self.assertTrue(auth_local)

        # Random unauthorized internet target should be rejected
        auth_random, reason = scope_manager.is_target_authorized("93.184.216.34") # example.com IP
        self.assertFalse(auth_random)

    def test_event_bus(self):
        received = []
        def handler(data):
            received.append(data)
        event_bus.subscribe("TEST_EVENT", handler)
        event_bus.publish("TEST_EVENT", {"val": 42})
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["val"], 42)

    def test_task_manager(self):
        def sample_work(ctx):
            ctx.update_progress(50.0, "Halfway")
            return "SUCCESS"
        tid = task_manager.run_task("UnitTestTask", sample_work)
        import time
        time.sleep(0.5)
        task = task_manager.get_task(tid)
        self.assertEqual(task["status"], TaskStatus.COMPLETED)
        self.assertEqual(task["result"], "SUCCESS")

    def test_password_lab(self):
        entropy = password_lab.calculate_entropy("P@ssw0rd123!")
        self.assertGreater(entropy, 20.0)

        strength = password_lab.evaluate_strength("A" * 16 + "1!a")
        self.assertEqual(strength["rating"], "STRONG")

        hashes = password_lab.generate_hashes("test")
        self.assertEqual(hashes["MD5"], "098f6bcd4621d373cade4e832627b4f6")
        
        cands = password_lab.identify_hash("098f6bcd4621d373cade4e832627b4f6")
        self.assertIn("MD5", cands)

    def test_forensics_toolkit(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"MZ\x90\x00\x03\x00\x00\x00SENTRIX_FORENSIC_SAMPLE_STRING\x00")
            temp_path = tf.name

        try:
            info = forensics_toolkit.inspect_file(temp_path)
            self.assertIn("Windows PE", info["detected_format"])
            self.assertIn("SENTRIX_FORENSIC", forensics_toolkit.extract_strings(temp_path)[0])
            hex_view = forensics_toolkit.get_hex_dump(temp_path)
            self.assertIn("MZ", hex_view)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_jwt_decoder(self):
        # sample JWT: {"alg":"none"}.{"user":"admin","exp":9999999999}.
        sample_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."
        res = api_security_tester.decode_jwt(sample_jwt)
        self.assertEqual(res["algorithm"], "NONE")
        self.assertTrue(any(f[0] == "CRITICAL" for f in res["findings"]))

    def test_cve_engine(self):
        cve_info = vulnerability_engine.lookup_cve("CVE-2017-0144")
        self.assertEqual(cve_info["severity"], "CRITICAL")
        self.assertTrue(cve_info["cisa_kev"])

    def test_reporting_generator(self):
        report = report_generator.generate_comprehensive_report(lang="TR")
        self.assertIn("SİBER GÜVENLİK", report)
        self.assertIn("Yönetici Özeti", report)

    def test_scanner_export(self):
        from modules.recon.scanner import PortScanResult
        res = [PortScanResult(80, "TCP", "OPEN", "HTTP", "Apache/2.4", 12.5)]
        json_out = port_scanner_engine.export_results(res, "json")
        self.assertIn("Apache/2.4", json_out)
        csv_out = port_scanner_engine.export_results(res, "csv")
        self.assertIn("80,TCP,OPEN", csv_out)

if __name__ == "__main__":
    unittest.main()
