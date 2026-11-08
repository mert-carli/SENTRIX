import unittest
import os
import tempfile
from core.database import db
from core.scope import scope_manager, ScopeViolationError
from core.event_bus import event_bus, SecurityEvent
from modules.windows_internals.event_normalizer import EventNormalizer
from modules.windows_internals.sysmon_collector import SysmonCollector
from modules.windows_internals.etw_collector import ETWCollector
from modules.threat_hunting.hunt_engine import ThreatHuntingEngine
from modules.threat_hunting.hypothesis_manager import HypothesisManager
from modules.detection_studio.rule_validator import RuleValidator
from modules.detection_studio.coverage_analyzer import DetectionCoverageAnalyzer
from modules.memory_forensics.memory_manager import MemoryManager
from modules.memory_forensics.process_artifacts import ProcessArtifactExtractor
from modules.memory_forensics.volatility_adapter import VolatilityAdapter
from modules.active_directory.acl_analyzer import ACLAnalyzer
from modules.active_directory.identity_graph import IdentityGraph
from modules.active_directory.risk_path_analyzer import RiskPathAnalyzer
from modules.container_security.docker_auditor import DockerAuditor
from modules.container_security.rbac_analyzer import KubernetesRBACAnalyzer
from modules.cloud_security.aws.aws_auditor import AWSSecurityAuditor
from modules.supply_chain.sbom_engine import SBOMEngine
from modules.supply_chain.license_analyzer import LicenseAnalyzer
from modules.crypto_lab.tls_inspector import TLSInspector
from modules.soar.playbook_engine import SOARPlaybookEngine
from modules.mobile_security.manifest_parser import AndroidManifestAuditor
from modules.firmware_security.firmware_analyzer import FirmwareAnalyzer
from modules.risk_engine.scoring_engine import ExplainableRiskScorer

class TestV4AdvancedEngines(unittest.TestCase):

    def test_scope_manager_v4_protection(self):
        # Localhost must be authorized
        auth, reason = scope_manager.is_target_authorized("127.0.0.1")
        self.assertTrue(auth)

        # Unlisted external IP should fail closed
        auth, reason = scope_manager.is_target_authorized("203.0.113.195")
        self.assertFalse(auth)
        self.assertIn("outside authorized", reason)

    def test_event_normalizer_and_bus(self):
        ev = EventNormalizer.normalize_windows_event("Security", "4624", fields={"Computer": "TEST-PC", "ProcessId": "0x12a"})
        self.assertEqual(ev.event_type, "WIN_AUTHENTICATION")
        self.assertEqual(ev.process_id, 298)
        self.assertEqual(ev.source_host, "TEST-PC")

        # Emit to bus
        event_bus.emit_security_event(ev)
        recent = event_bus.get_recent_events(limit=5)
        self.assertTrue(len(recent) > 0)

    def test_sysmon_and_etw_collectors(self):
        sysmon = SysmonCollector()
        status = sysmon.check_availability()
        self.assertIn("status", status)
        self.assertIn(status["status"], ["AVAILABLE", "DISABLED", "NOT_INSTALLED", "ERROR"])

        etw = ETWCollector()
        providers = etw.query_security_providers()
        self.assertTrue(len(providers) >= 5)

    def test_threat_hunting_hypotheses_and_engine(self):
        mgr = HypothesisManager()
        hypotheses = mgr.get_all_hypotheses()
        self.assertTrue(len(hypotheses) >= 4)

        engine = ThreatHuntingEngine()
        res = engine.start_hunt_campaign(hypotheses[0]["id"])
        self.assertTrue(res["success"])
        self.assertIn("hunt_id", res)
        self.assertIn("timeline", res)
        self.assertIn("graph", res)

    def test_detection_studio_rule_validator(self):
        # Sigma
        sigma_txt = "title: Test Rule\nlogsource:\n  category: process_creation\ndetection:\n  field: name\n  value: cmd.exe\n"
        res_sigma = RuleValidator.validate_rule("SIGMA", sigma_txt)
        self.assertTrue(res_sigma["valid"])

        # YARA
        yara_txt = "rule TestYara { strings: $a = \"malware\" condition: $a }"
        res_yara = RuleValidator.validate_rule("YARA", yara_txt)
        self.assertTrue(res_yara["valid"])

        # Suricata
        suri_txt = 'alert tcp any any -> any 80 (msg:"HTTP Probe"; sid:1000001;)'
        res_suri = RuleValidator.validate_rule("SURICATA", suri_txt)
        self.assertTrue(res_suri["valid"])

        # MITRE Coverage
        cov = DetectionCoverageAnalyzer.evaluate_coverage([{"mitre_technique": "T1059.001"}])
        self.assertEqual(cov["covered_techniques_count"], 1)

    def test_memory_forensics_adapters(self):
        vol = VolatilityAdapter()
        stat = vol.check_volatility_installed()
        self.assertIn("status", stat)

        # Process artifact parser
        sample_pslist = "PID\tPPID\tImageFileName\n100\t4\tsystem.exe\n200\t100\tsvchost.exe"
        procs = ProcessArtifactExtractor.parse_pslist_output(sample_pslist)
        self.assertEqual(len(procs), 2)
        self.assertEqual(procs[0]["pid"], 100)

        # Temporary memory image test
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"SAMPLE_MEMORY_DUMP_HEADER_DATA_12345")
            temp_path = tf.name

        try:
            mgr = MemoryManager()
            rec = mgr.register_memory_image(temp_path)
            self.assertEqual(rec["filename"], os.path.basename(temp_path))
            self.assertEqual(len(rec["sha256"]), 64)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_active_directory_acl_and_graph(self):
        eval_res = ACLAnalyzer.evaluate_relationship("EvilUser", "Domain Admins", "GenericAll")
        self.assertTrue(eval_res["is_dangerous"])
        self.assertEqual(eval_res["risk_score"], 90)

        graph = IdentityGraph()
        graph.add_node("U1", "CompromisedUser", "USER")
        graph.add_node("G1", "Domain Admins", "GROUP")
        graph.add_edge("U1", "G1", "MemberOf", is_risky=True)

        paths = RiskPathAnalyzer.find_attack_paths(graph, "Domain Admins")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["entry_point"], "U1")

    def test_cloud_and_container_security(self):
        # AWS Security Groups
        aws = AWSSecurityAuditor()
        sample_sgs = [{
            "GroupId": "sg-999",
            "IpPermissions": [{
                "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        }]
        findings = aws.audit_security_group_rules(sample_sgs)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

        # Kubernetes RBAC
        rbac_findings = KubernetesRBACAnalyzer.analyze_role_rules("cluster-admin-copy", [
            {"verbs": ["*"], "resources": ["*"]}
        ])
        self.assertEqual(len(rbac_findings), 1)
        self.assertEqual(rbac_findings[0]["severity"], "CRITICAL")

    def test_supply_chain_and_crypto(self):
        # SBOM Generation
        components = [{"name": "requests", "version": "2.31.0"}]
        sbom = SBOMEngine.generate_cyclonedx_json(components)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(len(sbom["components"]), 1)

        # License
        lic_eval = LicenseAnalyzer.evaluate_license("GPL-3.0")
        self.assertEqual(lic_eval["type"], "COPYLEFT")
        self.assertEqual(lic_eval["risk"], "HIGH")

        # TLS local inspector
        res = TLSInspector.inspect_endpoint("127.0.0.1", port=9999, timeout=0.5)
        self.assertEqual(res["status"], "CONNECTION_FAILED")

    def test_soar_playbook_and_specialized_labs(self):
        # SOAR engine
        soar = SOARPlaybookEngine()
        playbook = {
            "name": "Auto Incident Creation",
            "steps": [
                {"action": "CREATE_INCIDENT", "description": "Auto create incident"}
            ]
        }
        res = soar.execute_playbook(playbook, {"title": "Test SOAR Alert"})
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(len(res["steps"]), 1)

        # Mobile manifest
        mobile_findings = AndroidManifestAuditor.audit_manifest_flags(debuggable=True)
        self.assertTrue(any(f["severity"] == "CRITICAL" for f in mobile_findings))

        # Explainable Risk Scorer
        risk = ExplainableRiskScorer.calculate_risk(base_cvss=9.0, epss_score=0.5, is_cisa_kev=True)
        self.assertGreaterEqual(risk["overall_score"], 80.0)
        self.assertEqual(risk["rating"], "CRITICAL")

if __name__ == "__main__":
    unittest.main()
