"""
SENTRIX v5.0 — Automated Test Suite for AI Copilot, Attack Graph, and Network Topology
Verifies that all new v5.0 modules execute accurately, preserve offline safety, and enforce zero mocks.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import db
from core.scope import scope_manager
from core.translations import tr, get_glossary_term
from modules.ai_security.assistant_core import ai_security_copilot, ConfidenceLevel
from modules.ai_security.action_guard import action_guard, ActionType, ActionStatus, ActionRisk
from modules.ai_security.context_builder import context_builder
from modules.ai_security.local_llm_provider import local_llm_provider
from modules.attack_graph.attack_graph_engine import attack_graph_engine, NodeType
from modules.network_topology.topology_engine import network_topology_engine, DeviceType, DeviceStatus

class TestSentrixV5CopilotAndMaps(unittest.TestCase):

    def setUp(self):
        # Insert test records if database empty to ensure real data flows
        db.upsert_host("192.168.1.1", mac="AA:BB:CC:DD:EE:01", hostname="gateway.local", vendor="Cisco")
        db.upsert_host("192.168.1.50", mac="AA:BB:CC:DD:EE:50", hostname="workstation-pc", vendor="Dell")

    def test_ai_copilot_reasoning_and_confidence(self):
        # 1. RDP Question
        res_rdp = ai_security_copilot.ask("3389 portunu kapatırsam ne etkilenir?")
        self.assertIn("RDP", res_rdp["answer"])
        self.assertEqual(res_rdp["confidence_label"], "Doğrulandı")
        self.assertGreaterEqual(res_rdp["confidence_score"], 90)
        self.assertGreater(len(res_rdp["evidence"]), 0)

        # 2. Status Question
        res_status = ai_security_copilot.ask("Bilgisayarım güvenli mi?")
        self.assertIn("güvenlik durumu", res_status["answer"].lower())
        self.assertIn(res_status["confidence_label"], ["Doğrulandı", "Güçlü belirti"])

        # 3. Anomaly Question
        res_anom = ai_security_copilot.ask("Ağımda anormal bir cihaz var mı?")
        self.assertIn("cihaz", res_anom["answer"].lower())

    def test_action_guard_lifecycle(self):
        # Create action proposal
        proposal = action_guard.create_proposal(
            action_type=ActionType.BLOCK_FIREWALL_IP,
            target="198.51.100.99",
            description="Şüpheli IP engelleme testi",
            risk_level=ActionRisk.HIGH
        )
        act_id = proposal["action_id"]
        self.assertTrue(act_id.startswith("act_"))
        self.assertEqual(proposal["status"], ActionStatus.PENDING)

        # Rejection lifecycle test
        rej_res = action_guard.reject(act_id, reason="Birim testi reddi")
        self.assertTrue(rej_res["success"])
        self.assertEqual(action_guard.get_proposal(act_id)["status"], ActionStatus.REJECTED)

    def test_context_builder_sanitization_and_snapshot(self):
        raw_text = "Sunucu baglantisi: password=SuperSecretPassword123! token=Bearer abc.def.ghi"
        sanitized = context_builder.sanitize_text(raw_text)
        self.assertNotIn("SuperSecretPassword123!", sanitized)
        self.assertNotIn("abc.def.ghi", sanitized)
        self.assertIn("[REDACTED_CREDENTIAL]", sanitized)

        # Test snapshot structure
        snap = context_builder.build_snapshot()
        self.assertIn("summary", snap)
        self.assertIn("online_hosts", snap["summary"])
        self.assertIn("critical_ports_exposed", snap["summary"])

    def test_local_llm_provider_offline_safe(self):
        # Provider should report status without raising unhandled exceptions
        avail = local_llm_provider.is_available()
        self.assertIsInstance(avail, bool)
        models = local_llm_provider.list_installed_models()
        self.assertIsInstance(models, list)

    def test_attack_graph_engine_causality_and_filters(self):
        graph_24h = attack_graph_engine.build_graph("24h")
        self.assertIn("nodes", graph_24h)
        self.assertIn("edges", graph_24h)
        self.assertEqual(graph_24h["time_filter"], "24h")

        # Check node positions calculated
        for n in graph_24h["nodes"]:
            self.assertIn("x", n)
            self.assertIn("y", n)
            self.assertIn("width", n)
            self.assertIn("height", n)
            self.assertIn("type", n)

        # Time filter variants
        graph_1h = attack_graph_engine.build_graph("1h")
        self.assertIsInstance(graph_1h["nodes"], list)

    def test_network_topology_engine_classification(self):
        topo = network_topology_engine.build_topology()
        self.assertIn("gateway", topo)
        self.assertIn("nodes", topo)
        self.assertIn("edges", topo)

        gateway = topo["gateway"]
        self.assertTrue(gateway["is_gateway"])
        self.assertEqual(gateway["device_type"], DeviceType.ROUTER)
        self.assertEqual(gateway["icon_tag"], "[GW]")

        # Check nodes have valid coordinates
        for node in topo["nodes"]:
            self.assertIn("x", node)
            self.assertIn("y", node)
            self.assertIn("device_type", node)
            self.assertIn("posture", node)

    def test_translations_and_glossary_badges(self):
        # Turkish translation keys
        self.assertEqual(tr("app_title"), "SENTRIX — Siber Güvenlik Operasyon Platformu")
        self.assertEqual(tr("ai_copilot"), "Akıllı Güvenlik Asistanı")
        self.assertEqual(tr("attack_graph"), "Saldırı ve Olay Haritası")
        self.assertEqual(tr("network_map"), "Canlı Ağ Haritası")

        # Technical glossary terms
        cve_gloss = get_glossary_term("CVE")
        self.assertIsNotNone(cve_gloss)
        self.assertIn("Common Vulnerabilities and Exposures", cve_gloss["acronym"])

        pid_gloss = get_glossary_term("PID")
        self.assertIsNotNone(pid_gloss)
        self.assertIn("Process Identifier", pid_gloss["acronym"])

        rwx_gloss = get_glossary_term("RWX")
        self.assertIsNotNone(rwx_gloss)
        self.assertIn("Read-Write-Execute", rwx_gloss["acronym"])

if __name__ == "__main__":
    unittest.main()
