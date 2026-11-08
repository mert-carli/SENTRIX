# SENTRIX v4.0 — MASTER MODULE STATUS MATRIX
## Definitive Implementation, Integration, Permission & Verification Matrix

**Date:** 2026-11-06  
**Platform Version:** SENTRIX v4.0  
**Verification Standard:** Verified via Unit Tests, Integration Tests & Live Desktop Execution  

---

## Master Module Matrix

| Module Name | Source Path | Backend Engine Capabilities | UI View Connection | External Dependencies | Windows Permission | Automated Tests | Verified Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Relational Database** | `core/database.py` | 32 SQLite tables, WAL mode, auto PRAGMA migrations | Global state across all views | Native SQLite3 | Standard User | `test_core_and_modules.py` | **VERIFIED** |
| **Scope Manager** | `core/scope.py` | Fail-closed CIDR, IPv6, DNS rebinding & metadata shield | Top header badge & Recon inputs | Native `ipaddress`, `socket` | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Task Manager** | `core/task_manager.py` | Bounded ThreadPool, cancellation tokens, history | Status bar telemetry & task popups | Native `concurrent.futures` | Standard User | `test_core_and_modules.py` | **VERIFIED** |
| **Event Bus** | `core/event_bus.py` | `SecurityEvent` Pub/Sub & audit history buffer | Command center event dispatcher | Native `threading` | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Port Scanner & Recon**| `modules/recon/scanner.py` | Async TCP Connect, banner grabbing, CVE/EPSS mapping | `ui/views/recon_view.py` | Native sockets | Standard User | `test_core_and_modules.py` | **VERIFIED** |
| **OSINT & Attack Surface**| `modules/recon/osint.py` | DNS (A, AAAA, MX, NS, TXT), RDAP/WHOIS, crt.sh | `ui/views/recon_view.py` | Native sockets, requests | Standard User | `test_v3_engines.py` | **VERIFIED** |
| **Historical Diff Engine**| `modules/recon/diff_engine.py` | Delta comparison of open ports & service versions | `ui/views/network_ops_view.py` | SQLite DB | Standard User | `test_v3_engines.py` | **VERIFIED** |
| **PCAP Analyzer 2.0** | `modules/packet/pcap_analyzer.py`| Binary PCAP parser, IPv4/IPv6, UDP DNS queries, flows | `ui/views/forensics_view.py` | Native `struct`, `socket` | Standard User | `test_v3_engines.py` | **VERIFIED** |
| **WebSec & Workbench** | `modules/websec/pentest.py` | Headers, cookies, sensitive paths, HAR 1.2 export | `ui/views/websec_view.py` | `requests` | Standard User | `test_core_and_modules.py` | **VERIFIED** |
| **Wireless Security Lab**| `modules/wireless/wifi_lab.py` | Nearby AP scanner, RSSI, Multi-BSSID Evil Twin detector | `ui/views/wireless_view.py` | Windows `netsh wlan` | Standard User | `test_core_and_modules.py` | **VERIFIED** |
| **Active Directory Graph**| `modules/active_directory/` | Domain join, password policy, ACL analyzer, attack paths | `ui/views/enterprise_view.py` | Windows WMI / CimInstance | Standard / Domain User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Vulnerability Intel** | `modules/vuln_research/` | Curated CVE, CISA KEV catalog, FIRST.org EPSS scores | `ui/views/offensive_lab_view.py` | `requests` (optional fallback)| Standard User | `test_v3_engines.py` | **VERIFIED** |
| **PE Reverse Engineering**| `modules/reverse_eng/` | Native PE32/PE32+ header parser, entropy, suspicious APIs| `ui/views/forensics_view.py` | Native `struct` | Standard User | `test_v3_engines.py` | **VERIFIED** |
| **Malware Sandbox & VM** | `modules/malware_sandbox/` | Static IOC extractor, Hyper-V / VirtualBox snapshot check| `ui/views/forensics_view.py` | Hypervisor CLI | Standard User | `test_v3_engines.py` | **VERIFIED** |
| **Windows Internals** | `modules/windows_internals/` | EventLog collector, Sysmon detector, ETW, LOLBins | `ui/views/windows_internals_view.py`| `wevtutil`, `logman`, WMI | Standard (Admin for Security)| `test_v4_advanced_engines.py` | **VERIFIED** |
| **Memory Forensics** | `modules/memory_forensics/`| Volatility 3 adapter, process/net artifacts, RWX scanner | `ui/views/memory_forensics_view.py`| Volatility 3 (CLI) | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Threat Hunting** | `modules/threat_hunting/` | Hypothesis manager, structured query engine, timeline | `ui/views/threat_hunting_view.py` | SQLite DB | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Detection Studio** | `modules/detection_studio/`| Sigma, YARA & Suricata validator, MITRE coverage matrix | `ui/views/detection_studio_view.py` | Native regex / parsers | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Container Security** | `modules/container_security/`| Docker privileged audit, K8s RBAC wildcard analyzer | `ui/views/cloud_infra_view.py` | Docker / kubectl (CLI) | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Cloud Security** | `modules/cloud_security/` | AWS S3/SG, Azure NSG, GCP Firewall security auditors | `ui/views/cloud_infra_view.py` | AWS/Azure/GCP APIs (read-only)| Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Supply Chain & Crypto**| `modules/supply_chain/`, `crypto_lab/`| CycloneDX SBOM, OSV client, TLS inspector, Root CA store | `ui/views/cloud_infra_view.py` | Native `ssl`, PowerShell | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Deception & Labs** | `modules/deception_lab/`, `mobile_security/`, `firmware_security/`| Low-interaction HTTP/SSH decoy, APK MASVS, Firmware entropy | `ui/views/specialized_labs_view.py` | Native sockets, zipfile | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Attack Surface Risk** | `modules/risk_engine/` | Explainable risk scorer (CVSS+EPSS+KEV), Remediation plan | `ui/views/specialized_labs_view.py` | SQLite DB | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **SOAR & Playbooks** | `modules/soar/` | Workflow engine, human operator approval, rollback manager | `ui/views/soar_playbook_view.py` | SQLite DB | Standard User (Admin for rules)| `test_v4_advanced_engines.py` | **VERIFIED** |
| **Investigation Graph** | `modules/investigation_graph/`| Cross-module entity nodes (Host, User, Process, IP, Alert) | Integrated across workspaces | In-Memory Graph | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **External Tool Manager**| `modules/tools/tool_manager.py` | Centralized detection of Nmap, Wireshark, Volatility, YARA | `ui/views/reporting_view.py` | System PATH | Standard User | `test_v4_advanced_engines.py` | **VERIFIED** |
| **Reporting Center** | `modules/reporting/` | Bilingual (EN/TR) Markdown penetration testing report | `ui/views/reporting_view.py` | Native string formatting | Standard User | `test_core_and_modules.py` | **VERIFIED** |
