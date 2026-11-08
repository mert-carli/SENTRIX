# SENTRIX v4.0 — MASTER CHANGELOG & RELEASE HISTORY
## Complete Version Evolution, Architectural Overhauls & Feature Breakdown

---

## [4.0.0] — 2026-11-06
### Major Release: Ultimate Cybersecurity Operations Platform

#### Summary
SENTRIX v4.0 represents the definitive transformation of SENTRIX into an enterprise-grade Cyber Operations, Threat Hunting, Detection Engineering, DFIR, Cloud Security, and SOAR Platform for Windows 10/11 environments. Introducing 10 new specialized security engines, expanding the relational database to 32 tables, adding fail-closed DNS rebinding guards, and organizing all capabilities under a 6-workspace Command Center.

---

### New Core Architecture & Guardrails (`core/`)
- **Expanded Relational Database (`core/database.py`):**
  - Expanded from 19 to **32 relational SQLite tables**.
  - Added tables for Windows EventLog telemetry, process events, file events, registry events, memory artifacts, forensic cases, threat hunts, cloud assets, container assets, and SOAR playbooks.
  - Hardened with automatic runtime PRAGMA schema migrations and composite indexing.
- **Enhanced Scope Guard (`core/scope.py`):**
  - Added **DNS Rebinding Protection** and **Link-Local Cloud Metadata (169.254.169.254)** SSRF shielding.
  - Dual-stack IPv4 and IPv6 subnet containment checks.
- **Event Bus 2.0 (`core/event_bus.py`):**
  - Integrated the formal **`SecurityEvent`** data model with severity, confidence, correlation UUID, and evidence pointers.
  - Added in-memory ring buffer for live telemetry auditing.
- **Task Manager 2.0 (`core/task_manager.py`):**
  - Added bounded worker queue management, task execution history, and graceful system-wide shutdown routines.

---

### New Security Engines & Specialized Labs (`modules/`)

#### 1. Windows Internals & ETW Monitor (`modules/windows_internals/`)
- Native Windows EventLog collector querying Security, System, Application, and PowerShell operational channels via `wevtutil`.
- Microsoft Sysmon operational status inspector and telemetry stream parser.
- ETW provider discovery and active kernel trace session viewer (`logman`).
- Process monitor detecting suspicious parent-child spawn chains (e.g. Office applications spawning LOLBins).
- Windows Service auditor identifying Unquoted Service Path vulnerabilities.

#### 2. Memory Forensics Lab (`modules/memory_forensics/`)
- Volatility 3 framework CLI integration with plugin runner (`pslist`, `pstree`, `netscan`, `malfind`).
- Memory image registration, file size metadata, and SHA-256 cryptographic verification.
- Parser for suspicious unbacked executable memory regions with `PAGE_EXECUTE_READWRITE` permissions.

#### 3. Advanced Threat Hunting Workspace (`modules/threat_hunting/`)
- Pre-built hypothesis catalog mapped to MITRE ATT&CK techniques.
- Multi-dimensional query builder filtering by process, PID, hash, IP, and severity.
- Chronological investigation timeline builder and correlated entity graph visualizer.

#### 4. Detection Rule Studio (`modules/detection_studio/`)
- Multi-format rule editor and syntax validator for **Sigma YAML**, **YARA rules**, and **Suricata network rules**.
- Rule test runner evaluating detection logic against sample event baselines to detect false positives.
- Real-time MITRE ATT&CK enterprise matrix coverage evaluator.

#### 5. Active Directory Graph Explorer (`modules/active_directory/`)
- Read-only LDAP object inventory for Users, Groups, Computers, and OUs.
- Dangerous ACL relationship analyzer (`GenericAll`, `WriteDacl`, `ForceChangePassword`).
- Transitive privilege escalation attack path finder and Identity Security Scoring.

#### 6. Container & Kubernetes Security (`modules/container_security/`)
- Docker daemon auditor checking for `--privileged` containers and root UID executions.
- Kubernetes cluster context inspector and Pod Security Standard auditor.
- Kubernetes RBAC wildcard permission and privilege escalation analyzer.

#### 7. Cloud Security Auditor (`modules/cloud_security/`)
- Automated security configuration checks for AWS (S3 public buckets, 0.0.0.0/0 Security Groups).
- Azure NSG open administrative port audits.
- Google Cloud Platform (GCP) firewall rule exposure audits.

#### 8. Supply Chain Security & Cryptography Lab (`modules/supply_chain/`, `crypto_lab/`)
- CycloneDX 1.4 JSON Software Bill of Materials (SBOM) generator.
- Google OSV.dev vulnerability lookup client for installed dependencies.
- Open-source license legal risk evaluator (Copyleft GPL vs Permissive MIT/Apache).
- Live TLS endpoint inspector (detecting deprecated SSLv3/TLS 1.0/1.1 protocols, weak ciphers).
- Windows Local Machine Trusted Root CA certificate store auditor.

#### 9. Specialized Labs & Risk Engine (`modules/deception_lab/`, `mobile_security/`, `firmware_security/`, `risk_engine/`)
- Isolated low-interaction HTTP/SSH decoy honeypots with session connection tracking.
- Android APK static structure inspector and AndroidManifest security flag auditor mapped to OWASP MASVS.
- Firmware binary image analyzer calculating Shannon entropy and scanning for hardcoded private keys.
- Explainable Risk Engine combining CVSS, EPSS exploitation probabilities, and CISA KEV status into prioritized remediation plans.

#### 10. SOAR & Incident Playbook Engine (`modules/soar/`)
- Multi-step response workflow runner with action registry.
- Human-in-the-loop operator approval queue for intrusive actions (`FIREWALL_BLOCK`, `PROCESS_KILL`).
- Rollback manager preserving reverse containment procedures.

---

### Command Center 4.0 Interface (`ui/views/`, `main.py`)
- Restructured navigation into **6 categorized operational workspaces**:
  1. Operations
  2. Offensive Security Lab
  3. Detection & Intelligence
  4. Forensics & Research
  5. Cloud & Infrastructure
  6. Automation & Management
- High-contrast Dark Slate palette (`#0B111B`), command palette search (`Ctrl+P`), and real-time CPU/RAM hardware telemetry.
- Seamless, non-blocking execution across all 20 unified view panels.

---

## [3.0.0] — 2026-11-05
- Refactored into 19 relational SQLite tables with WAL mode.
- Added scope enforcement guard, sanitizing logger, native PCAP parser, and HTTP workbench with HAR 1.2 export.
- Integrated FIRST.org EPSS and CISA KEV scoring.

---

## [2.0.0] — 2026-10-15
- Replaced legacy scripts with modular CustomTkinter views.
- Introduced asynchronous TaskManager and SQLite storage.

---

## [1.0.0] — 2026-08-01
- Initial Windows network utility (`network_tools.py`) with ping sweep, basic port scan, and Wi-Fi password dump.
