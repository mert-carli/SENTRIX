# SENTRIX v3.0 — VERSION CHANGELOG & RELEASE HISTORY
## Complete Architecture Evolution, Feature Breakdown, and Migration Notes

---

## [3.0.0] — 2026-11-05
### Major Release: Complete Transformation to Ultimate Cyber Operations Platform

#### Summary
SENTRIX v3.0 represents a complete architectural overhaul and evolutionary leap from a basic network utility into a unified, professional Cyber Operations, Penetration Testing, DFIR, and Threat Hunting Platform. Built specifically for Windows 10/11 environments, v3.0 introduces 14+ specialized cybersecurity engines, a fail-closed scope enforcement architecture, a 19-table relational database engine, and a minimalist `#0B111B` dark slate command center interface.

---

### New Core Architecture (`core/`)
- **`core/database.py` (Relational SQLite WAL Engine):**
  - Expanded from a 3-table flat structure to a hardened **19-table relational schema**.
  - Enabled **Write-Ahead Logging (WAL)** mode and foreign key constraints for crash-resilient concurrent reads/writes.
  - Implemented automated runtime schema migrations (`PRAGMA table_info`) to ensure forward and backward compatibility without data loss.
  - Added indexes on frequently queried fields (`host`, `cve_id`, `timestamp`, `session_id`).
- **`core/scope.py` (Authorized Scope Enforcement Guard):**
  - Fail-closed target verification engine.
  - Enforces CIDR network calculations (`ipaddress.ip_network`), exact IP matching, FQDN resolution, and explicit exclusion overrides.
  - Integrated as a mandatory assertion check across all active scanning and offensive modules.
- **`core/task_manager.py` (Asynchronous Worker Pool):**
  - ThreadPoolExecutor architecture supporting cooperative cancellation tokens (`stop_requested`).
  - Thread-safe UI progress dispatching via decoupling callbacks.
- **`core/logger.py` (Sanitizing Audit Logger):**
  - Real-time credential redaction pipeline for Bearer tokens, API keys, passwords, and NTLM hashes.
  - Dual stream output: colorized console output and append-only disk auditing (`audit.log`).
- **`core/permission.py` (Windows Privilege Detection):**
  - Non-invasive detection of administrative tokens via `shell32.IsUserAnAdmin()`.
  - Enables graceful degradation for unprivileged users.
- **`core/config.py` (Curated Styling & Configuration):**
  - Modern, distraction-free Dark Slate color palette (`#0B111B` background, `#111C2E` surface cards, `#38BDF8` accent cyan).
  - High-DPI font definitions and cross-platform geometry settings.

---

### New Security Engines & Modules (`modules/`)

#### 1. Advanced Network Reconnaissance (`modules/recon/`)
- **`scanner.py`:** Multi-threaded asynchronous TCP Connect port scanner with socket banner grabbing, service fingerprinting, and automatic CVE/EPSS vulnerability association. Added JSON, CSV, and HTML export formats.
- **`osint.py`:** Comprehensive target domain reconnaissance supporting DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA), RDAP/WHOIS lookups, crt.sh Certificate Transparency parsing, and ASCII attack surface tree visualization.
- **`diff_engine.py`:** Historical scan delta engine highlighting newly opened ports, closed ports, and service version modifications across scan sessions.
- **`nmap_parser.py`:** Ingests external Nmap XML (`-oX`) scan files directly into SENTRIX's relational database.

#### 2. Packet Analysis & Forensics (`modules/packet/`)
- **`pcap_analyzer.py`:** 100% pure Python binary `.pcap` parser. Decodes Ethernet frames, IPv4 headers, TCP/UDP packets, and ICMP messages. Computes flow statistics, bandwidth metrics, top talkers, and flags network anomalies (SYN flood, port sweeps).

#### 3. Web Security & HTTP Workbench (`modules/websec/`)
- **`pentest.py`:** Inspects target URLs for missing security headers (HSTS, CSP, X-Frame-Options), audits cookie security flags (`Secure`, `HttpOnly`, `SameSite`), and probes for sensitive administrative endpoints and exposed config files.
- **`workbench.py`:** Custom raw HTTP request builder with timing analysis, side-by-side response body diffing, and export to **HAR 1.2** archive format.

#### 4. API Security (`modules/api_sec/`)
- **`api_tester.py`:** JSON Web Token (JWT) analyzer that decodes header and payload structures, detects algorithm vulnerabilities (such as `alg: "none"`), audits token expiration, and verifies signature integrity.

#### 5. Wireless Security Lab (`modules/wireless/`)
- **`wifi_lab.py`:** Discovers nearby 802.11 access points, queries active adapter metrics, inspects saved network profiles with masked password toggles, and implements multi-BSSID heuristic analysis to detect **Evil Twin** rogue access points.

#### 6. Active Directory & Identity Assessment (`modules/active_directory/`)
- **`ad_analyzer.py`:** Evaluates domain join status, primary domain controllers, password policy complexity and lockout thresholds, and inventories local Administrators.
- **`attack_path.py`:** Models BloodHound-style privilege escalation paths from standard users to Domain Admins and computes an automated **Identity Risk Score** (0-100).

#### 7. Vulnerability & Exploit Research (`modules/vuln_research/`)
- **`cve_engine.py`:** High-speed curated local database of critical vulnerabilities and CISA Known Exploited Vulnerabilities (KEV).
- **`epss_engine.py`:** Integrates FIRST.org Exploit Prediction Scoring System (EPSS) to determine real-world probability of active in-the-wild exploitation.

#### 8. Reverse Engineering & Binary Inspection (`modules/reverse_eng/`)
- **`pe_parser.py`:** Pure-Python 32-bit and 64-bit PE binary header parser. Extracts section headers, calculates Shannon section entropy to detect packers and cryptors, and flags suspicious Win32 API imports.
- **`binary_diff.py`:** Static executable diffing engine comparing section layouts, hashes, and imported function differences between binary versions.

#### 9. Malware Sandbox & Isolation (`modules/malware_sandbox/`)
- **`sandbox.py`:** Static file indicator extractor scanning for IPv4 addresses, URLs, and registry keys.
- **`vm_orchestrator.py`:** Hyper-V, VirtualBox, and VMware hypervisor manager providing snapshot readiness verification and isolation controls before dynamic detonation.

#### 10. Digital Forensics Toolkit (`modules/forensics/`)
- **`dfir.py`:** Includes magic byte file signature classification, dual-pane Hex dump viewer, ASCII/Unicode string extraction, USB mass storage connection history from the Windows Registry, and Windows Run keys persistence auditing.

#### 11. Endpoint Detection & Response (`modules/endpoint/`)
- **`edr_lite.py`:** Live process tree analyzer grouping processes by Parent PID (PPID), File Integrity Monitoring (FIM) with SHA-256 cryptographic baselines, and Windows Scheduled Tasks persistence auditing.

#### 12. Threat Intelligence & Detection (`modules/threat_intel/`, `modules/correlation/`)
- **`ti_center.py`:** IOC reputation checker for IPv4 addresses, domain names, and file hashes with MITRE ATT&CK technique mapping.
- **`sigma_engine.py`:** Evaluates process creation events and network connections against Sigma-compatible detection rules.
- **`engine.py`:** Cross-module socket correlation linking active open network ports to owning PIDs and processes.

#### 13. Security Automation & Tooling (`modules/automation/`, `modules/security_tools/`, `modules/terminal/`)
- **`workflow_engine.py`:** Multi-step automated security assessment pipeline executing Scope Verification -> Port Scan -> CVE Enrichment -> Web Audit -> Database Ingestion -> Markdown Reporting.
- **`toolkit.py`:** Offline security toolkit featuring CIDR subnet calculator, universal Base64/Hex/URL encoder/decoder, and Unix/ISO/FILETIME timestamp converter.
- **`orchestrator.py`:** Centralized execution manager for verified external tools (Nmap, Wireshark, TShark, YARA, Ghidra).

#### 14. Executive & Technical Reporting (`modules/reporting/`)
- **`report_generator.py`:** Bilingual (English and Turkish) assessment report generator compiling comprehensive Markdown deliverables containing executive summaries, finding tables, and remediation guidance.

---

### User Interface Overhaul (`ui/views/`, `main.py`)
- Redesigned the primary application layout into **5 categorized workspace domains**:
  1. **Operations:** Command Dashboard, Recon & Scan, Web Security, Wireless Lab.
  2. **Offensive Lab:** Active Directory, Vulnerability Research, Malware Sandbox, Password Lab.
  3. **Forensics:** DFIR Tools, PCAP Dissection, Linux & Cloud Security.
  4. **Intelligence:** Threat Intel Center, Correlation & Sigma Engine, EDR Lite.
  5. **Tools & Mgt:** Security Automation, Toolkit, External Tool Hub, Report Center.
- Added **Global Command Palette (`Ctrl+P` / `Ctrl+K`)** for instant workspace switching and workflow execution.
- Added real-time **Scope Badge** and **Windows Privilege Status Badge** in the top navigation bar.
- Replaced non-ASCII characters with standard codepage markers to ensure error-free operation on Turkish (`cp1254`) and international Windows codepages.

---

### Backward Compatibility & Legacy Preservation
- Preserved 100% of the original features from `network_tools.py` and `main_legacy.py`.
- Users can launch the legacy interface at any time via `python main_legacy.py` without conflicts.
- Retained full offline backup in `backup_v2/`.

---

## [2.0.0] — 2026-10-15
### Architectural Modernization & Modularization
- Replaced basic procedural scripts with modular object-oriented architecture.
- Migrated core UI from standard Tkinter to CustomTkinter for dark mode styling.
- Introduced initial `core/` folder with basic task execution and flat SQLite database.
- Split UI views into distinct tabs: Dashboard, Recon, Network, Diagnostics, Wi-Fi, Security, Threat Hunter, Monitoring, Reports.

---

## [1.0.0] — 2026-08-01
### Initial Prototype Release
- Basic Windows network diagnostic utility (`network_tools.py`).
- Simple ICMP ping sweep and sequential TCP port scanner.
- Local Wi-Fi profile and cleartext password viewer using `netsh wlan`.
- Basic system information display and external IP lookup.
