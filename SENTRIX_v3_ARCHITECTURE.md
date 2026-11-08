# SENTRIX v3.0 — SYSTEM ARCHITECTURE & TECHNICAL BLUEPRINT
**Target OS:** Windows 10/11 (64-bit)  
**Architecture Pattern:** Layered, Event-Driven, Micro-Engine Architecture  
**Database:** SQLite WAL (Write-Ahead Logging) Mode  
**Presentation Framework:** CustomTkinter / Tkinter Subsystem  

---

## 1. High-Level Architectural Layers

SENTRIX v3.0 separates operational responsibilities into five decoupled layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   LAYER 1: PRESENTATION (COMMAND CENTER)               │
│  - CustomTkinter Responsive Dark UI (#0B111B, High Density)            │
│  - Categorized Navigation: Operations, Offensive, Forensics, Intel, Tools│
│  - Global Command Palette & Real-Time Telemetry Bar                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Event Bus & Async Tasks
┌───────────────────────────────────▼────────────────────────────────────┐
│                LAYER 2: APPLICATION SERVICES & ORCHESTRATION           │
│  - TaskManager (Bounded Worker Pool & Cancellation Tokens)             │
│  - ScopeManager (CIDR & Domain Guard, Backend Enforcement)             │
│  - SecurityAutomationEngine (Chained Workflows with Rollback)          │
│  - IncidentResponseManager & Case Manifest Tracking                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Direct Engine Calls
┌───────────────────────────────────▼────────────────────────────────────┐
│                    LAYER 3: SPECIALIZED CYBER ENGINES                  │
│  ├── AdvancedRecon (PortScanner, BannerGrabber, OSINT, DiffEngine)     │
│  ├── WebSec (HTTP Workbench, ResponseDiff, HAR Export, EndpointScout)   │
│  ├── PacketForensics (PCAP Binary Parser, Flow Reconstructor)          │
│  ├── ActiveDirectory (AttackPathAnalyzer, IdentityScore, IAM Auditor)  │
│  ├── VulnerabilityResearch (EPSS Live/Offline, CISA KEV, RiskMatrix)   │
│  ├── RedTeamOps (AtomicTestRunner, ATT&CK Navigator, DetectionGap)     │
│  ├── ReverseEngineering (Native PE Parser, BinaryDiff, SectionEntropy) │
│  ├── MalwareSandbox (Hypervisor Detonation Safety, Static IOC Hunter)   │
│  ├── EndpointSec (ProcessTree, FIM Cryptographic Baseline, TasksAudit) │
│  ├── DetectionEngine (SigmaRuleMatcher, Multi-Event Socket Correlation)│
│  └── AISecurityAnalyst (Deterministic Grounded Explanations)           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                  LAYER 4: DATA PERSISTENCE & STORAGE                   │
│  - SQLite 3 (WAL Mode, Foreign Keys, Clustered Indexes)                │
│  - Central Security Data Model: Assets, Hosts, Ports, CVEs, Incidents  │
│  - Log Sanitation & Audit Trail (Regex Redaction of Credentials)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│             LAYER 5: WINDOWS SUBSYSTEM & HARDWARE INTERFACES           │
│  - Win32 APIs (ctypes, Shell32, Advapi32, Kernel32)                    │
│  - Native Networking Sockets (AF_INET, SOCK_STREAM, SOCK_DGRAM)        │
│  - Windows Management Instrumentation (WMI/CIM via PowerShell)         │
│  - Native CLI Tooling (Nmap, Wireshark/TShark, YARA, Ghidra, netsh)   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Central Security Data Model (Database Schema)

The SQLite database (`data/sentrix.db`) implements relational persistence across 19 core tables:

1. `projects`: Authorized target scopes, allowed CIDR ranges, domain whitelists, rate limits.
2. `operations`: Operational engagements (PENTEST, RED_TEAM, RECON, AUDIT).
3. `hosts`: Discovered target nodes, IP, MAC, hostname, OS fingerprint, latency, vendor.
4. `domains`: Domain names, apex names, resolved IPs, WHOIS registrar, expiration dates.
5. `scan_sessions`: Audit trail of executed scan sessions with raw outputs and execution times.
6. `open_ports`: Discovered sockets, protocol, service, version, state, CVE cross-references.
7. `vulnerabilities`: Normalized CVE records, CVSS scores, EPSS probabilities, CISA KEV flags.
8. `web_findings`: HTTP security header findings, cookie security attributes, sensitive endpoints.
9. `network_flows`: Source/Destination IP pairs, protocol, byte counters, anomaly flags.
10. `file_artifacts`: Binary forensics, SHA-256 hashes, detected format, entropy scores, packer flags.
11. `security_events`: Real-time raw telemetry ingest stream.
12. `alerts`: Correlated multi-stage alerts mapped to MITRE ATT&CK techniques.
13. `incidents`: Formal case workspace for incident responders with assigned analysts.
14. `evidence`: Forensic evidence manifest with cryptographic hashes and chain of custody.
15. `threat_indicators`: Central IOC intelligence cache (IP, Domain, Hash, URL).
16. `workflows`: Automation workflow definitions stored in structured JSON step arrays.
17. `workflow_runs`: Execution logs and completion status of automated workflows.
18. `detection_rules`: Ingested and active Sigma-style detection rules.
19. `audit_logs`: Timestamped system action logs with credential redaction.
