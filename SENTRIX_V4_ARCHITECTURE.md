# SENTRIX v4.0 — SYSTEM ARCHITECTURE BLUEPRINT
## Unified Cyber Operations, Threat Hunting & Incident Response Architecture

**Version:** 4.0.0  
**Target Operating System:** Windows 10 / 11 x64  
**Runtime:** Python 3.9 - 3.12 (Native Windows C-APIs, ctypes, WMI)  
**Database:** SQLite 3 (WAL Mode, 32 Relational Tables, Foreign Key Enforcement)  
**Classification:** Enterprise Engineering Architecture  

---

## 1. Multi-Tier Architectural Model

SENTRIX v4.0 is engineered around a **5-tier decoupled, event-driven architecture** ensuring minimal cognitive surface in the UI while delivering maximum analytical depth in the engine layer.

```
┌───────────────────────────────────────────────────────────────────────────┐
│                          1. PRESENTATION LAYER                            │
│  CustomTkinter Modern Dark Slate (#0B111B) | Collapsible 6 Workspace Nav  │
│  Global Command Palette (Ctrl+P) | Real-time UAC & Scope Telemetry Badges │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼─────────────────────────────────────┐
│                   2. ORCHESTRATION & SECURITY BOUNDARY                    │
│  ScopeManager (Fail-Closed, DNS Rebinding, SSRF & Metadata Shield)        │
│  TaskManager (Bounded ThreadPoolExecutor, Cancellation Tokens, Timeouts)  │
│  EventBus (Standardized SecurityEvent Pub/Sub, In-Memory Audit Buffer)    │
│  Permission Guard (UAC High-Integrity vs Standard Non-Elevated Context)   │
└──────────────────┬──────────────────┬──────────────────┬──────────────────┘
                   │                  │                  │
┌──────────────────▼──────┐   ┌───────▼────────┐   ┌─────▼──────────────────┐
│   OPERATIONS & OFFENSE  │   │  DFIR & MEMORY │   │ CLOUD & INFRASTRUCTURE │
│ - Recon & Port Scanner  │   │ - Volatility 3 │   │ - AWS / Azure / GCP    │
│ - OSINT & Attack Surface│   │ - Mem Artifacts│   │ - Docker & K8s RBAC    │
│ - WebSec & HTTP Workb.  │   │ - Prefetch/SRUM│   │ - Supply Chain SBOM    │
│ - AD Graph Explorer     │   │ - PE Analyzer  │   │ - TLS / Crypto Lab     │
│ - Deception & Decoys    │   │ - Sandbox VM   │   │ - SOAR Incident Runner │
└──────────────────┬──────┘   └───────┬────────┘   └─────┬──────────────────┘
                   │                  │                  │
┌──────────────────▼──────────────────▼──────────────────▼──────────────────┐
│                    4. DETECTION & CORRELATION ENGINES                     │
│  Sigma / YARA / Suricata Studio | MITRE ATT&CK Matrix Coverage Analyzer   │
│  Threat Hunting Engine | Central Investigation Graph | Explainable Risk   │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼─────────────────────────────────────┐
│                    5. PERSISTENCE & TELEMETRY STORAGE                     │
│  SQLite3 (data/sentrix.db) with WAL Mode & Auto PRAGMA Migrations         │
│  32 Relational Tables: Hosts, Ports, Events, Hunts, Cases, Playbooks      │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Standardized Security Event Model (`core/event_bus.py`)

All telemetry generated across Windows Event Logs, Sysmon, network packets, and threat hunting routines is normalized into the formal v4 **SecurityEvent** structure:

```python
@dataclass
class SecurityEvent:
    event_type: str             # e.g., WIN_AUTHENTICATION, PROCESS_CREATION, SUSPICIOUS_C2
    source_module: str          # e.g., windows_internals, threat_hunting, pcap_analyzer
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: int             # 0 to 100 percentage rating
    source_host: str            # Hostname or IP
    asset_id: Optional[str]     # Foreign key to hosts/cloud_assets
    process_id: Optional[int]   # Windows PID
    correlation_id: Optional[str]# Grouping UUID for multi-stage attacks
    evidence_refs: List[str]    # Pointers to raw log files or PCAP offsets
    payload: Dict[str, Any]     # Unpacked telemetry key-values
    event_id: str               # Unique UUIDv4
    timestamp_utc: str          # ISO-8601 UTC timestamp
    schema_version: str         # "4.0"
```

---

## 3. Storage Layer & 32-Table Relational Schema (`core/database.py`)

The persistent database `data/sentrix.db` is configured with `PRAGMA journal_mode=WAL;`, `PRAGMA foreign_keys=ON;`, and automatic schema migration checks on startup.

### Relational Table Classification:
1. **Scope & Engagements (3 tables):** `projects`, `operations`, `settings`
2. **Reconnaissance & Network (5 tables):** `hosts`, `domains`, `open_ports`, `scan_sessions`, `nmap_raw_scans`
3. **Web & Wireless (3 tables):** `web_findings`, `http_workbench_sessions`, `wifi_networks`
4. **Active Directory & Identity (2 tables):** `ad_inventory`, `saved_wifi_creds`
5. **Vulnerability Intelligence (2 tables):** `vulnerabilities`, `cve_cache`
6. **Telemetry & Windows Internals (5 tables):** `event_sources`, `security_events`, `process_events`, `file_events`, `registry_events`
7. **Adli Bilişim & Memory Forensics (4 tables):** `forensic_cases`, `forensic_evidence`, `memory_artifacts`, `file_hashes`
8. **Threat Hunting & Rules (4 tables):** `threat_hunts`, `hunt_queries`, `detection_rules`, `rule_executions`
9. **Cloud & Infrastructure (3 tables):** `cloud_assets`, `container_assets`, `software_components`
10. **Operations, SOAR & Incidents (6 tables):** `alerts`, `incidents`, `incident_actions`, `automation_playbooks`, `playbook_executions`, `risk_assessments`
11. **Auditing & History (2 tables):** `audit_logs`, `workflow_runs`

---

## 4. Fail-Closed Scope Enforcement Guard (`core/scope.py`)

```
[Incoming Target Request: IP / Domain / URI]
                      │
                      ▼
            [Normalize Hostname]
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
[In Excluded Targets?]      [Target is Loopback?]
   │ Yes                       │ Yes
   ▼                           ▼
[DENY: Excluded]            [ALLOW: Local Testing]
   │ No
   ▼
[Evaluate IPv4 / IPv6 against Allowed CIDRs]
   │ Match
   ▼
[ALLOW & AUDIT]
   │ No Match / Is Domain Name
   ▼
[Domain Whitelist Match?]
   │ No
   ▼
[DENY: Out of Scope]
   │ Yes
   ▼
[DNS Resolution & Rebinding Check]
   ├─ Resolves to Excluded IP? ──> [DENY: Rebinding Blocked]
   ├─ Resolves to 169.254.0.0/16? ─> [DENY: Cloud Metadata Blocked]
   └─ Clean Resolution ───────────> [ALLOW & AUDIT]
```

---

## 5. SOAR Playbook Execution with Human Safety Rails (`modules/soar/`)

To prevent unintended service outages or destructive operations on enterprise endpoints, the SOAR engine implements an **Approval Guard**:
- **Non-Destructive Actions:** (e.g., `CREATE_INCIDENT`, `ENRICH_IOC`, `PRESERVE_EVIDENCE`) execute autonomously.
- **Intrusive / Destructive Actions:** (e.g., `FIREWALL_BLOCK`, `PROCESS_KILL`, `QUARANTINE_HOST`) are routed to the **Operator Approval Queue** and halt execution until explicit human authorization is granted.
- **Rollback Manager:** Records reverse operation payloads (e.g., removing a host firewall block rule) to restore prior system state.

---

## 6. Central Investigation Graph Integration (`modules/investigation_graph/`)

The platform connects disparate analytical findings through a unified entity-relationship model:
- **Nodes:** `HOST`, `USER`, `PROCESS`, `FILE`, `IP`, `DOMAIN`, `SERVICE`, `CVE`, `ALERT`, `INCIDENT`, `EVIDENCE`.
- **Edges:** `SPAWNED`, `CONNECTED_TO`, `RESOLVES_TO`, `COMMUNICATES_WITH`, `VULNERABLE_TO`, `CONTAINS`, `TRIGGERED`.
This allows operators to pivot effortlessly from a discovered open port in Reconnaissance to owning process telemetry in Windows Internals, correlated Sigma alerts, and open incident tickets.
