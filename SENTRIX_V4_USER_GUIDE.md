# SENTRIX v4.0 — COMPREHENSIVE OPERATOR USER GUIDE
## Advanced Cyber Operations, Threat Hunting & Incident Response Manual

**Platform:** SENTRIX Cyber Operations Command Center v4.0  
**Interface Design:** Modern Minimalist Dark Slate (`#0B111B`)  
**Target Audience:** Penetration Testers, DFIR Analysts, Detection Engineers, Red/Blue Teamers  

---

## 1. Unified Workspace Navigation

SENTRIX v4.0 is structured into **6 specialized operational domains**, accessible from the left navigation bar or via the **Global Command Palette (`Ctrl+P` / `Ctrl+K`)**.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  SENTRIX v4.0   [ Global Search / Command Palette (Ctrl+P) ]     [ELEVATED (ADMIN)]    │
├──────────────────────┬─────────────────────────────────────────────────────────────────┤
│ 1. OPERATIONS        │ ACTIVE OPERATIONAL CANVAS                                       │
│  - Dashboard         │                                                                 │
│  - Network Ops       │  [01. Event Logs]  [02. Sysmon]  [03. ETW]  [04. Process/Services]│
│  - Reconnaissance    │  ┌────────────────────────────────────────────────────────────┐ │
│  - Web Security      │  │ Channel: [Security            ] [ FETCH RECENT EVENTS ]    │ │
│  - Wireless Lab      │  ├────────────────────────────────────────────────────────────┤ │
│                      │  │ [2026-11-06 12:00] [LOW] EventID: 4624 | User: Admin       │ │
│ 2. OFFENSIVE LAB     │  │ [2026-11-06 12:01] [MED] EventID: 4688 | Cmd: powershell   │ │
│  - Red Team & EPSS   │  │ [2026-11-06 12:02] [MED] EventID: 7045 | New Service Added │ │
│  - AD Graph Explorer │  └────────────────────────────────────────────────────────────┘ │
│  - Deception Lab     │                                                                 │
│                      │ STATUS TELEMETRY                                                │
│ 3. DETECTION & INTEL │ [12:05:00] [+] Scope verified: 192.168.1.0/24                   │
│  - Threat Hunting    │ [12:05:01] [*] 3 active ETW security providers monitoring       │
│  - Detection Studio  │                                                                 │
│  - Windows Internals │                                                                 │
│  - Threat Intel      │                                                                 │
│  - Correlation & IR  │                                                                 │
│                      │                                                                 │
│ 4. FORENSICS         │                                                                 │
│  - Memory Forensics  │                                                                 │
│  - DFIR & Timeline   │                                                                 │
│  - Endpoint EDR Lite │                                                                 │
│                      │                                                                 │
│ 5. CLOUD & INFRA     │                                                                 │
│  - Cloud, K8s & SBOM │                                                                 │
│                      │                                                                 │
│ 6. AUTOMATION & MGT  │                                                                 │
│  - SOAR & Response   │                                                                 │
│  - Automation Tools  │                                                                 │
│  - Reports & Scope   │                                                                 │
├──────────────────────┴─────────────────────────────────────────────────────────────────┤
│ Status: READY | Active Scope: 192.168.1.0/24 | DB: Connected (WAL) | CPU: 04% | RAM: 18%│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Workspace Domain Walkthroughs

### Workspace 1: Operations
- **Dashboard:** Real-time host discovery count, open port charts, recent high-severity alerts, and hardware telemetry.
- **Network Operations:** Interactive port scanning, latency measurements, socket banner grabbing, and historical diff viewer.
- **Reconnaissance:** OSINT domain intelligence (A, AAAA, MX, NS, TXT, SOA), RDAP/WHOIS ownership queries, and Certificate Transparency log parsing.
- **Web Security & Workbench:** Security headers audit, cookie flag inspection, custom raw HTTP request workbench with response body diffing and HAR 1.2 export.
- **Wireless Lab:** Active Wi-Fi metrics, masked password vault, nearby AP scanner, and Multi-BSSID Evil Twin rogue AP detection.

### Workspace 2: Offensive Security Lab
- **Red Team & EPSS Lab:** Automated CVE and CISA KEV mapping combined with FIRST.org EPSS exploitation probability ratings.
- **Active Directory Graph:** Domain join status, password policy audits, local admin inventory, BloodHound-style privilege escalation path modeling, and Identity Risk Scoring.
- **Deception & Honeypot Lab:** Low-interaction HTTP and SSH banner decoys that log unauthorized connection attempts without exposing internal assets.

### Workspace 3: Detection & Intelligence
- **Threat Hunting Workspace:** Hypothesis-driven behavioral hunting mapped to MITRE ATT&CK techniques, timeline builder, and entity relationship graphs.
- **Detection Rule Studio:** Multi-format syntax validator and editor for Sigma YAML, YARA, and Suricata rules, with ATT&CK enterprise matrix coverage evaluation.
- **Windows Internals & ETW:** Real-time inspection of Windows Event Logs (Security, System, App, PowerShell), Sysmon operational status, active ETW trace sessions, and unquoted service path audits.
- **Threat Intelligence:** Multi-source reputation queries for IP addresses, domain names, and file hashes.
- **Correlation & Incidents:** Sigma-compatible alert correlation linking open network ports with owning local Windows processes.

### Workspace 4: Forensics & Research
- **Memory Forensics Lab:** Memory image registration, SHA-256 verification, Volatility 3 plugin runner (`pslist`, `pstree`, `netscan`, `malfind`), and RWX memory injection scanning.
- **DFIR & Artifact Timeline:** Unified timeline merging Windows Prefetch execution history, System Event Logs, USB connection artifacts, and Run persistence keys.
- **Endpoint Security (EDR Lite 2.0):** Process tree with parent-child relationship modeling (detecting Office -> Shell LOLBin executions), cryptographic SHA-256 File Integrity Monitoring (FIM), and Windows Scheduled Tasks.

### Workspace 5: Cloud & Infrastructure
- **Cloud Posture:** Automated configuration audits for AWS (S3 public buckets, 0.0.0.0/0 Security Groups), Azure (NSG open ports), and GCP (Firewall rules).
- **Containers & Kubernetes:** Docker daemon inspection, `--privileged` container detection, root user execution checks, and Kubernetes RBAC wildcard permission analysis.
- **Supply Chain & SBOM:** CycloneDX 1.4 JSON Software Bill of Materials generation, OSV.dev vulnerability queries, and open-source license risk ratings.
- **Cryptography & TLS Lab:** Live TLS endpoint probing (detecting deprecated SSLv3/TLS 1.0/1.1 protocols, weak ciphers), X.509 certificate expiry/SAN validation, and Windows Trusted Root CA store audits.

### Workspace 6: Automation & Management
- **SOAR & Incident Response:** Multi-step response workflows with human-in-the-loop approval queues for intrusive actions (`FIREWALL_BLOCK`, `PROCESS_KILL`) and automated rollback procedures.
- **Automation & Toolkit:** Offline CIDR subnet calculator, universal Base64/Hex/URL encoder/decoder, and Unix/FILETIME timestamp converter.
- **Reports & Scope:** Bilingual (English / Türkçe) Markdown penetration testing report generator, external tool manager (Nmap, Wireshark, Volatility, YARA), and authorized target scope manager.

---

## 3. Global Shortcuts & Best Practices

| Shortcut | Action | Description |
| :--- | :--- | :--- |
| `Ctrl + P` / `Ctrl + K` | **Global Search** | Jump instantly to any module, view, or keyword |
| `Ctrl + S` | **Quick Save** | Export active data grid, workbench response, or report |
| `Escape` | **Dismiss** | Close active dialogs or cancel background worker tasks |
