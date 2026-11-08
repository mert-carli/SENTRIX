# SENTRIX v3.0 — COMPREHENSIVE OPERATOR USER GUIDE
## Advanced Cyber Operations, Ethical Hacking & Incident Response Manual

**Platform:** SENTRIX Cyber Operations Platform v3.0  
**Interface Design:** Modern Minimalist Dark Slate (`#0B111B`)  
**Target Audience:** Penetration Testers, DFIR Analysts, SOC Tier 2/3, Security Researchers  

---

## 1. Interface Architecture & Navigation

SENTRIX v3.0 features a unified, clutter-free desktop workspace engineered for rapid situational awareness and low cognitive overhead during active engagements.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  [SENTRIX v3.0]   [Ctrl+P Command Palette]    Scope: 192.168.1.0/24  |  UAC: ADMIN│
├─────────────────┬────────────────────────────────────────────────────────────────┤
│ WORKSPACES      │ ACTIVE OPERATIONAL CANVAS                                      │
│                 │                                                                │
│ [Operations]    │  ┌──────────────────────────────────────────────────────────┐  │
│  - Dashboard    │  │ Target Input: [192.168.1.50      ] [ SCAN TARGET ]       │  │
│  - Recon & Scan │  ├──────────────────────────────────────────────────────────┤  │
│  - Web Security │  │ PORT    STATE    SERVICE    VERSION         CVE / EPSS   │  │
│  - Wireless Lab │  │ 22/tcp  OPEN     OpenSSH    8.9p1 Ubuntu    CVE-2023-38408│ │
│                 │  │ 80/tcp  OPEN     Apache     2.4.52          0.0012 (12%) │  │
│ [Offensive Lab] │  │ 443/tcp OPEN     Apache     2.4.52          -            │  │
│  - Active Dir   │  │ 3389/tcpFILTERED ms-wbt-svr -               -            │  │
│  - Vuln Research│  └──────────────────────────────────────────────────────────┘  │
│  - PE Analyzer  │                                                                │
│                 │  LOG & EXECUTION TELEMETRY                                     │
│ [Forensics]     │  [14:22:01] [*] Initializing scan against target 192.168.1.50  │
│  - DFIR Tools   │  [14:22:02] [+] Scope verified. 3 ports open detected.         │
│  - PCAP Analysis│                                                                │
│ [Intelligence]  │                                                                │
│ [Tools & Mgt]   │                                                                │
├─────────────────┴────────────────────────────────────────────────────────────────┤
│ Status: READY | Active Scope: 192.168.1.0/24 | DB: Connected (WAL) | Tasks: 0   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Key UI Zones:
1. **Header Bar:**
   - **Logo & Title:** Displays current release version.
   - **Command Palette (`Ctrl+P` / `Ctrl+K`):** Global quick-switch modal to instantly jump to any module or execute hotkey workflows.
   - **Scope Badge:** Real-time indicator showing the current authorized target CIDR or domain boundary.
   - **Privilege Badge:** Indicates whether SENTRIX is running in `Standard User` mode or `Elevated Admin` mode.
2. **Left Navigation Sidebar:**
   - Organized into **5 Operational Workspace Categories** (Operations, Offensive Lab, Forensics, Intelligence, Tools & Mgt).
   - Single-click switching preserves form inputs and active scan results across view toggles.
3. **Operational Canvas:**
   - Primary interactive workspace containing specialized tool panels, interactive data grids, terminal logs, and technical inspectors.
4. **Bottom Status Strip:**
   - Real-time engine telemetry, thread pool task indicators, and database synchronization status.

---

## 2. Quick-Start Tutorial: 5-Minute Engagement

### Step 1: Configure Authorized Scope
Before launching any active scan, you must define the target boundary to prevent out-of-scope interaction:
1. Open the **Tools & Mgt -> Security Automation** or use the **Command Palette (`Ctrl+P`)** to select **Manage Scope**.
2. Enter your authorized IP range, for example: `192.168.1.0/24` or target hostname `scanme.nmap.org`.
3. Add any restricted systems (e.g., domain controllers or production printers) to the **Exclusions** list.
4. Click **Apply Scope**. The top header badge will turn green with your active boundary.

### Step 2: Run a Network Reconnaissance Scan
1. Navigate to **Operations -> Recon & Scan**.
2. Enter your target IP or CIDR (e.g., `192.168.1.50`).
3. Select scan profile:
   - **Top 100 Common Ports:** Rapid assessment (< 2 seconds).
   - **Full Well-Known (1-1024):** Standard infrastructure scan.
   - **Custom Range:** Specific operational target list (e.g., `80,443,8080,8443,3389`).
4. Click **Start Scan**. Observe real-time banner grabbing, service detection, and automated CVE/EPSS vulnerability mapping in the results table.

### Step 3: Inspect Web Application Endpoints
1. If ports `80` or `443` are discovered open, switch to **Operations -> Web Security**.
2. Enter `http://192.168.1.50` and click **Analyze Web Targets**.
3. Review:
   - Missing Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
   - Cookie Flags (Missing `Secure`, `HttpOnly`, or `SameSite`).
   - Exposed Administrative Paths (`/admin`, `/.env`, `/api/v1`).
4. Switch to the **HTTP Workbench** sub-tab to compose custom raw HTTP requests, inspect headers, and export your session as an industry-standard **HAR 1.2** archive.

### Step 4: Generate Executive & Technical Audit Report
1. Navigate to **Tools & Mgt -> Report Center**.
2. Select report language: **English** or **Türkçe**.
3. Choose scope: **Full Platform Engagement** or **Network Recon Only**.
4. Click **Generate Markdown Report**.
5. Save the generated `.md` file to your client deliverables folder.

---

## 3. Deep-Dive: Workspace Capabilities

### Workspace 1: Operations

#### 1.1 Command Dashboard
- **Target Counter:** Live metric of in-scope hosts scanned during current session.
- **Port Distribution Chart:** Visual breakdown of discovered open services (Web, SSH, Database, Management).
- **Recent Alerts:** High-severity findings (e.g., critical CVEs with EPSS > 50%, missing HSTS, unencrypted protocols).
- **One-Click Quick Actions:** Instant triggers for rapid recon, scope editing, and report generation.

#### 1.2 Network Reconnaissance & Port Engine
- **Engine Capabilities:** Multi-threaded asynchronous TCP Connect scanning, banner grabbing, and service fingerprinting.
- **Vulnerability Enrichment:** Automatically links discovered service versions (e.g., `OpenSSH 8.9p1`) to known CVEs and FIRST.org EPSS exploitation probability scores.
- **Historical Diff Viewer:** Compare two scans of the same host to immediately highlight newly opened ports, closed services, or changed software versions.
- **Nmap XML Import:** Ingest output from external scans (`nmap -oX output.xml`) into SENTRIX's relational database with a single click.

#### 1.3 Web Security & HTTP Workbench
- **Security Audit:** High-speed inspection of TLS/SSL parameters, HTTP response headers, and session cookies.
- **Endpoint Discovery:** Automated probing of sensitive administrative panels, backup files, and API routes.
- **HTTP Workbench:**
  - Build custom GET/POST/PUT/DELETE requests with custom headers and payloads.
  - View raw response bodies, formatted JSON, and response timing metrics.
  - Side-by-side **Response Diffing** to analyze authentication bypasses or behavioral changes.
  - Complete **HAR 1.2 Export** for sharing sessions with Burp Suite or OWASP ZAP.

#### 1.4 Wireless Security Lab
- **Nearby AP Scanner:** Discovers active 802.11 networks, signal strength (RSSI), channel allocations, and authentication modes (WPA2-PSK, WPA3, Enterprise, Open).
- **Evil Twin Detector:** Employs multi-BSSID heuristic analysis to detect rogue access points broadcasting duplicate SSIDs with mismatched MAC OUIs.
- **Password Vault:** Securely inspects known local Wi-Fi profiles with password masking toggles for security demonstrations.

---

### Workspace 2: Offensive Lab

#### 2.1 Active Directory & Identity Assessment
- **Domain vs Workgroup:** Detects domain join status, primary domain controller, and forest functional level.
- **Password Policy Auditor:** Evaluates lockout thresholds, minimum length, complexity rules, and reversible encryption status against CIS benchmarks.
- **Attack Path Visualizer:** Generates BloodHound-style privilege escalation graph summaries (e.g., `Standard User -> Service Account -> Domain Admin` paths) and computes an overall **Identity Risk Score**.

#### 2.2 Vulnerability & Exploit Research
- **Curated Offline CVE Database:** Instant lookup for critical vulnerabilities without requiring external API access.
- **Live NVD / CISA KEV Query:** Queries the CISA Known Exploited Vulnerabilities catalog to highlight actively exploited flaws.
- **FIRST.org EPSS Scoring:** Real-time probability ratings to prioritize vulnerabilities that attackers are actively exploiting in the wild.

#### 2.3 Malware Sandbox & PE Binary Analyzer
- **PE Header Dissection:** Pure-Python 32-bit and 64-bit PE header parser analyzing sections, entry points, and machine architectures.
- **Section Entropy Analysis:** Calculates Shannon entropy across `.text`, `.data`, and `.rsrc` sections to detect packers (UPX, Themida) and encrypted payloads (entropy > 7.0).
- **Suspicious API Inspection:** Scans import tables for known malware primitives (e.g., `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `AdjustTokenPrivileges`).
- **VM Orchestrator:** Manages Hyper-V and VirtualBox sandbox environments, automatically checking snapshot readiness before detonating untrusted binaries.

#### 2.4 Password & Credential Lab
- **Hash Identifier:** Recognizes over 30 hash types including NTLM, MD5, SHA-1, SHA-256, bcrypt, and Argon2 based on length, character set, and salt format.
- **Cracking Estimator:** Calculates brute-force resistance across various hardware tiers (CPU vs multi-GPU clusters).

---

### Workspace 3: Digital Forensics & Incident Response (DFIR)

#### 3.1 Digital Forensics Toolkit
- **Magic Byte File Classifier:** Identifies true file types based on header hex signatures, exposing extension-spoofed malicious files (e.g., an `.exe` masquerading as a `.pdf`).
- **Hex Dump Viewer:** Formatted dual-pane view showing raw byte offsets and printable ASCII characters.
- **String Extractor:** Extracts ASCII and UTF-16 Unicode strings from memory dumps and raw binaries with minimum length filters.
- **USB Device History:** Reads registry artifacts to list all USB mass storage devices ever connected to the host, including device vendor, serial numbers, and first/last mount times.
- **Run Keys Persistence Auditor:** Audits standard Windows persistence mechanisms (`HKCU/HKLM Run`, `RunOnce`, Startup folders).

#### 3.2 Packet Capture (PCAP) Dissection
- **Native Binary Parser:** Processes standard `.pcap` files without external dependencies.
- **Protocol Breakdown:** Categorizes Ethernet, IPv4, TCP, UDP, and ICMP frame distributions.
- **Conversation Top Talkers:** Aggregates bandwidth and frame counts by source/destination IP pairs.
- **Anomaly Detection:** Flags potential SYN floods, port scan sweeps, and cleartext credential transmissions.

#### 3.3 Linux & Cloud Security Audit
- **WSL / SSH Auditing:** Performs automated baseline checks against connected Linux environments, auditing `sudo` permissions, SUID binaries, SSH hardening parameters, and open network sockets.

---

### Workspace 4: Intelligence & Detection

#### 4.1 Threat Intelligence Center
- **IOC Reputation Checking:** Fast multi-source query for suspicious IPv4 addresses, domain names, and file hashes (SHA-256).
- **MITRE ATT&CK Mapping:** Associates discovered adversary techniques with formal ATT&CK matrix tactics and sub-techniques.

#### 4.2 Sigma Engine & Correlation
- **Sigma Rule Evaluator:** Evaluates process creation events and network connections against standard Sigma detection rules.
- **Cross-Module Socket Correlation:** Automatically correlates open network ports with active local processes and PID owners.

#### 4.3 Endpoint Detection & Response (EDR Lite)
- **Live Process Tree:** Displays running Windows processes organized by parent-child relationships (PPID), highlighting suspicious child processes (e.g., `cmd.exe` or `powershell.exe` spawned by `excel.exe`).
- **File Integrity Monitoring (FIM):** Generates and verifies cryptographic SHA-256 baselines across critical system directories (`C:\Windows\System32\drivers\etc`, startup scripts) to detect unauthorized tampering.
- **Scheduled Tasks Auditor:** Inspects registered Windows Task Scheduler jobs to surface malicious persistence mechanisms.

---

### Workspace 5: Tools & Management

#### 5.1 Security Automation & Workflows
- **Chained Security Assessment:** Executes an end-to-end automated security pipeline:
  1. *Step 1:* Verify target scope authorization.
  2. *Step 2:* Perform multi-threaded port and banner reconnaissance.
  3. *Step 3:* Map discovered service versions against known CVEs and EPSS scores.
  4. *Step 4:* Run web security header and sensitive path checks.
  5. *Step 5:* Compile structured audit findings directly into the SQLite database and export a Markdown summary.

#### 5.2 Cyber Security Toolkit
- **CIDR Subnet Calculator:** Computes network addresses, broadcast addresses, subnet masks, and usable host ranges.
- **Universal Encoder/Decoder:** Real-time offline conversion across Base64, Hexadecimal, and URL encoding formats.
- **Timestamp Converter:** Converts between Unix epoch seconds, ISO 8601 strings, and Windows 64-bit `FILETIME` structures (critical for Active Directory and NTFS forensics).

#### 5.3 External Tool Orchestrator
- **Centralized Tool Hub:** Inspects the host system for Nmap, Wireshark, TShark, YARA, and Ghidra installations.
- **Safe Execution Runner:** Executes verified command lines using strict argument lists with live output streaming.

#### 5.4 Report Generation Center
- **Bilingual Assessment Engine:** Compiles complete penetration testing and security assessment reports in English or Turkish.
- **Export Formats:** Generates clean, publication-ready GitHub-flavored Markdown (`.md`) easily converted to PDF or executive slide decks.

---

## 4. Operational Best Practices & Shortcuts

| Hotkey | Action | Description |
| :--- | :--- | :--- |
| `Ctrl + P` / `Ctrl + K` | **Command Palette** | Quick-jump to any module, view, or action |
| `Ctrl + S` | **Quick Save** | Export current table or workbench response |
| `Escape` | **Cancel / Dismiss** | Closes open modals or aborts active worker tasks |

### Safe Operating Checklist:
1. Always verify the green **Scope Badge** before initiating active network probes.
2. For live packet capture or event log queries, ensure SENTRIX was launched with Administrator privileges.
3. Keep `data/sentrix.db` backed up prior to large-scale enterprise assessments.
