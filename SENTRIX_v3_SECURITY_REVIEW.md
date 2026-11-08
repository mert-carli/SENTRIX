# SENTRIX v3.0 — SECURITY ARCHITECTURE & CODE REVIEW
## Comprehensive Security Audit, Threat Model & Defense-in-Depth Analysis

**Version:** 3.0.0  
**Target Platform:** Windows 10 / 11 (x64)  
**Security Classification:** Highly Confidential / Defensive & Authorized Offensive Tooling  
**Author:** Principal Cybersecurity Architect & DevSecOps Review Board  
**Status:** Approved & Implemented  

---

## 1. Executive Summary

SENTRIX v3.0 is a professional-grade Cyber Operations and Penetration Testing Platform designed for Windows environments. Because cybersecurity tools operate in sensitive operational contexts—handling network traffic, credentials, vulnerability signatures, and system diagnostics—the platform itself must adhere to the highest tier of security and defensive programming.

This document details the security posture, threat model, architectural guardrails, vulnerability mitigation strategies, and defensive controls implemented across SENTRIX v3.0.

### Key Security Posture Highlights:
- **Fail-Closed Scope Enforcement:** Active offensive and intrusive discovery actions cannot execute without positive authorization against an active scope definition (`core/scope.py`).
- **Zero Shell Injection Vector:** All external tool orchestration runs through strictly validated argument lists; standard `shell=True` execution with unchecked user input is prohibited across the platform.
- **Credential & Secret Redaction:** Automated real-time sanitizing in logging (`core/logger.py`) and export generators prevents accidental exposure of Bearer tokens, private keys, API keys, and NT hashes.
- **Full Parameterized SQL:** 100% of SQLite database queries in `core/database.py` use parameter binding (`?`), eliminating SQL injection.
- **Fail-Safe Windows Privilege Separation:** Non-administrative users can safely run all passive and unprivileged modules without crashing or unexpected elevation prompts. Privileged capabilities (e.g., raw sockets, driver access) gracefully degrade with informative user alerts.

---

## 2. Threat Modeling (STRIDE Analysis)

To evaluate potential attack vectors against the SENTRIX platform during field operations, a comprehensive STRIDE threat assessment was conducted.

| Threat Category | Potential Attack Vector | SENTRIX v3.0 Mitigation & Defense Controls | Residual Risk Level |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates legitimate target scope or spoofs DNS/RDAP responses. | Scope verification enforces canonical IP/CIDR evaluation. RDAP/TLS certificate parsing verifies cryptographic subject alternative names (SAN) and fingerprint authenticity. | Low |
| **Tampering** | Malicious target feeds crafted HTTP headers, oversized banners, or malformed PCAP files to corrupt state. | Strict input bounds on banner grabbing (1024-byte truncate, ASCII printable filtering), defensive binary bounds checking in `pcap_analyzer.py`, and structured JSON/HAR validation. | Low |
| **Repudiation** | Operator or unauthorized user performs unauthorized actions without audit proof. | Append-only SQLite structured logging (`core/logger.py` and `db.add_audit_log()`) records timestamp, operator session, target parameters, and execution hash. | Negligible |
| **Information Disclosure** | Leakage of discovered credentials, Wi-Fi keys, or sensitive target reports to untrusted parties. | Wi-Fi passwords stored masked by default (`wifi_lab.py`); log redaction scrubs API tokens and passwords; report generation operates strictly within user-specified local directories. | Low |
| **Denial of Service** | Infinite loops, socket hanging, or memory exhaustion when scanning high-latency / hostile networks. | Sockets enforce strict connection and read timeouts (default 0.75s - 2.0s); worker threads managed by centralized `TaskManager` with bounded pools; cancellation tokens supported across all async routines. | Low |
| **Elevation of Privilege** | Malicious executable placed in PATH hijacked by SENTRIX external tool orchestrator (`terminal/orchestrator.py`). | Orchestrator resolves binaries using absolute paths from verified standard system locations (`C:\Program Files\...`, System32); rejects execution if binary identity is unverified. | Low |

---

## 3. Scope Enforcement Architecture (`core/scope.py`)

A critical risk in penetration testing platforms is accidental testing of out-of-scope assets (IP addresses, cloud subnets, third-party infrastructure). SENTRIX v3.0 implements a mandatory, backend-enforced **Authorized Target Scope Guard**.

```
[User Trigger / Module Task]
          │
          ▼
   [ScopeManager.is_allowed(target)]
          │
    ┌─────┴────────────────────────┐
    ▼                              ▼
[In Exclusions?]              [In Inclusions?]
    │ Yes                          │ No
    ▼                              ▼
[BLOCK: Out of Scope]         [BLOCK: Deny by Default]
                                   │ Yes
                                   ▼
                              [ALLOW & AUDIT]
```

### Technical Implementation Details:
1. **Canonical IP Resolution:** Hostnames are resolved to underlying IPv4/IPv6 addresses prior to evaluation to prevent DNS rebinding bypasses.
2. **CIDR Network Matching:** Uses Python's native `ipaddress.ip_network` and `ipaddress.ip_address` to prevent string-based CIDR comparison flaws (e.g., ensuring `192.168.1.100` correctly matches `192.168.1.0/24` and is rejected if outside).
3. **Explicit Exclusion Overrides:** If a target matches an inclusion range but is listed in the `excluded_ips` list, exclusion takes precedence immediately (**Fail-Closed**).
4. **Programmatic Assertion Guard:**
   ```python
   # Enforced in scanner, pentester, and workflow automation
   if not scope_manager.is_allowed(target_host):
       raise PermissionError(f"Target {target_host} is strictly outside authorized scope.")
   ```

---

## 4. Input Validation & Command Execution Security

### 4.1 Subprocess & Command Injection Defense
Operating system commands executed via `modules/terminal/orchestrator.py` or diagnostic routines adhere to the following strict controls:
- **No `shell=True` with Dynamic Input:** Subprocesses are invoked using lists of arguments (`subprocess.Popen(["nmap", "-sS", target])`), ensuring the operating system executes the binary directly without shell parsing.
- **Port and Address Validation:** All port inputs are strictly checked against integer ranges (`1 <= port <= 65535`). Domain names and IP strings are verified via regex:
  - IPv4: `^([0-9]{1,3}\.){3}[0-9]{1,3}$`
  - FQDN: `^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$`
- **Argument Sanitization:** Metacharacters such as `|`, `&`, `;`, `$`, `>`, `<`, `` ` ``, and newlines are stripped or cause immediate validation failure before reaching OS subprocess wrappers.

### 4.2 Malicious Payload & Binary File Handling
- **PE Header Parsing (`modules/reverse_eng/pe_parser.py`):** Operates using memory-safe stream parsing with explicit bounds checks on file size, header offsets (`e_lfanew`), section counts, and data directories. Avoids buffer overflows and handles truncated files gracefully.
- **PCAP Parsing (`modules/packet/pcap_analyzer.py`):** Pure Python binary unpacker (`struct.unpack`) validates magic numbers (`0xa1b2c3d4`, `0xd4c3b2a1`), snapshot length limits, and packet header bounds to eliminate memory corruption risks common in C-based parsers.

---

## 5. Data Privacy & Credential Redaction (`core/logger.py`)

Log files and console outputs frequently capture raw communication streams that may contain sensitive credentials, session tokens, or private user data. SENTRIX v3.0 incorporates an active sanitization pipeline.

### Redaction Rules in `core/logger.py`:
- **Bearer & JWT Tokens:** Matched via `Bearer\s+[A-Za-z0-9\-_\.=]+` and replaced with `Bearer [REDACTED_TOKEN]`.
- **API Keys & Secrets:** Tokens following common key markers (`api_key=`, `secret=`, `token=`, `password=`) are scrubbed before writing to disk or terminal.
- **NTLM / NetNTLM Hashes:** Hashes extracted during authorized Active Directory assessments are masked in standard logging output to prevent accidental disk exposure.
- **Auditing Integrity:** Audit entries (`audit.log` and the `audit_logs` database table) retain unredacted target metadata and cryptographic checksums in a secured SQLite container with restricted NTFS permissions.

---

## 6. Database Hardening & Storage Security (`core/database.py`)

SENTRIX stores operational intelligence in `data/sentrix.db`. The storage engine is hardened against corruption, concurrency race conditions, and unauthorized tampering.

### Database Hardening Measures:
1. **Write-Ahead Logging (WAL):** Enabled via `PRAGMA journal_mode=WAL;`, ensuring concurrent readers do not block writers and providing crash-resilience.
2. **Foreign Key Integrity:** Enforced at runtime via `PRAGMA foreign_keys=ON;`.
3. **Synchronous Disk Flushing:** Configured to `PRAGMA synchronous=NORMAL;` balancing maximum throughput with ACID write guarantees.
4. **SQL Parameterization:** All SQL queries use SQLite's native `?` placeholder parameters. No string formatting (`f"SELECT ... WHERE host = '{host}'"`) exists in the persistence layer.
5. **Schema Migration Safety:** Database startup executes automatic schema evolution checks (`PRAGMA table_info`), ensuring seamless backward compatibility without data loss or column truncation.

---

## 7. Windows Privilege Model & Access Control

SENTRIX v3.0 operates under a dual-tier permission model designed for Windows 10/11:

### Tier 1: Standard User Mode (Least Privilege)
- **Permissions:** Standard non-elevated user token.
- **Available Operations:**
  - TCP Connect port scanning
  - OSINT & Attack Surface reconnaissance
  - HTTP / Web Security vulnerability testing & Workbench
  - Active Directory LDAP / Kerberos queries (using logged-in user credentials)
  - Memory-safe PE binary static analysis & Disassembly
  - Packet inspection of offline PCAP captures
  - Security encoding/decoding utilities and report compilation.
- **Guarantees:** No elevation prompts, no system-level registry modifications, zero risk of blue-screening or driver instability.

### Tier 2: Elevated Administrator Mode (UAC Elevated)
- **Permissions:** High-integrity administrator token.
- **Available Operations:**
  - Raw socket operations & TCP SYN stealth scanning (when Npcap is present)
  - Promiscuous mode live packet capture
  - Advanced forensic disk inspection and USB device history extraction
  - System-wide process tree inspection and thread memory querying
  - Windows Event Log (`Security.evtx`) direct channel querying.
- **Integrity Verification:** Checked via `core/permission.py` using `ctypes.windll.shell32.IsUserAnAdmin()`. If an unprivileged user triggers a Tier 2 action, the UI issues a clear notice explaining the requirement rather than failing abruptly.

---

## 8. Operational Security (OpSec) Recommendations for Practitioners

When deploying SENTRIX v3.0 in red team, blue team, or lab environments, operators should observe the following operational security best practices:

1. **Isolation in Malware Analysis:**
   - Always run the PE parser and dynamic sandbox modules in an isolated Virtual Machine (Hyper-V / VirtualBox) with host-only or disabled networking.
   - Verify VM snapshot status using `modules/malware_sandbox/vm_orchestrator.py` before executing untrusted binaries.
2. **Scan Rate Limiting:**
   - On production enterprise networks, limit scan concurrency (`max_workers <= 50`) and socket timeout (`timeout >= 1.0s`) to avoid triggering network intrusion prevention system (IPS) state-table exhaustion.
3. **Report Sanitization:**
   - Before distributing generated assessment reports to clients or public repositories, verify that internal hostnames, confidential IP addressing schemes, and proprietary API paths are reviewed and approved for disclosure.

---

## 9. Conclusion & Certification

The SENTRIX v3.0 architecture has been subjected to rigorous static analysis, structural verification, and comprehensive regression testing. The platform adheres strictly to modern cybersecurity engineering standards, providing powerful capabilities to ethical hackers, security analysts, and digital forensics professionals while maintaining strict guardrails against accidental misuse, injection vulnerabilities, and data leakage.
