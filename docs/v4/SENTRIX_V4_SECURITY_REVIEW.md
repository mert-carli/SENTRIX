# SENTRIX v4.0 — SECURITY ARCHITECTURE & THREAT MODEL REVIEW
## Enterprise Security Controls, Defense-in-Depth & Operational Guardrails

**Version:** 4.0.0  
**Classification:** Confidential / Defensive & Controlled Offensive Tooling  
**Author:** Principal Cybersecurity Architect & DevSecOps Review Board  
**Target OS:** Windows 10 / 11 x64  

---

## 1. Executive Summary

SENTRIX v4.0 operates in high-risk operational environments where operators analyze malware, investigate compromised endpoints, scan production networks, and audit cloud infrastructure. To guarantee that the platform itself cannot be compromised, weaponized, or cause unintended production outages, a rigorous **Defense-in-Depth** security architecture is enforced across every layer of the platform.

---

## 2. Threat Modeling (STRIDE Analysis for v4.0)

| STRIDE Threat | Attack Vector / Risk | SENTRIX v4.0 Mitigation & Control Implementation | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary crafts deceptive DNS records to induce out-of-scope scanning or impersonate an internal host. | `core/scope.py` implements **DNS Rebinding Protection**: resolves hostnames prior to socket binding, verifies underlying IPv4/IPv6 against allowed CIDRs, and blocks link-local metadata ranges (`169.254.0.0/16`). | Low |
| **Tampering** | Malicious binary, crafted PCAP, or corrupted memory image exploits parser vulnerabilities. | `modules/packet/pcap_analyzer.py` and `modules/reverse_eng/pe_parser.py` are written in pure memory-safe Python using strict byte-length bounds checks on all offsets and headers. | Low |
| **Repudiation** | Operator conducts unauthorized offensive scans or alters assessment logs without evidence. | All actions are committed to SQLite `audit_logs` table and written to append-only `sentrix_audit.log` with timestamp, session UUID, target parameters, and operator identity. | Negligible |
| **Information Disclosure** | Extracted credentials, Wi-Fi keys, or NTLM hashes leak via console outputs or diagnostic logs. | `core/logger.py` enforces active regex sanitization (`sanitize_message`), redacting passwords, API tokens, Bearer headers, and private keys with `[REDACTED_BY_SECURITY_POLICY]`. | Low |
| **Denial of Service** | Hostile network targets deliberately tarpit connections, hang scanning threads, or exhaust RAM. | Network sockets enforce connection and read timeouts (0.75s to 3.0s); `core/task_manager.py` limits worker pool size; cancellation tokens allow immediate operator abort. | Low |
| **Elevation of Privilege**| Unauthorized command execution or unauthorized destructive system modification via SOAR playbooks. | Intrusive actions (`FIREWALL_BLOCK`, `PROCESS_KILL`, `QUARANTINE`) require explicit operator authorization via `SOARApprovalManager`. Non-elevated accounts degrade gracefully without privilege escalation vulnerabilities. | Low |

---

## 3. Scope Enforcement & Anti-SSRF Architecture (`core/scope.py`)

A cornerstone of SENTRIX v4.0 is its **Fail-Closed Target Scope Guard**:
1. **CIDR & Subnet Containment:** Validates target IP against authorized subnets using native `ipaddress.ip_network`.
2. **Explicit Exclusion Precedence:** If an IP or domain matches an inclusion rule but is listed in `excluded_targets`, execution is immediately aborted with a `ScopeViolationError`.
3. **Anti-SSRF & Cloud Metadata Shield:** Domains resolving to link-local cloud metadata addresses (`169.254.169.254`, AWS IMDS / Azure Instance Metadata) are strictly blocked to eliminate Server-Side Request Forgery risks.
4. **DNS Rebinding Prevention:** Validates both the domain name and the resolved IP address to ensure malicious DNS TTL shifts cannot bypass CIDR boundaries.

---

## 4. Subprocess Execution & Command Injection Defense

Subprocess execution across all modules adheres to the following mandatory standards:
- **Zero Dynamic `shell=True`:** Subprocesses invoked in `modules/terminal/orchestrator.py`, `modules/container_security/`, and `modules/tools/tool_manager.py` use structured argument lists (`[binary_path, arg1, arg2]`), preventing OS command chaining (`|`, `&`, `;`, `$()`).
- **Binary Path Verification:** Tools are located via `shutil.which` or absolute system paths (`C:\Program Files\...`, System32), mitigating PATH-hijacking or unquoted search path vulnerabilities.

---

## 5. Human-in-the-Loop Safety Rails for SOAR (`modules/soar/`)

Unlike fully autonomous SOAR systems that can accidentally terminate critical business services:
- **Destructive Action Isolation:** Actions flagged as `is_destructive=True` cannot execute autonomously.
- **Approval Queue:** Such actions generate a cryptographically tracked approval record with target parameters and justification.
- **Rollback Registry:** Every executed containment action maintains a reversible rollback procedure (e.g., removing a firewall block rule) to restore operational baselines rapidly.

---

## 6. Conclusion

SENTRIX v4.0 achieves an exemplary security posture. By combining memory-safe Python engines, fail-closed target boundaries, regex-based log sanitization, and human-in-the-loop response authorization, the platform provides security researchers, red teamers, and SOC analysts with unprecedented operational power while ensuring total control, confidentiality, and host system integrity.
