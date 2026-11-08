# SENTRIX v4.0 — KNOWN LIMITATIONS & OPERATIONAL BOUNDARIES
## Technical Constraints, External Tool Dependencies & Permission Boundaries

**Version:** 4.0.0  
**Classification:** Operational Transparency Document  
**Date:** 2026-11-06  

---

## 1. Operating System Permission Boundaries

1. **Windows Security Event Log Channel (`Security.evtx`):**
   - *Limitation:* The Windows Security log channel contains sensitive authentication (4624/4625) and process execution (4688) records restricted by Windows Access Control Lists (ACLs).
   - *Behavior:* Reading this channel requires launching SENTRIX with elevated Administrator privileges. When running under a Standard User account, SENTRIX will not crash; it will report `PERMISSION_REQUIRED` and continue serving unprivileged channels (System, Application).
2. **Raw Socket SYN Stealth Scanning & Live Promiscuous Sniffing:**
   - *Limitation:* Windows disables raw socket transmission for non-administrative accounts and lacks native promiscuous packet capture drivers.
   - *Behavior:* Requires Administrator privileges and the third-party **Npcap** driver installed in WinPcap-compatible mode. If absent, SENTRIX uses its native multi-threaded **TCP Connect** engine, which works reliably across all Windows accounts.
3. **Forensic Access to Windows Prefetch & SYSTEM Registry Hive:**
   - *Limitation:* `C:\Windows\Prefetch\` and raw `HKLM\SYSTEM` hives are restricted to High-Integrity Administrator tokens.
   - *Behavior:* Under standard user accounts, prefetch queries report `ACCESS_DENIED` and fall back to user-level execution artifacts.

---

## 2. External Tool Dependency Behaviors

SENTRIX operates under a **Zero-Mock Policy**: when external tools are absent, it clearly reports their status rather than producing synthetic or fake results.

1. **Volatility 3 Framework:**
   - *Limitation:* Deep kernel-level memory artifact extraction (`windows.pslist`, `windows.malfind`) requires Volatility 3 (`vol` / `vol.py`) installed in PATH.
   - *Behavior:* SENTRIX registers memory images, calculates SHA-256 integrity hashes, and detects RWX permissions natively. If Volatility is missing, the UI displays `NOT_INSTALLED` with installation guidance.
2. **Container & Kubernetes Audits:**
   - *Limitation:* Live container inspection requires a running Docker daemon and a configured `kubectl` cluster context.
   - *Behavior:* If Docker or kubectl are offline, SENTRIX indicates `DAEMON_NOT_RUNNING` or `NO_CONTEXT` without failing.
3. **Trivy Vulnerability Scanner:**
   - *Limitation:* Container image CVE matching depends on Trivy CLI.
   - *Behavior:* When missing, SENTRIX falls back to static layer and manifest inspections.

---

## 3. Network & Internet Dependency Behaviors

1. **OSINT (RDAP, WHOIS & Certificate Transparency):**
   - *Limitation:* Querying crt.sh and regional internet registries requires outbound HTTPS access.
   - *Behavior:* If operated in an air-gapped lab without internet, external OSINT lookups will time out gracefully while local DNS and IP range analysis continue working offline.
2. **FIRST.org EPSS & NVD Vulnerability Queries:**
   - *Limitation:* Live EPSS score retrieval and NVD API queries require internet connectivity.
   - *Behavior:* SENTRIX bundles an offline curated database of critical CVEs and CISA Known Exploited Vulnerabilities (KEV) to ensure functional offline risk scoring.
