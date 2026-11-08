# SENTRIX v4.0 — DEPENDENCY MANIFEST & EXTERNAL TOOL COMPATIBILITY
## Comprehensive Library Inventory, License Review & Tool Integration Status

**Version:** 4.0.0  
**Target Platform:** Windows 10 / 11 x64  
**Runtime:** Python 3.9 - 3.12 (Tested on Python 3.11.9)  

---

## 1. Python Direct Dependencies (`requirements.txt`)

| Package Name | Minimum Version | Verified Version | License | Architectural Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `customtkinter` | `>= 5.2.0` | `5.2.2` | Creative Commons Zero v1.0 Universal | High-DPI dark mode graphical user interface |
| `pillow` | `>= 10.0.0` | `10.4.0` | HPND / PIL License (Permissive) | Asset and icon rendering |
| `requests` | `>= 2.31.0` | `2.31.0` | Apache-2.0 | HTTP client for WebSec, OSINT & CVE/EPSS queries |
| `packaging` | `>= 23.0` | `24.1` | Apache-2.0 / BSD-2-Clause | Version comparison for dependencies and CVEs |
| `psutil` | `>= 5.9.0` | `5.9.8` | BSD-3-Clause | Windows process inspection & system hardware telemetry |

*(Zero copyleft GPL/AGPL dependencies exist in the core runtime; all libraries are fully permissive and enterprise-compliant.)*

---

## 2. Python Standard Library Usage (Hardened Core)

SENTRIX deliberately relies on Python's robust standard library for critical cryptographic and networking tasks to avoid third-party supply chain risks:
- `sqlite3`: Hardened relational database storage with WAL mode.
- `socket` & `ssl`: Native TCP/UDP sockets, TLS/SSL handshake negotiation, and raw banner grabbing.
- `struct`: Binary unpacking of `.pcap` packet headers, PE executable structures, and DNS packets.
- `ipaddress`: Strict RFC1918, RFC4193, and RFC4291 subnet and address validation.
- `concurrent.futures`: Multi-threaded task execution and cancellation workers.
- `xml.etree.ElementTree`: High-speed parsing of Windows EventLog XML and Nmap scan outputs.
- `winreg`: Native Windows Registry querying for autostart persistence and AppCompatCache artifacts.
- `hashlib` & `hmac`: SHA-256, MD5, and cryptographic integrity verification.

---

## 3. Optional External Tools Compatibility Matrix

SENTRIX v4.0 operates completely autonomously using native Python engines. However, when installed, it seamlessly harnesses the following industry tools:

| External Tool | Tested Executable | Minimum Recommended Version | Function in SENTRIX v4.0 | Detection Path |
| :--- | :--- | :--- | :--- | :--- |
| **Nmap** | `nmap.exe` | 7.90+ | Raw SYN stealth scanning and NSE script engine | `C:\Program Files (x86)\Nmap\nmap.exe` |
| **Npcap** | `wpcap.dll` | 1.70+ | Raw packet injection & live promiscuous packet capture | Windows Driver Store |
| **Wireshark / TShark** | `tshark.exe` | 4.0+ | Deep packet dissection and PCAPNG stream analysis | `C:\Program Files\Wireshark\tshark.exe` |
| **Volatility 3** | `vol.exe` / `vol.py` | 2.4.0+ | Windows kernel memory dump artifact extraction | `C:\Volatility3\`, Python PATH |
| **YARA** | `yara64.exe` | 4.2+ | High-speed pattern and signature matching on binaries | `C:\Program Files\YARA\yara64.exe` |
| **Trivy** | `trivy.exe` | 0.45+ | Container image vulnerability and SBOM scanning | System PATH |
| **Docker CLI** | `docker.exe` | 24.0+ | Container inventory and privileged runtime audits | System PATH |
| **kubectl** | `kubectl.exe` | 1.28+ | Kubernetes cluster context and RBAC permission auditing | System PATH |
| **VirtualBox** | `VBoxManage.exe`| 7.0+ | Malware sandbox snapshot verification and control | `C:\Program Files\Oracle\VirtualBox\` |
