# SENTRIX v3.0 — INSTALLATION & ENVIRONMENT SETUP GUIDE
## Professional Deployment, Dependencies, and External Tool Configuration

**Platform:** Windows 10 / 11 (64-bit)  
**Target Runtime:** Python 3.9 - 3.12 (Verified on Python 3.11.9)  
**Framework:** CustomTkinter, SQLite3 (WAL Mode), Native Windows Win32/WMI APIs  

---

## 1. System Requirements

### Hardware Requirements
- **CPU:** Dual-core 2.0 GHz or higher (Quad-core recommended for multi-threaded port scanning and PCAP processing).
- **RAM:** Minimum 4 GB (8 GB+ recommended for analyzing large binary files and memory dumps).
- **Storage:** 500 MB free disk space for core installation and dependencies. Additional space recommended for SQLite operational database (`data/sentrix.db`), packet captures, and generated audit reports.
- **Display:** 1366x768 minimum resolution (1920x1080 Full HD recommended for optimal multi-pane cyber operations dashboard view).

### Operating System Support
- Windows 10 (Build 19041+) 64-bit
- Windows 11 (All builds) 64-bit
- Windows Server 2019 / 2022 (Supported with Desktop Experience installed)

---

## 2. Python Environment Setup

SENTRIX v3.0 is built to run cleanly in an isolated Python virtual environment.

### Step 1: Verify Python Installation
Open Windows PowerShell and check that Python 3.9+ is installed and accessible:
```powershell
python --version
```
> **Note:** If Windows opens the Microsoft Store or displays an AppExecutionAlias error, ensure your Python installation is added to PATH or use the full path to your Python binary (e.g., `C:\Python311\python.exe`).

### Step 2: Clone or Open the Project Directory
Navigate to the root directory of the SENTRIX project:
```powershell
cd C:\Users\<Username>\Desktop\Projelerim\SENTRIX
```

### Step 3: Create and Activate Virtual Environment
```powershell
# Create the virtual environment
python -m venv venv

# If PowerShell blocks script execution, temporarily allow local scripts:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

### Step 4: Install Dependencies
Install all required platform libraries via `pip`:
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

#### Core Dependency Manifest:
| Package | Version | Purpose |
| :--- | :--- | :--- |
| `customtkinter` | `>= 5.2.0` | High-DPI modern dark UI framework |
| `pillow` | `>= 10.0.0` | Asset and image rendering |
| `requests` | `>= 2.31.0` | HTTP communications and REST API queries |
| `packaging` | `>= 23.0` | Version comparison and library compatibility |

*(All cryptographic, hashing, socket, thread management, and SQLite features utilize Python's hardened standard library for maximum stability and zero unneeded bloat.)*

---

## 3. Automated Integrity Verification

Before launching the user interface, run the automated test suites to verify that the database engine, cryptographic handlers, port scanners, and analysis parsers function correctly:

```powershell
# Run the core architecture & module unit tests
.\venv\Scripts\python.exe -m unittest tests/test_core_and_modules.py

# Run the v3 advanced security engines test suite
.\venv\Scripts\python.exe -m unittest tests/test_v3_engines.py
```

Expected output:
```
Ran 10 tests in 0.558s
OK

Ran 10 tests in 7.646s
OK
```

---

## 4. Optional External Tool Integrations

SENTRIX v3.0 operates autonomously using native Python engines for port scanning, banner grabbing, OSINT, PCAP analysis, and PE binary inspection. However, for advanced enterprise-grade engagements, SENTRIX seamlessly integrates with established industry tooling if installed on the host system.

SENTRIX automatically detects these tools and adjusts capabilities accordingly:

### 1. Nmap & Npcap (Raw Sockets & Stealth SYN Scans)
- **Role:** High-speed raw packet generation and advanced NSE script execution.
- **Installation:**
  1. Download the official installer from [nmap.org](https://nmap.org/download.html).
  2. During installation, select **Install Npcap**. Check the box: *"Install Npcap in WinPcap API-compatible Mode"*.
  3. Ensure `nmap.exe` is added to the Windows system `PATH`.
- **SENTRIX Status:** Automatically detected in `Operations -> Network & Recon` and `Tools -> External Tool Hub`.

### 2. Wireshark & TShark (Deep Packet Inspection)
- **Role:** Advanced protocol dissection and network traffic streaming.
- **Installation:**
  1. Download from [wireshark.org](https://www.wireshark.org/download.html).
  2. Install with default settings; ensure TShark command-line utility is included.
- **SENTRIX Status:** Detected by `modules/terminal/orchestrator.py` for automated packet dissection.

### 3. YARA (Malware Signature Matching)
- **Role:** High-performance pattern and rule matching on suspicious executables.
- **Installation:**
  - Place `yara64.exe` in `C:\Program Files\YARA\` or any directory in your system `PATH`.
- **SENTRIX Status:** Supported in `Offensive Lab -> Malware Sandbox & PE Analyzer`.

### 4. Hyper-V / VirtualBox / VMware (Dynamic Sandbox Orchestration)
- **Role:** Safe execution and automated snapshot reverting for live malware detonation.
- **Installation:**
  - **Hyper-V:** Enable via Windows Features (`Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`).
  - **VirtualBox:** Install VirtualBox and ensure `VBoxManage.exe` is in `PATH`.
- **SENTRIX Status:** Monitored and controlled via `modules/malware_sandbox/vm_orchestrator.py`.

---

## 5. Launching the Application

SENTRIX v3.0 supports two operational modes based on target engagement depth:

### Mode A: Standard User Mode (Daily Operations & Recon)
For passive reconnaissance, OSINT, web application vulnerability testing, offline PCAP forensics, PE header analysis, and report generation:
```powershell
.\venv\Scripts\python.exe main.py
```

### Mode B: Elevated Administrator Mode (Deep System & Raw Network Ops)
Required for raw socket captures, live promiscuous mode, Windows Event Log forensic extraction, and full USB hardware history:
1. Press `Win + X` and select **Terminal (Admin)** or **Windows PowerShell (Admin)**.
2. Navigate to the project folder and launch:
```powershell
cd C:\Users\<Username>\Desktop\Projelerim\SENTRIX
.\venv\Scripts\python.exe main.py
```
*The top-right status bar in SENTRIX will update its badge from `Standard User` to `Elevated Admin`.*

### Mode C: Legacy Sentinel v2 Interface Fallback
To run the previous SENTRIX v2 interface without losing any legacy features:
```powershell
.\venv\Scripts\python.exe main_legacy.py
```

---

## 6. Troubleshooting & FAQs

### Q1: The terminal shows `UnicodeEncodeError: 'charmap' codec can't encode character`
**Cause:** Windows command prompt or PowerShell with Turkish or non-UTF8 system codepage (e.g., `cp1254`).  
**Resolution:** SENTRIX v3.0 core engines use plain ASCII status markers (`[OK]`, `[FAIL]`, `[+]`, `[*]`) to prevent codepage crashes. Ensure you are running the latest v3.0 codebase.

### Q2: CustomTkinter window appears blurry or misaligned on high-DPI monitors (4K / 1440p)
**Cause:** Windows scaling factor set above 100%.  
**Resolution:** SENTRIX v3.0 automatically calls `ctypes.windll.shcore.SetProcessDpiAwareness(1)` at startup. If needed, you can right-click `python.exe`, select **Properties -> Compatibility -> Change high DPI settings**, and set DPI scaling to *Application*.

### Q3: Why does Port Scan report "Access Denied" on SYN Scan?
**Cause:** TCP SYN scans require raw network socket access, which is restricted to Administrator privileges on Windows and requires the Npcap driver.  
**Resolution:** Run PowerShell as Administrator and verify Npcap is installed. Alternatively, use standard **TCP Connect** mode, which works reliably under standard user accounts.

### Q4: Database locked error (`sqlite3.OperationalError: database is locked`)
**Cause:** Multiple processes writing to the SQLite database simultaneously.  
**Resolution:** SENTRIX v3.0 configures Write-Ahead Logging (`WAL`) mode and sets a busy timeout of 5000ms. If an old zombie process is holding the database, close any lingering instances using Task Manager or run:
```powershell
Stop-Process -Name python -Force
```
