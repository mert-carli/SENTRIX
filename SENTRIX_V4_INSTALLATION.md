# SENTRIX v4.0 — INSTALLATION & ENVIRONMENT SETUP GUIDE
## Professional Deployment, Virtual Environment Configuration & Tool Integration

**Platform:** Windows 10 / 11 (64-bit)  
**Target Runtime:** Python 3.9 - 3.12 (Verified on Python 3.11.9)  
**Architecture:** 64-bit Native Windows  

---

## 1. System Requirements

### Hardware Requirements
- **Processor:** Dual-core 2.0 GHz or higher (Quad-core recommended for multi-threaded port scanning and PCAP processing).
- **Memory (RAM):** Minimum 4 GB (8 GB+ recommended for analyzing large memory dumps and packet captures).
- **Disk Space:** 500 MB free space for core installation and dependencies. Additional space recommended for SQLite operational database (`data/sentrix.db`) and evidence files.
- **Display Resolution:** Minimum 1366x768 (1920x1080 Full HD recommended for optimal multi-pane command center view).

---

## 2. Step-by-Step Installation

### Step 1: Clone or Navigate to Project Directory
Open Windows PowerShell and navigate to the project directory:
```powershell
cd C:\Users\<YourUser>\Desktop\Projelerim\SENTRIX
```

### Step 2: Configure Virtual Environment
If not already created, set up an isolated virtual environment:
```powershell
# Create Python virtual environment
python -m venv venv

# If execution policy blocks local scripts, permit temporarily:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
Install all platform dependencies via `pip`:
```powershell
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## 3. Automated Integrity Verification

Before launching the user interface, verify that the database engine, cryptographic handlers, port scanners, and analysis parsers function correctly:

```powershell
.\venv\Scripts\python.exe -m unittest tests/test_core_and_modules.py tests/test_v3_engines.py tests/test_v4_advanced_engines.py
```

Expected output:
```
..............................
----------------------------------------------------------------------
Ran 30 tests in 9.029s

OK
```

---

## 4. Launching the Application

SENTRIX v4.0 supports two operational modes based on target engagement depth:

### Mode A: Standard User Mode (Default Daily Operations)
For network scanning, OSINT, web security, threat hunting, detection studio, and report compilation:
- **Direct GUI Launch:** Double-click the **`SENTRIX v4.0`** desktop shortcut, or run:
```powershell
.\venv\Scripts\pythonw.exe main.py
```
- **Console Mode (with Live Logs):**
```powershell
.\SENTRIX_DEBUG.bat
```

### Mode B: Elevated Administrator Mode (Deep System & Raw Network Ops)
Required for reading the Windows Security Event Log channel, executing raw SYN packet scans with Npcap, and accessing Windows Prefetch / SRUM forensic artifacts:
1. Press `Win + X` and select **Windows PowerShell (Admin)** or **Terminal (Admin)**.
2. Navigate to the project root and launch:
```powershell
cd C:\Users\<YourUser>\Desktop\Projelerim\SENTRIX
.\venv\Scripts\python.exe main.py
```
*(The top-right status bar in SENTRIX will update its badge from `[STANDARD USER]` to `[ELEVATED (ADMIN)]`.)*

### Mode C: Legacy Interface Fallback
To launch the previous v2/v3 legacy interfaces without losing any historical features:
```powershell
.\venv\Scripts\python.exe main_legacy.py
```
*(Offline backups remain safely preserved in `backup_v2/` and `backup_v3/`.)*
