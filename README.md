# NetworkOS: Advanced Security & Reconnaissance Dashboard

NetworkOS is a comprehensive, cyberpunk-themed network analysis and security reconnaissance tool. Built with Python and `customtkinter`, it serves as a central command dashboard for monitoring network health, hunting threats, and performing OSINT.

![Interface Screenshot](https://raw.githubusercontent.com/user/NetworkOS/main/assets/screenshot.png) *(You can add a screenshot here later)*

## Features

- **Diagnostic Tools**: Ping, Traceroute, NSLookup, HTTP/SSL validation, and Internet connectivity checks.
- **Wi-Fi Analyzer**: Scan and dump local Wi-Fi networks, view current active profiles, and perform BSSID/Auth analysis.
- **Reconnaissance (OSINT)**:
  - **Host Discovery**: Ping sweeps and latency checks.
  - **DNS Recon**: Retrieve A, AAAA, MX, and TXT records.
  - **Domain Info**: Perform WHOIS/RDAP lookups for IP geolocation and ISP info.
  - **Service Detection**: Perform banner grabbing on common ports.
  - **Route Analysis**: Visual trace routing to targets.
  - **Local Map**: ASCII-based topology generation using ARP data.
- **Threat Hunter**: 
  - Anomaly detection based on active connection baseline building.
  - ARP spoofing monitor.
  - Real-time connection matrix filters (SYN-SENT, ESTABLISHED).
- **Security Audit**: Scans Windows Temp and Downloads folders for potentially risky executables (`.exe`, `.dll`, `.bat`).
- **Export & Reports**: Export raw logs and generate automated Markdown (`.md`) security summary reports.
- **Multilingual Support**: Switch seamlessly between English and Turkish (TR/EN).

## Requirements

- **OS:** Windows (uses native tools like `netsh`, `wevtutil`, `tracert`, `arp`)
- **Python:** 3.8+
- **Libraries:** 
  - `customtkinter` (for the modern GUI)
  - `pillow` (for optional image handling in ctk)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NetworkOS.git
   cd NetworkOS
   ```
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the main application:
```bash
python main.py
```

*Note: Some features like advanced threat hunting and ARP monitoring may require running the application as an Administrator for full access to Windows networking APIs.*

## Disclaimer
This tool is designed for educational purposes, network administration, and authorized security auditing only. The developers are not responsible for any misuse.

## License
MIT License
