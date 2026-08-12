# Sentrix

Sentrix is an advanced network analysis and security reconnaissance application developed in Python. It provides a comprehensive command dashboard for network diagnostics, threat hunting, and open-source intelligence (OSINT). Designed with a dark, professional interface using the CustomTkinter library, Sentrix is tailored for network administrators, security auditors, and cybersecurity enthusiasts.

## Core Capabilities

### 1. Diagnostic Tools
Sentrix includes a robust set of tools for everyday network troubleshooting:
*   Ping and Traceroute for latency and routing path analysis.
*   NSLookup for domain name system resolution.
*   HTTP and SSL validation tools to check the security configuration of web services.
*   General internet connectivity checks to ensure baseline access.

### 2. Wi-Fi Analysis
The application offers detailed Wi-Fi scanning capabilities. It can discover local Wi-Fi networks, extract active network profiles, and perform in-depth analysis on BSSID (Basic Service Set Identifier) and authentication protocols.

### 3. Open-Source Intelligence (OSINT) and Reconnaissance
Sentrix automates information gathering processes:
*   **Host Discovery:** Perform ping sweeps to identify live hosts on the local network.
*   **DNS Reconnaissance:** Retrieve specific DNS records including A, AAAA, MX, and TXT records.
*   **Domain Information:** Execute WHOIS and RDAP lookups to determine IP geolocation and Internet Service Provider (ISP) details.
*   **Service Detection:** Perform banner grabbing on common ports to identify running services.
*   **Visual Topology:** Generate an ASCII-based local network map utilizing ARP data.

### 4. Threat Hunting
Proactive security features allow users to monitor their environment:
*   Build a baseline of active connections to detect anomalous network behavior.
*   Monitor for ARP spoofing attacks in real-time.
*   Filter connection matrices specifically for SYN-SENT and ESTABLISHED states to track active and pending connections.

### 5. Security Auditing
The tool scans sensitive local directories (such as the Windows Temp and Downloads folders) for potentially risky executables, including .exe, .dll, and .bat files, helping to identify unauthorized or suspicious software.

### 6. Reporting and Export
Sentrix provides the ability to export raw logs and automatically generate structured security summary reports in Markdown format, facilitating documentation and sharing of findings.

### 7. Localization
The interface fully supports seamless switching between English and Turkish languages.

## Technical Requirements

*   **Operating System:** Windows (relies on native Windows networking tools such as netsh, wevtutil, tracert, and arp).
*   **Python Version:** Python 3.8 or newer.
*   **Dependencies:**
    *   `customtkinter` (for the graphical user interface)
    *   `pillow` (for handling image assets)
    *   `psutil`
    *   `requests`

## Installation Instructions

1. Clone the repository to your local machine:
   git clone https://github.com/yourusername/Sentrix.git
   cd Sentrix

2. Install the required dependencies using pip:
   pip install -r requirements.txt

## Execution Instructions

To launch the Sentrix application, execute the following command in your terminal:

python main.py

Note: Certain advanced features, such as threat hunting and ARP monitoring, require full access to Windows networking APIs. It is highly recommended to run the application with Administrator privileges to utilize these features fully.

## Disclaimer

Sentrix is developed strictly for educational purposes, authorized network administration, and lawful security auditing. The developers assume no responsibility for any unauthorized or malicious use of this tool.

## License

This project is licensed under the MIT License.
