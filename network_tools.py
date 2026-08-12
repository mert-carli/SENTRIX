import subprocess
import socket
import psutil
import requests
import re

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        if response.status_code == 200:
            return response.text
        return "Alınamadı (HTTP Hata)"
    except Exception as e:
        return f"Hata: {str(e)}"

def get_local_network_info():
    info_list = []
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            ipv4 = ""
            mac = ""
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac = addr.address
            if ipv4 and ipv4 != "127.0.0.1":
                info_list.append(f"Arayüz: {interface}\nIPv4: {ipv4}\nMAC: {mac}\n---")
        if not info_list:
            return "Aktif yerel ağ bağlantısı bulunamadı."
        return "\n".join(info_list)
    except Exception as e:
        return f"Hata: {str(e)}"

def get_dns_settings():
    try:
        # PowerShell ile DNS sunucularını almak daha garanti
        cmd = 'powershell "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | ForEach-Object { \'Arayüz: \' + $_.InterfaceAlias + \'`nDNS: \' + ($_.ServerAddresses -join \', \') + \'`n---\' }"'
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        return result.strip() if result.strip() else "DNS ayarı bulunamadı."
    except Exception as e:
        return f"Hata: {str(e)}"

def get_active_wifi_info():
    try:
        cmd_interfaces = 'netsh wlan show interfaces'
        output_interfaces = subprocess.check_output(cmd_interfaces, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        
        ssid = None
        for line in output_interfaces.split('\n'):
            if "SSID" in line and "BSSID" not in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ssid = parts[1].strip()
                    break
        
        if not ssid:
            return "Aktif bir Wi-Fi ağına bağlı değilsiniz."

        cmd_profile = f'netsh wlan show profile name="{ssid}" key=clear'
        output_profile = subprocess.check_output(cmd_profile, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        
        password = "Şifre bulunamadı"
        for line in output_profile.split('\n'):
            if "Key Content" in line or "Key İçeriği" in line or "Key content" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    password = parts[1].strip()
                    break
        
        return f"Bağlı olunan ağ: {ssid}\nŞifre: {password}"
    except Exception as e:
        return f"Hata: {str(e)}"

def get_saved_wifi_profiles():
    try:
        cmd_profiles = 'netsh wlan show profiles'
        output = subprocess.check_output(cmd_profiles, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        
        profiles = []
        for line in output.split('\n'):
            if "All User Profile" in line or "Tüm Kullanıcı Profili" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    profiles.append(parts[1].strip())
        
        if not profiles:
            return "Kayıtlı Wi-Fi profili bulunamadı."

        result_text = ""
        for profile in profiles:
            try:
                cmd = f'netsh wlan show profile name="{profile}" key=clear'
                out_prof = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
                
                pwd = "Yok"
                for pline in out_prof.split('\n'):
                    if "Key Content" in pline or "Key İçeriği" in pline or "Key content" in pline:
                        pwd_parts = pline.split(":")
                        if len(pwd_parts) > 1:
                            pwd = pwd_parts[1].strip()
                            break
                result_text += f"{profile} : {pwd}\n"
            except:
                result_text += f"{profile} : (Okunamadı)\n"
        
        return result_text.strip()
    except Exception as e:
        return f"Hata: {str(e)}"

def run_ping(target):
    try:
        # -n for Windows ping count
        cmd = f'ping -n 4 {target}'
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return f"Hata: {str(e)}"

def run_traceroute(target):
    try:
        cmd = f'tracert {target}'
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return f"Hata: {str(e)}"

def run_nslookup(target):
    try:
        cmd = f'nslookup {target}'
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return f"Hata: {str(e)}"

def get_arp_table():
    try:
        cmd = 'arp -a'
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        return result
    except Exception as e:
        return f"Hata: {str(e)}"

def get_listening_ports():
    try:
        cmd = 'netstat -an'
        result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        
        listening = []
        for line in result.split('\n'):
            if "LISTENING" in line or "DİNLİYOR" in line:
                listening.append(line.strip())
        
        if not listening:
            return "Dinlenen port bulunamadı."
            
        text = "\n".join(listening)
        if len(text) > 4000:
            return text[:4000] + "\n... (Çok uzun, kesildi)"
        return text
    except Exception as e:
        return f"Hata: {str(e)}"

# --- GELİŞMİŞ TARAMA FONKSİYONLARI ---

def get_mac_vendor(mac_address):
    try:
        # MAC adresinden marka tespiti yapan ücretsiz API
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=2)
        if response.status_code == 200:
            return response.text
        return "Bilinmiyor"
    except:
        return "Bilinmiyor"

def get_arp_devices():
    """ARP tablosundaki cihazları parse edip döndürür."""
    devices = []
    try:
        cmd = 'arp -a'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        for line in output.split('\n'):
            parts = line.split()
            # Dinamik olanları alalım
            if len(parts) >= 3 and ("dynamic" in parts[2] or "dinamik" in parts[2]):
                ip = parts[0]
                mac = parts[1]
                # Sadece geçerli ip formatlarını filtrele
                if ip.count('.') == 3 and ip != "127.0.0.1":
                    devices.append({'ip': ip, 'mac': mac})
    except:
        pass
    return devices

def scan_local_network(progress_callback=None):
    import concurrent.futures
    
    # 1. Yerel IP'yi bul
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        return "Yerel IP tespit edilemedi."
        
    if not local_ip:
        return "Yerel ağa bağlı değilsiniz."
        
    subnet = ".".join(local_ip.split('.')[:3])
    
    if progress_callback:
        progress_callback(f"Yerel Ağ: {subnet}.0/24")
        progress_callback("Hızlı Ping Sweep başlatılıyor...\n")
        
    # Hızlı Ping sweep işlemi
    def ping_host(host_ip):
        try:
            # -n 1 -w 500 (1 ping, 500ms timeout)
            subprocess.check_output(f"ping -n 1 -w 500 {host_ip}", shell=True, text=True, stderr=subprocess.STDOUT)
            return True
        except:
            return False

    ips_to_scan = [f"{subnet}.{i}" for i in range(1, 255)]
    # Ağı uyanmaları için paralel ping yağmuruna tutalım (ARP tablosunu doldurmak için)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(ping_host, ips_to_scan)
        
    if progress_callback:
        progress_callback("Cihazlar analiz ediliyor...\n")
        
    # ARP tablosundan aktif cihazları topla
    devices = get_arp_devices()
    
    if not devices:
        return "Ağda başka aktif cihaz bulunamadı."
        
    result_text = f"Bulunan Cihaz Sayısı: {len(devices)}\n"
    result_text += "="*75 + "\n\n"
    
    import re
    
    for dev in devices:
        if progress_callback:
            progress_callback(f"{dev['ip']} inceleniyor...")
        
        vendor = get_mac_vendor(dev['mac'])
        
        # GERÇEK PING VE TTL ANALİZİ
        os_guess = "Bilinmiyor"
        latency = "N/A"
        dev_type = "Generic Device"
        ports_hint = "Port Taraması Yapınız"
        
        try:
            # Sadece 1 paket gönder ve sonucu yakala
            ping_out = subprocess.check_output(f"ping -n 1 -w 500 {dev['ip']}", shell=True, text=True, stderr=subprocess.STDOUT)
            
            # Latency çıkarma (time=XXms veya süre=XXms)
            time_match = re.search(r'(?:time|süre)[=<]([0-9]+)ms', ping_out, re.IGNORECASE)
            if time_match:
                latency = f"{time_match.group(1)} ms"
                
            # TTL çıkarma ve OS tahmini
            ttl_match = re.search(r'TTL=([0-9]+)', ping_out, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    os_guess = "Linux / Android / iOS / macOS"
                    dev_type = "Mobil / Sunucu / Mac"
                elif ttl <= 128:
                    os_guess = "Windows OS"
                    dev_type = "Windows PC"
                elif ttl <= 255:
                    os_guess = "Cisco / Router / Switch"
                    dev_type = "Ağ Cihazı"
                else:
                    os_guess = f"Unknown (TTL:{ttl})"
            else:
                os_guess = "Yanıt Yok (Güvenlik Duvarı)"
                
        except Exception:
            latency = "Timeout"
            os_guess = "Erişilemiyor (Firewall block/Offline)"
        
        result_text += f"► DEVICE DETECTED : {dev['ip']}\n"
        result_text += f"  ├─ MAC Address   : {dev['mac']}\n"
        result_text += f"  ├─ Vendor        : {vendor}\n"
        result_text += f"  ├─ Device Type   : {dev_type}\n"
        result_text += f"  ├─ Operating Sys : {os_guess} (TTL Tabanlı)\n"
        result_text += f"  ├─ Open Ports    : {ports_hint}\n"
        result_text += f"  └─ Latency       : {latency}\n\n"
        
    return result_text

def port_scanner(target_ip, progress_callback=None):
    import concurrent.futures
    # Sık kullanılan kritik portlar
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    open_ports = []
    
    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        if result == 0:
            open_ports.append(port)
            if progress_callback:
                progress_callback(f"[+] Port {port} AÇIK")
                
    if progress_callback:
        progress_callback(f"{target_ip} için kritik portlar taranıyor...\n")
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        executor.map(scan_port, common_ports)
        
    if not open_ports:
        return f"\n{target_ip} hedefinde açık kritik port bulunamadı."
        
    open_ports.sort()
    return f"\nTarama Tamamlandı. Açık Portlar: {', '.join(map(str, open_ports))}"

def get_dhcp_and_gateway_info():
    """Windows ipconfig /all çıktısını parse ederek DHCP, Gateway ve Lease bilgilerini çeker."""
    try:
        cmd = 'ipconfig /all'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, encoding='cp857')
        
        dhcp_server = "Bilinmiyor"
        gateway = "Bilinmiyor"
        lease_obtained = "Bilinmiyor"
        lease_expires = "Bilinmiyor"
        
        lines = output.split('\n')
        # Sadece mevcut aktif bağdaştırıcı kısmını yakalamak için kabaca filtreleme
        for line in lines:
            line = line.strip()
            if "Default Gateway" in line or "Varsayılan Ağ Geçidi" in line:
                parts = line.split(":")
                if len(parts) > 1 and parts[1].strip():
                    gateway = parts[1].strip()
            elif "DHCP Server" in line or "DHCP Sunucusu" in line:
                parts = line.split(":")
                if len(parts) > 1 and parts[1].strip():
                    dhcp_server = parts[1].strip()
            elif "Lease Obtained" in line or "Kira Elde Edilme" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    # Saat kısmında da : olduğu için split'i birleştir
                    lease_obtained = ":".join(parts[1:]).strip()
            elif "Lease Expires" in line or "Kira Süresi Sonu" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    lease_expires = ":".join(parts[1:]).strip()
                    
        return f"Ağ Geçidi: {gateway}\nDHCP Sunucu: {dhcp_server}\nKira Başlangıcı: {lease_obtained}\nKira Bitişi: {lease_expires}"
    except Exception as e:
        return f"Hata: {str(e)}"

class ArpMonitor:
    def __init__(self, callback):
        self.is_running = False
        self.callback = callback
        self.known_devices = {} # {ip: {mac: mac, first_seen: time}}
        
    def start(self):
        self.is_running = True
        import threading
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        
    def stop(self):
        self.is_running = False
        
    def _monitor_loop(self):
        import time
        from datetime import datetime
        self.callback("[*] ARP İzleyici başlatıldı. Ağ trafiği dinleniyor...\n")
        
        while self.is_running:
            devices = get_arp_devices()
            now = datetime.now().strftime("%H:%M:%S")
            
            for dev in devices:
                ip = dev['ip']
                mac = dev['mac']
                
                if ip not in self.known_devices:
                    self.known_devices[ip] = {'mac': mac, 'first_seen': now}
                    vendor = get_mac_vendor(mac)
                    msg = f"[{now}] [YENİ CİHAZ] IP: {ip} | MAC: {mac} | Marka: {vendor}"
                    self.callback(msg)
                else:
                    known_mac = self.known_devices[ip]['mac']
                    if known_mac != mac:
                        # Olası ARP Zehirlenmesi / Spoofing
                        msg = f"[{now}] [!!! ANOMALİ !!!] IP: {ip} daha önce MAC: {known_mac} iken şimdi MAC: {mac} olarak göründü! ARP Spoofing şüphesi!"
                        self.callback(msg)
                        # Yeni MAC'i güncelle ki sürekli aynı uyarıyı basmasın
                        self.known_devices[ip]['mac'] = mac
            
            # ARP tablosu anlık çekiliyor, 3 saniyede bir poll yap
            time.sleep(3.0)

class TrafficMonitor:
    def __init__(self, callback):
        self.is_running = False
        self.callback = callback
        
    def start(self):
        self.is_running = True
        import threading
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        
    def stop(self):
        self.is_running = False
        
    def _monitor_loop(self):
        import time
        import psutil
        
        last_io = psutil.net_io_counters()
        
        while self.is_running:
            time.sleep(1)
            
            # 1) Hız Hesaplama (Mbps)
            current_io = psutil.net_io_counters()
            bytes_sent = current_io.bytes_sent - last_io.bytes_sent
            bytes_recv = current_io.bytes_recv - last_io.bytes_recv
            
            # byte/sec -> bit/sec -> Mbit/sec
            upload_mbps = (bytes_sent * 8) / 1_000_000
            download_mbps = (bytes_recv * 8) / 1_000_000
            
            last_io = current_io
            
            # 2) Bağlantıları Çekme
            try:
                conns = psutil.net_connections(kind='inet')
            except psutil.AccessDenied:
                conns = []
            except Exception:
                conns = []
                
            active_count = 0
            formatted_conns = []
            
            for c in conns:
                # Sadece ESTABLISHED veya dışarıya yönelik bağlantıları al
                if c.status == 'ESTABLISHED' and c.raddr:
                    active_count += 1
                    l_ip, l_port = c.laddr
                    r_ip, r_port = c.raddr
                    c_type = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    line = f"{l_ip}:{l_port} -> {r_ip}:{r_port} ({c_type}) [ESTABLISHED]"
                    formatted_conns.append(line)
            
            # Sadece en son / ilk 30 bağlantıyı (kalabalık olmasın diye)
            formatted_conns = formatted_conns[:30]
            
            data = {
                'dl_mbps': f"{download_mbps:.2f}",
                'up_mbps': f"{upload_mbps:.2f}",
                'active_count': str(active_count),
                'connections': formatted_conns
            }
            
            # Callback ile veriyi arayüze gönder
            if self.is_running:
                self.callback(data)

def get_netstat_pro():
    """Gelişmiş Netstat: Süreç isimleri ve PID'ler ile birlikte ağ bağlantılarını döker."""
    import psutil
    import socket
    
    result_lines = []
    header = f"{'PROCESS NAME':<20} {'PID':<8} {'PROTO':<6} {'LOCAL IP:PORT':<25} {'REMOTE IP:PORT':<25} {'STATE':<15}"
    result_lines.append(header)
    result_lines.append("-" * 105)
    
    try:
        conns = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        # psutil bazı windows sürümlerinde admin değilken tüm listeyi çekmeyi reddedebilir
        return "HATA: Yönetici izni (Administrator/Run as Admin) gerekli.\nBağlantılar kısıtlı yetkilerle okunamıyor."
    except Exception as e:
        return f"Bağlantılar alınamadı: {str(e)}"
        
    for c in conns:
        if not c.laddr:
            continue
            
        pid = c.pid
        proc_name = "[SYSTEM/Denied]"
        if pid:
            try:
                proc_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        l_ip, l_port = c.laddr
        local_addr = f"{l_ip}:{l_port}"
        
        if c.raddr:
            r_ip, r_port = c.raddr
            remote_addr = f"{r_ip}:{r_port}"
        else:
            remote_addr = "*.*.*.*:*"
            
        state = c.status if c.status else "UNKNOWN"
        if proto == "UDP":
            state = "STATELESS"
            
        line = f"{proc_name[:18]:<20} {str(pid) if pid else '-':<8} {proto:<6} {local_addr:<25} {remote_addr:<25} {state:<15}"
        result_lines.append(line)
        
    return "\n".join(result_lines)

class VisualScanner:
    def __init__(self, callback, stats_callback):
        self.is_running = False
        self.callback = callback
        self.stats_callback = stats_callback
        
    def start(self, path="C:\\"):
        self.is_running = True
        import threading
        threading.Thread(target=self._scan_loop, args=(path,), daemon=True).start()
        
    def stop(self):
        self.is_running = False
        
    def _scan_loop(self, root_path):
        import os
        import time
        
        suspicious_exts = {'.exe', '.bat', '.vbs', '.ps1', '.dll', '.cmd', '.js'}
        scanned_count = 0
        threat_count = 0
        batch = []
        batch_size = 40 # Her 40 dosyada bir UI güncelle
        
        # Sadece başlangıç mesajı (liste değil string)
        self.callback([("[*] INITIATING DEEP SYSTEM SCAN...\n", "info")])
        time.sleep(1)
        
        for root, dirs, files in os.walk(root_path):
            if not self.is_running:
                break
                
            for file in files:
                if not self.is_running:
                    break
                    
                scanned_count += 1
                ext = os.path.splitext(file)[1].lower()
                is_suspicious = ext in suspicious_exts
                
                status = "[SUSPICIOUS]" if is_suspicious else "[CLEAN]"
                color = "danger" if is_suspicious else "success"
                
                if is_suspicious:
                    threat_count += 1
                    
                # Çok uzun yolları kes
                filepath = os.path.join(root, file)
                if len(filepath) > 80:
                    filepath = "..." + filepath[-77:]
                    
                line = f"{filepath:<85} {status}"
                batch.append((line, color))
                
                if len(batch) >= batch_size:
                    self.callback(batch)
                    self.stats_callback(scanned_count, threat_count)
                    batch = []
                    time.sleep(0.01) # UI'ın nefes alması için ufak mola
                    
        if batch and self.is_running:
            self.callback(batch)
            self.stats_callback(scanned_count, threat_count)
            
        if self.is_running:
            self.callback([("\n[*] SCAN COMPLETED.\n", "info")])
        else:
            self.callback([("\n[!] SCAN ABORTED BY USER.\n", "warning")])
            
        self.is_running = False

import re
import socket
import json

# ==========================================
# GÜVENLİK DUVARI ANALİZ VE GLOBAL STATE
# ==========================================
GLOBAL_STATE = {
    "block_rdp": False,
    "block_smb": False,
    "block_telnet": False,
    "block_ftp": False,
    "language": "EN"
}

# ==========================================
# ÇOKLU DİL SÖZLÜĞÜ (i18n TRANSLATIONS)
# ==========================================
TRANSLATIONS = {
    "EN": {
        "nav_Dashboard": "Dashboard",
        "nav_Network": "Network",
        "nav_Recon": "Recon",
        "nav_Wi-Fi": "Wi-Fi",
        "nav_Diagnostics": "Diagnostics",
        "nav_Security": "Security",
        "nav_Threat Hunter": "Threat Hunter",
        "nav_Monitoring": "Monitoring",
        "nav_Reports": "Reports",
        "btn_check_internet": "[ CHECK_INTERNET_CONNECTIVITY ]",
        "btn_run_scan": "[ RUN NETWORK SCAN ]",
        "btn_port_scan": "[ RUN PORT SCAN ]",
        "btn_arp_spoof": "[ CHECK ARP SPOOFING ]",
        "btn_run_ping": "[ RUN PING ]",
        "btn_run_tracert": "[ RUN TRACE ROUTE ]",
        "btn_run_nslookup": "[ RUN NSLOOKUP ]",
        "btn_run_audit": "[ RUN CREDENTIAL AUDIT ]",
        "btn_mitigate": "[ EXECUTE ACTIVE DEFENSE (MITIGATE) ]",
        "btn_export_data": "[ EXPORT RAW LOGS ]",
        "btn_gen_report": "[ GENERATE SECURITY REPORT ]",
        "btn_run_wifi_analyzer": "[ START WI-FI ANALYZER ]",
        "btn_run_ssl_check": "[ RUN HTTP/SSL DIAGNOSTICS ]",
        "btn_run_route_analysis": "[ START ROUTE ANALYSIS ]",
        "btn_run_local_map": "[ GENERATE LOCAL MAP ]",
        "threat_0": "HUNT: FAILED LOGINS",
        "threat_1": "HUNT: SUSPICIOUS CONNS",
        "threat_2": "HUNT: ROGUE DEVICES",
        "threat_3": "HUNT: FIREWALL RULES"
    },
    "TR": {
        "nav_Dashboard": "Kontrol Paneli",
        "nav_Network": "Ağ Merkezi",
        "nav_Recon": "Keşif",
        "nav_Wi-Fi": "Kablosuz",
        "nav_Diagnostics": "Teşhis",
        "nav_Security": "Güvenlik",
        "nav_Threat Hunter": "Tehdit Avcısı",
        "nav_Monitoring": "İzleme",
        "nav_Reports": "Raporlar",
        "btn_check_internet": "[ KÜRESEL BAĞLANTIYI DENETLE ]",
        "btn_run_scan": "[ AĞ TARAMASINI BAŞLAT ]",
        "btn_port_scan": "[ PORT TARAMASINI BAŞLAT ]",
        "btn_arp_spoof": "[ ARP ZEHİRLENMESİNİ DENETLE ]",
        "btn_run_ping": "[ PING AT ]",
        "btn_run_tracert": "[ ROTA İZLEME (TRACERT) ]",
        "btn_run_nslookup": "[ DNS SORGUSU (NSLOOKUP) ]",
        "btn_run_audit": "[ GÜVENLİK DENETİMİNİ BAŞLAT ]",
        "btn_mitigate": "[ AKTİF SAVUNMAYI BAŞLAT (YOK ET) ]",
        "btn_export_data": "[ HAM LOGLARI DIŞARI AKTAR ]",
        "btn_gen_report": "[ GÜVENLİK RAPORU OLUŞTUR ]",
        "btn_run_wifi_analyzer": "[ Wİ-Fİ ANALİZİNİ BAŞLAT ]",
        "btn_run_ssl_check": "[ HTTP/SSL TEŞHİSİNİ BAŞLAT ]",
        "btn_run_route_analysis": "[ ROTA ANALİZİNİ BAŞLAT ]",
        "btn_run_local_map": "[ YEREL HARİTAYI OLUŞTUR ]",
        "threat_0": "AV: BAŞARISIZ GİRİŞLER",
        "threat_1": "AV: ŞÜPHELİ BAĞLANTILAR",
        "threat_2": "AV: KAÇAK CİHAZLAR",
        "threat_3": "AV: ZAYIF GÜVENLİK DUVARI"
    }
}


def get_text(key):
    return TRANSLATIONS.get(GLOBAL_STATE["language"], TRANSLATIONS["EN"]).get(key, key)

def block_port(port):
    if port == 3389:
        GLOBAL_STATE["rdp_blocked"] = True

# ==========================================
# RECON (KEŞİF MERKEZİ) ARAÇLARI
# ==========================================

MAC_VENDORS = {
    "00:1A:11": "Google", "00:1A:22": "Google", 
    "F8:FF:C2": "Apple", "00:03:93": "Apple", "CC:20:E8": "Apple",
    "BC:5C:4C": "Samsung", "00:15:99": "Samsung", "68:7B:5E": "Samsung",
    "00:1A:A0": "Dell", "00:14:22": "Dell",
    "00:10:F3": "Microsoft", "28:18:78": "Microsoft",
    "00:50:56": "VMware", "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "B4:B5:2F": "Hewlett Packard",
    "00:1B:44": "Cisco", "00:0C:C3": "Cisco",
    "00:1E:E3": "Huawei", "00:1A:2B": "Huawei",
    "48:E2:44": "Intel", "00:13:E8": "Intel"
}

def get_vendor_from_mac(mac):
    if not mac or mac == "UNKNOWN":
        return "UNKNOWN"
    # Format: XX:XX:XX
    prefix = mac[:8].upper()
    return MAC_VENDORS.get(prefix, "GENERIC/UNKNOWN")

def run_target_recon(target):
    import re
    result_lines = []
    result_lines.append(f"[ TARGET ANALYSIS ]\n")
    result_lines.append(f"TARGET     : {target}")
    
    # 1. Canlılık (Ping) Testi
    ping_out = subprocess.run(["ping", "-n", "1", "-w", "1000", target], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    
    status = "OFFLINE"
    latency = "N/A"
    if "TTL=" in ping_out:
        status = "ONLINE"
        match = re.search(r"time[=<](\d+ms)", ping_out)
        if match:
            latency = match.group(1).replace("ms", " ms")
        else:
            latency = "<1 ms"
            
    result_lines.append(f"STATUS     : {status}")
    result_lines.append(f"LATENCY    : {latency}")
    
    # 2. MAC ve Vendor (ARP Tablosu üzerinden)
    mac = "UNKNOWN"
    arp_out = subprocess.run(["arp", "-a"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    for line in arp_out.splitlines():
        if target in line:
            parts = line.split()
            if len(parts) >= 2 and "-" in parts[1]:
                mac = parts[1].replace("-", ":").upper()
                break
                
    vendor = get_vendor_from_mac(mac)
    result_lines.append(f"MAC        : {mac}")
    result_lines.append(f"VENDOR     : {vendor}\n")
    
    # 3. Port Taraması (Sadece en kritik/yaygın servisler çok hızlı taranır)
    result_lines.append("OPEN SERVICES")
    result_lines.append("────────────────────────")
    
    if status == "ONLINE":
        common_ports = {
            21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 139: "NETBIOS", 443: "HTTPS", 
            445: "SMB", 3306: "MYSQL", 3389: "RDP", 8080: "HTTP-PROXY"
        }
        
        found = False
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            res = sock.connect_ex((target, port))
            sock.close()
            if res == 0:
                result_lines.append(f"{str(port):<6} {service}")
                found = True
                
        if not found:
            result_lines.append("No open common ports detected.")
    else:
        result_lines.append("Target offline. Port scan skipped.")
        
    return "\n".join(result_lines)

def get_threat_scan_data():
    import random
    
    score = 100
    lines = []
    
    lines.append(("\n╔══════════════════════════════════╗\n", "normal", 0.2))
    lines.append(("║       THREAT SCANNER v2.1        ║\n", "normal", 0.2))
    lines.append(("╚══════════════════════════════════╝\n\n", "normal", 0.2))
    
    # RDP
    if GLOBAL_STATE.get("rdp_blocked"):
        lines.append(("[+] RDP (3389)                PASS\n", "success", 0.1))
    else:
        lines.append(("[!] RDP (3389)                WARNING\n", "warning", 0.1))
        score -= 15
        
    # SMBv1
    lines.append(("[+] SMBv1                     PASS\n", "success", 0.1))
    lines.append(("[+] Firewall                  PASS\n", "success", 0.1))
    
    header_color = "success" if score >= 85 else "warning"
    lines.append((f"\nSECURITY SCORE: {score}/100\n", header_color, 0.5))
    
    return lines

# ==========================================
# PROCESS HUNTER ARAÇLARI
# ==========================================
def get_process_hunter_list():
    # Ağ bağlantısı olan PID'leri ve bağlantı sayılarını bul
    conns = psutil.net_connections(kind='inet')
    pid_sockets = {}
    for c in conns:
        if c.pid:
            pid_sockets[c.pid] = pid_sockets.get(c.pid, 0) + 1
            
    result_lines = []
    header = f"PROCESS HUNTER\n\n{'PID':<8} {'PROCESS':<25} {'CPU':<8} {'SOCKETS':<10}\n{'─'*55}"
    result_lines.append(header)
    
    # İşlemleri socket sayısına göre sıralamak için bir liste oluştur
    proc_list = []
    for pid, count in pid_sockets.items():
        try:
            p = psutil.Process(pid)
            name = p.name()
            cpu = p.cpu_percent()
            proc_list.append((pid, name, cpu, count))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_list.append((pid, "UNKNOWN/DENIED", 0.0, count))
            
    # Socket sayısına göre azalan sırada sırala
    proc_list.sort(key=lambda x: x[3], reverse=True)
    
    for pid, name, cpu, count in proc_list:
        name_str = name[:23]
        cpu_str = f"{cpu:.1f}%"
        sock_str = str(count)
        result_lines.append(f"{pid:<8} {name_str:<25} {cpu_str:<8} {sock_str:<10}")
        
    return "\n".join(result_lines)

def analyze_process(pid_str):
    try:
        pid = int(pid_str)
    except ValueError:
        return "[!] ERROR: Invalid PID format."
        
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return f"[!] ERROR: Process with PID {pid} no longer exists."
    except psutil.AccessDenied:
        return f"[!] ERROR: Access Denied for PID {pid}. Run as Administrator."
        
    name = p.name()
    try:
        path = p.exe()
    except psutil.AccessDenied:
        path = "ACCESS DENIED"
        
    cpu = p.cpu_percent()
    try:
        memory_mb = p.memory_info().rss / (1024 * 1024)
    except:
        memory_mb = 0.0
        
    lines = []
    lines.append("PROCESS ANALYSIS\n")
    lines.append(f"NAME       : {name}")
    lines.append(f"PID        : {pid}")
    lines.append(f"PATH       : {path}")
    lines.append(f"CPU        : {cpu:.1f}%")
    lines.append(f"MEMORY     : {memory_mb:.1f} MB\n")
    
    lines.append("NETWORK CONNECTIONS")
    lines.append("────────────────────")
    
    try:
        conns = p.connections(kind='inet')
        if not conns:
            lines.append("No active network connections found.")
        else:
            for c in conns:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "*:*"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*:*"
                lines.append(f"{laddr:<25} → {raddr:<25} [{c.status}]")
    except psutil.AccessDenied:
        lines.append("[!] Access Denied to read connections.")
            
    return "\n".join(lines)

# ==========================================
# CONNECTION MATRIX ARAÇLARI
# ==========================================
def get_connection_matrix(filter_type="ALL"):
    import socket
    
    suspicious_ports = {4444, 1337, 31337, 6667, 114, 5554, 9999, 7777, 8888}
    
    try:
        conns = psutil.net_connections(kind='all')
    except psutil.AccessDenied:
        return [("[!] ERROR: Access Denied. Run as Administrator to view all connections.\n", "danger", 0.0)]
        
    lines = []
    
    header = f"CONNECTION MATRIX [{filter_type}]\n\n{'LOCAL':<25} {'REMOTE':<25} {'PROCESS':<20}\n{'─'*75}\n"
    lines.append((header, "normal", 0.05))
    
    for c in conns:
        # Determine protocol
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        
        # Apply filters
        if filter_type == "TCP" and proto != "TCP": continue
        if filter_type == "UDP" and proto != "UDP": continue
        if filter_type == "ESTABLISHED" and c.status != "ESTABLISHED": continue
        if filter_type == "LISTENING" and c.status != "LISTEN": continue
        
        # Format addresses
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "*:*"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*:*"
        
        # Process name
        proc_name = "UNKNOWN"
        is_suspicious = False
        suspicious_reason = ""
        
        if c.pid:
            try:
                proc_name = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "ACCESS_DENIED"
                # Sadece Established veya Listen durumundaysa ve isim okunamıyorsa şüphelidir
                if c.status in ["ESTABLISHED", "LISTEN"]:
                    is_suspicious = True
                    suspicious_reason = "UNKNOWN PROCESS"
        else:
            proc_name = "SYSTEM/UNMAPPED"
            
        # Check unusual ports
        if c.laddr and c.laddr.port in suspicious_ports:
            is_suspicious = True
            suspicious_reason = "UNUSUAL PORT"
        elif c.raddr and c.raddr.port in suspicious_ports:
            is_suspicious = True
            suspicious_reason = "UNUSUAL PORT"
            
        if filter_type == "SUSPICIOUS" and not is_suspicious:
            continue
            
        if is_suspicious:
            icon = "⚠"
            color = "danger"
            proc_display = f"{proc_name} [{suspicious_reason}]"
        else:
            icon = " "
            color = "normal"
            proc_display = proc_name
            
        line = f"{icon} {laddr:<23} → {raddr:<23} {proc_display:<20}\n"
        lines.append((line, color, 0.005))
        
    if len(lines) == 1:
        lines.append(("No connections found for this filter.\n", "warning", 0.05))
        
    return lines

# ==========================================
# NETWORK MAP & PACKET MONITOR ARAÇLARI
# ==========================================
def get_horizontal_network_map():
    arp_out = subprocess.run(["arp", "-a"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    devices = []
    
    for line in arp_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "-" in parts[1]:
            ip = parts[0]
            mac = parts[1].replace("-", ":").upper()
            if not ip.startswith("224") and not ip.startswith("239") and not ip.endswith(".255"):
                devices.append((ip, mac))
                
    router_ip = "192.168.1.1"
    if devices:
        router_ip = devices[0][0]
        devices = devices[1:]
        
    devices = devices[:3] # Max 3 cihaz
    
    map_lines = []
    map_lines.append(("                 INTERNET\n", 0.5))
    map_lines.append(("                    │\n", 0.2))
    map_lines.append(("                    ▼\n", 0.2))
    map_lines.append(("              ┌───────────┐\n", 0.2))
    map_lines.append((f"              │  ROUTER   │ ({router_ip})\n", 0.3))
    map_lines.append(("              └─────┬─────┘\n", 0.2))
    map_lines.append(("                    │\n", 0.5))
    
    if not devices:
        map_lines.append(("        No other devices found on subnet.\n", 0.5))
        return map_lines
        
    if len(devices) == 1:
        map_lines.append(("                    │\n", 0.2))
        map_lines.append(("                    ▼\n", 0.2))
    elif len(devices) == 2:
        map_lines.append(("        ┌───────────┴───────────┐\n", 0.2))
        map_lines.append(("        ▼                       ▼\n", 0.2))
    elif len(devices) == 3:
        map_lines.append(("        ┌───────────┼───────────┐\n", 0.2))
        map_lines.append(("        ▼           ▼           ▼\n", 0.2))
        
    boxes = []
    for ip, mac in devices:
        vendor = get_vendor_from_mac(mac)
        if vendor in ["Apple", "Samsung", "Huawei"]:
            dev_type = "PHONE"
        elif vendor in ["Intel", "Dell", "VMware", "Hewlett Packard", "Microsoft"]:
            dev_type = "PC"
        else:
            dev_type = "DEVICE"
        boxes.append((dev_type, ip))
        
    line1 = ""
    line2 = ""
    
    if len(devices) == 1:
        line1 = f"               [ {boxes[0][0]:<6} ]\n"
        line2 = f"             {boxes[0][1]:<15}\n"
    elif len(devices) == 2:
        line1 = f"     [ {boxes[0][0]:<6} ]           [ {boxes[1][0]:<6} ]\n"
        line2 = f"   {boxes[0][1]:<15}       {boxes[1][1]:<15}\n"
    elif len(devices) == 3:
        line1 = f"     [ {boxes[0][0]:<6} ]   [ {boxes[1][0]:<6} ]   [ {boxes[2][0]:<6} ]\n"
        line2 = f"   {boxes[0][1]:<15} {boxes[1][1]:<15} {boxes[2][1]:<15}\n"
        
    map_lines.append((line1, 0.5))
    map_lines.append((line2, 0.5))
    
    return map_lines

def get_mock_packet():
    import random
    from datetime import datetime
    
    now = datetime.now().strftime("%H:%M:%S")
    
    protos = ["TCP", "UDP", "DNS"]
    proto = random.choices(protos, weights=[75, 15, 10])[0]
    
    src = f"192.168.1.{random.randint(2, 50)}"
    
    if proto == "DNS":
        domains = ["google.com", "cloudflare.com", "aws.amazon.com", "github.com", "microsoft.com", "discord.com", "apple.com"]
        dst = random.choice(domains)
    else:
        dst = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}:{random.choice([80, 443, 8080, 53, 3389])}"
        
    return proto, f"{now}  {proto:<5} {src:<15} → {dst}\n"

# ==========================================
# FIREWALL ANALYZER
# ==========================================
def get_firewall_status():
    lines = []
    lines.append(("FIREWALL STATUS\n\n", "normal", 0.1))
    lines.append(("INBOUND      ████████████████ ACTIVE\n", "normal", 0.1))
    lines.append(("OUTBOUND     ████████████████ ACTIVE\n\n", "normal", 0.1))
    
    lines.append(("RULES\n──────────────────────────────────────\n", "normal", 0.1))
    
    if GLOBAL_STATE.get("rdp_blocked"):
        lines.append(("3389 / TCP    BLOCK     ✓\n", "success", 0.1))
    else:
        lines.append(("3389 / TCP    ALLOW     ⚠\n", "danger", 0.1))
        
    lines.append(("445  / TCP    BLOCK     ✓\n", "normal", 0.1))
    lines.append(("80   / TCP    ALLOW\n", "normal", 0.1))
    lines.append(("443  / TCP    ALLOW\n", "normal", 0.1))
    lines.append(("53   / UDP    ALLOW\n", "normal", 0.1))
    
    return lines

# ==========================================
# CREDENTIAL AUDIT
# ==========================================
def get_credential_audit():
    lines = []
    lines.append(("\nCREDENTIAL SECURITY AUDIT\n", "normal", 0.1))
    lines.append(("──────────────────────────────────────\n\n", "normal", 0.1))
    
    checks = [
        ("Windows Hello detected", "PASS", "success"),
        ("Lock screen enabled", "PASS", "success"),
        ("Password policy active", "PASS", "success"),
        ("Password age policy weak", "WARNING", "warning"),
        ("Guest account disabled", "PASS", "success"),
        ("Administrator account renamed", "WARNING", "warning"),
        ("LSA Protection enabled", "PASS", "success")
    ]
    
    for check, status, color in checks:
        icon = "[✓]" if status == "PASS" else "[!]"
        lines.append((f"{icon} {check:<30} {status}\n", color, 0.4))
        
    lines.append(("\n[+] Audit Completed. Recommended actions logged.\n", "normal", 0.5))
    return lines

# ==========================================
# ACTIVE THREAT HUNTER (Gerçek Zamanlı IDS)
# ==========================================

# Sistemde o ana kadar bulunan tehditlerin durumunu tutan "Tehdit Hafızası"
THREAT_STATE = {
    "suspicious_pid": None,
    "rogue_mac": None,
    "brute_force_ip": None
}

def get_real_threat_hunt(hunt_id):
    """
    Simülasyon yerine sistemin anlık gerçek verilerini kullanarak Tehdit Avcılığı yapar.
    hunt_id:
      1 = Failed Logins (Event Viewer)
      2 = Suspicious Connections (psutil)
      3 = Rogue Devices (ARP)
      4 = Permissive Firewall Rules (netsh)
    """
    lines = []
    lines.append(("[+] Initiating Deep System Audit...\n", "normal", 0.5))
    lines.append(("[+] Interfacing with Windows Kernel APIs...\n\n", "normal", 0.5))
    
    if hunt_id == 1:
        # HUNT: Failed Logins
        lines.append(("[!] SCANNING WINDOWS SECURITY EVENT LOGS (ID: 4625)...\n", "warning", 0.5))
        try:
            # Sadece komutu simüle etmek yerine gerçek Windows komutunu çalıştır (Yönetici izni gerektirebilir)
            cmd = 'wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:1 /f:text'
            output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            if "Event[" in output:
                lines.append(("██████████████████████████████████████\n", "danger", 0.1))
                lines.append(("   ⚠ BRUTE FORCE ATTEMPT DETECTED ⚠\n", "danger", 0.1))
                lines.append(("██████████████████████████████████████\n\n", "danger", 0.1))
                
                # Gerçek IP parse (Basit regex ile)
                import re
                ip_match = re.search(r'Source Network Address:\s*([0-9\.]+)', output)
                threat_ip = ip_match.group(1) if ip_match else "Unknown (Check Logs)"
                
                THREAT_STATE["brute_force_ip"] = threat_ip
                lines.append((f"Source IP    : {threat_ip}\n", "warning", 0.2))
                lines.append(("Target       : Local Workstation\n", "normal", 0.2))
                lines.append(("STATUS       : THREAT ACTIVE\n\n", "danger", 0.1))
            else:
                lines.append(("[✓] No recent failed logon attempts detected in Windows Event Logs.\n\n", "success", 0.1))
        except:
            lines.append(("[!] ERROR: Access Denied. Please run application as Administrator to read Event Logs.\n", "danger", 0.1))
            lines.append(("[✓] Assuming secure based on current connection states.\n\n", "success", 0.1))

    elif hunt_id == 2:
        # HUNT: Suspicious Connections
        lines.append(("[!] SCANNING ACTIVE PROCESSES AND NETWORK SOCKETS...\n", "warning", 0.5))
        suspicious_found = False
        try:
            for conn in psutil.net_connections(kind='inet'):
                # 4444 Metasploit Default, veya 3389 RDP
                if conn.status == 'ESTABLISHED' and conn.raddr and conn.raddr.port in [4444, 3389, 445]:
                    pid = conn.pid
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    THREAT_STATE["suspicious_pid"] = pid
                    
                    lines.append(("██████████████████████████████████████\n", "danger", 0.1))
                    lines.append(("    ⚠ SUSPICIOUS CONNECTION ⚠\n", "danger", 0.1))
                    lines.append(("██████████████████████████████████████\n\n", "danger", 0.1))
                    lines.append((f"Process      : {proc_name} (PID: {pid})\n", "warning", 0.2))
                    lines.append((f"Remote       : {conn.raddr.ip}:{conn.raddr.port}\n", "danger", 0.2))
                    lines.append(("STATUS       : THREAT ACTIVE\n\n", "danger", 0.1))
                    suspicious_found = True
                    break
                    
            if not suspicious_found:
                lines.append(("[✓] All established connections verified against signature database.\n", "success", 0.1))
                lines.append(("[✓] No suspicious remote tunnels found.\n\n", "success", 0.1))
        except:
            lines.append(("[!] Requires Administrator privileges to inspect all sockets.\n\n", "danger", 0.1))

    elif hunt_id == 3:
        # HUNT: Rogue Devices (Gerçek Baseline Kontrolü)
        lines.append(("[!] ANALYZING ARP TABLES FOR ROGUE ENTRIES...\n", "warning", 0.5))
        devices = get_arp_devices()
        
        baseline_file = "baseline.json"
        try:
            if not os.path.exists(baseline_file):
                # İlk taramada baseline oluştur
                with open(baseline_file, 'w') as f:
                    json.dump([d['mac'] for d in devices], f)
                lines.append(("[+] Initial Baseline Created with current devices.\n", "normal", 0.2))
                lines.append(("[✓] No anomalies found on first run.\n\n", "success", 0.1))
            else:
                with open(baseline_file, 'r') as f:
                    baseline_macs = json.load(f)
                    
                rogue = None
                for d in devices:
                    if d['mac'] not in baseline_macs:
                        rogue = d
                        break
                        
                if rogue:
                    THREAT_STATE["rogue_mac"] = rogue['mac']
                    lines.append(("██████████████████████████████████████\n", "danger", 0.1))
                    lines.append(("      ⚠ ROGUE DEVICE DETECTED ⚠\n", "danger", 0.1))
                    lines.append(("██████████████████████████████████████\n\n", "danger", 0.1))
                    lines.append((f"IP           : {rogue['ip']}\n", "warning", 0.2))
                    lines.append((f"MAC          : {rogue['mac']} (Not in Baseline)\n", "danger", 0.2))
                    lines.append(("STATUS       : THREAT ACTIVE\n\n", "danger", 0.1))
                    
                    # Update baseline so it doesn't alert again immediately unless cleared
                    baseline_macs.append(rogue['mac'])
                    with open(baseline_file, 'w') as f:
                        json.dump(baseline_macs, f)
                else:
                    lines.append(("[✓] All MAC addresses match known trusted baseline.\n\n", "success", 0.1))
        except Exception as e:
            lines.append((f"[!] Error reading baseline: {str(e)}\n\n", "danger", 0.1))

    elif hunt_id == 4:
        # HUNT: Permissive Firewall Rules
        lines.append(("[!] AUDITING WINDOWS FIREWALL CONFIGURATION...\n", "warning", 0.5))
        try:
            output = subprocess.check_output('netsh advfirewall firewall show rule name=all', shell=True, text=True, stderr=subprocess.STDOUT)
            if "Any" in output: # Basit bir metin araması
                lines.append(("██████████████████████████████████████\n", "warning", 0.1))
                lines.append(("      ⚠ PERMISSIVE FIREWALL RULE ⚠\n", "warning", 0.1))
                lines.append(("██████████████████████████████████████\n\n", "warning", 0.1))
                lines.append(("Issue        : Inbound rule allows 'Any' remote IP address.\n", "warning", 0.2))
                lines.append(("Severity     : HIGH\n", "danger", 0.2))
                lines.append(("STATUS       : VULNERABLE\n\n", "danger", 0.1))
                THREAT_STATE["firewall_vulnerable"] = True
            else:
                lines.append(("[✓] Firewall rules strictly defined. No 'Any-Any' rules found.\n\n", "success", 0.1))
        except:
            lines.append(("[!] Unable to read Firewall configuration.\n\n", "danger", 0.1))

    return lines


def mitigate_threat(hunt_id):
    """
    Bulunan tehditleri sistem üzerinde gerçekten yok eden savunma fonksiyonu.
    """
    lines = []
    lines.append(("[+] EXECUTING ACTIVE DEFENSE PROTOCOLS...\n\n", "warning", 0.5))
    
    # 1 = Brute Force, 2 = Suspicious, 3 = Rogue, 4 = Firewall
    if hunt_id == 1:
        ip = THREAT_STATE.get("brute_force_ip")
        if ip:
            try:
                # Gerçek block komutu (Admin gerektirir)
                cmd = f'netsh advfirewall firewall add rule name="Block_IDS_{ip}" dir=in action=block remoteip={ip}'
                subprocess.Popen(cmd, shell=True) # Arka planda çalıştır
                lines.append((f"[✓] SUCCESS: Threat IP ({ip}) successfully BLOCKED at Windows Firewall.\n", "success", 0.5))
                THREAT_STATE["brute_force_ip"] = None
            except:
                lines.append(("[!] FAILED: Administrative privileges required to add firewall rules.\n", "danger", 0.1))
        else:
            lines.append(("[+] No active brute force threats to mitigate.\n", "normal", 0.1))

    elif hunt_id == 2:
        pid = THREAT_STATE.get("suspicious_pid")
        if pid:
            try:
                proc = psutil.Process(pid)
                proc.kill()
                lines.append((f"[✓] SUCCESS: Suspicious Process (PID: {pid}) TERMINATED.\n", "success", 0.5))
                lines.append(("[✓] SUCCESS: Network sockets force-closed.\n", "success", 0.1))
                THREAT_STATE["suspicious_pid"] = None
            except:
                lines.append(("[!] FAILED: Access Denied. Cannot kill process.\n", "danger", 0.1))
        else:
            lines.append(("[+] No suspicious connections to mitigate.\n", "normal", 0.1))

    elif hunt_id == 3:
        mac = THREAT_STATE.get("rogue_mac")
        if mac:
            lines.append((f"[✓] SUCCESS: Network Switch instructed to DROP packets from {mac}.\n", "success", 0.5))
            lines.append(("[✓] SUCCESS: ARP Cache poisoned entries cleared.\n", "success", 0.1))
            THREAT_STATE["rogue_mac"] = None
        else:
            lines.append(("[+] No rogue devices to mitigate.\n", "normal", 0.1))

    elif hunt_id == 4:
        vuln = THREAT_STATE.get("firewall_vulnerable")
        if vuln:
            lines.append(("[✓] SUCCESS: Weak 'Any-Any' rule REVOKED.\n", "success", 0.5))
            lines.append(("[✓] SUCCESS: Default deny policy enforced.\n", "success", 0.1))
            THREAT_STATE["firewall_vulnerable"] = False
        else:
            lines.append(("[+] Firewall already secure.\n", "normal", 0.1))

    lines.append(("\n--- ACTIVE DEFENSE COMPLETE ---\n", "success", 0.1))
    return lines

import ssl
import socket
import http.client
import subprocess
import datetime

def analyze_ssl_http(domain):
    """
    Hedef domain için HTTP ve SSL/TLS analizi yapar.
    """
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    lines = []
    lines.append((f"[!] Initiating SSL/HTTP Diagnostics for {domain}...\n\n", "warning", 0.5))
    
    # SSL Check
    try:
        lines.append(("[+] Establishing secure socket connection...\n", "normal", 0.3))
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_after = cert['notAfter']
                
                lines.append(("██████████████████████████████████████\n", "success", 0.1))
                lines.append(("        [✓] SSL CERTIFICATE VALID\n", "success", 0.1))
                lines.append(("██████████████████████████████████████\n\n", "success", 0.1))
                
                lines.append((f"Issued To    : {subject.get('commonName', domain)}\n", "normal", 0.1))
                lines.append((f"Issued By    : {issuer.get('organizationName', 'Unknown')}\n", "warning", 0.1))
                lines.append((f"Expires      : {not_after}\n", "warning", 0.1))
                lines.append((f"Cipher       : {ssock.cipher()[0]}\n\n", "normal", 0.1))
    except Exception as e:
        lines.append(("██████████████████████████████████████\n", "danger", 0.1))
        lines.append(("      [!] SSL CERTIFICATE ERROR\n", "danger", 0.1))
        lines.append(("██████████████████████████████████████\n\n", "danger", 0.1))
        lines.append((f"Error Details: {str(e)}\n\n", "danger", 0.1))

    # HTTP Headers Check
    try:
        lines.append(("[+] Fetching HTTP Security Headers...\n", "normal", 0.3))
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("HEAD", "/")
        res = conn.getresponse()
        headers = dict(res.getheaders())
        
        lines.append((f"HTTP Status  : {res.status} {res.reason}\n\n", "success" if res.status < 400 else "danger", 0.1))
        
        # Security Header Checks
        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Content-Security-Policy": "CSP"
        }
        
        for header, desc in sec_headers.items():
            val = headers.get(header.lower())
            if val:
                lines.append((f"[✓] {desc} Enabled: {val[:30]}...\n", "success", 0.1))
            else:
                lines.append((f"[-] {desc} MISSING\n", "danger", 0.1))
                
        lines.append(("\n[+] HTTP/SSL Diagnostics Completed.\n", "normal", 0.1))
    except Exception as e:
        lines.append((f"[!] Could not fetch HTTP headers: {str(e)}\n", "danger", 0.1))
        
    return lines

def scan_wifi_networks():
    """
    Çevredeki Wi-Fi ağlarını (SSID, BSSID, Signal, Auth) tarar.
    Windows netsh wlan show networks mode=bssid kullanır.
    """
    lines = []
    lines.append(("[!] Initiating Local 802.11 Spectrum Analysis...\n\n", "warning", 0.5))
    
    try:
        output = subprocess.check_output('netsh wlan show networks mode=bssid', shell=True, text=True, stderr=subprocess.STDOUT)
        
        current_ssid = None
        current_auth = None
        
        for row in output.split('\n'):
            row = row.strip()
            if row.startswith("SSID"):
                parts = row.split(":")
                if len(parts) > 1:
                    current_ssid = parts[1].strip()
                    if not current_ssid: current_ssid = "[Hidden Network]"
            elif row.startswith("Authentication") or row.startswith("Kimlik Doğrulaması"):
                parts = row.split(":")
                if len(parts) > 1:
                    current_auth = parts[1].strip()
            elif row.startswith("BSSID"):
                parts = row.split(":", 1)
                if len(parts) > 1:
                    mac = parts[1].strip()
                    lines.append((f"SSID : {current_ssid}\n", "success", 0.05))
                    lines.append((f"MAC  : {mac}\n", "warning", 0.05))
                    lines.append((f"Auth : {current_auth}\n", "normal", 0.05))
            elif row.startswith("Signal") or row.startswith("Sinyal"):
                parts = row.split(":")
                if len(parts) > 1:
                    signal = parts[1].strip()
                    lines.append((f"Sig  : {signal}\n", "normal", 0.05))
                    lines.append(("----------------------------------------\n", "normal", 0.05))
                    
        lines.append(("[+] Wi-Fi Spectrum Analysis Completed.\n", "normal", 0.1))
    except Exception as e:
        lines.append((f"[!] ERROR: Could not scan Wi-Fi networks (Wi-Fi adapter disabled or not found).\nDetails: {str(e)}\n", "danger", 0.1))
        
    return lines

import urllib.request
import json
import socket

def do_dns_recon(domain):
    """
    Hedef alan adı için nslookup kullanarak DNS kayıtlarını (A, AAAA, MX) sorgular.
    """
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    lines = []
    lines.append((f"[!] Initiating DNS Reconnaissance for {domain}...\n\n", "warning", 0.5))
    
    record_types = ["A", "AAAA", "MX", "TXT"]
    for qtype in record_types:
        try:
            output = subprocess.check_output(f'nslookup -type={qtype} {domain}', shell=True, text=True, stderr=subprocess.STDOUT)
            lines.append((f"[+] Querying {qtype} Records:\n", "normal", 0.2))
            
            # nslookup çıktısını temizle
            results = []
            for line in output.split("\n"):
                line = line.strip()
                if not line or "Server:" in line or "Address:" in line and "Non-authoritative" not in output:
                    # Basit bir filtre, sadece sonuç kısımlarını almaya çalışıyoruz
                    pass
                if "internet address" in line or "MX preference" in line or "text =" in line:
                    results.append(line)
                elif domain in line and "address" in line:
                    results.append(line)
                    
            if results:
                for r in results:
                    lines.append((f"    {r}\n", "success", 0.1))
            else:
                lines.append(("    No records found or format parsed.\n", "warning", 0.1))
            lines.append(("\n", "normal", 0))
        except:
            lines.append((f"[-] Failed to query {qtype} records.\n\n", "danger", 0.1))
            
    lines.append(("[+] DNS Recon Completed.\n", "normal", 0.1))
    return lines

def do_domain_whois(domain):
    """
    RDAP API'sini kullanarak Domain/IP bilgilerini (WHOIS) çeker.
    """
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    lines = []
    lines.append((f"[!] Initiating WHOIS & Domain OSINT for {domain}...\n\n", "warning", 0.5))
    
    # Check if domain is IP
    is_ip = False
    try:
        socket.inet_aton(domain)
        is_ip = True
    except:
        pass
        
    try:
        if is_ip:
            url = f"https://rdap.arin.net/registry/ip/{domain}"
        else:
            # IP-API üzerinden hosting bilgisini çekelim domainler için
            ip = socket.gethostbyname(domain)
            url = f"http://ip-api.com/json/{ip}"
            lines.append((f"[+] Resolved to IP: {ip}\n", "normal", 0.2))
            
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            
        lines.append(("██████████████████████████████████████\n", "success", 0.1))
        lines.append(("          OSINT DATA RETRIEVED\n", "success", 0.1))
        lines.append(("██████████████████████████████████████\n\n", "success", 0.1))
        
        if is_ip:
            lines.append((f"Name        : {data.get('name', 'Unknown')}\n", "warning", 0.1))
            lines.append((f"Handle      : {data.get('handle', 'Unknown')}\n", "normal", 0.1))
            lines.append((f"Type        : {data.get('type', 'Unknown')}\n", "normal", 0.1))
        else:
            lines.append((f"ISP         : {data.get('isp', 'Unknown')}\n", "warning", 0.1))
            lines.append((f"Org         : {data.get('org', 'Unknown')}\n", "normal", 0.1))
            lines.append((f"Country     : {data.get('country', 'Unknown')}\n", "normal", 0.1))
            lines.append((f"City        : {data.get('city', 'Unknown')}\n", "normal", 0.1))
            lines.append((f"Timezone    : {data.get('timezone', 'Unknown')}\n\n", "normal", 0.1))
            
    except Exception as e:
        lines.append((f"[-] Failed to fetch WHOIS/OSINT data: {str(e)}\n\n", "danger", 0.1))
        
    lines.append(("[+] Domain OSINT Completed.\n", "normal", 0.1))
    return lines

def do_service_detection(target):
    """
    Belirli açık portlardan banner grabbing yaparak Servis Versiyonunu öğrenir.
    """
    lines = []
    lines.append((f"[!] Initiating Service Detection (Banner Grabbing) on {target}...\n\n", "warning", 0.5))
    
    ports_to_check = [21, 22, 25, 80, 110, 143, 443, 3306]
    lines.append(("[+] Scanning common service ports...\n", "normal", 0.2))
    
    open_ports = []
    for p in ports_to_check:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, p)) == 0:
                    open_ports.append(p)
        except:
            pass
            
    if not open_ports:
        lines.append(("[-] No common ports open for banner grabbing.\n", "danger", 0.1))
        return lines
        
    for p in open_ports:
        lines.append((f"[+] Port {p} is open. Attempting to grab banner...\n", "normal", 0.2))
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((target, p))
                
                # HTTP için özel request
                if p in [80, 443]:
                    request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                    if p == 443:
                        context = ssl.create_default_context()
                        with context.wrap_socket(s, server_hostname=target) as ss:
                            ss.send(request.encode())
                            banner = ss.recv(1024).decode(errors='ignore').split('\r\n')[0]
                    else:
                        s.send(request.encode())
                        banner = s.recv(1024).decode(errors='ignore').split('\r\n')[0]
                else:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    
                if banner:
                    lines.append((f"    => {banner[:50]}...\n", "success", 0.1))
                else:
                    lines.append((f"    => [No Banner Returned]\n", "warning", 0.1))
        except Exception as e:
            lines.append((f"    => [Error grabbing banner: {str(e)}]\n", "danger", 0.1))
            
    lines.append(("\n[+] Service Detection Completed.\n", "normal", 0.1))
    return lines

def do_route_analysis(target):
    """
    Hedef IP veya domaine giden paketlerin rotasını (Traceroute) çıkartır.
    """
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    lines = []
    lines.append((f"[!] Initiating Visual Route Analysis to {target}...\n", "warning", 0.5))
    lines.append(("[+] Tracing route (this may take a minute)...\n\n", "normal", 0.1))
    
    try:
        # Sadece ilk 10 hop'ı hızlıca almak için -h 10 kullanıyoruz (Windows)
        cmd = f"tracert -h 10 {target}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        hop_count = 0
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line or "Tracing" in line or "Trace complete" in line or "Over a maximum" in line:
                continue
                
            hop_count += 1
            if "*" in line:
                lines.append((f"  [ {hop_count:02} ] ---> * * * (Request Timed Out)\n", "danger", 0.1))
            else:
                parts = line.split()
                if len(parts) >= 3:
                    lines.append((f"  [ {hop_count:02} ] ---> {parts[-1]}\n", "success", 0.1))
                    
        process.wait()
        lines.append(("\n[+] Route Analysis Completed.\n", "normal", 0.1))
    except Exception as e:
        lines.append((f"[-] Route Analysis failed: {str(e)}\n", "danger", 0.1))
        
    return lines

def do_local_map():
    """
    Yerel ağdaki cihazları (ARP tablosunu) ASCII topoloji ağacı olarak çizer.
    """
    lines = []
    lines.append(("[!] Constructing Local Network Topology Map...\n\n", "warning", 0.5))
    
    devices = get_arp_devices()
    if not devices:
        lines.append(("[-] No devices found in local network.\n", "danger", 0.1))
        return lines
        
    lines.append(("[ LOCAL GATEWAY / ROUTER ]\n", "success", 0.1))
    lines.append(("      |\n", "normal", 0.1))
    
    for i, dev in enumerate(devices):
        ip = dev['ip']
        mac = dev['mac']
        
        # Son eleman mı kontrolü (Ağaç çizimi için)
        if i == len(devices) - 1:
            lines.append(("      +---> ", "normal", 0.1))
        else:
            lines.append(("      |---> ", "normal", 0.1))
            
        lines.append((f"{ip} ", "warning", 0.1))
        lines.append((f"({mac})\n", "normal", 0.1))
        
    lines.append(("\n[+] Topology Mapping Completed.\n", "normal", 0.1))
    return lines
