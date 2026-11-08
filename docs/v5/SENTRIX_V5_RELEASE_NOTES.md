# SENTRIX v5.0 — SİBER GÜVENLİK VE OPERASYON PLATFORMU
## Kapsamlı Mimari ve Geliştirme Sürüm Raporu

**Proje:** SENTRIX  
**Sürüm:** v5.0  
**Tarih:** 2026-11-06  
**Hedef İşletim Sistemi:** Windows 10/11 x64  
**Teknoloji Altyapısı:** Python 3.11, CustomTkinter 6.0, SQLite (WAL Modu, 32 Tablo)  
**Tasarım Felsefesi:** Minimal Surface, Maximum Capability (Dışarıdan sade, içeriden sınırsız derinlik)

---

## 1. Genel Bakış ve Yönetici Özeti

SENTRIX v5.0; önceki v4.0 sürümündeki 20 ileri düzey siber güvenlik modülünü, veritabanı altyapısını ve yerleşik testlerini eksiksiz koruyarak dört ana yetenek sütunu (Pillar) ile güçlendirilmiş profesyonel bir siber operasyon platformudur:

1. **Akıllı Güvenlik Asistanı (AI Security Copilot):** Doğal Türkçe soruları anlayıp sistem telemetrisiyle eşleştiren, kanıta dayalı analiz yapan ve riskli eylemleri operatör onayına sunan yapay zekâ asistanı.
2. **Gerçek Zamanlı Saldırı ve Olay İlişkileri Haritası (Attack & Incident Graph):** Olaylar arasındaki nedensellik bağını (`Kullanıcı -> Belge -> İşlem -> Ağ -> Kalıcılık`) 2B interaktif tuval üzerinde canlandıran ve teknik ayrıntı denetçisi sunan harita motoru.
3. **Canlı Ağ Topolojisi ve Cihaz Keşif Haritası (Live Network Topology Map):** Ağ geçidini merkez alan yıldız topolojisinde cihaz türlerini (`[GW]`, `[SRV]`, `[PC]`, `[PRN]`, `[?]`) sınıflandıran, yeni cihazları tespit eden ve 4 sekmeli cihaz denetçisi barındıran canlı ağ haritası.
4. **Baştan Sona Profesyonel Türkçe Arayüz:** Segoe UI tipografisi, 5 ana menü grubu (`GENEL`, `AĞ VE GÜVENLİK`, `TEHDİT ANALİZİ`, `İLERİ ARAÇLAR`, `YÖNETİM`), çift görünüm modu (*Temel Görünüm* / *Gelişmiş Görünüm*), teknik terim bilgi kartları (Glossary Tooltips) ve `#0B111B` kurumsal koyu renk paleti.

---

## 2. Dört Temel Geliştirme Sütununun Mimarisi

### 2.1. Akıllı Güvenlik Asistanı (`modules/ai_security/`)
- **Doğal Dil Analizi:** Türkçe soruları (`"Bilgisayarım güvenli mi?"`, `"3389 portunu kapatırsam ne etkilenir?"`, `"PowerShell komutu normal mi?"`, `"Ağımda anormal cihaz var mı?"`) analiz eder.
- **Güvenilirlik Seviyeleri (Confidence Scoring):**
  - `Doğrulandı (%90-100)`: Açık portlar, çalışan işlemler veya doğrulanmış günlük kayıtları.
  - `Güçlü belirti (%70-89)`: Bilinen saldırı kalıpları (LOLBin, yetkisiz betik argümanları).
  - `İncelenmesi gerekiyor (%40-69)`: Şüpheli ağ soketleri, yetkisiz cihazlar.
  - `Yetersiz veri (%0-39)`: Eksik telemetri durumunda dürüst bilgilendirme.
- **Yerel ve Gizlilik Odaklı LLM Desteği (`local_llm_provider.py`):**
  - Yerel Ollama (`http://localhost:11434/api/generate`) bağlantısını dener.
  - LLM bulunmadığında veya çevrimdışı olduğunda SENTRIX Sezgisel Kural Motoru kesintisiz yanıt verir.
  - Ağ haritası, parola ve zafiyet verileri izinsiz hiçbir dış bulut servisine aktarılmaz; sırlar (`sanitize_text`) ile maskelenir.
- **İnsan Onay Mekanizması (`action_guard.py`):**
  - İşlem sonlandırma (`taskkill`), güvenlik duvarında engelleme (`netsh advfirewall`), dosya karantinaya alma ve servis durdurma işlemleri doğrudan çalıştırılmaz.
  - Operatöre açık komut, risk derecesi ve geri alma (rollback) komutu sunularak `[Onayla]` / `[İptal]` onay kapısı işletilir.
  - Her onaylı eylem denetim günlüğüne (`audit_logs`) kaydedilir.

### 2.2. Saldırı ve Olay İlişkileri Haritası (`modules/attack_graph/`)
- **Nedensellik Zinciri Korelasyonu (`attack_graph_engine.py`):**
  - `alerts`, `security_events` ve `process_events` tablolarından gelen kayıtları otomatik olarak aşamalara ayırır:
    - *Seviye 0:* Kullanıcı Oturumu (`NodeType.USER`)
    - *Seviye 1:* Giriş Vektörü / Dosya (`NodeType.DOCUMENT`)
    - *Seviye 2:* Çalışan İşlem / PID (`NodeType.PROCESS`)
    - *Seviye 3:* Dış Ağ Bağlantısı (`NodeType.NETWORK`)
    - *Seviye 4:* Kayıt Defteri Kalıcılığı (`NodeType.PERSISTENCE`)
- **Zaman Filtresi:** `Son 1 saat`, `Son 24 saat`, `Son 7 gün`, `Tümü`.
- **İnteraktif 2B Tuval (`graph_visualizer.py`):**
  - Akıcı kaydırma (Pan) ve fare tekerleğiyle yakınlaştırma (Zoom).
  - Kritik (`#E56767`), Yüksek (`#E9AD48`), Orta (`#F1C40F`) ve Bilgi (`#4F8FF7`) renkli durum şeritleri.
  - Tıklanan düğümün sağ panelde açılan detay denetçisi ve `"Teknik Ayrıntıları Göster"` modu.

### 2.3. Canlı Ağ Topolojisi ve Cihaz Keşif Haritası (`modules/network_topology/`)
- **Yıldız Topolojisi Yerleşimi (`topology_engine.py`):**
  - Windows yönlendirme tablosu üzerinden varsayılan ağ geçidini (Default Gateway) otomatik keşfeder ve merkeze yerleştirir.
  - Yetkili kapsam (`core/scope.py`) dahilindeki tüm uç noktaları dairesel yörüngede bağlar.
- **Otomatik Cihaz Sınıflandırması:**
  - `[GW]` Yönlendirici / Ağ Geçidi
  - `[SRV]` Sunucu (Windows Server, Linux Server, SQL, DC)
  - `[PC]` Kişisel Bilgisayar / İş İstasyonu
  - `[PRN]` Ağ Yazıcısı (LPD, IPP, RAW portları ve donanım üreticileri)
  - `[?]` Bilinmeyen Cihaz
- **Yeni Cihaz Tespiti:** Temel ağ envanterine sonradan katılan cihazları saptar ve bildirim bandında uyarır.
- **4 Sekmeli Sağ Denetim Paneli (`ui/views/network_topology_view.py`):**
  - *[Bilgi]:* IP, MAC, Ana Bilgisayar, Üretici, İşletim Sistemi.
  - *[Güvenlik]:* Açık port listesi, port risk seviyesi, güvenlik durumu (`GÜVENLİ`, `DİKKAT`, `KRİTİK`).
  - *[Geçmiş]:* İlk görülme ve tarama farkları (`diff_engine.py`).
  - *[Aksiyonlar]:* Hızlı port taraması ve Güvenlik Duvarı engelleme önerisi.

### 2.4. Baştan Sona Profesyonel Türkçe Kullanıcı Arayüzü
- **5 Ana Menü Grubu:**
  1. **GENEL:** Genel Bakış, Akıllı Güvenlik Asistanı, Bildirimler ve Alarmlar
  2. **AĞ VE GÜVENLİK:** Canlı Ağ Haritası, Ağ Taraması & Keşif, Ağ Analiz Araçları, Web Güvenliği & API, Kablosuz Ağ Analizi
  3. **TEHDİT ANALİZİ:** Saldırı ve Olay Haritası, Tehdit Araştırması, Sistem İşlemleri & ETW, Dijital Adli İnceleme, Tehdit İstihbaratı
  4. **İLERİ ARAÇLAR:** Bellek Analizi, Bulut & Konteyner, Kural Stüdyosu (YARA/Sigma), Otomasyon & SOAR, Zafiyet Araştırması (EPSS), Active Directory Analizi, Bal Küpü (Honeypot)
  5. **YÖNETİM:** Raporlar & Yetkili Kapsam, Siber Araç Seti & Kripto
- **Çift Görünüm Modu:**
  - *Temel Görünüm:* Son kullanıcı ve operatör için özet metrikler, anlaşılır dil, rehber yönlendirmeler.
  - *Gelişmiş Görünüm:* Derinlemesine loglar, ham argümanlar, PID değerleri, MITRE teknikleri ve JSON çıktıları.
- **Teknik Terim Bilgi Kartları (Glossary Tooltips):**
  - `PID`, `PPID`, `CVE`, `EPSS`, `CIDR`, `MAC`, `ETW`, `SYSMON`, `RWX`, `SOAR` terimlerinin üzerine gelindiğinde veya tıklandığında beliren eğitim açıklamaları.

---

## 3. Doğrulama ve Test Sonuçları

Platformun tüm sürümler arasındaki geriye dönük uyumluluğu ve sıfır sahte veri prensibi otomatik test paketiyle teyit edilmiştir:

| Test Paketi | Kapsam | Test Sayısı | Başarılı | Başarısız | Hata | Durum |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `tests/test_core_and_modules.py` | SQLite WAL, Kapsam Denetimi, Görev Yöneticisi, Port Tarayıcı, JWT, EDR Lite | 10 | 10 | 0 | 0 | **BAŞARILI** |
| `tests/test_v3_engines.py` | Kripto Toolkit, EPSS Skoru, PCAP Ayrıştırma, Nmap XML, AD Saldırı Yolu | 10 | 10 | 0 | 0 | **BAŞARILI** |
| `tests/test_v4_advanced_engines.py` | Bellek RWX, ETW/Sysmon, Tehdit Hipotezleri, SOAR Playbook, K8s Güvenliği | 10 | 10 | 0 | 0 | **BAŞARILI** |
| `tests/test_v5_copilot_and_maps.py` | AI Copilot, ActionGuard Onay Kapısı, Saldırı Grafiği, Topoloji Sınıflandırması, Sözlük | 7 | 7 | 0 | 0 | **BAŞARILI** |
| **TOPLAM** | **Bütünleşik SENTRIX v5.0 Testleri** | **37** | **37** | **0** | **0** | **%100 GEÇTİ** |

---

## 4. Masaüstü Entegrasyonu ve Başlatma

- **Masaüstü Kısayolu:** Masaüstünde `SENTRIX v5.0.lnk` oluşturulmuştur.
- **Çalışma Durumu:** Uygulama Windows arka plan penceresi (`pythonw.exe main.py`) olarak başarıyla başlatılmış ve ekranda canlı olarak çalışmaktadır.
- **Komut Satırı Başlatma:**
  ```powershell
  cd C:\Users\userk\Desktop\Projelerim\SENTRIX
  .\venv\Scripts\pythonw.exe main.py
  ```
