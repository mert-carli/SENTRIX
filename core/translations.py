"""
SENTRIX v5.0 — Merkezi Türkçe ve Uluslararası Dil Sözlüğü
Türkçe öncelikli, teknik terimlerin kullanıcı dostu açıklamalarını barındıran yerelleştirme modülü.
"""

from typing import Dict, Any, Optional

TRANSLATIONS_TR = {
    # Genel Uygulama Başlıkları
    "app_title": "SENTRIX — Siber Güvenlik Operasyon Platformu",
    "ai_copilot": "Akıllı Güvenlik Asistanı",
    "attack_graph": "Saldırı ve Olay Haritası",
    "network_map": "Canlı Ağ Haritası",

    # Navigasyon Başlıkları & Gruplar
    "nav_general": "GENEL",
    "nav_network_sec": "AĞ VE GÜVENLİK",
    "nav_threat_analysis": "TEHDİT ANALİZİ",
    "nav_advanced_tools": "İLERİ ARAÇLAR",
    "nav_management": "YÖNETİM",

    # Menü Öğeleri
    "menu_overview": "Genel Bakış",
    "menu_ai_copilot": "Akıllı Güvenlik Asistanı",
    "menu_notifications": "Bildirimler & Alarmlar",
    
    "menu_network_map": "Ağ Haritası",
    "menu_network_scan": "Ağ Taraması",
    "menu_vulnerabilities": "Güvenlik Açıkları",
    "menu_web_sec": "Web Güvenliği",
    "menu_wireless": "Kablosuz Ağlar",

    "menu_security_events": "Güvenlik Olayları",
    "menu_attack_graph": "Saldırı ve Olay Haritası",
    "menu_threat_hunting": "Tehdit Araştırması",
    "menu_processes": "Çalışan İşlemler",
    "menu_file_analysis": "Dosya & Zararlı Analizi",

    "menu_forensics": "Adli İnceleme (DFIR)",
    "menu_memory": "Bellek Analizi",
    "menu_cloud": "Bulut Güvenliği",
    "menu_containers": "Konteyner Güvenliği",
    "menu_detection_rules": "Güvenlik Kuralları",
    "menu_automation": "Otomasyon & SOAR",

    "menu_reports": "Güvenlik Raporları",
    "menu_history": "Geçmiş İşlemler",
    "menu_settings": "Ayarlar & Kapsam",

    # Durum & Önem Dereceleri
    "sev_critical": "Kritik",
    "sev_high": "Yüksek",
    "sev_medium": "Orta",
    "sev_low": "Düşük",
    "sev_info": "Bilgi",

    # Güvenilirlik & Analiz Durumları
    "conf_verified": "Doğrulandı",
    "conf_strong": "Güçlü Belirti",
    "conf_investigate": "İncelenmesi Gerekiyor",
    "conf_insufficient": "Yetersiz Veri",

    # Ortak İşlem Butonları
    "btn_scan": "Taramayı Başlat",
    "btn_cancel": "İşlemi İptal Et",
    "btn_refresh": "Yenile",
    "btn_details": "Ayrıntıları Görüntüle",
    "btn_tech_details": "Teknik Ayrıntıları Göster",
    "btn_basic_view": "Temel Görünüm",
    "btn_advanced_view": "Gelişmiş Görünüm",
    "btn_export": "Dışa Aktar",
    "btn_approve": "Onayla ve Çalıştır",
    "btn_reject": "Reddet",
    "btn_remediate": "Çözüm Adımlarını Uygula",

    # Durum Mesajları
    "status_healthy": "Sistem Normal ve Güvende",
    "status_warning": "İncelenmesi Gereken Durumlar Var",
    "status_critical": "Kritik Güvenlik Müdahalesi Gerekiyor",
    "msg_no_data": "Henüz analiz edilecek veri bulunamadı.",
    "msg_permission_req": "Bu işlem için yönetici (Administrator) yetkisi gerekiyor.",
    "msg_feature_unavailable": "Bu özellik şu anda kullanılamıyor. Ayrıntıları görüntüleyebilirsiniz.",
    "msg_scanning": "Tarama ve analiz devam ediyor...",
    "msg_new_device": "Ağınızda yeni bir cihaz tespit edildi.",
    "msg_ai_unconfigured": "Akıllı Asistan henüz yapılandırılmadı. Ayarlar sekmesinden yerel (Ollama) veya bulut modelinizi belirleyebilirsiniz.",
    "msg_scope_violation": "Hedef, yetkili inceleme kapsamınızın dışında bırakılmış."
}

# Terim Sözlüğü ve Eğitim Açıklamaları (Tooltip / Bilgi Kartları)
GLOSSARY = {
    "PID": {
        "title": "PID — İşlem Kimliği",
        "acronym": "Process Identifier",
        "desc": "Windows tarafından çalışan her programa verilen benzersiz numara (Process ID)."
    },
    "PPID": {
        "title": "PPID — Başlatan İşlem Kimliği",
        "acronym": "Parent Process Identifier",
        "desc": "Bir programı başlatan ana uygulamanın kimlik numarası (Parent Process ID)."
    },
    "CVE": {
        "title": "CVE — Güvenlik Açığı Kimliği",
        "acronym": "Common Vulnerabilities and Exposures",
        "desc": "Bilinen güvenlik açıklarını tanımlamak için kullanılan uluslararası kayıt numarası (Common Vulnerabilities and Exposures)."
    },
    "EPSS": {
        "title": "EPSS — Sömürülme Olasılığı Skoru",
        "acronym": "Exploit Prediction Scoring System",
        "desc": "Bir güvenlik açığının gerçek dünyada saldırganlar tarafından kullanılma olasılık yüzdesi (0.0 - 1.0)."
    },
    "CIDR": {
        "title": "CIDR — Ağ Alt Ağ Bloğu",
        "acronym": "Classless Inter-Domain Routing",
        "desc": "Ağdaki IP adresi aralıklarını tanımlayan standart gösterim (Örn: 192.168.1.0/24)."
    },
    "MAC": {
        "title": "MAC — Fiziksel Donanım Adresi",
        "acronym": "Media Access Control",
        "desc": "Bir ağ kartına veya cihaza üretim sırasında atanan benzersiz fiziksel tanımlayıcı."
    },
    "ETW": {
        "title": "ETW — Windows Olay İzleme",
        "acronym": "Event Tracing for Windows",
        "desc": "Windows çekirdeği tarafından donanım ve yazılım olaylarını gerçek zamanlı kaydeden yüksek hızlı izleme mekanizması."
    },
    "SYSMON": {
        "title": "Sysmon — Sistem Güvenlik Monitörü",
        "acronym": "System Monitor",
        "desc": "Microsoft tarafından süreç, dosya ve ağ aktivitelerini derinlemesine kaydetmek için geliştirilen güvenlik servisi."
    },
    "RWX": {
        "title": "RWX — Okunabilir, Yazılabilir, Çalıştırılabilir Bellek",
        "acronym": "Read-Write-Execute",
        "desc": "Hem yazılıp hem kod çalıştırılabilen bellek alanıdır; genellikle zararlı kod enjeksiyonlarında görülür."
    },
    "SOAR": {
        "title": "SOAR — Güvenlik Otomasyonu ve Müdahale",
        "acronym": "Security Orchestration, Automation, and Response",
        "desc": "Güvenlik alarmlarına karşı önceden belirlenmiş adımlarla otomatik veya onaylı müdahale gerçekleştiren sistem."
    }
}

def tr(key: str, default: Optional[str] = None) -> str:
    """Metin anahtarının Türkçe karşılığını döndürür."""
    return TRANSLATIONS_TR.get(key, default or key)

def get_glossary_term(term: str) -> Dict[str, str]:
    """Teknik terimin anlaşılır açıklamasını döndürür."""
    return GLOSSARY.get(term.upper(), {
        "title": term,
        "desc": "Teknik terim ayrıntısı bulunamadı."
    })
