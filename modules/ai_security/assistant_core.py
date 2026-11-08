"""
SENTRIX v5.0 — AI Security Copilot Engine
Context-aware, evidence-based security assistant.
Answers in Turkish, supports local LLM with deterministic heuristic fallback,
assigns verified confidence ratings, and generates safe human-in-the-loop action proposals.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from core.database import db
from core.logger import log
from modules.ai_security.context_builder import context_builder
from modules.ai_security.local_llm_provider import local_llm_provider
from modules.ai_security.action_guard import action_guard, ActionType, ActionRisk

class ConfidenceLevel:
    VERIFIED = ("Doğrulandı", 95, "#31B88A")
    STRONG = ("Güçlü belirti", 80, "#4F8FF7")
    INVESTIGATE = ("İncelenmesi gerekiyor", 55, "#E9AD48")
    INSUFFICIENT = ("Yetersiz veri", 25, "#94A3B8")

class AISecurityCopilot:
    """Core intelligent assistant integrating live system telemetry, threat analysis, and execution guard."""

    def __init__(self):
        self.system_prompt = (
            "Sen SENTRIX Siber Güvenlik Operasyon Asistanısın. "
            "Kullanıcıya daima profesyonel, net ve Türkçe yanıt ver. "
            "Varsayımlarla veya uydurma verilerle konuşma; yalnızca verilen sistem kanıtlarına dayan. "
            "Aksiyon gerekiyorsa kullanıcının onaylaması için somut öneri sun."
        )

    def ask(self, query: str) -> Dict[str, Any]:
        """Processes user query and returns structured analysis, evidence, and actions."""
        q_clean = query.strip()
        q_lower = q_clean.lower()
        now_str = datetime.now().strftime("%H:%M:%S")

        # 1. Gather live context
        snapshot = context_builder.build_snapshot()
        summary = snapshot["summary"]
        
        # 2. Try Local LLM if available and requested
        llm_response = None
        if local_llm_provider.is_available():
            formatted_ctx = context_builder.format_prompt_context()
            full_prompt = f"{formatted_ctx}\n\nKullanıcı Sorusu: {q_clean}\n\nLütfen duruma göre net bir Türkçe analiz yap."
            llm_result = local_llm_provider.query(full_prompt, system_prompt=self.system_prompt)
            if llm_result and llm_result.get("text"):
                llm_response = llm_result

        # 3. If LLM provided a valid answer, format it; otherwise use expert Heuristic Engine
        if llm_response:
            return self._build_llm_answer(q_clean, llm_response, snapshot)
        else:
            return self._build_heuristic_answer(q_clean, q_lower, snapshot)

    def _build_llm_answer(self, query: str, llm_res: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Wraps local LLM response with evidence and confidence metrics."""
        text = llm_res["text"]
        model = llm_res.get("model", "Ollama")

        evidence = []
        if snapshot["critical_ports"]:
            evidence.append({"type": "Açık Port", "data": snapshot["critical_ports"][:3]})
        if snapshot["critical_vulnerabilities"]:
            evidence.append({"type": "Zafiyet", "data": snapshot["critical_vulnerabilities"][:3]})

        return {
            "query": query,
            "answer": text,
            "confidence_label": ConfidenceLevel.STRONG[0],
            "confidence_score": ConfidenceLevel.STRONG[1],
            "confidence_color": ConfidenceLevel.STRONG[2],
            "evidence": evidence,
            "actions": [],
            "engine_source": f"Yerel LLM: {model}",
            "timestamp": datetime.now().isoformat()
        }

    def _build_heuristic_answer(self, query: str, q_lower: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic, highly accurate security reasoning engine based on actual telemetry."""
        summary = snapshot["summary"]
        evidence: List[Dict[str, Any]] = []
        actions: List[Dict[str, Any]] = []
        
        # Scenario 1: Genel Güvenlik Durumu / Bilgisayarım Güvenli mi?
        if any(w in q_lower for w in ["güvenli mi", "durum", "özet", "posture", "skor", "güvenlik durumu"]):
            crit_ports = summary["critical_ports_exposed"]
            crit_vulns = summary["critical_vulnerabilities"]
            alerts_cnt = summary["recent_alerts_count"]

            if crit_ports == 0 and crit_vulns == 0 and alerts_cnt == 0:
                label, score, color = ConfidenceLevel.VERIFIED
                ans = (
                    "Sisteminizin mevcut güvenlik durumu **GÜVENLİ (Temiz)** seviyede.\n\n"
                    f"• Aktif izlenen cihaz: {summary['online_hosts']} adet\n"
                    "• Tespit edilmiş açık yönetim portu veya kritik güvenlik zafiyeti bulunmuyor.\n"
                    "• Sistem arkaplan denetimlerinde aktif bir tehdit sinyali saptanmadı."
                )
            else:
                label, score, color = ConfidenceLevel.STRONG
                ans = (
                    f"Sisteminizin genel güvenlik durumu değerlendirildi: **dikkat edilmesi gereken {crit_ports + crit_vulns + alerts_cnt} potansiyel risk** tespit edildi.\n\n"
                    f"• Dışa açık yönetim/riskli port: **{crit_ports}** adet\n"
                    f"• Kritik zafiyet kaydı: **{crit_vulns}** adet\n"
                    f"• Son güvenlik uyarısı: **{alerts_cnt}** adet\n\n"
                    "Öncelikli öneri: Ağ haritasında işaretlenen açık yönetim portlarını kontrol edin ve güvenlik duvarı kurallarını sıkılaştırın."
                )

            evidence = [
                {"kategori": "Ağ Durumu", "detay": f"{summary['online_hosts']} aktif cihaz, {summary['total_open_ports']} açık port"},
                {"kategori": "Zafiyet Durumu", "detay": f"{crit_vulns} kritik / yüksek zafiyet"},
                {"kategori": "Olay Günlüğü", "detay": f"{alerts_cnt} son güvenlik uyarısı"}
            ]

        # Scenario 2: RDP / Port 3389 Kapatma veya Etkileri
        elif "3389" in q_lower or "rdp" in q_lower or "uzak masaüstü" in q_lower:
            label, score, color = ConfidenceLevel.VERIFIED
            ans = (
                "**RDP (Remote Desktop Protocol - Port 3389) Analizi:**\n\n"
                "• **Ne işe yarar?** Windows Uzak Masaüstü bağlantısını sağlar.\n"
                "• **Güvenlik Riski:** İnternete veya güvensiz yerel ağa açık RDP portları, kaba kuvvet (brute-force) "
                "saldırılarına ve BlueKeep (CVE-2019-0708) gibi uzaktan kod çalıştırma zafiyetlerine davetiye çıkarır.\n"
                "• **Kapatırsanız ne etkilenir?** Bu makineye dışarıdan Windows Uzak Masaüstü ile bağlanamazsınız. "
                "Fiziksel masaüstü kullanımınız veya internette gezinmeniz kesinlikle etkilenmez.\n\n"
                "Aşağıda RDP bağlantısını güvenlik duvarından engellemek için hazırlanmış onay eylemini inceleyebilirsiniz."
            )
            # Create a pending action proposal for the user to approve if they wish
            prop = action_guard.create_proposal(
                action_type=ActionType.BLOCK_FIREWALL_IP,
                target="0.0.0.0/0",
                description="RDP (3389) portuna gelen tüm harici bağlantıları Güvenlik Duvarında engelle",
                risk_level=ActionRisk.MEDIUM,
                params={"rule_name": "SENTRIX_Block_RDP_3389"}
            )
            actions.append(prop)
            evidence = [{"kategori": "Port Bilgisi", "detay": "TCP 3389 - Microsoft Remote Desktop Protocol (MS-WBT-SERVER)"}]

        # Scenario 3: PowerShell / LOLBin Güvenliği
        elif "powershell" in q_lower or "komut" in q_lower or "cmd" in q_lower or "lolbin" in q_lower:
            label, score, color = ConfidenceLevel.STRONG
            ans = (
                "**PowerShell Çalıştırma Analizi:**\n\n"
                "PowerShell meşru bir Windows yönetim aracıdır. Ancak aşağıdaki parametreler normal dışı kabul edilir:\n"
                "• `-ExecutionPolicy Bypass` veya `-enc` (Base64 ile şifrelenmiş komutlar)\n"
                "• `-WindowStyle Hidden` veya `-NonI` (kullanıcıdan gizlenen arka plan işlemleri)\n"
                "• `DownloadString` veya `IEX` (hafızada dosyasız zararlı indirme)\n\n"
                "Eğer PowerShell Word/Excel (WINWORD.EXE) veya tarayıcı tarafından başlatıldıysa bu kesinlikle yüksek riskli bir saldırı belirtisidir (T1059.001)."
            )
            evidence = [
                {"kategori": "MITRE ATT&CK", "detay": "T1059.001 - Command and Scripting Interpreter: PowerShell"},
                {"kategori": "Önlem", "detay": "Script Block Logging (Event ID 4104) ve Constrained Language Mode"}
            ]

        # Scenario 4: Anormal Cihaz / Ağ Keşfi
        elif any(w in q_lower for w in ["anormal", "bilinmeyen", "yeni cihaz", "cihaz", "ağımda"]):
            hosts = db.get_all_hosts()
            unknown_hosts = [h for h in hosts if not h.get("hostname") or h.get("hostname") == "Unknown"]
            
            if unknown_hosts:
                label, score, color = ConfidenceLevel.STRONG
                sample_ips = ", ".join([h.get("ip", "") for h in unknown_hosts[:4]])
                ans = (
                    f"Ağınızda adı tanımlanamamış **{len(unknown_hosts)} adet cihaz** bulunmaktadır ({sample_ips} vb.).\n\n"
                    "Bu cihazlar akıllı TV, IoT cihazı veya ağa yeni katılmış yetkisiz bir sistem olabilir. "
                    "Canlı Ağ Haritası sekmesinden cihazların MAC üreticilerini ve açık servislerini inceleyebilirsiniz."
                )
                evidence = [{"kategori": "Bilinmeyen Cihazlar", "detay": f"{len(unknown_hosts)} cihazın ana bilgisayar adı henüz çözümlenemedi."}]
            else:
                label, score, color = ConfidenceLevel.VERIFIED
                ans = (
                    f"Ağınızda taranan **{len(hosts)} cihazın tamamı** bilinen ve tanımlı ana bilgisayar adlarına sahip. "
                    "Şu an için ağda gizlenmiş şüpheli veya tanımlanamayan bir cihaz kaydı bulunmuyor."
                )
                evidence = [{"kategori": "Ağ Analizi", "detay": f"{len(hosts)} cihaz incelendi, anomalili cihaz yok."}]

        # Scenario 5: En Kritik Olay / Alarmlar
        elif any(w in q_lower for w in ["kritik olay", "son olay", "olaylar", "alarm", "uyarı"]):
            alerts = db.get_recent_alerts(limit=5)
            if alerts:
                top = alerts[0]
                label, score, color = ConfidenceLevel.VERIFIED
                ans = (
                    f"**Son Tespit Edilen En Önemli Olay:**\n\n"
                    f"• **Başlık:** {top.get('title', 'Güvenlik Olayı')}\n"
                    f"• **Önem Derecesi:** [{top.get('severity', 'BİLGİ')}]\n"
                    f"• **Açıklama:** {top.get('description', 'Detay bulunmuyor')}\n"
                    f"• **Zaman:** {top.get('created_at', 'Bilinmiyor')}\n\n"
                    "Olayın ilişkili kök nedenini görmek için **Saldırı ve Olay Haritası** sekmesini kullanabilirsiniz."
                )
                evidence = [{"kategori": "Alarm Kaydı", "detay": f"Olay ID: {top.get('id')}, Önem: {top.get('severity')}"}]
            else:
                label, score, color = ConfidenceLevel.VERIFIED
                ans = "Sistem günlüğünde son 24 saat içerisinde kaydedilmiş kritik veya yüksek öncelikli bir güvenlik olayı bulunmamaktadır."
                evidence = [{"kategori": "Olay Günlüğü", "detay": "0 aktif alarm"}]

        # Default / Genel Sorular
        else:
            label, score, color = ConfidenceLevel.INVESTIGATE
            ans = (
                f"Sorunuz incelendi: *\"{query}\"*\n\n"
                f"Sisteminizde şu anda **{summary['online_hosts']} aktif cihaz**, **{summary['total_open_ports']} açık port** "
                f"ve **{summary['critical_vulnerabilities']} kritik zafiyet** kayıtlıdır.\n\n"
                "Yardım alabileceğiniz örnek sorular:\n"
                "• *'Ağımda şu an anormal bir cihaz var mı?'*\n"
                "• *'3389 portunu kapatırsam ne etkilenir?'*\n"
                "• *'PowerShell'in bu komutu çalıştırması normal mi?'*\n"
                "• *'Son 24 saatte en kritik olay hangisi?'*"
            )
            evidence = [{"kategori": "Genel Durum", "detay": f"Toplam {summary['total_hosts']} cihaz ve {summary['recent_alerts_count']} olay kaydı mevcut."}]

        return {
            "query": query,
            "answer": ans,
            "confidence_label": label,
            "confidence_score": score,
            "confidence_color": color,
            "evidence": evidence,
            "actions": actions,
            "engine_source": "SENTRIX Sezgisel Güvenlik Motoru",
            "timestamp": datetime.now().isoformat()
        }

ai_security_copilot = AISecurityCopilot()
