"""
SENTRIX v5.0 — AI Security Copilot Workspace View
Interactive chat assistant with confidence ratings, evidence drawers,
one-click prompt suggestions, and operator approval gates for containment actions.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, Any, List, Optional
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_CARD, COLOR_BORDER,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_ACCENT_PRIMARY,
    COLOR_STATE_SUCCESS, COLOR_STATE_WARNING, COLOR_STATE_CRITICAL,
    FONT_TITLE_MD, FONT_BODY_LG, FONT_BODY_MD, FONT_BODY_SM, FONT_CODE_SM,
    BaseWorkspaceView, create_card_frame, create_term_badge
)
from modules.ai_security.assistant_core import ai_security_copilot
from modules.ai_security.action_guard import action_guard
from modules.ai_security.local_llm_provider import local_llm_provider
from core.translations import tr

class AICopilotView(BaseWorkspaceView):
    """Modern conversational security assistant interface with human-in-the-loop action guards."""

    def __init__(self, parent, main_app):
        super().__init__(parent, main_app, title_tr_key="ai_copilot", subtitle_tr_key="ai_copilot")
        self._build_copilot_layout()
        self._add_welcome_message()

    def _build_copilot_layout(self):
        # Header quick chips container
        self.chips_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.chips_frame.pack(fill="x", padx=16, pady=(0, 8))

        suggestions = [
            "Bilgisayarım güvenli mi?",
            "Son 24 saatte en kritik olay hangisi?",
            "3389 portunu kapatırsam ne etkilenir?",
            "Ağımda şu an anormal bir cihaz var mı?",
            "PowerShell komutu çalıştırması normal mi?"
        ]

        for s in suggestions:
            btn = ctk.CTkButton(
                self.chips_frame,
                text=s,
                height=26,
                fg_color=COLOR_CARD,
                hover_color=COLOR_BORDER,
                text_color=COLOR_TEXT_SECONDARY,
                font=FONT_BODY_SM,
                corner_radius=13,
                command=lambda q=s: self._on_chip_click(q)
            )
            btn.pack(side="left", padx=3, pady=2)

        # Chat scrollable area
        self.chat_container = ctk.CTkScrollableFrame(
            self,
            fg_color=COLOR_BG_MAIN,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.chat_container.pack(fill="both", expand=True, padx=16, pady=4)

        # Bottom Input Bar
        self.input_card = create_card_frame(self, corner_radius=8)
        self.input_card.pack(fill="x", padx=16, pady=(8, 12))
        self.input_card.grid_columnconfigure(0, weight=1)

        self.txt_query = ctk.CTkEntry(
            self.input_card,
            placeholder_text="Güvenlikle ilgili bir soru sorun... (Örn: Ağımda şüpheli bir cihaz var mı?)",
            height=38,
            font=FONT_BODY_MD,
            fg_color=COLOR_BG_MAIN,
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.txt_query.grid(row=0, column=0, padx=(10, 8), pady=8, sticky="ew")
        self.txt_query.bind("<Return>", lambda e: self._send_message())

        self.btn_send = ctk.CTkButton(
            self.input_card,
            text="Sor",
            width=80,
            height=38,
            font=FONT_BODY_MD,
            fg_color=COLOR_ACCENT_PRIMARY,
            hover_color="#3B7AE0",
            text_color="#FFFFFF",
            corner_radius=6,
            command=self._send_message
        )
        self.btn_send.grid(row=0, column=1, padx=(0, 10), pady=8)

        # Status footer indicator
        llm_status = "Ollama Yerel Modeli Aktif" if local_llm_provider.is_available() else "Çevrimdışı Kural Motoru Aktif (Gizlilik Garantili)"
        self.lbl_engine_status = ctk.CTkLabel(
            self,
            text=f"• Sistem Motoru: {llm_status} | İstemci Verileri Dışarı Aktarılmaz",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_engine_status.pack(anchor="w", padx=20, pady=(0, 6))

    def _add_welcome_message(self):
        welcome_text = (
            "Merhaba! Ben **SENTRIX Akıllı Güvenlik Asistanı**.\n\n"
            "Ağınızdaki aktif cihazları, açık portları, güvenlik açıklarını ve sistem günlüklerini "
            "anlık olarak izliyor ve analiz ediyorum.\n\n"
            "Yukarıdaki öneri başlıklarından birini seçebilir veya aklınıza gelen herhangi bir "
            "güvenlik sorusunu doğrudan sorabilirsiniz."
        )
        self._append_assistant_message({
            "answer": welcome_text,
            "confidence_label": "Doğrulandı",
            "confidence_score": 100,
            "confidence_color": COLOR_STATE_SUCCESS,
            "engine_source": "SENTRIX Güvenlik Çekirdeği",
            "evidence": [],
            "actions": []
        })

    def _on_chip_click(self, query: str):
        self.txt_query.delete(0, "end")
        self.txt_query.insert(0, query)
        self._send_message()

    def _send_message(self):
        query = self.txt_query.get().strip()
        if not query:
            return

        self.txt_query.delete(0, "end")
        self._append_user_message(query)

        # Run assistant reasoning in background thread so UI stays 100% smooth
        threading.Thread(target=self._process_query_async, args=(query,), daemon=True).start()

    def _process_query_async(self, query: str):
        try:
            response = ai_security_copilot.ask(query)
            if self.winfo_exists():
                self.after(0, lambda: self._append_assistant_message(response))
        except Exception:
            pass

    def _append_user_message(self, text: str):
        msg_frame = ctk.CTkFrame(self.chat_container, fg_color="transparent")
        msg_frame.pack(fill="x", padx=10, pady=6, anchor="e")

        bubble = ctk.CTkFrame(msg_frame, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        bubble.pack(side="right", padx=6)

        lbl = ctk.CTkLabel(
            bubble,
            text=text,
            font=FONT_BODY_MD,
            text_color=COLOR_TEXT_PRIMARY,
            wraplength=550,
            justify="left"
        )
        lbl.pack(padx=12, pady=8)

        self._scroll_to_bottom()

    def _append_assistant_message(self, resp: Dict[str, Any]):
        msg_frame = ctk.CTkFrame(self.chat_container, fg_color="transparent")
        msg_frame.pack(fill="x", padx=10, pady=8, anchor="w")

        bubble = ctk.CTkFrame(msg_frame, fg_color=COLOR_BG_SECONDARY, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        bubble.pack(side="left", fill="x", expand=True, padx=6)

        # Header bar of message
        header = ctk.CTkFrame(bubble, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(8, 4))

        title = ctk.CTkLabel(
            header,
            text="SENTRIX Asistan",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOR_ACCENT_PRIMARY
        )
        title.pack(side="left")

        # Confidence Badge
        conf_label = resp.get("confidence_label", "İncelenmesi gerekiyor")
        conf_score = resp.get("confidence_score", 70)
        conf_color = resp.get("confidence_color", COLOR_STATE_WARNING)

        conf_badge = ctk.CTkLabel(
            header,
            text=f"● {conf_label} (%{conf_score})",
            font=("Segoe UI", 10, "bold"),
            text_color=conf_color
        )
        conf_badge.pack(side="left", padx=10)

        # Source badge
        source = resp.get("engine_source", "Kural Motoru")
        src_lbl = ctk.CTkLabel(
            header,
            text=source,
            font=("Segoe UI", 9),
            text_color=COLOR_TEXT_SECONDARY
        )
        src_lbl.pack(side="right")

        # Response text
        ans_text = resp.get("answer", "")
        body_lbl = ctk.CTkLabel(
            bubble,
            text=ans_text,
            font=FONT_BODY_MD,
            text_color=COLOR_TEXT_PRIMARY,
            wraplength=640,
            justify="left"
        )
        body_lbl.pack(anchor="w", padx=12, pady=(4, 8))

        # Evidence Drawer
        evidence_list = resp.get("evidence", [])
        if evidence_list:
            ev_btn = ctk.CTkButton(
                bubble,
                text="▼ Kanıtları Göster",
                height=24,
                width=120,
                fg_color=COLOR_CARD,
                hover_color=COLOR_BORDER,
                font=FONT_BODY_SM,
                text_color=COLOR_ACCENT_PRIMARY
            )
            ev_btn.pack(anchor="w", padx=12, pady=4)

            ev_box = ctk.CTkFrame(bubble, fg_color=COLOR_BG_MAIN, corner_radius=6, border_width=1, border_color=COLOR_BORDER)

            for ev in evidence_list:
                ev_str = f"• [{ev.get('kategori', ev.get('type', 'Kanıt'))}]: {ev.get('detay', str(ev.get('data', '')))}"
                lbl_ev = ctk.CTkLabel(ev_box, text=ev_str, font=FONT_CODE_SM, text_color=COLOR_TEXT_SECONDARY, justify="left")
                lbl_ev.pack(anchor="w", padx=8, pady=2)

            def toggle_evidence(btn=ev_btn, box=ev_box):
                if box.winfo_ismapped():
                    box.pack_forget()
                    btn.configure(text="▼ Kanıtları Göster")
                else:
                    box.pack(fill="x", padx=12, pady=(0, 8))
                    btn.configure(text="▲ Kanıtları Gizle")

            ev_btn.configure(command=toggle_evidence)

        # Human-in-the-loop Action Proposals
        actions = resp.get("actions", [])
        for act in actions:
            self._render_action_proposal(bubble, act)

        self._scroll_to_bottom()

    def _render_action_proposal(self, parent_frame, proposal: Dict[str, Any]):
        """Renders an action approval card with confirm and cancel buttons."""
        action_id = proposal["action_id"]
        desc = proposal["description"]
        risk = proposal.get("risk_level", "YÜKSEK")

        act_card = ctk.CTkFrame(parent_frame, fg_color="#1E1719", corner_radius=6, border_width=1, border_color=COLOR_STATE_CRITICAL)
        act_card.pack(fill="x", padx=12, pady=8)

        lbl_head = ctk.CTkLabel(
            act_card,
            text=f"⚠️ ÖNERİLEN GÜVENLİK AKSİYONU [{risk} RİSK]",
            font=("Segoe UI", 10, "bold"),
            text_color=COLOR_STATE_CRITICAL
        )
        lbl_head.pack(anchor="w", padx=10, pady=(6, 2))

        lbl_desc = ctk.CTkLabel(
            act_card,
            text=f"{desc}\nKomut: {proposal.get('command', '')}",
            font=FONT_BODY_SM,
            text_color=COLOR_TEXT_PRIMARY,
            justify="left"
        )
        lbl_desc.pack(anchor="w", padx=10, pady=2)

        btn_row = ctk.CTkFrame(act_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(4, 8))

        lbl_status = ctk.CTkLabel(btn_row, text="", font=FONT_BODY_SM)

        def on_confirm(btn_c, btn_r, status_lbl=lbl_status, a_id=action_id):
            btn_c.configure(state="disabled")
            btn_r.configure(state="disabled")
            res = action_guard.approve_and_execute(a_id)
            if res["success"]:
                status_lbl.configure(text=f"✓ {res['message']}", text_color=COLOR_STATE_SUCCESS)
            else:
                status_lbl.configure(text=f"✗ {res['message']}", text_color=COLOR_STATE_CRITICAL)
            status_lbl.pack(side="left", padx=8)

        def on_cancel(btn_c, btn_r, status_lbl=lbl_status, a_id=action_id):
            btn_c.configure(state="disabled")
            btn_r.configure(state="disabled")
            res = action_guard.reject(a_id, reason="Operatör tarafından iptal edildi")
            status_lbl.configure(text="İşlem iptal edildi.", text_color=COLOR_TEXT_SECONDARY)
            status_lbl.pack(side="left", padx=8)

        btn_confirm = ctk.CTkButton(
            btn_row,
            text="Onayla ve Uygula",
            height=26,
            width=120,
            fg_color=COLOR_STATE_SUCCESS,
            hover_color="#27946E",
            text_color="#FFFFFF",
            font=FONT_BODY_SM
        )
        btn_confirm.pack(side="left", padx=(0, 6))

        btn_reject = ctk.CTkButton(
            btn_row,
            text="İptal",
            height=26,
            width=70,
            fg_color=COLOR_CARD,
            hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_SECONDARY,
            font=FONT_BODY_SM
        )
        btn_reject.pack(side="left")

        btn_confirm.configure(command=lambda: on_confirm(btn_confirm, btn_reject))
        btn_reject.configure(command=lambda: on_cancel(btn_confirm, btn_reject))

    def _scroll_to_bottom(self):
        self.after(50, lambda: self.chat_container._parent_canvas.yview_moveto(1.0))
