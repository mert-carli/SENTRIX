import customtkinter as ctk
from core.translations import tr, get_glossary_term

# SENTRIX v5.0 — Profesyonel Kurumsal Koyu Renk Paleti (Section 5.2)
COLOR_BG_MAIN = "#0B111B"         # Ana arka plan
COLOR_BG_SECONDARY = "#111A27"    # İkincil yüzey
COLOR_CARD = "#162131"            # Kart yüzeyi
COLOR_BORDER = "#263447"          # İnce sınır çizgisi
COLOR_TEXT_PRIMARY = "#E8EDF4"    # Ana metin
COLOR_TEXT_SECONDARY = "#94A3B8"  # İkincil / yardımcı metin
COLOR_ACCENT = "#4F8FF7"          # Vurgu mavisi
COLOR_SUCCESS = "#31B88A"         # Başarılı / Güvenli
COLOR_WARNING = "#E9AD48"         # Uyarı / Dikkat
COLOR_CRITICAL = "#E56767"        # Kritik / Tehlike
COLOR_HOVER = "#1B273A"           # Buton üzerine gelme

# Geriye dönük uyumluluk takma adları
COLOR_ACCENT_PRIMARY = COLOR_ACCENT
COLOR_ACCENT_TERMINAL = COLOR_ACCENT
COLOR_STATE_SUCCESS = COLOR_SUCCESS
COLOR_STATE_CRITICAL = COLOR_CRITICAL
COLOR_STATE_WARNING = COLOR_WARNING

# Windows Modern Tipografi Hiyerarşisi (Segoe UI Variable & Consolas)
FONT_PAGE_TITLE = ("Segoe UI", 20, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_TITLE_MD = FONT_TITLE
FONT_SUBTITLE = ("Segoe UI", 13, "bold")
FONT_BTN = ("Segoe UI", 12, "bold")
FONT_TEXT = ("Segoe UI", 12)
FONT_BODY_LG = ("Segoe UI", 13)
FONT_BODY_MD = FONT_TEXT
FONT_BODY_SM = ("Segoe UI", 11)
FONT_CAPTION = ("Segoe UI", 11)
FONT_CODE = ("Consolas", 11)
FONT_CODE_SM = ("Consolas", 10)

def create_header(parent, text: str, subtitle: str = "") -> ctk.CTkFrame:
    """Başlık ve açıklama altlığı oluşturan standart başlık bloğu."""
    f = ctk.CTkFrame(parent, fg_color="transparent")
    f.pack(fill="x", padx=20, pady=(15, 10))
    lbl_title = ctk.CTkLabel(f, text=text, font=FONT_PAGE_TITLE, text_color=COLOR_TEXT_PRIMARY)
    lbl_title.pack(side="left")
    if subtitle:
        lbl_sub = ctk.CTkLabel(f, text=f"  // {subtitle}", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_sub.pack(side="left", padx=(5, 0), pady=(3, 0))
    return f

def create_card_frame(parent, fg_color: str = COLOR_CARD, border_color: str = COLOR_BORDER, corner_radius: int = 6, **kwargs) -> ctk.CTkFrame:
    """Temiz kenarlıklı, modern kart yüzeyi oluşturur."""
    return ctk.CTkFrame(
        parent, fg_color=fg_color, border_width=1,
        border_color=border_color, corner_radius=corner_radius, **kwargs
    )

def create_button(parent, text: str, command, is_danger: bool = False, is_accent: bool = False, height: int = 34, width: int = 140) -> ctk.CTkButton:
    if is_danger:
        fg = "#3A1417"
        hover = "#521B20"
        border = COLOR_CRITICAL
        text_color = COLOR_CRITICAL
    elif is_accent:
        fg = "#182C4A"
        hover = "#203B63"
        border = COLOR_ACCENT
        text_color = COLOR_ACCENT
    else:
        fg = COLOR_BG_SECONDARY
        hover = COLOR_HOVER
        border = COLOR_BORDER
        text_color = COLOR_TEXT_PRIMARY

    return ctk.CTkButton(
        parent, text=text, command=command, font=FONT_BTN,
        fg_color=fg, hover_color=hover, border_width=1,
        border_color=border, text_color=text_color,
        corner_radius=4, height=height, width=width
    )

def create_term_badge(parent, term: str) -> ctk.CTkButton:
    """Teknik terimler için üzerine tıklandığında açıklama gösteren bilgi rozeti."""
    info = get_glossary_term(term)
    
    def show_info():
        top = ctk.CTkToplevel(parent)
        top.title(info["title"])
        top.geometry("380x160")
        top.configure(fg_color=COLOR_BG_MAIN)
        top.transient(parent.winfo_toplevel())
        top.grab_set()

        lbl_t = ctk.CTkLabel(top, text=info["title"], font=FONT_TITLE, text_color=COLOR_ACCENT)
        lbl_t.pack(padx=20, pady=(20, 5), anchor="w")
        lbl_d = ctk.CTkLabel(top, text=info["desc"], font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY, wraplength=340, justify="left")
        lbl_d.pack(padx=20, pady=10, anchor="w")
        btn = ctk.CTkButton(top, text="Anladım", command=top.destroy, width=100, height=30, fg_color=COLOR_HOVER, text_color=COLOR_TEXT_PRIMARY)
        btn.pack(pady=(5, 15))

    btn_badge = ctk.CTkButton(
        parent, text=f"[{term} ?]", command=show_info,
        width=55, height=22, font=("Segoe UI", 10, "bold"),
        fg_color="transparent", text_color=COLOR_TEXT_SECONDARY,
        hover_color=COLOR_HOVER, corner_radius=3
    )
    return btn_badge

def create_textbox(parent, height: int = 300) -> ctk.CTkTextbox:
    tb = ctk.CTkTextbox(
        parent, font=FONT_CODE, corner_radius=4,
        fg_color="#070C13", text_color=COLOR_TEXT_PRIMARY,
        border_color=COLOR_BORDER, border_width=1
    )
    tb.tag_config("normal", foreground=COLOR_TEXT_PRIMARY)
    tb.tag_config("accent", foreground=COLOR_ACCENT)
    tb.tag_config("warning", foreground=COLOR_WARNING)
    tb.tag_config("danger", foreground=COLOR_CRITICAL)
    tb.tag_config("success", foreground=COLOR_SUCCESS)
    tb.tag_config("muted", foreground=COLOR_TEXT_SECONDARY)
    return tb

def safe_textbox_write(tb: ctk.CTkTextbox, text: str, tag: str = "normal", clear_first: bool = False):
    tb.configure(state="normal")
    if clear_first:
        tb.delete("0.0", "end")
    tb.insert("end", text, tag)
    tb.see("end")
    tb.configure(state="disabled")

class BaseWorkspaceView(ctk.CTkFrame):
    def __init__(self, parent, controller, title_tr_key: str = "", subtitle_tr_key: str = "", **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.controller = controller
        self.title_tr_key = title_tr_key
        self.subtitle_tr_key = subtitle_tr_key
        self.is_advanced_view = False

    def toggle_view_mode(self, on_toggle=None):
        """Temel ve Gelişmiş Görünüm arasında geçiş yapar."""
        self.is_advanced_view = not self.is_advanced_view
        if on_toggle:
            on_toggle(self.is_advanced_view)
