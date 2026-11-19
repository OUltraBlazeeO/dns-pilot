"""Semantic tokens shared by Qt controls, navigation, diagnostic graphics and previews."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Theme:
    name: str
    background: str
    sidebar: str
    surface: str
    raised: str
    border: str
    text: str
    muted: str
    accent: str
    action: str
    on_action: str
    selected: str
    success: str
    warning: str
    error: str
    heading: str
    data_font: str
    radius: int
    space: int
    row_height: int
    title_size: int


THEMES = {
    "utility": Theme("Dark Utility", "#101720", "#101820", "#19232e", "#22303c", "#394754",
                     "#f0f5f6", "#b0c0ca", "#32dfd6", "#38dbd3", "#092329", "#174849",
                     "#80e9af", "#ffdc79", "#ff9998", "Segoe UI", "Segoe UI", 7, 8, 30, 21),
    "aurora": Theme("Aurora Glass", "#100e32", "#161637", "#21264c", "#303963", "#58578b",
                    "#f6f5ff", "#c8c8e9", "#b4a5ff", "#aa91ff", "#160d39", "#453782",
                    "#74f2d5", "#ffdc93", "#ffa6c0", "Segoe UI Variable Display", "Segoe UI", 16, 14, 40, 24),
    "coral": Theme("Editorial / Coral", "#fbf8f4", "#f5eee9", "#fffdfb", "#f3ebe6", "#cbbfb9",
                   "#142943", "#4c5c6e", "#9f382e", "#f58b79", "#341b1e", "#ffdbce",
                   "#14643a", "#805300", "#9d283a", "Georgia", "Segoe UI", 10, 13, 41, 27),
    "lab": Theme("Network Lab", "#070b0c", "#090e0f", "#0c1214", "#141e1c", "#3b4944",
                 "#e5ece7", "#a6b8ae", "#ffc14c", "#f6ba43", "#201707", "#3d3018",
                 "#78f099", "#ffd677", "#ff9c8a", "Bahnschrift", "Consolas", 3, 6, 28, 19),
}


def stylesheet(key: str) -> str:
    t = THEMES[key]
    panel, backdrop, active = t.surface, t.background, t.selected
    if key == "aurora":
        backdrop = "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #0c1833,stop:0.62 #282053,stop:1 #121331)"
        panel = "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 rgba(46,64,103,215),stop:1 rgba(45,33,88,218))"
        active = "qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #293c79,stop:1 #543c89)"
    r = t.radius
    control = max(2, r-3)
    padding = t.space//2 + 2
    return f"""
    QWidget {{color:{t.text};font-family:'Segoe UI';font-size:10pt;}}
    QMainWindow,QDialog,QMessageBox {{background:{backdrop};}}
    QScrollArea,QStackedWidget,QWidget#page,QScrollArea > QWidget > QWidget {{background:transparent;}}
    QWidget#sidebar {{background:{t.sidebar};border-right:1px solid {t.border};}}
    QWidget#card {{background:{panel};border:1px solid {t.border};border-radius:{r}px;}}
    QLabel {{background:transparent;}} QLabel#muted {{color:{t.muted};}}
    QLabel#brand {{font-family:'{t.heading}';font-size:18pt;font-weight:700;}}
    QLabel#title {{font-family:'{t.heading}';font-size:{t.title_size}pt;font-weight:700;}}
    QLabel#cardTitle {{font-family:'{t.heading}';font-size:{11 if key != 'coral' else 14}pt;font-weight:600;}}
    QLabel#accent {{color:{t.accent};font:600 12pt '{t.data_font}';}}
    QLabel#banner {{background:{panel};color:{t.muted};border:1px solid {t.border};border-radius:{control}px;padding:{padding}px 11px;}}
    QPushButton {{background:{t.raised};border:1px solid {t.border};padding:{padding}px 11px;border-radius:{control}px;}}
    QPushButton:hover,QToolButton:hover {{border-color:{t.accent};}}
    QPushButton:disabled {{color:{t.muted};background:{t.surface};}}
    QPushButton#primary {{background:{t.action};color:{t.on_action};border-color:{t.action};font-weight:650;}}
    QPushButton#nav {{text-align:left;border:1px solid transparent;background:transparent;padding:{padding+2}px 10px;}}
    QPushButton#nav:checked {{background:{active};color:{t.text};border-left:3px solid {t.accent};}}
    QPushButton#preview {{border:2px solid {t.border};background:{t.surface};padding:5px;}}
    QPushButton#preview:checked {{border:2px solid {t.accent};background:{t.selected};}}
    QPushButton:focus,QLineEdit:focus,QComboBox:focus,QPlainTextEdit:focus,QSpinBox:focus {{border:2px solid {t.accent};}}
    QLineEdit,QPlainTextEdit,QComboBox,QSpinBox,QListWidget,QTableWidget {{background:{t.surface};
        alternate-background-color:{t.raised};border:1px solid {t.border};border-radius:{control}px;padding:{padding-1}px;
        selection-background-color:{t.selected};selection-color:{t.text};}}
    QLineEdit,QPlainTextEdit,QTableWidget {{font-family:'{t.data_font}';}}
    QAbstractItemView {{background:{t.surface};color:{t.text};selection-background-color:{t.selected};selection-color:{t.text};}}
    QHeaderView::section,QTableCornerButton::section {{background:{t.raised};color:{t.muted};border:0;border-bottom:1px solid {t.border};padding:{padding}px;}}
    QToolTip,QMenu {{background:{t.surface};color:{t.text};border:1px solid {t.border};padding:4px;}}
    QProgressBar {{border:0;background:{t.border};border-radius:2px;max-height:6px;}} QProgressBar::chunk {{background:{t.accent};}}
    QCheckBox {{spacing:7px;}} QCheckBox::indicator {{width:14px;height:14px;border:1px solid {t.muted};border-radius:{min(4,r)}px;background:{t.surface};}}
    QCheckBox::indicator:checked {{background:{t.accent};border:3px solid {t.selected};}}
    QScrollArea {{border:0;}} QScrollBar:vertical {{width:10px;background:{t.background};}}
    QScrollBar::handle:vertical {{background:{t.border};min-height:22px;border-radius:4px;}}
    QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{height:0;}}
    """
