from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QHBoxLayout, QHeaderView, QLabel, QListWidget, QListWidgetItem,
                               QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)


def label(text="", role=""):
    w = QLabel(text)
    w.setTextFormat(Qt.TextFormat.PlainText)
    w.setWordWrap(True)
    w.setObjectName(role)
    w.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return w


def button(text, action, role=""):
    w = QPushButton(text)
    w.setObjectName(role)
    w.clicked.connect(lambda _checked=False: action())
    w.setCursor(Qt.CursorShape.PointingHandCursor)
    return w


def row(*widgets):
    w = QWidget()
    layout = QHBoxLayout(w)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    for item in widgets:
        layout.addWidget(item)
    return w


def card(title, *widgets):
    w = QWidget()
    w.setObjectName("card")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(18, 15, 18, 17)
    lay.setSpacing(10)
    lay.addWidget(label(title, "cardTitle"))
    for child in widgets:
        lay.addWidget(child)
    return w


def table(headings):
    t = QTableWidget(0, len(headings))
    t.setHorizontalHeaderLabels(headings)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.verticalHeader().hide()
    t.verticalHeader().setDefaultSectionSize(36)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    t.horizontalHeader().setStretchLastSection(True)
    t.setShowGrid(False)
    t.setAlternatingRowColors(True)
    t.setMinimumHeight(155)
    return t


def append(t, values, data=None):
    n = t.rowCount()
    t.insertRow(n)
    for col, value in enumerate(values):
        item = QTableWidgetItem(str(value))
        item.setToolTip(str(value))
        if col == 0:
            item.setData(Qt.ItemDataRole.UserRole, data)
        t.setItem(n, col, item)


def selected(t):
    item = t.item(t.currentRow(), 0)
    return item.data(Qt.ItemDataRole.UserRole) if item else None


def choose(parent, title, choices, checked):
    d = QDialog(parent)
    d.setWindowTitle(title)
    d.resize(600, 460)
    lay = QVBoxLayout(d)
    lst = QListWidget()
    for key, text in choices:
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, key)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(Qt.CheckState.Checked if key in checked else Qt.CheckState.Unchecked)
        lst.addItem(item)
    lay.addWidget(lst)
    ok = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    ok.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
    ok.accepted.connect(d.accept)
    ok.rejected.connect(d.reject)
    lay.addWidget(ok)
    if d.exec():
        return [lst.item(i).data(Qt.ItemDataRole.UserRole) for i in range(lst.count()) if lst.item(i).checkState() == Qt.CheckState.Checked]
    return None
