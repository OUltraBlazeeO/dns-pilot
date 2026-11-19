from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import math
import os
import statistics
import sys
import urllib.request
from dataclasses import asdict, replace
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QByteArray, QPropertyAnimation, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFileDialog,
                               QGraphicsOpacityEffect, QGridLayout, QHBoxLayout, QLineEdit, QMainWindow,
                               QMessageBox, QPlainTextEdit, QProgressBar, QScrollArea, QSpinBox,
                               QStackedWidget, QTableWidget, QVBoxLayout, QWidget)

from .desktop import BROWSERS, Job, batch, browser_path, open_browser, system_check
from .diagnostics import Checker, ranking
from .model import PROVIDERS, Server, presets, url
from .widgets import append, button, card, choose, label, row, selected, table
from .appearance import THEMES, stylesheet
from .visuals import LatencyPlot, Rail, StageChart, brand_mark, theme_thumbnail
from .windows import Manager, addresses, inventory, primary, supports_doh

PAGES = ["Главная", "Проверка сайтов", "Сравнение DNS", "DNS-серверы", "Настройки сети", "Браузеры", "История", "Настройки приложения"]
MODES = {"auto": "автоматически", "manual": "вручную", "unknown": "не удалось определить"}


def edit(hint, value=""):
    w = QLineEdit(value)
    w.setPlaceholderText(hint)
    w.setClearButtonEnabled(True)
    return w


def multi(value):
    w = QPlainTextEdit(value)
    w.setMaximumHeight(88)
    w.setPlaceholderText("По одному домену или URL на строку")
    return w


def spin(value, maximum):
    w = QSpinBox()
    w.setRange(1, maximum)
    w.setValue(value)
    return w


def check(title, value):
    w = QCheckBox(title)
    w.setChecked(value)
    return w


def sites_of(field):
    sites = list(dict.fromkeys(url(line) for line in field.toPlainText().splitlines() if line.strip()))
    if not sites:
        raise ValueError("Введите хотя бы один сайт.")
    return sites


def pretty(record):
    lines = [record["site"], f'{record["name"]} · {record["server"]} · {record["protocol"]}', record.get("dns_status", ""), record["summary"],
             f'Общее время {record["total_ms"]} мс · DNS-тайм-ауты {record["timeouts"]}']
    for h in record["hops"]:
        lines += ["", h["url"]]
        for q in h["queries"]:
            info = q.get("error") or (q.get("rcode", "") + " " + ", ".join(q.get("ips", [])))
            lines.append(f'  DNS {q["type"]} · {q.get("protocol", "")} · {q["ms"]} мс · {info}')
            if q.get("bootstrap"):
                lines.append(f'  Bootstrap {q["bootstrap"]} · {q.get("bootstrap_source", "заданный IP")}')
        for a in h["attempts"]:
            parts = [a["ip"]]
            for stage in ("tcp", "tls", "http"):
                if stage + "_ms" in a:
                    parts.append(f'{stage.upper()} {a[stage + "_ms"]} мс')
            lines.append("  " + " · ".join(parts))
            if "error" in a:
                lines.append("  " + a["error"])
        if h.get("redirect"):
            lines.append("  → " + h["redirect"])
    return "\n".join(lines)


class Window(QMainWindow):
    def __init__(self, store, settings, detect=True):
        super().__init__()
        self.store, self.s = store, settings
        self.manager = Manager(store.root)
        self.jobs = set()
        self.probe = None
        self.changing = self.reading = False
        self.adapters = []
        self.best = None
        self.results = []
        self.required = set()
        self.selections = [["1.1.1.1"], ["1.1.1.1", "8.8.8.8", "9.9.9.9"]]
        self.setWindowTitle("DNS Pilot")
        self.resize(1160, 790)
        self.setMinimumSize(720, 510)
        self.plot_records = store.records(80)[::-1]
        self.latest = self.plot_records[-1] if self.plot_records else None
        self.home_signature = None
        root = QWidget()
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        side = Rail()
        self.sidebar = side
        side.setObjectName("sidebar")
        side.setFixedWidth(223)
        nav = QVBoxLayout(side)
        nav.setContentsMargins(12, 22, 12, 18)
        self.brand = label("DNS Pilot", "brand")
        self.mark = label()
        self.mark.setFixedSize(38,38)
        self.mark.setScaledContents(True)
        nav.addWidget(row(self.mark,self.brand))
        nav.addSpacing(22)
        self.nav = []
        for i, title in enumerate(PAGES):
            b = button(title, lambda n=i: self.go(n), "nav")
            b.setToolTip(title)
            b.setAccessibleName(title)
            b.setCheckable(True)
            self.nav.append(b)
            nav.addWidget(b)
        nav.addStretch()
        self.rail_footer = label("DNS Pilot   /   1.1", "muted")
        nav.addWidget(self.rail_footer)
        shell.addWidget(side)
        body = QVBoxLayout()
        body.setContentsMargins(20, 16, 20, 16)
        body.setSpacing(10)
        self.banner = label("Определение подключения…", "banner")
        body.addWidget(self.banner)
        self.title = label("", "title")
        body.addWidget(self.title)
        self.stack = QStackedWidget()
        body.addWidget(self.stack, 1)
        self.stage_line = label("Готово к проверке", "muted")
        self.stop = button("Отменить", self.cancel)
        self.stop.hide()
        body.addWidget(row(self.stage_line, self.stop))
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.hide()
        body.addWidget(self.bar)
        shell.addLayout(body, 1)
        self.page_layouts = []
        for _ in PAGES:
            viewport = QScrollArea()
            viewport.setWidgetResizable(True)
            page = QWidget()
            page.setObjectName("page")
            layout = QVBoxLayout(page)
            layout.setContentsMargins(1, 2, 8, 6)
            layout.setSpacing(12)
            self.page_layouts.append(layout)
            viewport.setWidget(page)
            self.stack.addWidget(viewport)
        self.home()
        self.test_pages()
        self.catalog()
        self.network()
        self.browsers()
        self.history()
        self.settings_page()
        self.apply_theme(self.s.theme if self.s.theme in THEMES else "utility", persist=False)
        self.populate_servers()
        self.refresh_history()
        if self.s.geometry:
            self.restoreGeometry(QByteArray.fromBase64(self.s.geometry.encode()))
        self.go(0)
        if detect:
            QTimer.singleShot(0, self.refresh_network)

    def go(self, index):
        for i, b in enumerate(self.nav):
            b.setChecked(i == index)
        self.title.setText(PAGES[index])
        self.stack.setCurrentIndex(index)
        eff = QGraphicsOpacityEffect(self.stack)
        self.stack.setGraphicsEffect(eff)
        self.fade = QPropertyAnimation(eff, b"opacity", self)
        self.fade.setDuration(125)
        self.fade.setStartValue(0.72)
        self.fade.setEndValue(1.0)
        self.fade.finished.connect(lambda: self.stack.setGraphicsEffect(None))
        self.fade.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def home(self):
        lay = self.page_layouts[0]
        self.home_grid = QGridLayout()
        lay.addLayout(self.home_grid)
        self.net_name, self.net_info = label("Определение…", "accent"), label("", "muted")
        self.dns_name, self.dns_info = label("—", "accent"), label("", "muted")
        self.network_card = card("Активная сеть", self.net_name, self.net_info)
        self.dns_card = card("Текущий DNS", self.dns_name, self.dns_info)
        self.quick = edit("Домен или полный URL", "wikipedia.org")
        self.quick_dns = QComboBox()
        self.quick_dns.setEditable(True)
        self.quick_dns.setToolTip("Выберите сохранённый DNS или введите IP / HTTPS URL.")
        self.quick_dns.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.quick_card = card("Быстрая проверка", self.quick, self.quick_dns, button("Проверить", self.quick_start, "primary"))
        self.best_info = label("Запустите сравнение, чтобы выбрать DNS для ваших сайтов.", "muted")
        self.best_apply = button("Применить…", self.preview_best)
        self.best_apply.setEnabled(False)
        self.recommend_card = card("Рекомендованный DNS", self.best_info, button("Подобрать лучший DNS", lambda: self.go(2)), self.best_apply)
        self.home_chart = StageChart()
        self.latency_plot = LatencyPlot()
        self.plot_card = card("Задержка DNS", self.latency_plot)
        self.lab_route = label("", "accent")
        self.lab_terminal = QPlainTextEdit()
        self.lab_terminal.setReadOnly(True)
        self.lab_terminal.setMaximumHeight(110)
        self.lab_box = card("Журнал диагностики", self.lab_route, self.lab_terminal)
        self.recent = table(["Время", "Сайт", "Результат"])
        self.recent.doubleClicked.connect(lambda _: self.detail(selected(self.recent)))
        self.history_card = card("Последние проверки", self.recent)
        lay.addStretch()

    def arrange_home(self):
        key = self.s.theme
        compact = self.width() < 990
        if self.home_signature == (key, compact):
            return
        self.home_signature = key, compact
        grid = self.home_grid
        while grid.count():
            grid.takeAt(0)
        blocks = {"network":self.network_card,"dns":self.dns_card,"quick":self.quick_card,"pick":self.recommend_card,
                  "stages":self.home_chart,"history":self.history_card,"log":self.lab_box,"plot":self.plot_card}
        rows = {
            "utility":[("network","dns"),("quick","pick"),("stages","plot"),("history",)],
            "aurora":[("network","dns"),("stages",),("quick","pick"),("plot","history")],
            "coral":[("quick","network"),("stages","dns"),("pick","plot"),("history",)],
            "lab":[("network","dns"),("quick","stages"),("log","plot"),("history","pick")],
        }[key]
        self.lab_box.setVisible(key == "lab")
        if compact:
            rows = [(name,) for group in rows for name in group]
        for r, group in enumerate(rows):
            for c, name in enumerate(group):
                grid.addWidget(blocks[name],r,c,1,2 if len(group)==1 else 1)
        grid.setColumnStretch(0,3 if key in ("lab","coral") else 1)
        grid.setColumnStretch(1,2 if key in ("lab","coral") else 1)
        grid.setSpacing(THEMES[key].space)

    def refresh_charts(self):
        self.latency_plot.configure(self.s.theme,self.plot_records)
        for chart in (self.home_chart,self.check_chart):
            chart.configure(self.s.theme,self.latest)
        record = self.latest
        if record:
            self.lab_route.setText("ПК  →  " + record["server"] + "  →  " + record["site"])
            self.lab_terminal.setPlainText(pretty(record))
        else:
            self.lab_route.setText("ПК  →  DNS  →  сайт")
            self.lab_terminal.setPlainText("Ожидание первой проверки")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self,"theme_buttons"):
            self.arrange_home()
            self.nav_size()

    def nav_size(self):
        compact = self.width() < 990
        self.sidebar.setFixedWidth(78 if compact else (218 if self.s.theme == "lab" else 228))
        self.brand.setVisible(not compact)
        self.rail_footer.setVisible(not compact)
        for i,b in enumerate(self.nav):
            b.setText("" if compact else PAGES[i])

    def test_pages(self):
        self.fields, self.pick_buttons = [], []
        for i in range(2):
            lay = self.page_layouts[i+1]
            field = multi(self.s.sites)
            self.fields.append(field)
            pick = button("", lambda n=i: self.pick(n))
            self.pick_buttons.append(pick)
            controls = [pick]
            if i:
                self.must = button("Обязательные сайты…", self.pick_required)
                controls.append(self.must)
            controls.append(button("Подобрать лучший DNS" if i else "Запустить проверку", lambda n=i: self.launch(n), "primary"))
            lay.addWidget(card("Сайты для проверки", field, row(*controls)))
        self.test_table = table(["Сайт", "DNS", "DNS, мс", "HTTP", "Всего, мс", "Результат"])
        self.check_chart = StageChart()
        self.page_layouts[1].addWidget(self.check_chart)
        self.test_table.setToolTip("Дважды нажмите на строку, чтобы увидеть адреса, ответы DNS и время каждого этапа.")
        self.test_table.doubleClicked.connect(lambda _: self.detail(selected(self.test_table)))
        self.page_layouts[1].addWidget(self.test_table, 1)
        self.run_summary = label("", "muted")
        self.page_layouts[1].addWidget(self.run_summary)
        self.page_layouts[1].addWidget(row(button("Подробности", lambda: self.detail(selected(self.test_table))),
                                            button("Скопировать", lambda: self.copy_table(self.test_table))))
        self.live_detail = QPlainTextEdit()
        self.live_detail.setReadOnly(True)
        self.live_detail.setMaximumHeight(150)
        self.live_detail.setVisible(self.s.detailed)
        self.page_layouts[1].addWidget(self.live_detail)
        self.test_table.itemSelectionChanged.connect(self.show_inline)
        self.rank_note = label("Для рекомендации нужны успешные HTTPS-проверки. Обязательный сайт должен пройти каждый повтор.", "muted")
        self.sort = QComboBox()
        self.sort.setToolTip("Медиана DNS измеряется по успешным разрешениям. NOERROR включает ответы без записей запрошенного типа.")
        self.sort.addItems(["По рекомендации", "По скорости DNS", "По надёжности DNS", "По успешным HTTPS"])
        self.sort.currentIndexChanged.connect(self.draw_ranking)
        self.rank_table = table(["DNS", "HTTPS", "Надёжность", "Медиана DNS"])
        self.page_layouts[2].addWidget(row(self.sort, button("Применить рекомендацию…", self.preview_best)))
        self.page_layouts[2].addWidget(self.rank_table, 1)
        self.page_layouts[2].addWidget(self.rank_note)
        self.rank_table.cellDoubleClicked.connect(self.rank_details)
        self.page_layouts[2].addWidget(button("Скопировать сравнение", self.copy_rank))

    def catalog(self):
        lay = self.page_layouts[3]
        self.editing_address = None
        self.catalog_actions = row(button("Добавить DNS", self.new_custom, "primary"),
                                   button("Редактировать", self.edit_custom),
                                   button("Удалить", self.remove_custom))
        lay.addWidget(self.catalog_actions)
        self.serv_table = table(["Провайдер", "Протокол", "Основной DNS / DoH URL", "Резервный DNS"])
        lay.addWidget(self.serv_table, 1)
        self.catalog_tools = row(button("Проверить соединение", self.test_selected),
                                 button("Проверить сайт", self.catalog_test))
        lay.addWidget(self.catalog_tools)
        self.custom_name = edit("Название")
        self.custom_type = QComboBox()
        self.custom_type.addItems(["Обычный DNS · IPv4 / IPv6", "DNS-over-HTTPS"])
        self.custom_addr = edit("Основной DNS · IP-адрес")
        self.custom_secondary = edit("Резервный DNS · необязательно")
        self.custom_boot = edit("Bootstrap IP для DoH (необязательно)")
        self.bootstrap_note = label("Без bootstrap IP Windows разрешит имя DoH-сервера. Проверяемый домен будет отправлен на указанный HTTPS URL.", "muted")
        self.editor = card("Параметры сервера", row(self.custom_name, self.custom_type), self.custom_addr,
                           self.custom_secondary, self.custom_boot, self.bootstrap_note,
                           row(button("Проверить соединение", self.test_draft),
                               button("Сохранить", self.add_custom, "primary"), button("Отмена", self.close_editor)))
        lay.addWidget(self.editor)
        self.catalog_report = label("", "muted")
        lay.addWidget(self.catalog_report)
        self.custom_type.currentIndexChanged.connect(self.editor_mode)
        for field in (self.custom_addr, self.custom_boot, self.custom_secondary):
            field.textChanged.connect(self.catalog_report.clear)
        self.serv_table.itemSelectionChanged.connect(self.catalog_report.clear)
        self.close_editor()

    def profiles(self):
        profiles = {s.address: s for s in presets()}
        for item in self.s.custom:
            s = Server(**item)
            profiles[s.address] = s
        return list(profiles.values())

    def servers(self):
        endpoints = {s.address: s for s in presets()}
        custom = [Server(**item) for item in self.s.custom]
        for profile in custom:
            for endpoint in profile.endpoints():
                endpoints[endpoint.address] = endpoint
        # An explicit user profile supplies the display name for its primary IP.
        for profile in custom:
            endpoints[profile.address] = profile.endpoints()[0]
        return list(endpoints.values())

    def populate_servers(self):
        quick_address = self.quick_dns.currentData()
        draft_text = self.quick_dns.currentText()
        typed = draft_text and self.quick_dns.findText(draft_text) < 0
        self.quick_dns.clear()
        self.serv_table.setRowCount(0)
        for s in self.servers():
            self.quick_dns.addItem(s.label, s.address)
        if typed:
            self.quick_dns.setEditText(draft_text)
        elif self.quick_dns.findData(quick_address) >= 0:
            self.quick_dns.setCurrentIndex(self.quick_dns.findData(quick_address))
        self.net_profiles.clear()
        self.net_profiles.addItem("Ввести вручную или выбрать из каталога…", None)
        for s in self.profiles():
            append(self.serv_table, [s.name, "DoH" if s.doh else f"IPv{ipaddress.ip_address(s.address).version}",
                                     s.address, s.secondary or "—"], s.address)
            if not s.doh:
                self.net_profiles.addItem(s.label + (" / " + s.secondary if s.secondary else ""), s.address)
        self.serv_table.setColumnWidth(0, 175)
        self.serv_table.setColumnWidth(1, 105)
        self.serv_table.setColumnWidth(2, 260)
        self.pick_labels()
        self.browser_list()
        self.win_endpoint.clear()
        for s in self.servers():
            if s.doh:
                self.win_endpoint.addItem(s.name, s.address)
        self.system_template()

    def close_editor(self):
        self.editor.hide()
        self.catalog_tools.show()
        self.editing_address = None
        self.catalog_report.clear()

    def editor_mode(self):
        doh = self.custom_type.currentIndex() == 1
        self.custom_addr.setPlaceholderText("HTTPS URL для DoH" if doh else "Основной DNS · IP-адрес")
        self.custom_secondary.setVisible(not doh)
        self.custom_boot.setVisible(doh)
        self.bootstrap_note.setVisible(doh)
        self.catalog_report.clear()

    def open_editor(self, profile=None):
        self.editing_address = profile.address if profile else None
        self.custom_type.setCurrentIndex(int(bool(profile and profile.doh)))
        self.custom_name.setText(profile.name if profile else "")
        self.custom_addr.setText(profile.address if profile else "")
        self.custom_secondary.setText(profile.secondary if profile else "")
        self.custom_boot.setText(profile.bootstrap if profile else "")
        self.editor_mode()
        self.catalog_tools.hide()
        self.editor.show()
        self.custom_name.setFocus()

    def new_custom(self):
        self.open_editor()

    def selected_profile(self, *, custom=False):
        addr = selected(self.serv_table)
        profiles = [Server(**v) for v in self.s.custom] if custom else self.profiles()
        profile = next((s for s in profiles if s.address == addr), None)
        if profile is None:
            raise ValueError("Выберите пользовательский сервер." if custom else "Выберите сервер в каталоге.")
        return profile

    def edit_custom(self):
        self.open_editor(self.selected_profile(custom=True))

    def draft_profile(self):
        doh = self.custom_type.currentIndex() == 1
        addr = self.custom_addr.text().strip()
        if doh:
            addr = url(addr, doh=True)
        elif "://" in addr:
            raise ValueError("Для HTTPS URL выберите DNS-over-HTTPS.")
        s = Server(self.custom_name.text().strip(), addr,
                   self.custom_boot.text().strip() if doh else "",
                   "" if doh else self.custom_secondary.text().strip())
        for raw in ([s.bootstrap] if doh else [s.address, s.secondary]):
            if raw:
                ip = ipaddress.ip_address(raw)
                if ip.is_unspecified or ip.is_multicast or str(ip) == "255.255.255.255":
                    raise ValueError("Введите индивидуальный IP-адрес DNS-сервера.")
        return s

    def update_custom(self, original, replacement):
        network_choice = self.net_profiles.currentData()
        items = [v for v in self.s.custom if Server(**v).address != original]
        if replacement:
            if any(Server(**v).address == replacement.address for v in items):
                raise ValueError("Этот основной адрес уже есть в пользовательском каталоге.")
            items.append(asdict(replacement))
        previous = next((s for s in self.profiles() if s.address == original), None)
        saved = replace(self.s, custom=items)
        self.store.save(saved)
        self.s.custom = items
        existing = {v.address for v in self.servers()}
        if previous:
            changed = {previous.address: replacement.address if replacement else None}
            if previous.secondary:
                changed[previous.secondary] = replacement.secondary if replacement else None
            for i, choices in enumerate(self.selections):
                updated = [changed.get(v) or (v if v in existing or v not in changed else None) for v in choices]
                self.selections[i] = list(dict.fromkeys(v for v in updated if v))
        self.populate_servers()
        if network_choice:
            if network_choice == original:
                network_choice = replacement.address if replacement and not replacement.doh else None
            idx = self.net_profiles.findData(network_choice)
            if idx > 0:
                self.net_profiles.setCurrentIndex(idx)
                self.load_network_profile(idx)
            else:
                self.pref.clear()
                self.alt.clear()
        self.close_editor()
        if replacement:
            for idx in range(self.serv_table.rowCount()):
                if self.serv_table.item(idx, 0).data(Qt.ItemDataRole.UserRole) == replacement.address:
                    self.serv_table.selectRow(idx)
                    self.serv_table.scrollToItem(self.serv_table.item(idx, 0))
                    break

    def add_custom(self):
        self.update_custom(self.editing_address, self.draft_profile())
        self.stage_line.setText("Сервер сохранён")

    def remove_custom(self):
        s = self.selected_profile(custom=True)
        if self.ask("Удалить сервер?", s.label):
            self.update_custom(s.address, None)
            self.stage_line.setText("Сервер удалён из каталога")

    def test_selected(self):
        self.start_dns_probe(self.selected_profile())

    def test_draft(self):
        self.start_dns_probe(self.draft_profile())

    def start_dns_probe(self, profile):
        if self.probe or self.changing:
            raise ValueError("Дождитесь окончания текущей операции или отмените проверку.")
        controls = (self.editor, self.serv_table, self.catalog_tools, self.catalog_actions)
        for widget in controls:
            widget.setEnabled(False)
        self.stop.show()
        self.catalog_report.setText("Выполняется DNS-запрос к " + profile.name + "…")
        self.stage_line.setText("Проверка DNS · example.org")
        settings = replace(self.s)
        async def run(_):
            return await Checker(settings).probe_server(profile)
        def done(results):
            lines = []
            for i, info in enumerate(results):
                role = "Резервный" if i else "Основной"
                response = "Ответ DNS · " + info["rcode"] if "rcode" in info else info.get("error", "Нет ответа")
                if info.get("error") and info.get("rcode") == "NOERROR":
                    response += " · " + info["error"]
                lines.append(f'{role} · {info["address"]} · {info["protocol"]} · {response} · {info["ms"]:.1f} мс')
            self.catalog_report.setText("\n".join(lines))
            self.stage_line.setText("Проверка соединения завершена")
        def end():
            self.probe = None
            self.stop.hide()
            for widget in controls:
                widget.setEnabled(True)
        self.probe = self.job(run, done, end=end, error=self.catalog_report.setText)
        self.probe.stopped.connect(lambda: self.catalog_report.setText("Проверка отменена"))

    def catalog_test(self):
        self.selections[0] = [s.address for s in self.selected_profile().endpoints()]
        self.pick_labels()
        self.go(1)

    def pick(self, index):
        picked = choose(self, "Выбор DNS-серверов", [(s.address, s.label) for s in self.servers()], self.selections[index])
        if picked is not None:
            self.selections[index] = picked
            self.pick_labels()

    def pick_labels(self):
        for i, b in enumerate(self.pick_buttons):
            b.setText(f"Выбрать DNS · {len(self.selections[i])}")
            b.setToolTip("\n".join(self.selections[i]))

    def pick_required(self):
        choices = sites_of(self.fields[1])
        picked = choose(self, "Обязательные сайты", [(v, v) for v in choices], self.required)
        if picked is not None:
            self.required = set(picked)
            self.must.setText(f"Обязательные сайты · {len(picked)}")

    def quick_start(self):
        text = self.quick_dns.currentText()
        s = next((s for s in self.servers() if text in (s.label, s.address)), None) or Server("Введённый DNS", text)
        target = url(self.quick.text())
        self.go(1)
        self.fields[0].setPlainText(target)
        self.selections[0] = [s.address]
        self.pick_labels()
        self.start_test([s], [target], False)

    def launch(self, i):
        selected_addresses = self.selections[i]
        lookup = {s.address: s for s in self.servers()}
        servers = [lookup.get(a) or Server("Введённый DNS", a) for a in selected_addresses]
        if not ((2 if i else 1) <= len(servers) <= 20):
            raise ValueError("Выберите от 2 до 20 DNS." if i else "Выберите от 1 до 20 DNS.")
        self.start_test(servers, sites_of(self.fields[i]), bool(i))

    def start_test(self, servers, sites, compare):
        if self.probe or self.changing:
            raise ValueError("Дождитесь окончания операции или отмените проверку.")
        must = self.required.intersection(sites)
        auto = None
        if compare and self.s.auto_apply:
            auto = self.adapter()
            candidates = "\n".join(s.address for s in servers if not s.doh)
            if not self.ask("Разрешить однократное применение?", self.adapter_text(auto) +
                            "\nПосле завершения победитель заменит список своего семейства одним проверенным IP.\nКандидаты:\n" +
                            (candidates or "Только DoH — настройка вручную") + "\nДля изменения Windows потребуется UAC."):
                return
        if compare:
            self.best = None
            self.results = []
            self.best_apply.setEnabled(False)
            self.best_info.setText("Сравнение выполняется…")
            self.rank_table.setRowCount(0)
        settings = replace(self.s)
        self.test_table.setRowCount(0)
        self.run_summary.clear()
        self.bar.setRange(0, len(servers)*len(sites)*settings.repeats)
        self.bar.setValue(0)
        self.bar.show()
        self.stop.show()
        self.stage_line.setText("Начало проверки…")
        def finished(results):
            self.stage_line.setText(f"Проверка завершена · {len(results)} измерений")
            stats = []
            for server in servers:
                group = [r for r in results if r.server == server.address]
                queries = sum(r.queries for r in group)
                times = [r.dns_ms for r in group if r.dns_ms is not None]
                median = f"{statistics.median(times):.1f} мс" if times else "—"
                rate = f"{sum(r.answered for r in group)/queries:.0%}" if queries else "—"
                stats.append(f"{server.address} · DNS NOERROR {rate} · тайм-аутов {sum(r.timeouts for r in group)} · медиана {median}")
            self.run_summary.setText("\n".join(stats))
            if compare:
                self.results, self.ranked_sites, self.ranked_required = results, sites, must
                ranks = ranking(results, must)
                self.best = next((r for r in ranks if r["eligible"]), None)
                self.draw_ranking()
                note = "Подходящий DNS не найден."
                if self.best:
                    r = self.best
                    note = f'{r["address"]} · HTTPS {r["wins"]}/{r["runs"]} · успешные DNS-ответы {r["reliability"]:.0%} · медиана {r["median"]:.1f} мс'
                self.best_info.setText(note)
                self.best_apply.setEnabled(bool(self.best))
                self.rank_note.setText(note + "\nПорядок выбора: обязательные сайты во всех повторах → число успешных HTTPS → доля DNS-ответов NOERROR → меньшая медиана DNS.")
                if auto and self.best and not self.best["address"].startswith("https:"):
                    addr = self.best["address"]
                    self.commit(auto, ipaddress.ip_address(addr).version, [addr], sites[0])
        def end():
            self.probe = None
            self.stop.hide()
            self.bar.hide()
            self.refresh_history()
        self.probe = self.job(lambda emit: batch(servers, sites, settings, emit), finished, end=end, progress=self.progress)

    def progress(self, event):
        if event[0] == "stage":
            _, tag, current = event
            self.stage_line.setText("  →  ".join(f"【{v}】" if v == current else v for v in ("DNS","TCP","TLS","HTTP")) + "    " + tag)
            return
        r = event[1]
        if self.s.history:
            self.store.add(r)
        append(self.test_table, [r.site, r.server, r.dns_ms if r.dns_ms is not None else "—", r.code or "—", r.total_ms, r.summary], r.record())
        self.latest = r.record()
        self.plot_records = (self.plot_records+[self.latest])[-80:]
        self.refresh_charts()
        self.color_result(self.test_table.rowCount()-1)
        self.test_table.selectRow(self.test_table.rowCount()-1)
        self.bar.setValue(self.bar.value()+1)
        if self.s.detailed:
            logging.info("%s", pretty(r.record()))

    def cancel(self):
        if self.probe:
            self.probe.cancel()

    def draw_ranking(self, *_):
        if not self.results:
            return
        rows = ranking(self.results, self.ranked_required)
        index = self.sort.currentIndex()
        if index:
            key = ("median", "reliability", "wins")[index-1]
            rows.sort(key=lambda r: r[key], reverse=index != 1)
        sites = self.ranked_sites
        self.rank_table.setRowCount(0)
        self.rank_table.setColumnCount(4+len(sites))
        self.rank_table.setHorizontalHeaderLabels(["DNS", "HTTPS", "DNS NOERROR", "Медиана, мс"] + [("★ " if s in self.ranked_required else "") + s.removeprefix("https://").rstrip("/") for s in sites])
        maximum = max((r["median"] for r in rows if math.isfinite(r["median"])), default=1)
        for r in rows:
            cells = []
            for site in sites:
                group = [v for v in self.results if v.site == site and v.server == r["address"]]
                https = sum(v.success and v.hops[-1]["url"].startswith("https://") for v in group)
                cells.append(f"DNS {sum(v.dns_ok for v in group)}/{len(group)} · HTTPS {https}/{len(group)}")
            speed = "—" if not math.isfinite(r["median"]) else f'{r["median"]:.1f}  ' + "▏"*max(1, round(12*r["median"]/max(1,maximum)))
            append(self.rank_table, [r["address"], f'{r["wins"]}/{r["runs"]}', f'{r["reliability"]:.0%}', speed, *cells], r["address"])
        self.rank_table.resizeColumnsToContents()

    def rank_details(self, row_index, column):
        addr = self.rank_table.item(row_index, 0).text()
        site = self.ranked_sites[column-4] if column >= 4 else None
        records = [pretty(r.record()) for r in self.results if r.server == addr and (not site or r.site == site)]
        self.text_dialog("Измерения DNS", "\n\n".join(records))

    def copy_rank(self):
        lines = [[self.rank_table.horizontalHeaderItem(i).text() for i in range(self.rank_table.columnCount())]]
        lines.extend([[self.rank_table.item(r,c).text() for c in range(self.rank_table.columnCount())] for r in range(self.rank_table.rowCount())])
        self.copy("\n".join("\t".join(line) for line in lines))

    def show_inline(self):
        record = selected(self.test_table)
        if record:
            self.check_chart.configure(self.s.theme,record)
        if record and self.s.detailed:
            self.live_detail.setPlainText(pretty(record))

    def network(self):
        lay = self.page_layouts[4]
        self.nic = QComboBox()
        self.nic.currentIndexChanged.connect(self.display_adapter)
        self.nic.activated.connect(self.remember_adapter)
        self.nic_note = label("", "muted")
        lay.addWidget(card("Сетевой адаптер", row(self.nic, button("Обновить", self.refresh_network)), self.nic_note))
        self.family = QComboBox()
        self.family.addItems(["IPv4", "IPv6"])
        self.pref, self.alt = edit("Основной DNS"), edit("Резервный DNS (необязательно)")
        self.net_profiles = QComboBox()
        self.net_profiles.activated.connect(self.load_network_profile)
        self.pref.textEdited.connect(self.detach_network_profile)
        self.alt.textEdited.connect(self.detach_network_profile)
        self.family.activated.connect(self.detach_network_profile)
        self.check_site = edit("Сайт для проверки после изменения", "https://example.org")
        lay.addWidget(card("DNS выбранного семейства", self.net_profiles, self.family, row(self.pref, self.alt),
                           label("После применения проверить через Windows", "muted"), self.check_site,
                           row(button("Применить…", self.ask_apply, "primary"), button("Автоматически (DHCP)…", lambda: self.ask_apply("auto"))),
                           row(button("Вернуть исходные настройки…", lambda: self.ask_apply("restore")),
                               button("Вернуть предыдущие…", lambda: self.ask_apply("previous")))))
        self.sys_doh = label(("Откройте свойства нужного подключения → Назначение DNS-сервера → Изменить. Выберите IPv4 или IPv6, введите IP и включите DNS через HTTPS. Для своего сервера укажите шаблон вручную."
                               if supports_doh() else "В этой версии Windows системная настройка DoH через «Параметры» недоступна. Прямая диагностика DoH и настройка браузера доступны."), "muted")
        self.win_endpoint = QComboBox()
        self.win_template = label("", "muted")
        self.win_endpoint.currentIndexChanged.connect(self.system_template)
        lay.addWidget(card(f"Защищённый DNS Windows · сборка {sys.getwindowsversion().build}", self.sys_doh,
                           self.win_endpoint, self.win_template, row(button("Скопировать шаблон", lambda: self.copy(self.win_endpoint.currentData())),
                           button("Открыть параметры сети Windows", self.open_system_settings))))
        lay.addStretch()

    def detach_network_profile(self):
        self.net_profiles.setCurrentIndex(0)

    def load_network_profile(self, index):
        address = self.net_profiles.itemData(index)
        if address:
            profile = next(s for s in self.profiles() if s.address == address)
            self.family.setCurrentIndex(0 if ipaddress.ip_address(address).version == 4 else 1)
            self.pref.setText(address)
            self.alt.setText(profile.secondary)
        else:
            self.pref.clear()
            self.alt.clear()

    def system_template(self, *_):
        endpoint = self.win_endpoint.currentData()
        if not endpoint:
            return
        ips = next((ips for ips, template in PROVIDERS.values() if template == endpoint), [])
        hint = ", ".join(ips) if ips else "Уточните у владельца сервера IP для системного DoH."
        self.win_template.setText(hint + "\n" + endpoint)

    def open_system_settings(self):
        a = self.nic.currentData()
        os.startfile("ms-settings:network-wifi" if a and a["type"] == 71 else "ms-settings:network-status")

    def refresh_network(self):
        if self.reading or self.changing:
            return
        self.reading = True
        self.banner.setText("Определение подключения…")
        def done(items):
            self.adapters = items
            current = primary(items)
            manual = getattr(self, "manual_adapter", "")
            identity = manual if any(a["guid"] == manual for a in items) else current or self.s.adapter_guid
            self.nic.blockSignals(True)
            self.nic.clear()
            self.nic.addItem("Выберите адаптер…", None)
            idx = 0
            for a in sorted(items, key=lambda a: (not a["up"], a["name"])):
                self.nic.addItem(a["name"] + (" · основной маршрут" if a["guid"] == current else ""), a)
                if a["guid"] == identity:
                    idx = self.nic.count()-1
            self.nic.setCurrentIndex(idx)
            self.nic.blockSignals(False)
            self.display_adapter()
        def failed(error):
            self.nic.clear()
            self.banner.setText("Сведения о сети недоступны")
            self.nic_note.setText(error)
            self.net_name.setText("Не удалось прочитать Windows")
            self.net_info.setText("Откройте «Настройки сети» и нажмите «Обновить».")
            self.stage_line.setText("Ошибка чтения сетевых адаптеров")
        self.job(lambda _: asyncio.to_thread(inventory), done, error=failed, end=lambda: setattr(self, "reading", False))

    @staticmethod
    def adapter_text(a):
        return (a["name"] + "\nIPv4 · " + (", ".join(a["v4"]) or "—") + " · " + MODES[a["mode4"]] +
                "\nIPv6 · " + (", ".join(a["v6"]) or "—") + " · " + MODES[a["mode6"]])

    def remember_adapter(self, _index):
        adapter = self.nic.currentData()
        self.manual_adapter = adapter["guid"] if adapter else ""
        self.s.adapter_guid = self.manual_adapter
        self.store.save(self.s)

    def display_adapter(self, *_):
        a = self.nic.currentData()
        if not a:
            self.banner.setText("Основное подключение требует выбора · Настройки сети")
            self.net_name.setText("Выберите подключение")
            self.net_info.setText("У семейств IP могут быть разные основные маршруты.")
            self.dns_name.setText("—")
            self.dns_info.setText("")
            self.nic_note.setText("Выберите адаптер вручную. В списке также показаны VPN и виртуальные интерфейсы.")
            return
        typ = {71:"Wi-Fi",6:"Ethernet",131:"Туннель",23:"PPP"}.get(a["type"], "Сетевой адаптер")
        if a["virtual"]:
            typ += " · виртуальный"
        state = "Подключено" if a["up"] else "Отключено"
        dns = a["v4"] + a["v6"]
        self.banner.setText(f'{typ}   /   {a["name"]}   ·   {a.get("ssid") or state}   ·   DNS {dns[0] if dns else "—"}')
        self.net_name.setText(a["name"])
        self.net_info.setText(typ + " · " + state + ("\nSSID · " + (a["ssid"] or "нет данных") if a["type"] == 71 else ""))
        self.dns_name.setText(dns[0] if dns else "Нет адресов")
        self.dns_info.setText("Резервный · " + (dns[1] if len(dns)>1 else "—") + "\nIPv4 " + MODES[a["mode4"]] + " · IPv6 " + MODES[a["mode6"]])
        proxies = urllib.request.getproxies()
        route_note = "Прямая диагностика обходит системный HTTP-прокси." if proxies else "Диагностика использует прямое соединение."
        self.nic_note.setText(self.adapter_text(a) + "\nАдреса интерфейса · " + (", ".join(a["ips"]) or "—") +
                              "\nТранспорт системных запросов не подтверждён. " + route_note +
                              (" VPN и фильтры могут менять маршрут." if any(i["up"] and i["virtual"] for i in self.adapters) else ""))

    def adapter(self):
        a = self.nic.currentData()
        if not a:
            self.go(4)
            raise ValueError("Сначала выберите адаптер в разделе «Настройки сети».")
        return a

    def ask_apply(self, mode="manual"):
        if self.changing or self.probe:
            raise ValueError("Сначала завершите текущую операцию.")
        a = self.adapter()
        family = (4, 6)[self.family.currentIndex()]
        if mode == "manual":
            values = addresses(family, [self.pref.text().strip()] + ([self.alt.text().strip()] if self.alt.text().strip() else []))
        elif mode in ("restore", "previous"):
            values = self.manager.saved(a["guid"], family, previous=mode == "previous")
        else:
            values = []
        target = url(self.check_site.text())
        try:
            ipaddress.ip_address(urlsplit(target).hostname)
        except ValueError:
            pass
        else:
            raise ValueError("Для проверки системного DNS укажите сайт с доменным именем.")
        if self.ask("Применить изменения DNS?", self.adapter_text(a) +
                    f"\n\nНовая конфигурация IPv{family} · " + (", ".join(values) or "автоматически") +
                    "\nПроверка через Windows · " + target):
            self.commit(a, family, values, target, rollback=mode == "previous")

    def commit(self, adapter, family, values, target, rollback=False):
        if self.changing:
            return
        self.changing = True
        self.stage_line.setText("Сохранение конфигурации и запрос прав Windows…")
        async def work(emit):
            after = await asyncio.to_thread(self.manager.apply, adapter, family, values, rollback=rollback)
            emit("Windows подтвердила DNS. Проверяется доступ через системный резолвер…")
            return after, await system_check(target, self.s)
        retry = []
        def done(pair):
            _after, result = pair
            self.stage_line.setText("DNS подтверждён Windows · " + result.summary)
            if result.code is None and not rollback:
                retry.append((result.summary, _after))
            else:
                self.text_dialog("Результат применения", self.adapter_text(_after) + "\n\nПроверка системным резолвером Windows\n" + pretty(result.record()))
        def failed(err):
            self.stage_line.setText(err)
            if not rollback and self.manager.path(adapter["guid"], family).with_suffix(".previous.json").exists() and "Повторное чтение" in err:
                retry.append((err, None))
            else:
                self.warn(err)
        def end():
            self.changing = False
            if retry and self.ask("Восстановить предыдущий DNS?", retry[0][0] + "\nОткат затронет только выбранное семейство этого адаптера."):
                before = self.manager.saved(adapter["guid"], family, previous=True)
                def revert(fresh):
                    self.commit(fresh, family, before, target, rollback=True)
                if retry[0][1]:
                    revert(retry[0][1])
                else:
                    self.job(lambda _: asyncio.to_thread(self.manager.current, adapter["guid"]), revert)
            else:
                self.refresh_network()
        self.job(work, done, progress=self.stage_line.setText, error=failed, end=end)

    def preview_best(self):
        if not self.best:
            raise ValueError("Сначала выполните сравнение DNS.")
        addr = self.best["address"]
        self.go(4)
        if addr.startswith("https:"):
            self.win_endpoint.setCurrentIndex(self.win_endpoint.findData(addr))
            self.sys_doh.setText("Рекомендован DoH · " + addr + "\n" + ("Откройте свойства подключения Windows, введите IP провайдера и этот шаблон DoH." if supports_doh() else "Эта версия Windows поддерживает выбор DoH в приложении и браузере."))
            self.copy(addr)
            return
        self.family.setCurrentIndex(0 if ipaddress.ip_address(addr).version == 4 else 1)
        self.detach_network_profile()
        self.pref.setText(addr)
        self.alt.clear()
        if self.ranked_sites:
            self.check_site.setText(self.ranked_sites[0])
        self.ask_apply()

    def browsers(self):
        lay = self.page_layouts[5]
        self.browser, self.provider = QComboBox(), QComboBox()
        self.browser.addItems(BROWSERS.keys())
        self.browser_info = label()
        self.browser_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.browser_url = edit("DoH URL")
        self.browser_url.setReadOnly(True)
        self.browser_page = edit("Страница настройки")
        self.browser_page.setReadOnly(True)
        self.guide = label("", "muted")
        lay.addWidget(card("Браузер и провайдер", row(self.browser, self.provider), self.browser_info,
                           row(self.browser_url, button("Скопировать DoH URL", lambda: self.copy(self.browser_url.text())))))
        lay.addWidget(card("Настройка защищённого DNS", self.browser_page, self.guide,
                           button("Открыть настройки браузера", lambda: open_browser(self.browser.currentText()), "primary")))
        lay.addStretch()
        self.browser.currentIndexChanged.connect(self.browser_guide)
        self.provider.currentIndexChanged.connect(self.browser_guide)

    def browser_list(self):
        self.provider.clear()
        for name, (ips, doh) in PROVIDERS.items():
            self.provider.addItem(name, (ips, doh))
        for s in self.s.custom:
            if s["address"].startswith("https:"):
                self.provider.addItem(s["name"], ([s["bootstrap"]] if s["bootstrap"] else [], s["address"]))
        self.browser_guide()

    def browser_guide(self, *_):
        data = self.provider.currentData()
        if not data:
            return
        name = self.browser.currentText()
        ips, endpoint = data
        detected = "Найден на этом компьютере" if browser_path(name) else "Установка не обнаружена"
        typ = "Адреса DNS" if self.provider.currentText() in PROVIDERS else "Bootstrap IP"
        self.browser_info.setText(f'{name} · {detected}\n{typ} · ' + (", ".join(ips) or "не указаны"))
        self.browser_url.setText(endpoint)
        self.browser_page.setText(BROWSERS[name][2])
        steps = ("Выберите уровень защиты DNS через HTTPS и свой провайдер." if name == "Mozilla Firefox"
                 else "Найдите «Использовать безопасный DNS», включите его и выберите своего поставщика.")
        self.guide.setText("1. Откройте страницу настроек по адресу выше. Если браузер открыл обычную вкладку, вставьте адрес вручную.\n2. " +
                           steps + "\n3. Вставьте скопированный DoH URL и сохраните выбор.\n\nБраузер может разрешать имена независимо от DNS Windows.")

    def history(self):
        lay = self.page_layouts[6]
        self.hist = table(["Время", "Сайт", "DNS", "Протокол", "Всего, мс", "Результат"])
        self.hist.doubleClicked.connect(lambda _: self.detail(selected(self.hist)))
        lay.addWidget(self.hist, 1)
        lay.addWidget(row(button("Подробности", lambda: self.detail(selected(self.hist))),
                          button("Копировать", lambda: self.copy_table(self.hist)),
                          button("Экспорт CSV", lambda: self.export("csv")), button("Экспорт JSON", lambda: self.export("json")),
                          button("Очистить…", self.clear_history)))

    def refresh_history(self):
        self.hist.setRowCount(0)
        self.recent.setRowCount(0)
        for i, r in enumerate(self.store.records(500)):
            stamp = r["timestamp"].replace("T", " ")[:19]
            append(self.hist, [stamp, r["site"], r["server"], r["protocol"], r["total_ms"], r["summary"]], r)
            if i < 5:
                append(self.recent, [stamp, r["site"], r["summary"]], r)
        self.recent.setColumnWidth(0, 150)
        self.hist.setColumnWidth(0, 150)
        self.hist.setToolTip("Последние 500 записей. Экспорт включает всю историю.")

    def clear_history(self):
        if self.ask("Очистить историю?", "Все сохранённые результаты будут удалены с этого компьютера."):
            self.store.clear()
            self.plot_records.clear()
            self.latest = None
            self.refresh_charts()
            self.refresh_history()

    def export(self, fmt):
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить историю", "DNS Pilot." + fmt, fmt.upper() + " (*." + fmt + ")")
        if path:
            self.store.export(Path(path), fmt)
            self.stage_line.setText("История экспортирована")

    def settings_page(self):
        lay = self.page_layouts[7]
        self.theme_buttons = {}
        grid = QGridLayout()
        picker = QWidget()
        picker.setLayout(grid)
        for i,(key,tokens) in enumerate(THEMES.items()):
            b = button(tokens.name, lambda k=key: self.apply_theme(k), "preview")
            b.setCheckable(True)
            b.setIcon(theme_thumbnail(key))
            b.setIconSize(QSize(90,44))
            grid.addWidget(b,i//2,i%2)
            self.theme_buttons[key] = b
        lay.addWidget(card("Оформление", picker))
        self.logs = check("Подробный вывод и технический журнал", self.s.detailed)
        self.keep = check("Сохранять историю проверок", self.s.history)
        self.auto = check("Предлагать однократное автоприменение перед подбором", self.s.auto_apply)
        self.v4, self.v6 = check("IPv4 (A)", self.s.v4), check("IPv6 (AAAA)", self.s.v6)
        self.dt, self.wt = spin(self.s.dns_timeout, 30), spin(self.s.web_timeout, 60)
        self.reps, self.workers = spin(self.s.repeats, 10), spin(self.s.parallel, 20)
        self.defaults = multi(self.s.sites)
        lay.addWidget(card("История и журнал", self.keep, self.logs))
        lay.addWidget(card("Параметры диагностики", row(label("Тайм-аут DNS, с"), self.dt, label("Тайм-аут этапа HTTPS, с"), self.wt),
                           row(label("Повторов"), self.reps, label("Параллельных проверок"), self.workers),
                           row(self.v4, self.v6), self.auto))
        lay.addWidget(card("Сайты по умолчанию", self.defaults))
        lay.addWidget(button("Сохранить настройки", self.save_settings, "primary"))
        lay.addStretch()

    def color_result(self, index):
        result = self.test_table.item(index, 0).data(Qt.ItemDataRole.UserRole)
        t = THEMES[self.s.theme]
        color = t.success if result["success"] else t.warning if result["code"] else t.error
        self.test_table.item(index, 5).setForeground(QColor(color))

    def apply_theme(self, key, *, persist=True):
        t = THEMES[key]
        if persist:
            self.store.save(replace(self.s,theme=key,light=key=="coral"))
        self.s.theme, self.s.light = key, key=="coral"
        self.setStyleSheet(stylesheet(key))
        self.sidebar.key = key
        self.sidebar.update()
        self.mark.setPixmap(brand_mark(key))
        self.rail_footer.setStyleSheet("color: #f7eee8;" if key=="coral" else "")
        for name,b in self.theme_buttons.items():
            b.setChecked(name == key)
        for w in self.findChildren(QWidget,"card"):
            if w.layout():
                w.layout().setContentsMargins(t.space+5,t.space+2,t.space+5,t.space+2)
                w.layout().setSpacing(t.space)
        for layout in self.page_layouts:
            layout.setSpacing(t.space)
        for widget in self.findChildren(QTableWidget):
            widget.verticalHeader().setDefaultSectionSize(t.row_height)
            widget.setShowGrid(key=="lab")
            widget.setAlternatingRowColors(key in ("utility","lab"))
            widget.setStyleSheet(f"gridline-color:{t.border};" if key=="lab" else "")
        glyphs = ["\ue80f","\ue774","\ue9d9","\ue968","\ue839","\ue71b","\ue81c","\ue713"]
        for i,b in enumerate(self.nav):
            pix = QPixmap(40,40)
            pix.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pix)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(QColor(t.accent))
            if key=="lab":
                painter.drawRoundedRect(1,1,37,37,3,3)
            elif key=="aurora":
                painter.setBrush(QColor(t.selected))
                painter.drawEllipse(1,1,37,37)
            painter.setFont(QFont("Segoe MDL2 Assets",16))
            painter.drawText(pix.rect(),Qt.AlignmentFlag.AlignCenter,glyphs[i])
            painter.end()
            b.setIcon(QIcon(pix))
            b.setIconSize(QSize(21,21) if key=="utility" else QSize(25,25))
        self.nav_size()
        self.arrange_home()
        self.refresh_charts()
        for idx in range(self.test_table.rowCount()):
            self.color_result(idx)

    def save_settings(self):
        sites_of(self.defaults)
        if not self.v4.isChecked() and not self.v6.isChecked():
            raise ValueError("Выберите IPv4 или IPv6.")
        for name, widget in (("v4",self.v4),("v6",self.v6),("detailed",self.logs),
                             ("auto_apply",self.auto),("history",self.keep)):
            setattr(self.s, name, widget.isChecked())
        for name, widget in (("dns_timeout",self.dt),("web_timeout",self.wt),("parallel",self.workers),("repeats",self.reps)):
            setattr(self.s, name, widget.value())
        old = self.s.sites
        self.s.sites = self.defaults.toPlainText()
        for field in self.fields:
            if field.toPlainText() == old:
                field.setPlainText(self.s.sites)
        self.store.save(self.s)
        self.live_detail.setVisible(self.s.detailed)
        self.stage_line.setText("Настройки сохранены")

    def job(self, coroutine, done, *, progress=None, error=None, end=None):
        worker = Job(coroutine)
        self.jobs.add(worker)
        if progress:
            worker.progress.connect(progress, Qt.ConnectionType.QueuedConnection)
        worker.done.connect(done, Qt.ConnectionType.QueuedConnection)
        worker.failed.connect(error or self.warn, Qt.ConnectionType.QueuedConnection)
        worker.stopped.connect(self.job_stopped)
        def release():
            self.jobs.discard(worker)
            worker.deleteLater()
            if end:
                end()
        worker.finished.connect(release, Qt.ConnectionType.QueuedConnection)
        worker.start()
        return worker

    def job_stopped(self):
        self.stage_line.setText("Проверка отменена. Завершённые измерения доступны в таблице.")
        if self.best_info.text() == "Сравнение выполняется…":
            self.best_info.setText("Сравнение отменено")

    def detail(self, record):
        if record:
            self.text_dialog("Подробности проверки", pretty(record) + "\n\n" + json.dumps(record, indent=2, ensure_ascii=False))

    def copy_table(self, t):
        record = selected(t)
        if record:
            self.copy(pretty(record))

    def text_dialog(self, title, text):
        d = QDialog(self)
        d.setWindowTitle(title)
        d.resize(720, 480)
        lay = QVBoxLayout(d)
        field = QPlainTextEdit(text)
        field.setReadOnly(True)
        lay.addWidget(field)
        lay.addWidget(row(button("Скопировать", lambda: self.copy(text)), button("Закрыть", d.accept)))
        d.exec()

    def copy(self, value):
        QApplication.clipboard().setText(value)
        self.stage_line.setText("Скопировано в буфер обмена")

    def ask(self, title, message):
        d = QMessageBox(self)
        d.setWindowTitle(title)
        d.setTextFormat(Qt.TextFormat.PlainText)
        d.setText(message)
        yes = d.addButton("Подтвердить", QMessageBox.ButtonRole.AcceptRole)
        no = d.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
        d.setDefaultButton(no)
        d.exec()
        return d.clickedButton() == yes

    def warn(self, error):
        logging.warning("%s", error)
        QMessageBox.warning(self, "DNS Pilot", str(error))

    def closeEvent(self, event):
        if self.jobs:
            self.cancel()
            self.stage_line.setText("Завершается операция. Окно закроется после её окончания.")
            event.ignore()
            if not getattr(self, "closing", False):
                self.closing = QTimer(self)
                self.closing.setInterval(150)
                self.closing.timeout.connect(lambda: self.close() if not self.jobs else None)
                self.closing.start()
            return
        self.s.geometry = bytes(self.saveGeometry().toBase64()).decode()
        self.store.save(self.s)
        self.store.db.close()
        event.accept()
