import asyncio
import os
import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.model import Result, Settings
from app.storage import Store
from app.ui import Window


@pytest.fixture
def window(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    w = Window(Store(tmp_path), Settings(repeats=1), detect=False)
    w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen)
    w.show()
    yield w
    w.close()
    app.processEvents()


def finish(w):
    deadline = time.monotonic() + 5
    while w.jobs and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.005)
    assert not w.jobs


def test_desktop_flow(window, monkeypatch):
    w = window
    async def fixture_batch(servers, sites, settings, emit):
        results = []
        for s in servers:
            r = Result(sites[0], s.address, s.name, "UDP", success=True, dns_ok=True, dns_ms=7,
                       code=200, queries=2, answered=2, hops=[{"url":sites[0],"queries":[],"attempts":[]}])
            emit(("stage", s.name, "TLS"))
            emit(("result", r))
            results.append(r)
        return results
    monkeypatch.setattr("app.ui.batch", fixture_batch)
    w.quick_dns.setEditText("192.0.2.1")
    w.quick.setText("site.invalid")
    w.quick_start()
    finish(w)
    assert w.test_table.rowCount() == 1 and w.hist.rowCount() == 1 and w.probe is None
    assert "100%" in w.run_summary.text()
    w.fields[1].setPlainText("site.invalid")
    w.required = {"https://site.invalid/"}
    w.launch(1)
    finish(w)
    assert w.rank_table.rowCount() == 3 and w.best and w.best["eligible"]
    assert w.hist.rowCount() == 4
    w.new_custom()
    w.custom_type.setCurrentIndex(1)
    w.custom_name.setText("Мой DoH")
    w.custom_addr.setText("https://resolver.invalid/dns-query")
    w.custom_boot.setText("192.0.2.5")
    w.add_custom()
    w.provider.setCurrentIndex(w.provider.count()-1)
    assert w.browser_url.text() == "https://resolver.invalid/dns-query"
    assert w.store.settings().custom[0]["bootstrap"] == "192.0.2.5"
    assert w.win_endpoint.findData("https://resolver.invalid/dns-query") >= 0


def test_custom_profile_lifecycle(window, monkeypatch):
    w = window
    def unexpected_write(*args, **kwargs):
        pytest.fail("Каталог не должен менять DNS адаптера")
    monkeypatch.setattr(w.manager, "apply", unexpected_write)
    w.go(3)
    w.new_custom()
    w.custom_name.setText("Локальная сеть")
    w.custom_addr.setText("2001:db8::53")
    w.custom_secondary.setText("192.0.2.53")
    with pytest.raises(ValueError, match="одному семейству"):
        w.add_custom()
    assert not w.s.custom
    w.custom_secondary.setText("2001:db8::54")
    w.add_custom()
    assert w.store.settings().custom[0]["secondary"] == "2001:db8::54"
    w.catalog_test()
    assert w.selections[0] == ["2001:db8::53", "2001:db8::54"]
    assert set(w.selections[0]) <= {s.address for s in w.servers()}
    idx = w.net_profiles.findData("2001:db8::53")
    w.net_profiles.setCurrentIndex(idx)
    w.net_profiles.activated.emit(idx)
    assert w.family.currentText() == "IPv6"
    assert (w.pref.text(),w.alt.text()) == ("2001:db8::53","2001:db8::54")
    w.edit_custom()
    w.custom_name.setText("Новый DNS")
    w.custom_addr.setText("192.0.2.80")
    w.custom_secondary.setText("192.0.2.81")
    w.add_custom()
    assert w.selections[0] == ["192.0.2.80","192.0.2.81"]
    assert w.family.currentText() == "IPv4" and w.alt.text() == "192.0.2.81"
    monkeypatch.setattr(w, "ask", lambda *args: True)
    w.remove_custom()
    assert not w.store.settings().custom and not w.selections[0]
    assert w.net_profiles.findData("192.0.2.80") < 0 and not w.alt.text()


def test_probe_from_unsaved_editor(window, monkeypatch):
    async def reply(self, host, kind, server, info):
        assert host == "example.org"
        info.update(protocol="UDP",rcode="NOERROR",ms=1.2)
        return []
    monkeypatch.setattr("app.diagnostics.Checker.query", reply)
    window.new_custom()
    window.custom_name.setText("DNS")
    window.custom_addr.setText("192.0.2.5")
    window.custom_secondary.setText("192.0.2.6")
    window.test_draft()
    finish(window)
    assert window.catalog_report.text().count("1.2 мс") == 2
    assert "192.0.2.6" in window.catalog_report.text() and not window.store.settings().custom


def test_gui_cancellation(window, monkeypatch):
    async def slow(*args):
        await asyncio.sleep(60)
    monkeypatch.setattr("app.ui.batch",slow)
    window.quick_start()
    window.cancel()
    finish(window)
    assert "отменена" in window.stage_line.text()
    assert window.hist.rowCount() == 0


def test_four_live_themes_change_layout_and_persist(window):
    w = window
    assert w.s.theme == "utility"
    w.quick.setText("kept.invalid")
    positions = set()
    for key,button in w.theme_buttons.items():
        button.click()
        assert w.s.theme == key == w.store.settings().theme
        assert button.isChecked() and not button.icon().isNull()
        assert w.home_chart.key == key and w.latency_plot.key == key
        assert w.quick.text() == "kept.invalid"
        positions.add(tuple(w.home_grid.getItemPosition(w.home_grid.indexOf(widget)) for widget in
                            (w.quick_card,w.home_chart,w.plot_card)))
    assert len(positions) == 4
    w.resize(800,600)
    QApplication.processEvents()
    assert w.home_signature == ("lab",True)
    assert w.home_grid.getItemPosition(w.home_grid.indexOf(w.quick_card))[1] == 0
