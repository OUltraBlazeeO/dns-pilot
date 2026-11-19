import asyncio
import json
from copy import deepcopy
from unittest.mock import AsyncMock, Mock, patch

import dns.message
import dns.rrset
import pytest
from PySide6.QtWidgets import QApplication

from app.desktop import system_check
from app.diagnostics import Checker, address_category, control_site
from app.model import Result, Server, Settings, url
from app.privacy import redact
from app.storage import Store, atomic
from app.ui import Window
from app.windows import Manager, addresses, protected_adapter


def adapter():
    return dict(name="test", guid="{C756966E-8E31-4D28-A440-ED465492BC7D}", mode4="manual",
                v4=["192.0.2.1"], mode6="auto", v6=[], encryption={}, templates=[])


@pytest.fixture
def transaction(tmp_path):
    state = adapter()

    def write(_, family, values):
        state[f"v{family}"] = values
        state[f"mode{family}"] = "manual" if values else "auto"

    return Manager(tmp_path, lambda: [deepcopy(state)], write), state


def test_cancel_preserves_last_committed_checkpoint(transaction):
    m, a = transaction
    for last in ("2", "3"):
        m.apply(deepcopy(a), 4, ["192.0.2."+last])
    m.write = Mock(side_effect=PermissionError("UAC"))
    with pytest.raises(PermissionError):
        m.apply(deepcopy(a), 4, ["192.0.2.4"])
    assert m.saved(a["guid"], 4, previous=True) == ["192.0.2.2"]
    assert m.pending() is None


@pytest.mark.parametrize("phase", ["prepared", "applying", "verifying", "completed"])
def test_restart_at_durable_phase(transaction, phase, monkeypatch):
    manager, a = transaction
    real_phase = manager.phase

    def crash(op, new):
        real_phase(op, new)
        if new == phase:
            raise SystemExit()

    monkeypatch.setattr(manager, "phase", crash)
    with pytest.raises(SystemExit):
        manager.apply(deepcopy(a), 4, ["8.8.8.8"])
    restarted = Manager(manager.root, manager.read, manager.write)
    if phase == "completed":
        assert restarted.pending() is None and a["v4"] == ["8.8.8.8"]
        assert restarted.saved(a["guid"], 4, True) == ["192.0.2.1"]
    else:
        with pytest.raises(RuntimeError, match="незавершённой"):
            restarted.apply(deepcopy(a), 4, ["1.1.1.1"])
        restarted.recover()
        assert a["v4"] == ["192.0.2.1"] and not restarted.pending()


def test_drift_blocks_recovery_and_does_not_touch_other_family(transaction):
    m, a = transaction
    m.apply(deepcopy(a), 4, ["8.8.8.8"], defer_completion=True)
    a["v6"] = ["::1"]
    m.write = Mock()
    with pytest.raises(ValueError, match="другого семейства"):
        m.recover()
    m.write.assert_not_called()
    assert m.pending()


def test_backup_schema_and_digest(transaction):
    m, a = transaction
    m.apply(deepcopy(a), 4, ["8.8.8.8"])
    path = m.path(a["guid"], 4)
    data = json.loads(path.read_text("utf-8"))
    data["v4"] = ["192.0.2.77"]
    atomic(path, data)
    with pytest.raises(ValueError, match="целостность"):
        m.saved(a["guid"], 4)
    atomic(path, dict(a, v4=[]))
    with pytest.raises(ValueError, match="Пустой"):
        m.saved(a["guid"], 4)
    with pytest.raises(ValueError):
        addresses(4, ["255.255.255.255"])


def test_privacy_retention_export_and_legacy_profile(tmp_path):
    db = Store(tmp_path)
    atomic(tmp_path/"settings.json", {"history_limit": 2, "custom":[{"name":"DNS","address":"https://example.org/doh"}]})
    assert db.settings().custom[0]["bootstrap"] == ""
    for i in range(4):
        r = Result(f"https://example.org/{i}?access_token=PRIVATE&x=other", "::1", "DNS", "UDP")
        r.warnings = ["redirect ?password=PRIVATE"]
        db.add(r)
    assert len(db.records()) == 2
    assert "PRIVATE" not in str(list(db.db.execute("SELECT data FROM checks")))
    for fmt in ("json", "csv"):
        p = tmp_path / ("history."+fmt)
        db.export(p, fmt)
        assert "PRIVATE" not in p.read_text("utf-8-sig")
    assert len(json.loads((tmp_path/"history.json").read_text())) == 2
    db.db.execute("INSERT INTO checks(data) VALUES ('invalid-json')")
    assert len(db.records()) == 2
    db.db.close()


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.1.2.3", "169.254.1.2", "::1", "fc00::1",
                                  "fe80::1", "::ffff:127.0.0.1", "224.0.0.1", "::", "100.64.0.1"])
def test_special_destination_denied_by_default(addr):
    async def run():
        c = Checker(Settings())
        c.resolve = AsyncMock(return_value=[addr])
        with patch("app.diagnostics.exchange", new_callable=AsyncMock) as transport:
            r = await c.check("example.org", Server("local", "127.0.0.1"))
        assert address_category(addr) and not r.success and r.dns_ok and r.warnings
        transport.assert_not_awaited()
    asyncio.run(run())


@pytest.mark.parametrize("blocked", [False, True])
def test_downgrade(blocked):
    async def run():
        c = Checker(Settings(block_downgrade=blocked))
        c.resolve = AsyncMock(return_value=["1.1.1.1"])
        exchange = AsyncMock(side_effect=[(302,{b"location":b"http://other.example/test"},b""),(200,{},b"")])
        with patch("app.diagnostics.exchange", exchange):
            r = await c.check("https://site.example", Server("test","1.1.1.1"))
        assert r.downgraded and r.warnings and r.success == (not blocked)
        assert exchange.await_count == (1 if blocked else 2)
        assert r.hops[0]["redirect"] == "http://other.example/test"
    asyncio.run(run())


def test_second_bootstrap_and_idna():
    async def run():
        async def request(endpoint, ip, wire, *args):
            if ip == "192.0.2.1":
                raise ConnectionError("unavailable")
            q = dns.message.from_wire(wire)
            r = dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text(q.question[0].name, 1, "IN", "A", "192.0.2.5"))
            return r.to_wire()
        c = Checker(Settings())
        info = {}
        with patch("app.diagnostics.system_addresses", AsyncMock(return_value=["192.0.2.1","192.0.2.2"])), patch("app.doh.request", request):
            assert await c.query("example.org","A",Server("DoH","https://example.org/dns-query"), info) == ["192.0.2.5"]
        assert len(info["bootstrap_attempts"]) == 2
    asyncio.run(run())
    assert url("faß.example") == "https://xn--fa-hia.example/"


def test_http_body_cap_and_original_query():
    from app.transport import exchange
    import ssl
    async def run():
        requests = []
        async def handler(reader, writer):
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 32768\r\n\r\n"+b"x"*32768)
            await writer.drain()
            writer.close()
        async with await asyncio.start_server(handler,"127.0.0.1",0) as listener:
            port = listener.sockets[0].getsockname()[1]
            site = f"http://site.invalid:{port}/?api_key=private"
            trace = {}
            code, _, body = await exchange(site,"127.0.0.1",3,ssl.create_default_context(),trace,lambda _:None,deep=True)
            assert code == 200 and not body and trace["sample_bytes"] == 16384 and trace["content_type"] == "text/plain"
            assert b"api_key=private" in requests[0] and "private" not in redact(site)
    asyncio.run(run())


def test_final_confirmation_virtual_and_control_domain(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM","offscreen")
    app = QApplication.instance() or QApplication([])
    w = Window(Store(tmp_path), Settings(), detect=False)
    a = dict(adapter(), virtual=True, type=131)
    addr = "1.1.1.1"
    site = "https://example.org/"
    r = Result(site,addr,"DNS","UDP",success=True,dns_ok=True,hops=[{"url":site}])
    ranks = [dict(address=addr, eligible=True, median=3, reliability=1, wins=1, runs=1)]
    w.best = ranks[0]
    assert protected_adapter(a) and control_site([r],addr,{site}) == site
    commit = Mock()
    monkeypatch.setattr(w, "commit", commit)
    for answers in ([False], [True,False], [True,True]):
        ask = Mock(side_effect=answers)
        monkeypatch.setattr(w,"ask",ask)
        w.confirm_winner(a, addr, [r], ranks, {site})
        assert ask.call_count == len(answers)
    commit.assert_called_once_with(a,4,[addr],site)
    w.required = {"https://missing.example/"}
    with pytest.raises(ValueError,match="обязательные"):
        w.start_test([], [site], True)
    w.close()
    app.processEvents()


def test_system_lookup_and_numeric_control():
    async def run():
        with patch("app.desktop.system_addresses",AsyncMock(return_value=["1.1.1.1"])), patch("app.diagnostics.exchange",AsyncMock(return_value=(204,{},b""))):
            r = await system_check("example.org", Settings())
        assert r.hops[0]["system_lookup"] and r.code == 204
        r.site = "https://1.1.1.1/"
        with pytest.raises(ValueError, match="доменным"):
            control_site([r],r.server,set())
    asyncio.run(run())



def test_orphan_guard_and_powershell_syntax(monkeypatch):
    import base64
    import os
    import re
    from app import windows
    a = adapter()
    birth = windows.process_birth()
    actual = windows.ps(f"[Diagnostics.Process]::GetProcessById({os.getpid()}).StartTime.ToUniversalTime().ToFileTimeUtc()")
    assert int(actual) == birth
    windows.wait_for_writer(a["guid"])
    captured = []
    native_ps = windows.ps
    monkeypatch.setattr(windows, "ps", lambda script, timeout: captured.append(script) or "24")
    with pytest.raises(PermissionError):
        windows.change(a, 4, ["8.8.8.8"])
    token = re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", captured[0]).group(1)
    # Compile the helper in Windows PowerShell without invoking its script block.
    check = "$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + token + "')); [void][scriptblock]::Create($s); 'OK'"
    assert native_ps(check) == "OK"
    script = base64.b64decode(token).decode("utf-16-le")
    assert "Get-Process -Id $p.owner" in script and "WaitOne" in script


def test_corrupt_db_still_allows_window_and_saves_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM","offscreen")
    app = QApplication.instance() or QApplication([])
    file = tmp_path/"history.db"
    file.write_bytes(b"broken database")
    store = Store(tmp_path)
    assert store.warning and not store.persistent
    w = Window(store,Settings(),detect=False)
    w.retention.setValue(19)
    w.deep.setChecked(True)
    w.save_settings()
    assert w.store.settings().history_limit == 19 and w.store.settings().deep_http
    w.close()
    app.processEvents()
    assert file.read_bytes() == b"broken database"


def test_compact_pages_fit_all_themes(tmp_path, monkeypatch):
    from PySide6.QtTest import QTest
    monkeypatch.setenv("QT_QPA_PLATFORM","offscreen")
    app = QApplication.instance() or QApplication([])
    window = Window(Store(tmp_path), Settings(), detect=False)
    window.show()
    window.resize(720,510)
    for key in window.theme_buttons:
        window.apply_theme(key,persist=False)
        for i in range(8):
            window.go(i)
            QTest.qWait(15)
            assert window.stack.widget(i).horizontalScrollBar().maximum() == 0, (key,i)
    window.close()
    app.processEvents()
