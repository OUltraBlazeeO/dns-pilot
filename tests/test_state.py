import json
from copy import deepcopy
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from app.diagnostics import ranking
from app.model import Result, Server, Settings
from app.storage import Store
from app.windows import Manager, addresses, primary


def adapter(identity="{C756966E-8E31-4D28-A440-ED465492BC7D}", name="LAN", metric=20, up=True):
    return {"guid":identity,"name":name,"up":up,"routes":[{"prefix":"0.0.0.0/0","metric":metric}],
            "mode4":"auto","mode6":"manual","v4":["192.0.2.1"],"v6":["2001:db8::1"],"encryption":{},"templates":[]}


def test_primary_routes_and_fallback():
    wifi = adapter(name="Беспроводная сеть 2")
    vpn = adapter("vpn","WARP",3)
    assert primary([wifi,vpn]) == "vpn"
    vpn["routes"][0]["metric"] = 20
    assert primary([wifi,vpn]) is None
    vpn["routes"] = [{"prefix":p,"metric":90} for p in ("0.0.0.0/1","128.0.0.0/1")]
    assert primary([wifi,vpn]) == "vpn"
    vpn["routes"] = [{"prefix":"::/0","metric":1}]
    assert primary([wifi,vpn]) is None
    vpn["up"] = False
    wifi["routes"] = []
    assert primary([wifi,vpn]) == wifi["guid"]
    wifi["up"] = False
    assert primary([wifi,vpn]) is None


def test_restore_original_and_previous(tmp_path):
    current = adapter()
    def write(_, family, values):
        current[f"mode{family}"] = "manual" if values else "auto"
        current[f"v{family}"] = values or ["192.0.2.1"]
    manager = Manager(tmp_path, lambda:[deepcopy(current)], write)
    for values in (["8.8.8.8","8.8.4.4"],["1.1.1.1"]):
        manager.apply(deepcopy(current),4,values)
        assert current["v4"] == values
    assert manager.saved(current["guid"],4,True) == ["8.8.8.8","8.8.4.4"]
    manager.apply(deepcopy(current),4,manager.saved(current["guid"],4))
    assert current["mode4"] == "auto" and current["v6"] == ["2001:db8::1"]
    original = json.loads(manager.path(current["guid"],4).read_text("utf-8"))
    assert original["guid"] == current["guid"] and original["templates"] == []


def test_uac_refusal_no_change_and_stale_preview(tmp_path):
    current = adapter()
    writer = Mock(side_effect=PermissionError("UAC"))
    m = Manager(tmp_path, lambda:[deepcopy(current)], writer)
    with pytest.raises(PermissionError):
        m.apply(current,4,["1.1.1.1"])
    assert m.saved(current["guid"],4) == []
    stale = deepcopy(current)
    stale["v4"] = []
    with pytest.raises(ValueError):
        m.apply(stale,4,["8.8.8.8"])
    assert writer.call_count == 1
    current["mode4"] = "unknown"
    with pytest.raises(ValueError):
        m.apply(current,4,[])
    assert writer.call_count == 1


def test_failed_readback(tmp_path):
    current = adapter()
    m = Manager(tmp_path,lambda:[deepcopy(current)],Mock())
    with pytest.raises(RuntimeError, match="подтвердило"):
        m.apply(current,4,["8.8.8.8"])


def test_denied_rollback_keeps_previous_checkpoint(tmp_path):
    current = adapter()
    m = Manager(tmp_path,lambda:[deepcopy(current)],Mock())
    original = deepcopy(current)
    original.update(mode4="manual",v4=["192.0.2.8"])
    from app.storage import atomic
    path = m.path(current["guid"],4).with_suffix(".previous.json")
    atomic(path,original)
    m.write.side_effect = PermissionError("UAC")
    with pytest.raises(PermissionError):
        m.apply(current,4,original["v4"],rollback=True)
    assert m.saved(current["guid"],4,previous=True) == original["v4"]


@pytest.mark.parametrize("family,values", [(4,["1.1.1.1;calc"]),(4,["::1"]),(6,["https://dns.google/dns-query"])])
def test_invalid_network_values(family,values):
    with pytest.raises(ValueError):
        addresses(family,values)


def test_rank_mandatory_every_repeat():
    results = []
    for addr,ms in [("fast",2),("stable",50)]:
        for ok in [True,addr=="stable"]:
            results.append(Result("required",addr,addr,"UDP",success=ok,dns_ok=True,dns_ms=ms,answered=1,queries=1,hops=[{"url":"https://required"}]))
    ranks = ranking(results,{"required"})
    assert ranks[0]["address"] == "stable" and not ranks[1]["eligible"]
    assert not any(r["eligible"] for r in ranking(results,{"missing"}))


def test_settings_history_and_export(tmp_path):
    db = Store(tmp_path)
    s = Settings(light=True,history=False,custom=[asdict(Server("Тест","::1"))])
    db.save(s)
    assert db.settings() == s
    db.add(Result("site","::1","DNS","UDP",summary="Ошибка"))
    db.export(tmp_path/"out.csv","csv")
    db.export(tmp_path/"out.json","json")
    assert "Ошибка" in (tmp_path/"out.csv").read_text("utf-8-sig")
    assert json.loads((tmp_path/"out.json").read_text("utf-8")) == db.records()
    db.clear()
    assert db.records() == []
    db.db.close()


def test_old_light_settings_choose_coral(tmp_path):
    db = Store(tmp_path)
    (tmp_path/"settings.json").write_text('{"light":true,"custom":[{"name":"LAN","address":"192.0.2.53","bootstrap":""}]}',encoding="utf-8")
    s = db.settings()
    assert s.theme == "coral" and Server(**s.custom[0]).secondary == ""
    db.db.close()
