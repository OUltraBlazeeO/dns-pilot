"""Read-only inventory and a separately elevated, family-scoped DNS transaction."""
import base64
import ctypes
import ipaddress
import json
import os
import hashlib
import threading

from .model import dns_ip
import subprocess
import sys
import uuid
import winreg
import xml.etree.ElementTree as ET
from ctypes import wintypes
from pathlib import Path

from .storage import atomic

SYSTEM = Path(os.environ["SystemRoot"]) / "System32"
POWERSHELL = SYSTEM / "WindowsPowerShell/v1.0/powershell.exe"
PREAMBLE = """
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
"""
INVENTORY = """
$adapters = @(Get-NetAdapter -IncludeHidden)
$dns = @(Get-DnsClientServerAddress)
$interfaces = @(Get-NetIPInterface)
$routes = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
    $_.DestinationPrefix -in '0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1'
})
$addresses = @(Get-NetIPAddress)
$templates = $null
if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
  try { $templates = @(Get-DnsClientDohServerAddress | Select ServerAddress,DohTemplate,AutoUpgrade,AllowFallbackToUdp) } catch {}
}
$items = @(foreach ($a in $adapters) {
  $idx = [int]$a.ifIndex
  $r = @(foreach ($route in $routes | Where-Object InterfaceIndex -eq $idx) {
    $iface = $interfaces | Where-Object { $_.InterfaceIndex -eq $idx -and $_.AddressFamily -eq $route.AddressFamily } | Select -First 1
    if ($iface -and $iface.ConnectionState -eq 'Connected') {
      @{ prefix=$route.DestinationPrefix; metric=([int]$route.RouteMetric + [int]$iface.InterfaceMetric) }
    }
  })
  @{name=$a.Name; guid=[string]$a.InterfaceGuid; index=$idx; up=([int]$a.InterfaceOperationalStatus -eq 1);
    type=[int]$a.InterfaceType; virtual=([bool]$a.Virtual -or !$a.HardwareInterface); description=$a.InterfaceDescription;
    routes=$r; ips=@($addresses | Where-Object InterfaceIndex -eq $idx | ForEach-Object IPAddress);
    v4=@($dns | Where-Object { $_.InterfaceIndex -eq $idx -and [int]$_.AddressFamily -eq 2 } | ForEach-Object ServerAddresses | Where-Object {$_});
    v6=@($dns | Where-Object { $_.InterfaceIndex -eq $idx -and [int]$_.AddressFamily -eq 23 } | ForEach-Object ServerAddresses | Where-Object {$_})}
})
@{adapters=$items;templates=$templates} | ConvertTo-Json -Depth 7 -Compress
"""


def encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def ps(script, timeout=35):
    p = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                        encoded(PREAMBLE + script)], capture_output=True, timeout=timeout,
                       creationflags=subprocess.CREATE_NO_WINDOW, encoding="utf-8", errors="replace")
    if p.returncode:
        error = p.stderr.strip()
        if error.startswith("#< CLIXML"):
            try:
                tree = ET.fromstring(error.split("\n", 1)[1])
                error = " ".join(n.text or "" for n in tree if n.attrib.get("S") == "Error").replace("_x000D__x000A_", "\n")
            except (ValueError, IndexError):
                pass
        raise RuntimeError((error or p.stdout or f"PowerShell {p.returncode}").strip()[:1600])
    return p.stdout.strip()


def guid(value):
    return "{" + str(uuid.UUID(value)).upper() + "}"


def regtree(key):
    children, count, _ = winreg.QueryInfoKey(key)
    values = {}
    for i in range(count):
        name, val, _kind = winreg.EnumValue(key, i)
        values[name] = val.hex() if isinstance(val, bytes) else val
    for i in range(children):
        name = winreg.EnumKey(key, i)
        with winreg.OpenKey(key, name) as child:
            values[name] = regtree(child)
    return values


def registry_state(adapter):
    identity = guid(adapter["guid"])
    for family, service in ((4, "Tcpip"), (6, "Tcpip6")):
        path = rf"SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces\{identity}"
        mode = "unknown"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                try:
                    value = winreg.QueryValueEx(k, "NameServer")[0]
                except FileNotFoundError:
                    value = ""
                manual = [str(ipaddress.ip_address(s)) for s in str(value).replace(",", " ").replace(";", " ").split()]
                actual = [str(ipaddress.ip_address(s)) for s in adapter[f"v{family}"]]
                mode = "manual" if manual and manual == actual else ("auto" if not manual else "unknown")
        except (OSError, ValueError):
            pass
        adapter[f"mode{family}"] = mode
    try:
        path = rf"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\{identity}\DohInterfaceSettings"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            adapter["encryption"] = regtree(k)
    except FileNotFoundError:
        adapter["encryption"] = {}
    except OSError:
        adapter["encryption"] = None


def ssid(identity):
    # WLAN_CONNECTION_ATTRIBUTES starts with state, mode, profile[256], DOT11_SSID.
    wlan = ctypes.WinDLL("wlanapi")
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    if wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)):
        return None
    data, size = ctypes.c_void_p(), wintypes.DWORD()
    try:
        interface = ctypes.create_string_buffer(uuid.UUID(identity).bytes_le)
        if wlan.WlanQueryInterface(handle, interface, 7, None, ctypes.byref(size), ctypes.byref(data), None):
            return None
        raw = ctypes.string_at(data, size.value)
        length = int.from_bytes(raw[520:524], "little")
        if raw[:4] == b"\x01\x00\x00\x00" and 0 < length <= 32:
            return raw[524:524+length].decode("utf-8", "replace")
    finally:
        if data:
            wlan.WlanFreeMemory(data)
        wlan.WlanCloseHandle(handle, None)


def inventory():
    info = json.loads(ps(INVENTORY))
    for adapter in info["adapters"]:
        adapter["guid"] = guid(adapter["guid"])
        registry_state(adapter)
        adapter["ssid"] = ssid(adapter["guid"]) if adapter["up"] and adapter["type"] == 71 else None
        adapter["templates"] = info["templates"]
    return info["adapters"]


def primary(adapters):
    active = [a for a in adapters if a["up"]]
    winners = set()
    for default, halves in [("0.0.0.0/0", ["0.0.0.0/1", "128.0.0.0/1"]), ("::/0", ["::/1", "8000::/1"])]:
        routes = [(r["prefix"], r["metric"], a["guid"]) for a in active for r in a["routes"]]
        for half in halves:
            options = [(metric, g) for prefix, metric, g in routes if prefix == half]
            if not options:
                options = [(metric, g) for prefix, metric, g in routes if prefix == default]
            if options:
                lowest = min(options)[0]
                winners.update(g for m, g in options if m == lowest)
    if len(winners) == 1:
        return next(iter(winners))
    if not winners:
        return next((a["guid"] for a in active if a["name"] == "Беспроводная сеть 2"), None)
    return None


def addresses(family, values):
    if family not in (4, 6):
        raise ValueError("Неизвестное семейство IP.")
    ips = [dns_ip(x) for x in values]
    if any(ip.version != family or ip.is_unspecified or ip.is_multicast or "%" in str(ip) for ip in ips):
        raise ValueError(f"Введите адрес DNS IPv{family} без идентификатора зоны.")
    return list(dict.fromkeys(str(ip) for ip in ips))


def process_birth():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(wintypes.HANDLE(-1), *(ctypes.byref(t) for t in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def wait_for_writer(identity):
    """An already authorised writer may briefly outlive the desktop process."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel.CreateMutexW(None, False, r"Local\DNSPilot-" + guid(identity))
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    handle = wintypes.HANDLE(handle)
    try:
        status = kernel.WaitForSingleObject(handle, 10000)
        if status not in (0, 0x80):
            raise RuntimeError("Предыдущая запись Windows ещё не завершена. Повторите восстановление.")
        kernel.ReleaseMutex(handle)
    finally:
        kernel.CloseHandle(handle)


def change(adapter, family, values):
    # Pass data separately from the fixed elevated command. Resolve the GUID again after UAC.
    payload = dict(owner=os.getpid(), birth=str(process_birth()), guid=guid(adapter["guid"]), family=f"IPv{family}", values=addresses(family, values),
                   expected=adapter[f"v{family}"], mode=adapter[f"mode{family}"])
    blob = base64.b64encode(json.dumps(payload).encode()).decode("ascii")
    elevated = PREAMBLE + "$payload='" + blob + "'\n" + r"""
try {
  $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
  $gate = [Threading.Mutex]::new($false, ('Local\DNSPilot-' + $p.guid))
  try { $held = $gate.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held = $true }
  if (!$held) {exit 22}
  $owner = Get-Process -Id $p.owner -ErrorAction SilentlyContinue
  if (!$owner -or $owner.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -ne $p.birth) {exit 22}
  $a = @(Get-NetAdapter -IncludeHidden | Where-Object { [guid]$_.InterfaceGuid -eq [guid]$p.guid })
  if ($a.Count -ne 1) {exit 21}
  $obj = Get-DnsClientServerAddress -InterfaceIndex $a[0].ifIndex -AddressFamily $p.family
  if (!$obj -or (($obj.ServerAddresses -join ',') -ne ($p.expected -join ','))) {exit 22}
  $service = if ($p.family -eq 'IPv4') {'Tcpip'} else {'Tcpip6'}
  $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$service\Parameters\Interfaces\" + $p.guid
  $raw = (Get-ItemProperty -LiteralPath $path).NameServer
  if (([bool]$raw) -ne ($p.mode -eq 'manual')) {exit 22}
  $enc = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\" + $p.guid + "\DohInterfaceSettings"
  if (Test-Path -LiteralPath $enc) {
    $key = Get-Item -LiteralPath $enc
    if ($key.SubKeyCount -or $key.ValueCount) {exit 22}
  }
  if (@($p.values).Count -gt 0) {
    $obj | Set-DnsClientServerAddress -ServerAddresses ([string[]]$p.values) -ErrorAction Stop
  } else { $obj | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop }
  exit 0
} catch {
  $status = $_.Exception.HResult
  if ($status) {exit $status}
  exit 23
} finally {
  if ($held) { $gate.ReleaseMutex() }
  if ($gate) { $gate.Dispose() }
}
"""
    args = encoded(elevated)
    # Start-Process passes only switches and a base64 token to system Windows PowerShell.
    outer = """
try {
 $child=Start-Process -FilePath ([IO.Path]::Combine($PSHOME,'powershell.exe')) -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','TOKEN')
 Write-Output $child.ExitCode
} catch { Write-Output 24 }
""".replace("TOKEN", args)
    code = ps(outer, timeout=None)  # Keep ownership of the operation throughout the UAC prompt.
    if code == "24":
        raise PermissionError("Повышение прав отменено или недоступно.")
    if code != "0":
        raise RuntimeError({"21": "Адаптер исчез.", "22": "Конфигурация изменилась. Обновите данные.",
                            "23": "Windows отклонила изменение DNS.", "24": "Повышение прав отменено или недоступно."}.get(code, "Ошибка изменения DNS Windows · код " + code))


def adapter_kind(a):
    name = (a.get("name", "") + " " + a.get("description", "")).lower()
    if a.get("type") in (23, 131):
        return "Туннель / VPN"
    if a.get("virtual") and any(x in name for x in ("warp", "vpn", "wireguard", "wintun", "tap-windows")):
        return "VPN"
    if a.get("virtual"):
        return "Виртуальный адаптер"
    return {71: "Wi-Fi", 6: "Ethernet"}.get(a.get("type"), "Физический адаптер")


def protected_adapter(a):
    return bool(a.get("virtual") or a.get("type") in (23, 131))


def digest(data):
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def seal(data):
    data = dict(data, schema=2)
    return dict(data, sha256=digest(data))


def validated(path, legacy=False):
    data = json.loads(path.read_text("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Недопустимый формат снимка DNS.")
    if legacy and "schema" not in data and "sha256" not in data:
        return data
    checksum = data.pop("sha256", None)
    if data.get("schema") != 2 or checksum != digest(data):
        raise ValueError("Нарушена целостность записи DNS. Сохраните её для ручной проверки.")
    return data


def desired(snapshot, family):
    mode = snapshot.get(f"mode{family}")
    raw = snapshot.get(f"v{family}")
    if mode not in ("manual", "auto") or not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise ValueError("Некорректный снимок DNS.")
    if mode == "manual" and not raw:
        raise ValueError("Пустой список в снимке ручного DNS.")
    return addresses(family, raw) if mode == "manual" else []


def unchanged(other, before, family):
    alt = 6 if family == 4 else 4
    return (other.get("encryption") == before.get("encryption") and
            other.get("templates") == before.get("templates") and
            other.get(f"mode{alt}") == before.get(f"mode{alt}") and
            other.get(f"v{alt}") == before.get(f"v{alt}"))


class Manager:
    def __init__(self, root, read=inventory, write=change):
        self.root, self.read, self.write = Path(root), read, write
        self.journal = self.root / "backups" / "operation.json"
        self.lock = threading.RLock()

    def path(self, identity, family):
        return self.root / "backups" / f"{guid(identity)}-v{family}.json"

    def current(self, identity):
        found = next((a for a in self.read() if a["guid"] == identity), None)
        if not found:
            raise ValueError("Адаптер исчез. Обновите список.")
        return found

    def pending(self):
        if not self.journal.exists():
            return None
        op = validated(self.journal)
        desired(op["before"], op["family"])
        if op["phase"] == "completed":
            self.journal.unlink()
            return None
        return op

    def phase(self, op, name):
        op["phase"] = name
        atomic(self.journal, seal(op))

    def complete(self):
        with self.lock:
            op = self.pending()
            if not op or op["phase"] != "verifying":
                raise RuntimeError("Операция DNS не готова к завершению.")
            before, family = op["before"], op["family"]
            current = self.current(before["guid"])
            if desired(current, family) != op["values"] or not unchanged(current, before, family):
                self.phase(op, "recovery")
                raise RuntimeError("Повторное чтение Windows не подтвердило итоговую конфигурацию.")
            if not op["rollback"]:
                path = self.path(op["before"]["guid"], op["family"])
                atomic(path.with_suffix(".previous.json"), seal(op["before"]))
            self.phase(op, "completed")
            self.journal.unlink()

    def recover(self):
        """Called only after the user has reviewed and confirmed the pending snapshot."""
        with self.lock:
            op = self.pending()
            if not op:
                return None
            before, family = op["before"], op["family"]
            if self.write is change:
                wait_for_writer(before["guid"])
            current = self.current(before["guid"])
            previous = desired(before, family)
            actual = desired(current, family)
            if not unchanged(current, before, family):
                raise ValueError("Изменились параметры шифрования или другого семейства. Требуется ручная сверка.")
            if actual != previous:
                if actual != op["values"]:
                    raise ValueError("Текущие DNS изменены извне. Сверьте снимок и настройки Windows вручную.")
                self.phase(op, "recovery")
                self.write(current, family, previous)
                current = self.current(before["guid"])
                if desired(current, family) != previous or not unchanged(current, before, family):
                    raise RuntimeError("Windows не подтвердила восстановление DNS.")
            self.phase(op, "completed")
            self.journal.unlink()
            return current

    def apply(self, preview, family, values, *, rollback=False, defer_completion=False):
        with self.lock:
            if self.pending():
                raise RuntimeError("Требуется восстановление незавершённой операции DNS.")
            return self._apply(preview, family, values, rollback, defer_completion)

    def _apply(self, preview, family, values, rollback, defer_completion):
        values = addresses(family, values)
        identity = preview["guid"]
        before = self.current(identity)
        keys = (f"mode{family}", f"v{family}", "encryption")
        if any(before[k] != preview[k] for k in keys) or not unchanged(before, preview, family):
            raise ValueError("Настройки изменились после просмотра. Обновите адаптер.")
        if before[keys[0]] not in ("auto", "manual") or before["encryption"] is None:
            raise ValueError("Нельзя достоверно сохранить исходную конфигурацию.")
        if before["encryption"]:
            raise ValueError("У адаптера индивидуальные настройки шифрования. Откройте параметры Windows, чтобы сохранить их при изменении DNS.")
        desired(before, family)
        path = self.path(identity, family)
        if not path.exists():
            atomic(path, seal(before))
        else:
            self.saved(identity, family)  # A damaged original must never be overwritten.
        op = dict(before=before, family=family, values=values, rollback=rollback)
        self.phase(op, "prepared")
        self.phase(op, "applying")
        try:
            self.write(before, family, values)
        except PermissionError:
            self.journal.unlink()
            raise
        except Exception:
            self.phase(op, "recovery")
            raise
        self.phase(op, "verifying")
        try:
            after = self.current(identity)
            if desired(after, family) != values or not unchanged(after, before, family):
                raise ValueError("состояние адаптера отличается от ожидаемого")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            self.phase(op, "recovery")
            raise RuntimeError("Повторное чтение Windows не подтвердило изменение: " + str(exc)) from exc
        if not defer_completion:
            self.complete()
        return after

    def saved(self, identity, family, previous=False):
        path = self.path(identity, family)
        if previous:
            path = path.with_suffix(".previous.json")
        if not path.exists():
            raise ValueError("Для этого адаптера и семейства ещё нет резервной копии.")
        data = validated(path, legacy=True)
        if data.get("guid") != identity or data.get(f"mode{family}") not in ("auto", "manual"):
            raise ValueError("Недопустимая резервная копия.")
        return desired(data, family)


def supports_doh():
    return sys.getwindowsversion().build >= 22000
