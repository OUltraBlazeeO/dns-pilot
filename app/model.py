from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from urllib.parse import quote, urlsplit, urlunsplit


def url(value: str, *, doh: bool = False) -> str:
    value = value.strip()
    if not value or any(ord(c) < 33 or c == "\\" for c in value):
        raise ValueError("Введите домен или URL без пробелов.")
    if "://" not in value:
        if doh:
            raise ValueError("Для DoH нужен полный HTTPS URL.")
        value = "https://" + value
    u = urlsplit(value)
    if u.scheme not in (("https",) if doh else ("http", "https")) or u.username is not None or not u.hostname:
        raise ValueError("Допустим HTTP(S) URL без логина и пароля.")
    host = u.hostname.encode("idna").decode("ascii").rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in host.split(".")):
            raise ValueError("Недопустимое имя узла.") from None
    if u.port == 0:
        raise ValueError("Недопустимый номер порта.")
    authority = host + (f":{u.port}" if u.port else "")
    return urlunsplit((u.scheme, authority, quote(u.path or "/", safe="/%:@!$&'()*+,;=-._~"), quote(u.query, safe="/?%:@!$&'()*+,;=-._~"), ""))


@dataclass(frozen=True)
class Server:
    name: str
    address: str
    bootstrap: str = ""
    secondary: str = ""

    def __post_init__(self):
        addr = self.address.strip()
        if "://" in addr:
            addr = url(addr, doh=True)
        else:
            try:
                addr = str(ipaddress.ip_address(addr))
            except ValueError as exc:
                raise ValueError("Введите IPv4, IPv6 или полный HTTPS URL для DoH.") from exc
        object.__setattr__(self, "address", addr)
        if self.secondary:
            if self.doh:
                raise ValueError("Резервный IP указывается для обычного DNS.")
            try:
                backup = ipaddress.ip_address(self.secondary.strip())
            except ValueError as exc:
                raise ValueError("Введите корректный резервный IP-адрес.") from exc
            primary = ipaddress.ip_address(addr)
            if backup.version != primary.version:
                raise ValueError("Основной и резервный адреса должны относиться к одному семейству IP.")
            if backup == primary:
                raise ValueError("Основной и резервный адреса совпадают.")
            object.__setattr__(self, "secondary", str(backup))
        if self.bootstrap:
            if not self.doh:
                raise ValueError("Bootstrap IP используется только для DoH.")
            object.__setattr__(self, "bootstrap", str(ipaddress.ip_address(self.bootstrap.strip())))
        if not self.name.strip():
            raise ValueError("Введите название сервера.")

    @property
    def doh(self):
        return self.address.startswith("https://")

    @property
    def label(self):
        return f"{self.name}  ·  {self.address}"

    def endpoints(self) -> list[Server]:
        """Each benchmark measures exactly one destination, including a backup."""
        if not self.secondary:
            return [self]
        return [Server(self.name, self.address), Server(self.name + " · резервный", self.secondary)]


PROVIDERS = {
    "Cloudflare": (["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"], "https://cloudflare-dns.com/dns-query"),
    "Google Public DNS": (["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"], "https://dns.google/dns-query"),
    "Quad9": (["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"], "https://dns.quad9.net/dns-query"),
    "Cloudflare Families": (["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"], "https://security.cloudflare-dns.com/dns-query"),
}


def presets() -> list[Server]:
    return [server for name, (ips, endpoint) in PROVIDERS.items()
            for server in [Server(name, ips[0]), Server(name, endpoint, ips[0]), *[Server(name, ip) for ip in ips[1:]]]]


@dataclass
class Settings:
    light: bool = False
    theme: str = "utility"
    dns_timeout: int = 3
    web_timeout: int = 6
    repeats: int = 2
    parallel: int = 4
    v4: bool = True
    v6: bool = True
    history: bool = True
    detailed: bool = False
    auto_apply: bool = False
    sites: str = "wikipedia.org\ngithub.com"
    custom: list[dict] = field(default_factory=list)
    geometry: str = ""
    adapter_guid: str = ""


@dataclass
class Result:
    site: str
    server: str
    name: str
    protocol: str
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))
    summary: str = ""
    success: bool = False
    dns_ok: bool = False
    dns_status: str = "Нет измерения"
    dns_ms: float | None = None
    total_ms: float = 0
    queries: int = 0
    answered: int = 0
    timeouts: int = 0
    code: int | None = None
    hops: list[dict] = field(default_factory=list)

    def record(self):
        return asdict(self)
