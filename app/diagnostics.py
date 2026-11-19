import asyncio
import ipaddress
import httpx
from . import doh
from .resolver import system_addresses
import ssl
import statistics
import time
from urllib.parse import urljoin, urlsplit

import dns.asyncquery
import dns.exception
import dns.message
import dns.rcode
import certifi

from .model import Result, Server, Settings, url
from .transport import exchange, ms


def message(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, dns.exception.Timeout, httpx.TimeoutException)):
        return "Тайм-аут"
    return str(exc) or type(exc).__name__


def address_category(value):
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for kind, flag in (("неопределённый", ip.is_unspecified), ("multicast", ip.is_multicast),
                       ("loopback", ip.is_loopback), ("link-local", ip.is_link_local),
                       ("зарезервированный", ip.is_reserved), ("локальный", ip.is_private)):
        if flag:
            return kind
    return "" if ip.is_global else "служебный"


def control_site(results, address, required):
    candidates = [r.site for r in results if r.server == address and passed(r)]
    for site in sorted(set(candidates), key=lambda s: (s not in required, s)):
        try:
            ipaddress.ip_address(urlsplit(site).hostname)
        except ValueError:
            return site
    raise ValueError("Для применения нужен успешно проверенный HTTPS-сайт с доменным именем.")


def passed(result):
    return bool(result.success and result.dns_ok and not result.downgraded and result.hops
                and result.hops[-1]["url"].startswith("https://"))


class Checker:
    def __init__(self, settings: Settings, context: ssl.SSLContext | None = None, dns_port: int = 53):
        self.settings = settings
        self.context = context or ssl.create_default_context()
        if context is None:
            self.context.load_verify_locations(certifi.where())
        # HTTPX configures ALPN on its SSLContext. The HTTP/1.1 site socket must have its own.
        self.doh_context = ssl.create_default_context() if context is None else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if context is None:
            self.doh_context.load_verify_locations(certifi.where())
        else:
            roots = "".join(ssl.DER_cert_to_PEM_cert(cert) for cert in context.get_ca_certs(binary_form=True))
            if roots:
                self.doh_context.load_verify_locations(cadata=roots)
        self.dns_port = dns_port

    async def probe_server(self, profile: Server) -> list[dict]:
        async def probe(endpoint):
            info = {"address": endpoint.address, "type": "A" if self.settings.v4 else "AAAA"}
            await self.query("example.org", info["type"], endpoint, info)
            return info
        return list(await asyncio.gather(*(probe(s) for s in profile.endpoints())))

    async def query(self, host, kind, server, info):
        q = dns.message.make_query(host + ".", kind)
        start = time.perf_counter()
        try:
            async with asyncio.timeout(self.settings.dns_timeout):
                if server.doh:
                    info["protocol"] = "DoH"
                    endpoint = urlsplit(server.address).hostname
                    if server.bootstrap:
                        peers = [server.bootstrap]
                    else:
                        try:
                            peers = [str(ipaddress.ip_address(endpoint))]
                        except ValueError:
                            info["bootstrap_source"] = "Windows"
                            peers = await system_addresses(endpoint)
                    attempts = info["bootstrap_attempts"] = []
                    for i, peer in enumerate(peers):
                        info["bootstrap"] = peer
                        trace = {"ip": peer}
                        attempts.append(trace)
                        budget = max(.01, (self.settings.dns_timeout - (time.perf_counter()-start))/(len(peers)-i))
                        try:
                            async with asyncio.timeout(budget):
                                body = await doh.request(server.address, peer, q.to_wire(), budget, self.doh_context, trace)
                            break
                        except (OSError, httpx.HTTPError, TimeoutError, ValueError) as exc:
                            trace["error"] = message(exc)
                            if i == len(peers)-1:
                                raise
                    else:
                        raise ValueError("Нет IP для имени DoH-сервера.")
                    reply = dns.message.from_wire(body)
                    if not q.is_response(reply):
                        raise ValueError("Ответ DoH не соответствует запросу.")
                else:
                    info["protocol"] = "UDP"
                    reply, tcp = await dns.asyncquery.udp_with_fallback(q, server.address, port=self.dns_port,
                                                                        timeout=self.settings.dns_timeout)
                    if tcp:
                        info["protocol"] = "TCP"
                info["rcode"] = dns.rcode.to_text(reply.rcode())
                if reply.rcode() != dns.rcode.NOERROR:
                    raise ValueError(info["rcode"])
                chained = reply.resolve_chaining()
                info["ips"] = [r.address for r in chained.answer] if chained.answer else []
                if not info["ips"] and chained.canonical_name != q.question[0].name:
                    info["alias"] = chained.canonical_name.to_text(omit_final_dot=True)
                return info["ips"]
        except Exception as exc:
            info["error"] = message(exc)
            info["timeout"] = isinstance(exc, (TimeoutError, dns.exception.Timeout, httpx.TimeoutException))
            return []
        finally:
            info["ms"] = ms(start)

    async def resolve(self, host, server, hop):
        async def family(kind):
            name = host
            seen = set()
            for _ in range(8):
                info = {"type": kind, "name": name}
                hop["queries"].append(info)
                seen.add(name.lower())
                addresses = await self.query(name, kind, server, info)
                name = info.get("alias")
                if addresses or not name:
                    return addresses
                if name.lower() in seen:
                    break
            info["error"] = "Цикл или слишком длинная цепочка CNAME."
            return []
        kinds = [k for k, enabled in (("A", self.settings.v4), ("AAAA", self.settings.v6)) if enabled]
        groups = await asyncio.gather(*(family(k) for k in kinds))
        # Alternate families so that an unreachable family cannot consume all attempts.
        return [g[i] for i in range(max(map(len, groups), default=0)) for g in groups if i < len(g)]

    async def check(self, site: str, server: Server, stage=lambda _: None) -> Result:
        result = Result(site, server.address, server.name, "DoH" if server.doh else "UDP")
        start = time.perf_counter()
        current = url(site)
        deadline = asyncio.timeout(self.settings.dns_timeout * 2 + 3 * self.settings.web_timeout)
        try:
            async with deadline:
                return await self._walk(current, result, server, stage)
        except Exception as exc:
            result.summary = message(exc)
            return result
        finally:
            result.total_ms = ms(start)

    async def _walk(self, current, result, server, stage):
        visited, dns_times = set(), []
        for _ in range(9):
            result.final_url = current
            if current in visited:
                raise ValueError("Цикл перенаправлений.")
            visited.add(current)
            u = urlsplit(current)
            hop = {"url": current, "queries": [], "attempts": []}
            result.hops.append(hop)
            stage("DNS")
            try:
                literal = ipaddress.ip_address(u.hostname)
            except ValueError:
                before = time.perf_counter()
                ips = await self.resolve(u.hostname, server, hop)
                hop["dns_ms"] = ms(before)
                for q in hop["queries"]:
                    result.queries += 1
                    result.answered += int(q.get("rcode") == "NOERROR" and "error" not in q)
                    result.timeouts += int(q.get("timeout", False))
                    if q.get("protocol") == "TCP":
                        result.protocol = "UDP → TCP"
                hop["dns_ok"] = result.dns_ok = bool(ips)
                if not ips:
                    errors = ", ".join(dict.fromkeys(q.get("error", "нет записей " + q["type"]) for q in hop["queries"]))
                    if any(q.get("rcode") not in (None,"NOERROR") for q in hop["queries"]):
                        result.dns_status = "DNS вернул ошибку"
                    elif any("rcode" in q for q in hop["queries"]):
                        result.dns_status = "DNS ответил без адресов"
                    elif hop["queries"] and all(q.get("timeout") for q in hop["queries"]):
                        result.dns_status = "DNS не ответил"
                    else:
                        result.dns_status = "Ошибка соединения с DNS"
                    raise ValueError(result.dns_status + " · " + errors)
                result.dns_status = "DNS ответил успешно"
                dns_times.append(hop["dns_ms"])
                result.dns_ms = round(statistics.median(dns_times), 2)
            else:
                ips = [str(literal)] if (self.settings.v4 if literal.version == 4 else self.settings.v6) else []
                hop["literal"] = True
                if not result.queries:
                    result.dns_status = "Указан IP напрямую"
                if not ips:
                    raise ValueError("Семейство адреса отключено.")
            hop["ips"] = ips
            allowed = []
            for ip in ips:
                category = address_category(ip)
                if category:
                    hop.setdefault("special_ips", {})[ip] = category
                    result.warnings.append(f"Специальный IP {ip} · {category}")
                if not category or (self.settings.allow_local and category not in ("multicast", "неопределённый")):
                    allowed.append(ip)
            if not allowed:
                raise ValueError("Соединение заблокировано · " + ", ".join(result.warnings))
            for ip in allowed:
                attempt = {"ip": ip}
                hop["attempts"].append(attempt)
                try:
                    status, headers, _body = await exchange(current, ip, self.settings.web_timeout, self.context, attempt, stage, deep=self.settings.deep_http)
                    break
                except Exception as exc:
                    attempt["error"] = message(exc)
            else:
                errors = "; ".join(dict.fromkeys(a["stage"] + ": " + a["error"] for a in hop["attempts"]))
                raise ValueError(errors)
            result.code = status
            if status in (301, 302, 303, 307, 308) and b"location" in headers:
                result.code = None  # The final destination has not responded yet.
                current = url(urljoin(current, headers[b"location"].decode("latin-1")))
                hop["redirect"] = current
                dest = urlsplit(current)
                if u.hostname != dest.hostname:
                    result.warnings.append(f"Переход на другой домен · {dest.hostname}")
                if u.scheme == "https" and dest.scheme == "http":
                    result.downgraded = True
                    result.warnings.append(f"HTTPS → HTTP · {hop['url']} → {current}")
                    if self.settings.block_downgrade:
                        raise ValueError("Переход HTTPS → HTTP заблокирован · " + current)
                continue
            if self.settings.deep_http:
                media = attempt.get("content_type", "").split(";",1)[0].strip().lower()
                if "/" not in media:
                    result.warnings.append("Ответ без корректного Content-Type")
                elif media not in ("text/html", "application/xhtml+xml"):
                    result.warnings.append("Тип содержимого · " + media)
            result.success = 200 <= status < 400
            if result.success:
                result.summary = f"{u.scheme.upper()} доступен · HTTP {status}"
            elif status in (403, 429):
                result.summary = f"Сервер доступен · ограничение HTTP {status}"
            else:
                result.summary = f"Сервер ответил · HTTP {status}"
            if result.downgraded:
                result.summary = f"Незащищённый переход · HTTP {status}"
            if result.warnings:
                result.summary += " · " + " | ".join(dict.fromkeys(result.warnings))
            return result
        raise ValueError("Превышен предел перенаправлений.")


def ranking(results: list[Result], required: set[str]):
    rows = []
    for addr in dict.fromkeys(r.server for r in results):
        group = [r for r in results if r.server == addr]
        wins = sum(passed(r) for r in group)
        eligible = bool(wins) and all(any(r.site == s for r in group) and
                                       all(passed(r) for r in group if r.site == s) for s in required)
        score = sum(r.answered for r in group) / max(1, sum(r.queries for r in group))
        times = [r.dns_ms for r in group if r.dns_ms is not None]
        rows.append(dict(address=addr, eligible=eligible, wins=wins, runs=len(group), reliability=score,
                         median=statistics.median(times) if times else float("inf")))
    return sorted(rows, key=lambda r: (not r["eligible"], -r["wins"], -r["reliability"], r["median"], r["address"]))
