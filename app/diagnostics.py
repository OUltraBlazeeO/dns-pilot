import asyncio
import ipaddress
import socket
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
    if isinstance(exc, (TimeoutError, dns.exception.Timeout)):
        return "Тайм-аут"
    return str(exc) or type(exc).__name__


class Checker:
    def __init__(self, settings: Settings, context: ssl.SSLContext | None = None, dns_port: int = 53):
        self.settings = settings
        self.context = context or ssl.create_default_context()
        if context is None:
            self.context.load_verify_locations(certifi.where())
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
                    bootstrap = server.bootstrap
                    info["protocol"] = "DoH"
                    if not bootstrap:
                        endpoint = urlsplit(server.address).hostname
                        try:
                            bootstrap = str(ipaddress.ip_address(endpoint))
                        except ValueError:
                            peers = await asyncio.get_running_loop().getaddrinfo(endpoint, None, type=socket.SOCK_STREAM)
                            bootstrap = peers[0][4][0]
                            info["bootstrap_source"] = "Windows"
                    info["bootstrap"] = bootstrap
                    status, headers, body = await exchange(server.address, bootstrap, self.settings.dns_timeout,
                                                          self.context, info.setdefault("doh", {}), lambda _: None, q.to_wire())
                    if status != 200 or headers.get(b"content-type", b"").split(b";")[0].lower() != b"application/dns-message":
                        raise ValueError(f"DoH HTTP {status}, {headers.get(b'content-type', b'')!r}")
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
            info["timeout"] = isinstance(exc, (TimeoutError, dns.exception.Timeout))
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
        visited = set()
        dns_times = []
        try:
            for _ in range(9):
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
                    result.dns_ok = bool(ips)
                    if not ips:
                        errors = ", ".join(dict.fromkeys(q.get("error", "нет записей " + q["type"]) for q in hop["queries"]))
                        if any("rcode" in q for q in hop["queries"]):
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
                for ip in ips:
                    attempt = {"ip": ip}
                    hop["attempts"].append(attempt)
                    try:
                        status, headers, _body = await exchange(current, ip, self.settings.web_timeout, self.context, attempt, stage)
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
                    continue
                result.success = 200 <= status < 400
                if result.success:
                    result.summary = f"{u.scheme.upper()} доступен · HTTP {status}"
                elif status in (403, 429):
                    result.summary = f"Сервер доступен · ограничение HTTP {status}"
                else:
                    result.summary = f"Сервер ответил · HTTP {status}"
                return result
            raise ValueError("Превышен предел перенаправлений.")
        except Exception as exc:
            result.summary = message(exc)
            return result
        finally:
            result.total_ms = ms(start)


def ranking(results: list[Result], required: set[str]):
    rows = []
    for addr in dict.fromkeys(r.server for r in results):
        group = [r for r in results if r.server == addr]
        def passed(r):
            return bool(r.success and r.dns_ok and r.hops and r.hops[-1]["url"].startswith("https://"))
        wins = sum(passed(r) for r in group)
        eligible = bool(wins) and all(any(r.site == s for r in group) and
                                       all(passed(r) for r in group if r.site == s) for s in required)
        score = sum(r.answered for r in group) / max(1, sum(r.queries for r in group))
        times = [r.dns_ms for r in group if r.dns_ms is not None]
        rows.append(dict(address=addr, eligible=eligible, wins=wins, runs=len(group), reliability=score,
                         median=statistics.median(times) if times else float("inf")))
    return sorted(rows, key=lambda r: (not r["eligible"], -r["wins"], -r["reliability"], r["median"], r["address"]))
