"""HTTP/1.1 over a numeric destination. DNS resolution is outside this module."""
import asyncio
import ipaddress
import ssl
import time
from urllib.parse import urlsplit

import h11


def ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


async def exchange(target: str, address: str, timeout: float, context: ssl.SSLContext,
                   trace: dict, stage, payload: bytes | None = None) -> tuple[int, dict, bytes]:
    u = urlsplit(target)
    writer = None
    ip = str(ipaddress.ip_address(address))

    def begin(name):
        trace["stage"] = name
        stage(name)
        return time.perf_counter()

    try:
        start = begin("TCP")
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(ip, u.port or (443 if u.scheme == "https" else 80))
        trace["tcp_ms"] = ms(start)
        if u.scheme == "https":
            start = begin("TLS")
            async with asyncio.timeout(timeout):
                await writer.start_tls(context, server_hostname=u.hostname, ssl_handshake_timeout=timeout)
            trace["tls_ms"] = ms(start)
            trace["tls_version"] = writer.get_extra_info("ssl_object").version()
        start = begin("HTTP")
        headers = [("Host", u.netloc), ("Connection", "close"), ("User-Agent", "DNS-Pilot/1.0")]
        if payload is not None:
            headers.extend([("Content-Type", "application/dns-message"), ("Accept", "application/dns-message"),
                            ("Content-Length", str(len(payload)))])
        path = u.path + ("?" + u.query if u.query else "")
        conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=65536)
        async with asyncio.timeout(timeout):
            writer.write(conn.send(h11.Request(method="POST" if payload is not None else "GET", target=path, headers=headers)))
            if payload is not None:
                writer.write(conn.send(h11.Data(data=payload)))
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
            body = bytearray()
            response = None
            while True:
                event = conn.next_event()
                if event is h11.NEED_DATA:
                    conn.receive_data(await reader.read(16384))
                elif isinstance(event, h11.Response):
                    response = (event.status_code, dict(event.headers))
                    trace.update(http_ms=ms(start), code=event.status_code)
                    if payload is None:
                        return *response, b""
                elif isinstance(event, h11.Data):
                    body.extend(event.data)
                    if len(body) > 65535:
                        raise ValueError("Слишком большой ответ DoH.")
                elif isinstance(event, h11.EndOfMessage) and response:
                    return *response, bytes(body)
                elif isinstance(event, h11.ConnectionClosed) or event is h11.PAUSED:
                    raise ConnectionError("Сервер закрыл соединение.")
    finally:
        if writer:
            writer.transport.abort()
