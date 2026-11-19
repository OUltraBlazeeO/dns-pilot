"""DoH over a pinned numeric peer. HTTP/2 :authority and TLS SNI retain the endpoint name."""
import ssl
from urllib.parse import urlsplit

import httpx


async def request(endpoint, ip, wire, timeout, context: ssl.SSLContext, trace):
    original = urlsplit(endpoint)
    target = httpx.URL(endpoint).copy_with(host=ip)
    headers = {"Host": original.netloc, "Accept": "application/dns-message",
               "Content-Type": "application/dns-message", "Accept-Encoding": "identity"}
    async with httpx.AsyncClient(verify=context, http2=True, trust_env=False, timeout=timeout) as client:
        async with client.stream("POST", target, headers=headers, content=wire,
                                 extensions={"sni_hostname": original.hostname}) as response:
            trace["http_version"] = response.http_version
            response.raise_for_status()
            if response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/dns-message":
                raise ValueError("DoH вернул неподходящий Content-Type.")
            body = bytearray()
            async for chunk in response.aiter_raw(16384):
                if len(body)+len(chunk) > 65535:
                    raise ValueError("Слишком большой ответ DoH.")
                body.extend(chunk)
            return bytes(body)
