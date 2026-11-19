"""HTTP/2-only resolver with TLS, DNS wire format and a pinned loopback address."""
import asyncio
import ssl
from unittest.mock import patch

import dns.message
import dns.rrset
import h2.config
import h2.connection
import h2.events
import trustme

from app.diagnostics import Checker
from app.model import Server, Settings


def test_http2_only_doh_and_independent_website_alpn():
    async def run():
        ca = trustme.CA()
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ca.issue_cert("resolver.invalid", "site.invalid").configure_cert(server_ctx)
        server_ctx.set_alpn_protocols(["h2","http/1.1"])
        client_ctx = ssl.create_default_context()
        ca.configure_trust(client_ctx)
        names, requests = [], []
        server_ctx.set_servername_callback(lambda obj,name,ctx:names.append(name))

        async def serve(reader, writer):
            try:
                if writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
                    requests.append(await reader.readuntil(b"\r\n\r\n"))
                    writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return
                conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
                conn.initiate_connection()
                writer.write(conn.data_to_send())
                data = bytearray()
                while chunk := await reader.read(65536):
                    ended = False
                    for event in conn.receive_data(chunk):
                        if isinstance(event,h2.events.RequestReceived):
                            requests.append(dict(event.headers)[b":authority"])
                        elif isinstance(event,h2.events.DataReceived):
                            data.extend(event.data)
                        elif isinstance(event,h2.events.StreamEnded):
                            q = dns.message.from_wire(bytes(data))
                            answer = dns.message.make_response(q)
                            answer.answer.append(dns.rrset.from_text(q.question[0].name,5,"IN","A","127.0.0.1"))
                            conn.send_headers(event.stream_id,[(b":status",b"200"),(b"content-type",b"application/dns-message")])
                            conn.send_data(event.stream_id,answer.to_wire(),end_stream=True)
                            ended = True
                    writer.write(conn.data_to_send())
                    await writer.drain()
                    if ended:
                        return
            finally:
                writer.close()

        async with await asyncio.start_server(serve,"127.0.0.1",0,ssl=server_ctx) as listener:
            port = listener.sockets[0].getsockname()[1]
            server = Server("local",f"https://resolver.invalid:{port}/dns-query","127.0.0.1")
            c = Checker(Settings(v6=False,allow_local=True),client_ctx)
            with patch("socket.getaddrinfo",side_effect=AssertionError("Unexpected system lookup")):
                result = await c.check(f"https://site.invalid:{port}/",server)
        assert result.code == 204, result.summary
        assert result.hops[0]["queries"][0]["bootstrap_attempts"][0]["http_version"] == "HTTP/2"
        assert requests[0] == f"resolver.invalid:{port}".encode()
        assert b"GET / HTTP/1.1" in requests[1]
        assert names == ["resolver.invalid","site.invalid"]
    asyncio.run(run())
