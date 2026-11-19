"""Loopback DNS and TLS servers. The .invalid test names cannot resolve publicly."""
import asyncio
import socket
import ssl
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest
import trustme

from app.diagnostics import Checker
from app.model import Server, Settings, url


def wire(packet, *, rcode=0, truncate=False):
    q = dns.message.from_wire(packet)
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    if truncate:
        r.flags |= dns.flags.TC
    elif not rcode and q.question[0].rdtype == 1:
        r.answer.append(dns.rrset.from_text(q.question[0].name, 10, "IN", "A", "127.0.0.1"))
    return r.to_wire()


class UDP(asyncio.DatagramProtocol):
    def __init__(self, fn):
        self.fn = fn

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, packet, addr):
        data = self.fn(packet)
        if data:
            self.transport.sendto(data, addr)


async def udp(fn):
    t, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UDP(fn), local_addr=("127.0.0.1",0))
    return t, t.get_extra_info("sockname")[1]


@pytest.mark.parametrize("rcode,expected", [(dns.rcode.NXDOMAIN,"NXDOMAIN"),(dns.rcode.SERVFAIL,"SERVFAIL"),(dns.rcode.REFUSED,"REFUSED"), (None,"Тайм-аут")])
def test_dns_failure(rcode, expected):
    async def run():
        t, port = await udp(lambda packet: wire(packet, rcode=rcode) if rcode else None)
        try:
            c = Checker(Settings(v6=False, dns_timeout=1), dns_port=port)
            r = await c.check("nonexistent.invalid", Server("local","127.0.0.1"))
            assert expected in r.summary and not r.dns_ok
            assert r.timeouts == int(rcode is None)
        finally:
            t.close()
    asyncio.run(run())


def test_truncated_udp_uses_tcp():
    async def run():
        t, port = await udp(lambda p: wire(p, truncate=True))
        async def tcp(reader, writer):
            size = int.from_bytes(await reader.readexactly(2), "big")
            data = wire(await reader.readexactly(size))
            writer.write(len(data).to_bytes(2,"big")+data)
            await writer.drain()
            writer.close()
        listener = await asyncio.start_server(tcp, "127.0.0.1", port)
        try:
            info = {}
            c = Checker(Settings(), dns_port=port)
            assert await c.query("pilot.invalid","A",Server("test","127.0.0.1"),info) == ["127.0.0.1"]
            assert info["protocol"] == "TCP"
        finally:
            listener.close()
            await listener.wait_closed()
            t.close()
    asyncio.run(run())


def test_direct_probe_each_dns_independently():
    async def run():
        primary, port = await udp(wire)
        loop = asyncio.get_running_loop()
        backup, _ = await loop.create_datagram_endpoint(lambda: UDP(lambda p: wire(p, rcode=dns.rcode.REFUSED)),
                                                         local_addr=("127.0.0.2", port))
        try:
            checker = Checker(Settings(), dns_port=port)
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("Unexpected system lookup")):
                result = await checker.probe_server(Server("pair","127.0.0.1",secondary="127.0.0.2"))
            assert [(r["address"],r["rcode"]) for r in result] == [("127.0.0.1","NOERROR"),("127.0.0.2","REFUSED")]
            assert all(r["ms"] >= 0 for r in result)
        finally:
            primary.close()
            backup.close()
    asyncio.run(run())


@pytest.mark.parametrize("use_doh,final", [(False,200),(True,403),(False,429),(True,503)])
def test_pinned_tls_redirects_and_doh(use_doh, final):
    async def run():
        ca = trustme.CA()
        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ca.issue_cert("one.invalid","two.invalid","resolver.invalid").configure_cert(server_ssl)
        client_ssl = ssl.create_default_context()
        ca.configure_trust(client_ssl)
        sni, requests, dns_names = [], [], []
        server_ssl.set_servername_callback(lambda obj, name, ctx: sni.append(name))
        def answer(data):
            dns_names.append(str(dns.message.from_wire(data).question[0].name))
            return wire(data)
        async def handle(reader, writer):
            line = await reader.readline()
            headers = {}
            while (line2 := await reader.readline()) not in (b"", b"\r\n"):
                k,v = line2.decode().strip().split(":",1)
                headers[k.lower()] = v.strip()
            host = headers["host"].split(":")[0]
            requests.append((host, line.decode().strip()))
            if host == "resolver.invalid":
                body = answer(await reader.readexactly(int(headers["content-length"])))
                resp = f"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {len(body)}\r\n\r\n".encode()+body
            elif host == "one.invalid":
                resp = f"HTTP/1.1 302 Found\r\nLocation: https://two.invalid:{port}/page?q=1\r\nContent-Length: 0\r\n\r\n".encode()
            else:
                resp = f"HTTP/1.1 {final} Status\r\nContent-Length: 0\r\n\r\n".encode()
            writer.write(resp)
            await writer.drain()
            writer.close()
        listener = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ssl)
        port = listener.sockets[0].getsockname()[1]
        t, dns_port = await udp(answer)
        server = Server("DoH", f"https://resolver.invalid:{port}/dns-query","127.0.0.1") if use_doh else Server("udp","127.0.0.1")
        checker = Checker(Settings(allow_local=True), client_ssl, dns_port)
        try:
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("Unexpected system resolver")):
                result = await checker.check(f"https://one.invalid:{port}/start", server)
            assert result.code == final, result.record()
            assert result.success == (final == 200)
            assert len(result.hops) == 2 and result.answered == 4
            assert result.hops[1]["attempts"][0]["ip"] == "127.0.0.1"
            assert {"one.invalid","two.invalid"} <= set(sni)
            assert set(dns_names) == {"one.invalid.","two.invalid."}
            assert ("two.invalid","GET /page?q=1 HTTP/1.1") in requests
            if use_doh:
                assert "resolver.invalid" in sni and ("resolver.invalid", "POST /dns-query HTTP/1.1") in requests
            untrusted = Checker(Settings(v6=False, allow_local=True), dns_port=dns_port)
            failed = await untrusted.check(f"https://one.invalid:{port}",server)
            assert "CERTIFICATE_VERIFY_FAILED" in failed.summary
        finally:
            t.close()
            listener.close()
            await listener.wait_closed()
    asyncio.run(run())


def test_cancel_network_loss_and_retry():
    async def run():
        t, port = await udp(lambda p: None)
        c = Checker(Settings(dns_timeout=20), dns_port=port)
        try:
            job = asyncio.create_task(c.check("cancel.invalid",Server("test","127.0.0.1")))
            await asyncio.sleep(0.05)
            job.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(job, 1)
            with patch("app.diagnostics.dns.asyncquery.udp_with_fallback", side_effect=OSError("Сеть отключена")):
                result = await c.check("offline.invalid",Server("test","127.0.0.1"))
            assert "Сеть отключена" in result.summary and not result.success
        finally:
            t.close()
    asyncio.run(run())


@pytest.mark.parametrize("bad", ["ftp://abc","https://u:p@abc","http://a\n.invalid","https://a:65536","https://a\\b",""])
def test_invalid_urls(bad):
    with pytest.raises(ValueError):
        url(bad)


def test_ipv6_resolver_and_destination():
    async def run():
        def answer(data):
            query = dns.message.from_wire(data)
            reply = dns.message.make_response(query)
            reply.answer.append(dns.rrset.from_text(query.question[0].name, 1, "IN", "AAAA", "::1"))
            return reply.to_wire()
        async def http(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
            await writer.drain()
            writer.close()
        loop = asyncio.get_running_loop()
        try:
            udp6, _ = await loop.create_datagram_endpoint(lambda: UDP(answer), local_addr=("::1",0), family=socket.AF_INET6)
        except OSError as exc:
            pytest.skip(f"IPv6 loopback unavailable: {exc}")
        async with await asyncio.start_server(http,"::1",0,family=socket.AF_INET6) as web:
            try:
                c = Checker(Settings(v4=False,v6=True,allow_local=True), dns_port=udp6.get_extra_info("sockname")[1])
                r = await c.check(f"http://six.invalid:{web.sockets[0].getsockname()[1]}",Server("IPv6","::1"))
                assert r.success and r.code == 204 and r.hops[0]["ips"] == ["::1"]
                assert r.hops[0]["queries"][0]["type"] == "AAAA"
            finally:
                udp6.close()
    asyncio.run(run())


def test_cname_only_response_uses_same_dns():
    async def run():
        names = []
        def answer(data):
            query = dns.message.from_wire(data)
            name = query.question[0].name
            names.append(str(name))
            if str(name) == "alias.invalid.":
                reply = dns.message.make_response(query)
                reply.answer.append(dns.rrset.from_text(name,1,"IN","CNAME","target.invalid."))
                return reply.to_wire()
            return wire(data)
        transport, port = await udp(answer)
        try:
            c = Checker(Settings(v6=False),dns_port=port)
            hop = {"queries":[]}
            assert await c.resolve("alias.invalid",Server("local","127.0.0.1"),hop) == ["127.0.0.1"]
            assert names == ["alias.invalid.","target.invalid."]
        finally:
            transport.close()
    asyncio.run(run())
