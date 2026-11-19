"""Bound the lifetime of a GUI job independently of blocking Windows resolver calls."""
import asyncio
import ctypes as ct
import socket
import threading
from ctypes import wintypes as wt

_slots = threading.BoundedSemaphore(8)


async def blocking_lookup(fn, *args):
    while not _slots.acquire(blocking=False):
        await asyncio.sleep(.025)
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def finish(value, error):
        if not future.done():
            if error:
                future.set_exception(error)
            else:
                future.set_result(value)

    def run():
        try:
            value, error = fn(*args), None
        except Exception as exc:
            value, error = None, exc
        finally:
            _slots.release()
        try:
            loop.call_soon_threadsafe(finish, value, error)
        except RuntimeError:
            pass  # The requesting job already closed its event loop.

    thread = threading.Thread(target=run, daemon=True, name="DNS Pilot resolver")
    try:
        thread.start()
    except BaseException:
        _slots.release()
        raise
    return await future


async def system_addresses(host, family=socket.AF_UNSPEC):
    peers = await blocking_lookup(socket.getaddrinfo, host, None, family, socket.SOCK_STREAM)
    return list(dict.fromkeys(p[4][0] for p in peers))


class QueryRequest(ct.Structure):
    _fields_ = [("version", wt.DWORD), ("name", wt.LPCWSTR), ("kind", wt.WORD),
                ("options", ct.c_ulonglong), ("servers", ct.c_void_p), ("index", wt.ULONG),
                ("callback", ct.c_void_p), ("context", ct.c_void_p)]


class QueryResult(ct.Structure):
    _fields_ = [("version", wt.DWORD), ("status", wt.LONG), ("options", ct.c_ulonglong),
                ("records", ct.c_void_p), ("reserved", ct.c_void_p)]


class Record(ct.Structure):
    _fields_ = [("next", ct.c_void_p), ("name", ct.c_void_p), ("kind", wt.WORD),
                ("length", wt.WORD), ("flags", wt.DWORD), ("ttl", wt.DWORD),
                ("reserved", wt.DWORD), ("data", ct.c_ubyte * 16)]


def interface_query(host, kind, index):
    if index <= 0:
        raise ValueError("Не указан индекс сетевого интерфейса.")
    dll = ct.WinDLL("dnsapi")
    query = dll.DnsQueryEx
    query.argtypes = [ct.POINTER(QueryRequest), ct.POINTER(QueryResult), ct.c_void_p]
    query.restype = wt.LONG
    release = dll.DnsRecordListFree
    release.argtypes = [ct.c_void_p, ct.c_int]
    release.restype = None
    req = QueryRequest(version=1, name=host.rstrip(".")+".", kind=kind,
                       options=0x8 | 0x40, index=index)  # BYPASS_CACHE | NO_HOSTS_FILE
    result = QueryResult(version=1)
    status = query(ct.byref(req), ct.byref(result), None)
    try:
        if status == 9501:  # DNS_INFO_NO_RECORDS
            return []
        if status or result.status:
            raise OSError(status or result.status, "Ошибка DNS выбранного интерфейса")
        ptr, addresses = result.records, []
        while ptr:
            rec = Record.from_address(ptr)
            if rec.kind == kind and rec.length >= (4 if kind == 1 else 16):
                size = 4 if kind == 1 else 16
                addresses.append(socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                                  bytes(rec.data[:size])))
            ptr = rec.next
        return addresses
    finally:
        if result.records:
            release(result.records, 1)


async def verify_interface(host, index, settings):
    kinds = [k for k, use in ((1, settings.v4), (28, settings.v6)) if use]
    async with asyncio.timeout(settings.dns_timeout):
        responses = await asyncio.gather(*(blocking_lookup(interface_query, host, k, index) for k in kinds),
                                         return_exceptions=True)
    ips = [ip for group in responses if isinstance(group, list) for ip in group]
    if not ips:
        raise ValueError("Резолвер выбранного интерфейса не подтвердил адрес домена.")
    return ips
