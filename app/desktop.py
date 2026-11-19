import asyncio
import os
import socket
import subprocess
import winreg
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from .diagnostics import Checker
from .model import url
from .resolver import system_addresses


class Job(QThread):
    progress = Signal(object)
    done = Signal(object)
    failed = Signal(str)
    stopped = Signal()

    def __init__(self, fn):
        super().__init__()
        self.fn = fn
        self.loop = self.task = None
        self.stop_requested = False

    def cancel(self):
        self.stop_requested = True
        if self.loop and self.task:
            try:
                self.loop.call_soon_threadsafe(self.task.cancel)
            except RuntimeError:
                pass

    def run(self):
        async def work():
            self.loop = asyncio.get_running_loop()
            self.task = asyncio.current_task()
            if self.stop_requested:
                raise asyncio.CancelledError
            return await self.fn(self.progress.emit)
        try:
            self.done.emit(asyncio.run(work()))
        except asyncio.CancelledError:
            self.stopped.emit()
        except Exception as exc:
            self.failed.emit(str(exc) or type(exc).__name__)
        finally:
            self.task = self.loop = None


async def batch(servers, sites, settings, emit):
    checker = Checker(settings)
    pairs = iter((server, site) for server in servers for site in sites)
    results = []

    async def worker():
        for server, site in pairs:
            for i in range(settings.repeats):
                tag = f"{server.name} · {site} · {i+1}/{settings.repeats}"
                def stage(name):
                    emit(("stage", tag, name))
                result = await checker.check(site, server, stage)
                results.append(result)
                emit(("result", result))
    async with asyncio.TaskGroup() as group:
        for _ in range(min(settings.parallel, len(servers)*len(sites))):
            group.create_task(worker())
    return results


async def system_check(site, settings):
    """Use Windows getaddrinfo, with the regular website/TLS/redirect checks."""
    class SystemChecker(Checker):
        async def resolve(self, host, _server, hop):
            family = socket.AF_UNSPEC if settings.v4 and settings.v6 else (socket.AF_INET if settings.v4 else socket.AF_INET6)
            try:
                async with asyncio.timeout(settings.dns_timeout):
                    peers = await system_addresses(host, family)
            except (TimeoutError, OSError) as exc:
                raise ConnectionError("Системный резолвер Windows: " + (str(exc) or "тайм-аут")) from exc
            hop["system_lookup"] = True
            return peers
    from types import SimpleNamespace
    system = SimpleNamespace(name="Windows", address="Системный резолвер", doh=False)
    result = await SystemChecker(settings).check(url(site), system)
    result.protocol = "Windows · транспорт не определён"
    return result


BROWSERS = {
    "Microsoft Edge": ("msedge.exe", "Microsoft/Edge/Application/msedge.exe", "edge://settings/privacy"),
    "Google Chrome": ("chrome.exe", "Google/Chrome/Application/chrome.exe", "chrome://settings/security"),
    "Mozilla Firefox": ("firefox.exe", "Mozilla Firefox/firefox.exe", "about:preferences#privacy"),
    "Brave": ("brave.exe", "BraveSoftware/Brave-Browser/Application/brave.exe", "brave://settings/security"),
}


def browser_path(name):
    exe, path, _url = BROWSERS[name]
    candidates = [Path(os.environ[k]) / path for k in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA") if k in os.environ]
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}") as key:
                candidates.append(Path(winreg.QueryValueEx(key, "")[0].strip('"')))
        except OSError:
            pass
    return next((p for p in candidates if p.is_absolute() and p.name.lower() == exe and p.is_file()), None)


def open_browser(name):
    path = browser_path(name)
    if path is None:
        raise ValueError("Исполняемый файл браузера не найден. Вставьте адрес страницы в браузер вручную.")
    subprocess.Popen([str(path), BROWSERS[name][2]], cwd=path.parent)
