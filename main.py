import logging
import os
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PySide6.QtCore import QLockFile, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from app.model import Settings
from app.storage import Store
from app.ui import Window


def main():
    live = sys.argv[1:] == ["--self-test-live"]
    smoke = live or sys.argv[1:] == ["--self-test"]
    if smoke:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication([sys.argv[0]])
    app.setApplicationName("DNS Pilot")
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(str(Path(__file__).parent / "assets/pilot.ico")))
    tmp = tempfile.TemporaryDirectory() if smoke else None
    root = Path(tmp.name) if tmp else Path(os.environ["LOCALAPPDATA"]) / "DNS Pilot"
    root.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(root / "session.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QMessageBox.information(None, "DNS Pilot", "DNS Pilot уже запущен или каталог данных занят.")
        return 1
    logging.basicConfig(level=logging.INFO, handlers=[RotatingFileHandler(root / "pilot.log", maxBytes=500000,
                        backupCount=2, encoding="utf-8")], format="%(asctime)s %(levelname)s %(message)s")
    store = Store(root)
    try:
        settings = store.settings()
    except (ValueError, TypeError, KeyError) as exc:
        from datetime import datetime
        backup = root / ("settings.damaged-" + datetime.now().strftime("%Y%m%d%H%M%S") + ".json")
        (root / "settings.json").replace(backup)
        QMessageBox.warning(None, "DNS Pilot", f"Не удалось прочитать настройки. Копия сохранена в {backup}.\n{exc}")
        settings = Settings()
    window = Window(store, settings, detect=not smoke)
    def on_error(kind, value, tb):
        if smoke:
            logging.error("Самопроверка", exc_info=(kind, value, tb))
            app.exit(2)
        else:
            logging.getLogger().log(logging.DEBUG if isinstance(value, ValueError) else logging.ERROR,
                                    "Ошибка операции", exc_info=(kind, value, tb))
            window.warn(str(value))
    sys.excepthook = on_error
    window.show()
    if smoke:
        def verify():
            import dns.asyncbackend
            import dns.message
            import dns.rrset
            from app.diagnostics import Checker
            Checker(settings)
            dns.asyncbackend.get_backend("asyncio")
            assert dns.message.from_wire(dns.message.make_query("example.org.", "AAAA").to_wire()).question
            assert dns.rrset.from_text("example.org.", 1, "IN", "A", "192.0.2.1")
            for i in range(8):
                window.go(i)
            assert window.stack.count() == 8 and window.quick_dns.count() >= 20
            if live:
                from app.model import presets
                from app.windows import inventory
                from app.desktop import batch
                import asyncio
                async def diagnose(emit):
                    adapters = await asyncio.to_thread(inventory)
                    assert any(a["up"] for a in adapters)
                    cfg = Settings(repeats=1, v6=False)
                    return await batch(presets()[:2], ["https://github.com/"], cfg, emit)
                def complete(results):
                    if len(results) == 2 and all(r.success and r.dns_ok for r in results):
                        QTimer.singleShot(0, window.close)
                    else:
                        app.exit(3)
                window.job(diagnose, complete, error=lambda _: app.exit(3))
            else:
                window.close()
        QTimer.singleShot(50, verify)
    code = app.exec()
    store.db.close()
    lock.unlock()
    logging.shutdown()
    if tmp:
        tmp.cleanup()
    return code


if __name__ == "__main__":
    sys.exit(main())
