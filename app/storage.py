import csv
import json
import math
import os
import sqlite3
import tempfile
from dataclasses import asdict, fields
from pathlib import Path

from .privacy import redact
from .model import Server, Settings, url


def atomic(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
        name = f.name
        try:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            f.close()
            os.unlink(name)
            raise
    try:
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def valid_record(record):
    def timing(value):
        return value is None or type(value) in (float, int) and math.isfinite(value) and value >= 0

    if not isinstance(record, dict):
        return False
    if not all(isinstance(record.get(k), str) for k in ("site", "server", "name", "summary", "timestamp", "protocol")):
        return False
    if not all(timing(record.get(k)) for k in ("dns_ms", "total_ms", "timeouts")):
        return False
    if "total_ms" not in record or "timeouts" not in record or not isinstance(record.get("hops"), list):
        return False
    warnings = record.get("warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        return False
    for hop in record["hops"]:
        if not isinstance(hop, dict) or not isinstance(hop.get("url"), str) or not timing(hop.get("dns_ms")):
            return False
        if not isinstance(hop.get("queries"), list) or not isinstance(hop.get("attempts"), list):
            return False
        for query in hop["queries"]:
            if not isinstance(query, dict) or "ms" not in query or "type" not in query:
                return False
            if not isinstance(query.get("ips", []), list) or not all(isinstance(x,str) for x in query.get("ips", [])):
                return False
        for attempt in hop["attempts"]:
            if not isinstance(attempt, dict) or not isinstance(attempt.get("ip"), str):
                return False
            if not all(timing(attempt.get(k)) for k in ("tcp_ms","tls_ms","http_ms")):
                return False
    return True


class Store:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.warning = ""
        self.persistent = True
        self.history_limit = Settings().history_limit
        self.path = root / "history.db"
        try:
            self.db = sqlite3.connect(self.path)
            self.db.execute("CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
            if self.db.execute("PRAGMA user_version").fetchone()[0] == 0:
                with self.db:
                    for idx, raw in self.db.execute("SELECT id,data FROM checks ORDER BY id"):
                        clean = redact(raw)
                        if clean != raw:
                            try:
                                clean = json.dumps(redact(json.loads(raw)), ensure_ascii=False)
                            except ValueError:
                                continue
                            self.db.execute("UPDATE checks SET data=? WHERE id=?", (clean, idx))
                    self.db.execute("PRAGMA user_version=1")
        except sqlite3.Error:
            if hasattr(self, "db"):
                self.db.close()
            self.persistent = False
            self.warning = "История недоступна. Исходная база сохранена. Диагностика и восстановление DNS доступны."
            self.db = sqlite3.connect(":memory:")
            self.db.execute("CREATE TABLE checks (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")

    def settings(self) -> Settings:
        path = self.root / "settings.json"
        if not path.exists():
            return Settings()
        data = json.loads(path.read_text("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Некорректный формат настроек.")
        s = Settings(**{f.name: data[f.name] for f in fields(Settings) if f.name in data})
        if "theme" not in data and s.light:
            s.theme = "coral"
        for f in fields(Settings):
            if type(getattr(s, f.name)) is not type(getattr(Settings(), f.name)):
                raise ValueError(f"Некорректная настройка {f.name}")
        for n, low, high in [(s.history_limit, 1, 100000), (s.repeats, 1, 10), (s.parallel, 1, 20), (s.dns_timeout, 1, 30), (s.web_timeout, 1, 60)]:
            if not low <= n <= high:
                raise ValueError("Настройки выходят за допустимые пределы.")
        if not (s.v4 or s.v6):
            raise ValueError("Требуется IPv4 или IPv6.")
        s.custom = [asdict(Server(**cust)) for cust in s.custom]
        for line in s.sites.splitlines():
            if line.strip():
                url(line)
        self.limit(s.history_limit)
        return s

    def save(self, settings):
        atomic(self.root / "settings.json", asdict(settings))

    def limit(self, count):
        with self.db:
            self.db.execute("DELETE FROM checks WHERE id <= (SELECT id FROM checks ORDER BY id DESC LIMIT 1 OFFSET ?)", (count,))
        self.history_limit = count

    def add(self, result):
        with self.db:
            self.db.execute("INSERT INTO checks(data) VALUES (?)", (json.dumps(redact(result.record()), ensure_ascii=False),))
            self.limit(self.history_limit)

    def records(self, limit=None):
        return list(self.iter_rows(self.db, limit))

    @staticmethod
    def iter_rows(db, limit=None):
        for (raw,) in db.execute("SELECT data FROM checks ORDER BY id DESC"):
            try:
                result = json.loads(raw)
                if not valid_record(result):
                    continue
                yield redact(result)
            except (TypeError, ValueError):
                continue
            if limit is not None:
                limit -= 1
                if limit <= 0:
                    return

    def clear(self):
        with self.db:
            self.db.execute("DELETE FROM checks")

    def export(self, path: Path, fmt: str):
        path = path.resolve()
        if path.parent == self.root.resolve() and (path.name == "settings.json" or path.suffix.lower() not in (".csv",".json")):
            raise ValueError("Выберите отдельный файл экспорта.")
        if path.is_relative_to((self.root / "backups").resolve()):
            raise ValueError("Выберите папку вне резервных копий DNS.")
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
            staging = Path(temp.name)
        try:
            self._export(staging, fmt)
            os.replace(staging, path)
        finally:
            staging.unlink(missing_ok=True)

    def _export(self, path, fmt):
        if self.persistent:
            from contextlib import closing
            with closing(sqlite3.connect(self.path.resolve().as_uri()+"?mode=ro", uri=True)) as db:
                self.write_export(path, fmt, self.iter_rows(db))
        else:
            self.write_export(path, fmt, self.records())

    @staticmethod
    def write_export(path, fmt, rows):
        if fmt == "json":
            with path.open("w", encoding="utf-8") as out:
                out.write("[")
                for i, item in enumerate(rows):
                    if i:
                        out.write(",\n")
                    json.dump(item,out,ensure_ascii=False)
                out.write("]")
        else:
            keys = ["timestamp", "site", "server", "protocol", "dns_status", "dns_ok", "dns_ms", "code", "summary", "total_ms", "timeouts", "hops"]
            with path.open("w", encoding="utf-8-sig", newline="") as out:
                writer = csv.DictWriter(out, keys, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    row["hops"] = json.dumps(row["hops"], ensure_ascii=False)
                    for k in keys:
                        if isinstance(row.get(k), str) and row[k].startswith(("=", "+", "-", "@", "\t", "\r")):
                            row[k] = "'" + row[k]
                    writer.writerow(row)
