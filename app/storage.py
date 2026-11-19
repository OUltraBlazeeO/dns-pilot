import csv
import json
import os
import sqlite3
import tempfile
from dataclasses import asdict, fields
from pathlib import Path

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


class Store:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(root / "history.db")
        self.db.execute("CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")

    def settings(self) -> Settings:
        path = self.root / "settings.json"
        if not path.exists():
            return Settings()
        data = json.loads(path.read_text("utf-8"))
        s = Settings(**{f.name: data[f.name] for f in fields(Settings) if f.name in data})
        if "theme" not in data and s.light:
            s.theme = "coral"
        for f in fields(Settings):
            if type(getattr(s, f.name)) is not type(getattr(Settings(), f.name)):
                raise ValueError(f"Некорректная настройка {f.name}")
        for n, low, high in [(s.repeats, 1, 10), (s.parallel, 1, 20), (s.dns_timeout, 1, 30), (s.web_timeout, 1, 60)]:
            if not low <= n <= high:
                raise ValueError("Настройки выходят за допустимые пределы.")
        if not (s.v4 or s.v6):
            raise ValueError("Требуется IPv4 или IPv6.")
        for cust in s.custom:
            Server(**cust)
        for line in s.sites.splitlines():
            if line.strip():
                url(line)
        return s

    def save(self, settings):
        atomic(self.root / "settings.json", asdict(settings))

    def add(self, result):
        with self.db:
            self.db.execute("INSERT INTO checks(data) VALUES (?)", (json.dumps(result.record(), ensure_ascii=False),))

    def records(self, limit=None):
        sql = "SELECT data FROM checks ORDER BY id DESC LIMIT ?"
        return [json.loads(row[0]) for row in self.db.execute(sql, (limit if limit is not None else -1,))]

    def clear(self):
        with self.db:
            self.db.execute("DELETE FROM checks")

    def export(self, path: Path, fmt: str):
        rows = self.records()
        if fmt == "json":
            atomic(path, rows)
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
