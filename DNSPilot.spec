from PyInstaller.utils.hooks import collect_submodules
import os
import sys
from pathlib import Path
import PySide6

# Limit native dependency discovery to Windows, CPython and Qt.
# Developer tools on PATH may carry incompatible ICU and UCRT binaries.
qt = Path(PySide6.__file__).parent
system = Path(os.environ["SystemRoot"])
os.environ["PATH"] = os.pathsep.join(map(str, [qt, Path(sys.base_prefix), system / "System32", system]))

a = Analysis(["main.py"], datas=[("assets/pilot.ico", "assets")],
             hiddenimports=["dns._asyncio_backend", *collect_submodules("dns.rdtypes")],
             excludes=["pytest","trustme","httpx","httpx2","cryptography","trio","tkinter","numpy",
                       "PySide6.QtQml","PySide6.QtQuick","PySide6.QtNetwork"])
for idx, (dest, source, kind) in enumerate(a.binaries):
    if dest.lower() in ("vcruntime140.dll", "vcruntime140_1.dll") and (qt / dest).exists():
        a.binaries[idx] = (dest, str(qt / dest), kind)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="DNS Pilot", console=False,
          icon="assets/pilot.ico", upx=False)
