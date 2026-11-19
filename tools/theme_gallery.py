"""Render README screenshots from a temporary profile and real public DNS checks."""
import sys
import tempfile
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.appearance import THEMES
from app.model import Server, Settings
from app.storage import Store
from app.ui import Window


def main():
    app = QApplication([])
    app.setStyle("Fusion")
    with tempfile.TemporaryDirectory() as tmp:
        window = Window(Store(Path(tmp)),Settings(repeats=3,v6=False),detect=False)
        window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen)
        window.resize(1280,900)
        window.display_adapter()
        window.show()
        window.quick.setText("https://example.org/")
        window.start_test([Server("Cloudflare","1.1.1.1"),Server("Google","8.8.8.8")],
                          ["https://example.org/"], True)
        while window.jobs:
            app.processEvents()
            time.sleep(.01)
        window.go(0)
        image = QImage(1440,1080,QImage.Format.Format_RGB32)
        image.fill(QColor("#17202a"))
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        try:
            for i,(key,t) in enumerate(THEMES.items()):
                window.apply_theme(key)
                QTest.qWait(160)
                snapshot = window.grab()
                x,y = (i%2)*720,(i//2)*540
                painter.setPen(QColor("#ffffff"))
                painter.setFont(QFont("Segoe UI",14,QFont.Weight.DemiBold))
                painter.drawText(x+12,y+27,t.name)
                scaled = snapshot.scaled(712,500,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation)
                painter.drawPixmap(x+4,y+34,scaled)
        finally:
            painter.end()
            window.close()
        dest = ROOT/"docs/themes.jpg"
        dest.parent.mkdir(exist_ok=True)
        if not image.save(str(dest),"JPEG",83):
            raise OSError(dest)


if __name__=="__main__":
    main()
