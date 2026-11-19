"""Generate the small compass application mark using Qt's vector painter."""
import struct
from pathlib import Path
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPainterPath, QPen

images = []
for size in (16, 32, 48, 64, 128, 256):
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size/64, size/64)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#172629"))
    p.drawRoundedRect(0, 0, 64, 64, 15, 15)
    p.setPen(QPen(QColor("#438f87"), 2))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(QPointF(32,32), 23,23)
    path = QPainterPath(QPointF(46,16))
    for x,y in ((36,39),(18,48),(27,26)):
        path.lineTo(x,y)
    path.closeSubpath()
    p.fillPath(path, QColor("#70e2cf"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#172629"))
    p.drawEllipse(QPointF(32,32), 3,3)
    p.end()
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buffer, "PNG")
    images.append((size, bytes(data)))
offset = 6 + len(images)*16
directory = bytearray(struct.pack("<HHH",0,1,len(images)))
for size,data in images:
    directory.extend(struct.pack("<BBBBHHII",size%256,size%256,0,0,1,32,len(data),offset))
    offset += len(data)
dest = Path(__file__).resolve().parents[1] / "assets/pilot.ico"
dest.parent.mkdir(exist_ok=True)
dest.write_bytes(directory+b"".join(data for _, data in images))
