from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget

from .appearance import THEMES


class Rail(QWidget):
    """The reference-specific silhouette lives in the rail, behind the navigation."""
    key = "utility"

    def paintEvent(self,event):
        t = THEMES[self.key]
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w,h = self.width(),self.height()
        p.fillRect(self.rect(),QColor(t.sidebar))
        if self.key == "aurora":
            fade = QLinearGradient(0,h*.5,w,h)
            fade.setColorAt(0,QColor(t.sidebar))
            fade.setColorAt(1,QColor("#303074"))
            p.fillRect(self.rect(),fade)
            for n in range(18):
                path = QPainterPath(QPointF(-10,h-90-n*2))
                path.cubicTo(w*.35,h-160-n,w*.68,h+12-n*4,w+8,h-105-n*3)
                color = QColor("#9788ff")
                color.setAlpha(24+n*2)
                p.setPen(QPen(color,1))
                p.drawPath(path)
        if self.key == "coral":
            for offset,color in ((34,"#f18c78"),(0,"#193452")):
                path = QPainterPath(QPointF(0,h-45-offset))
                path.cubicTo(w*.35,h-104-offset,w*.54,h+24-offset,w,h-115-offset)
                path.lineTo(w,h)
                path.lineTo(0,h)
                p.fillPath(path,QColor(color))
        p.setPen(QColor(t.border))
        p.drawLine(w-1,0,w-1,h)
        p.end()


def brand_mark(key):
    t = THEMES[key]
    px = QPixmap(88,88)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(2,2)
    p.setPen(Qt.PenStyle.NoPen)
    def poly(points,color):
        p.setBrush(QColor(color))
        p.drawPolygon(QPolygonF([QPointF(x,y) for x,y in points]))
    if key=="utility":
        for y,color in ((21,"#166a73"),(14,"#169da7"),(6,t.accent)):
            poly([(2,y+8),(22,y),(42,y+8),(22,y+18)],color)
    elif key=="coral":
        p.setBrush(QColor(t.action))
        p.drawRoundedRect(QRectF(2,2,40,40),11,11)
        p.setPen(QPen(QColor(t.on_action),2.5))
        p.drawPolyline(QPolygonF([QPointF(x,y) for x,y in ((7,25),(14,25),(20,13),(24,31),(29,21),(37,21))]))
    elif key=="aurora":
        for i,color in enumerate(("#7e72ff","#5c99f8","#a59bff")):
            path = QPainterPath(QPointF(3,16+i*8))
            path.cubicTo(17,24+i*8,26,0+i*8,41,10+i*8)
            p.setPen(QPen(QColor(color),5,Qt.PenStyle.SolidLine,Qt.PenCapStyle.RoundCap))
            p.drawPath(path)
    else:
        p.setPen(QPen(QColor(t.accent),2))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPolygon(QPolygonF([QPointF(x,y) for x,y in ((4,12),(22,3),(39,12),(39,31),(22,41),(4,31))]))
        p.drawPolyline(QPolygonF([QPointF(4,12),QPointF(22,22),QPointF(39,12)]))
        p.drawLine(22,22,22,41)
    p.end()
    return px


def theme_thumbnail(key):
    t = THEMES[key]
    pix = QPixmap(160, 74)
    pix.fill(QColor(t.background))
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    def block(x, y, w, h, color, radius=2):
        p.setBrush(QColor(color))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(x,y,w,h), radius,radius)
    block(0,0,30,74,t.sidebar,0)
    block(4,7,22,4,t.accent)
    for y in (22,31,40,49):
        block(5,y,18,2,t.muted)
    block(36,7,63,4,t.text)
    if key == "coral":
        block(36,17,116,21,t.text,5)
        block(42,24,46,5,t.background)
        block(102,44,51,19,t.action)
        block(36,44,60,20,t.raised)
    elif key == "aurora":
        gradient = QLinearGradient(36,14,155,48)
        gradient.setColorAt(0,QColor("#224e63"))
        gradient.setColorAt(1,QColor("#553786"))
        p.setBrush(gradient)
        p.drawRoundedRect(QRectF(35,17,119,28),7,7)
        block(41,26,61,4,t.success)
        block(36,50,72,17,t.raised,5)
        block(113,50,41,17,t.surface,5)
    else:
        for y in (18,43):
            block(36,y,70,20,t.surface,2)
            block(110,y,43,20,t.raised,2)
        if key == "lab":
            p.setPen(QPen(QColor(t.success),1))
            for x in (41,59,77,95):
                p.drawEllipse(QPointF(x,27),3,3)
                if x < 95:
                    p.drawLine(x+4,27,x+14,27)
        else:
            block(41,24,35,3,t.accent)
        for y in (47,53,59):
            block(41,y,56,1,t.muted)
    p.end()
    return QIcon(pix)


class StageChart(QWidget):
    """Render timings from the latest measured hop, with a distinct view per theme."""
    def __init__(self):
        super().__init__()
        self.key, self.record = "utility", None
        self.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Fixed)
        self.setAccessibleName("Последняя проверка. Время этапов DNS, TCP, TLS и HTTP.")

    def sizeHint(self):
        return QSize(320, 118 if self.key in ("aurora","coral") else 94)

    def configure(self, key, record):
        self.key, self.record = key, record
        self.updateGeometry()
        self.update()
        self.setToolTip(record["summary"] if record else "Измерения появятся после проверки сайта")

    def paintEvent(self, event):
        t = THEMES[self.key]
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        base = QColor(t.surface)
        if self.key == "aurora":
            base = QLinearGradient(0,0,w,h)
            for pos,color in ((0,"#123b4a"),(.55,"#253b69"),(1,"#382664")):
                base.setColorAt(pos,QColor(color))
        elif self.key == "coral":
            base = QColor("#192f4b")
        p.setPen(QPen(QColor(t.border),1))
        p.setBrush(base)
        p.drawRoundedRect(QRectF(1,1,w-2,h-2),t.radius,t.radius)
        ink = QColor("#fffaf4" if self.key == "coral" else t.text)
        accent = QColor("#ffab96" if self.key == "coral" else t.accent)
        line = QColor("#aebece" if self.key == "coral" else t.muted)
        p.setFont(QFont(t.heading,12,QFont.Weight.DemiBold))
        p.setPen(ink)
        record = self.record or {}
        p.drawText(QRectF(12,5,w-24,25),Qt.AlignmentFlag.AlignVCenter,
                   p.fontMetrics().elidedText(record.get("site","Этапы проверки"),Qt.TextElideMode.ElideMiddle,w-30))
        hop = (record.get("hops") or [{}])[-1]
        attempt = (hop.get("attempts") or [{}])[-1]
        stages = [("DNS",hop.get("dns_ms"))] + [(s,attempt.get(s.lower()+"_ms")) for s in ("TCP","TLS","HTTP")]
        width = (w-26)/4
        maximum = max([v for _,v in stages if v is not None]+[1])
        for i,(stage,value) in enumerate(stages):
            x = 13 + i*width
            p.setPen(line)
            p.setFont(QFont(t.data_font,9))
            p.drawText(QPointF(x,45),stage)
            p.setFont(QFont(t.data_font,11,QFont.Weight.DemiBold))
            p.setPen(ink)
            p.drawText(QPointF(x,66),f"{value:.0f} мс" if value is not None else "—")
            bar = QRectF(x,76,width-12,4)
            if self.key == "lab":
                p.setPen(QPen(QColor(t.border),1))
                p.drawLine(QPointF(x,79),QPointF(x+width-5,79))
                p.setBrush(QColor(t.success if value is not None else t.background))
                p.drawEllipse(QPointF(x+3,79),4,4)
                if value is not None:
                    for j in range(round(8*value/maximum)):
                        p.fillRect(QRectF(x+12+j*(width-23)/8,74,3,8),accent)
            elif self.key == "aurora":
                p.setPen(QPen(QColor(t.border),3))
                p.drawEllipse(QRectF(x,78,23,23))
                if value is not None:
                    p.setPen(QPen(QColor(t.success),3))
                    p.drawArc(QRectF(x,78,23,23),90*16,-int(5760*value/maximum))
            else:
                p.fillRect(bar,QColor("#526780" if self.key=="coral" else t.border))
                if value is not None:
                    bar.setWidth(bar.width()*value/maximum)
                    p.fillRect(bar,accent)
        p.end()


class LatencyPlot(QWidget):
    def __init__(self):
        super().__init__()
        self.key, self.samples = "utility", []
        self.setMinimumHeight(90)
        self.setMinimumWidth(130)
        self.setAccessibleName("График времени DNS по последним проверкам сайта через тот же сервер")

    def configure(self, key, records):
        self.key = key
        last = records[-1] if records else {}
        self.samples = [r["dns_ms"] for r in records if r["server"] == last.get("server")
                        and r["site"] == last.get("site") and r.get("dns_ms") is not None][-24:]
        self.setToolTip(f'{last.get("site","")}  {last.get("server","")}'.strip())
        self.update()

    def paintEvent(self,event):
        t = THEMES[self.key]
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(8,29,max(1,self.width()-16),max(20,self.height()-49))
        p.setPen(QPen(QColor(t.border),1,Qt.PenStyle.DotLine))
        for n in range(4):
            y = rect.top()+rect.height()*n/3
            p.drawLine(QPointF(rect.left(),y),QPointF(rect.right(),y))
        p.setPen(QColor(t.muted))
        p.setFont(QFont(t.data_font,9))
        if self.samples:
            high = max(max(self.samples),1)
            points = [QPointF(rect.left()+rect.width()*i/max(1,len(self.samples)-1),
                              rect.bottom()-rect.height()*v/high) for i,v in enumerate(self.samples)]
            p.drawText(8,17,f"{self.samples[-1]:.1f} мс   ·   измерений {len(points)}")
            path = QPainterPath(points[0])
            for old,new in zip(points,points[1:]):
                if self.key=="lab":
                    path.lineTo(new.x(),old.y())
                path.lineTo(new)
            color = QColor(t.success if self.key=="lab" else t.accent)
            if self.key in ("aurora","coral"):
                area = QPainterPath(path)
                area.lineTo(points[-1].x(),rect.bottom())
                area.lineTo(points[0].x(),rect.bottom())
                fill = QColor(color)
                fill.setAlpha(37)
                p.fillPath(area,fill)
            p.setPen(QPen(color,2))
            p.drawPath(path)
            p.setBrush(color)
            for point in points:
                p.drawEllipse(point,2.5,2.5)
        else:
            p.drawText(8,17,"Ожидание измерений DNS")
        p.end()
