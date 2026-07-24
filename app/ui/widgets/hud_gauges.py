"""
app.ui.widgets.hud_gauges — Cyber Security HUD Radial Arc Gauges & Live Traffic Heatmap.
"""

from __future__ import annotations

import math
from typing import List
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QSizePolicy
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QColor, QFont, QPen, QBrush, QConicalGradient, QPainterPath


class RadialGaugeWidget(QWidget):
    """
    Semi-circular radial arc gauge for Threat Score (0-100) & LSTM Anomaly Index (0.0-1.0).
    """

    def __init__(self, title: str = "THREAT SCORE", max_value: float = 100.0, parent=None) -> None:
        super().__init__(parent)
        self.title = title
        self.max_value = max_value
        self.current_value = 0.0
        self.setMinimumSize(110, 80)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)

    def set_value(self, val: float) -> None:
        self.current_value = max(0.0, min(self.max_value, float(val)))
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        margin = 12
        side = min(w, h * 2) - margin * 2
        rect = QRectF((w - side) / 2, h - side / 2 - 10, side, side)

        # Background track arc (180 degrees: 180 to 0)
        track_pen = QPen(QColor("#0F172A"), 10, Qt.SolidLine, Qt.FlatCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, 0 * 16, 180 * 16)

        # Outer border accent
        border_pen = QPen(QColor("#000000"), 3, Qt.SolidLine)
        painter.setPen(border_pen)
        painter.drawArc(rect.adjusted(-5, -5, 5, 5), 0 * 16, 180 * 16)

        # Value Arc fill
        pct = self.current_value / self.max_value
        span_angle = int(-180 * pct * 16)

        if self.current_value > 75:
            arc_color = QColor("#EF4444")
        elif self.current_value > 45:
            arc_color = QColor("#FACC15")
        else:
            arc_color = QColor("#A3E635")

        value_pen = QPen(arc_color, 10, Qt.SolidLine, Qt.FlatCap)
        painter.setPen(value_pen)
        painter.drawArc(rect, 180 * 16, span_angle)

        # Center Text
        val_str = f"{self.current_value:.0f}" if self.max_value == 100 else f"{self.current_value:.2f}"
        val_font = QFont("Consolas", max(11, int(h * 0.22)), QFont.Bold)
        painter.setFont(val_font)
        painter.setPen(QPen(arc_color))
        val_rect = QRectF(0, h - int(h * 0.42), w, int(h * 0.25))
        painter.drawText(val_rect, Qt.AlignCenter, val_str)

        # Title Label
        title_font = QFont("Segoe UI", max(7, int(h * 0.12)), QFont.Bold)
        painter.setFont(title_font)
        painter.setPen(QPen(QColor("#94A3B8")))
        title_rect = QRectF(0, h - int(h * 0.18), w, int(h * 0.15))
        painter.drawText(title_rect, Qt.AlignCenter, self.title.upper())


class TrafficHeatmapWidget(QWidget):
    """
    60-second rolling packet volume sparkline heatmap bar.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(160, 45)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.history: List[float] = [0.0] * 60

    def add_sample(self, pkt_rate: float) -> None:
        self.history.append(float(pkt_rate))
        if len(self.history) > 60:
            self.history = self.history[-60:]
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()

        # Neo-Brutalist Frame
        frame_rect = QRectF(0, 0, w, h)
        painter.setBrush(QBrush(QColor("#0F172A")))
        painter.setPen(QPen(QColor("#000000"), 3))
        painter.drawRoundedRect(frame_rect, 4, 4)

        max_val = max(max(self.history), 10.0)
        n = len(self.history)
        bar_w = max(2.0, (w - 12) / n)

        for i, val in enumerate(self.history):
            x = 6 + i * bar_w
            bar_h = max(2.0, (val / max_val) * (h - 14))
            y = h - 6 - bar_h

            if val > 100:
                color = QColor("#EF4444")
            elif val > 40:
                color = QColor("#FACC15")
            else:
                color = QColor("#38BDF8")

            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawRect(QRectF(x, y, max(1.5, bar_w - 1), bar_h))

        # Title Overlay
        painter.setFont(QFont("Segoe UI", 7, QFont.Bold))
        painter.setPen(QPen(QColor("#A3E635")))
        painter.drawText(QRectF(8, 4, w - 16, 12), Qt.AlignLeft | Qt.AlignTop, "LIVE PACKET RATE (60s)")
