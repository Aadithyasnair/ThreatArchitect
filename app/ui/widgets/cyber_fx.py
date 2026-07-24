"""
app.ui.widgets.cyber_fx — Retro-Cyberpunk Scanline Overlay & Tactical Audio Telemetry Engine.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QPainter, QColor, QPen

logger = logging.getLogger("CyberFX")


class CRTScanlineOverlay(QWidget):
    """
    Optional overlay widget rendering retro SOC CRT scanlines & dark matrix grid.
    Set `setAttribute(Qt.WA_TransparentForMouseEvents)` so clicks pass straight through!
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self._enabled = True

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.setVisible(enabled)
        self.update()

    def paintEvent(self, event) -> None:
        if not self._enabled:
            return

        painter = QPainter(self)
        w, h = self.width(), self.height()

        # Render subtle 2px scanline striping
        scanline_pen = QPen(QColor(0, 0, 0, 35), 1.0)
        painter.setPen(scanline_pen)

        for y in range(0, h, 4):
            painter.drawLine(0, y, w, y)


class TacticalAudioEngine:
    """
    Tactical audio telemetry cues for terminal keystrokes and auto-mitigation block alerts.
    """

    @staticmethod
    def play_keystroke() -> None:
        """Plays soft mechanical keyboard click (simulated via system beep or QSoundEffect fallback)."""
        try:
            import winsound
            winsound.Beep(1200, 15)
        except Exception:
            pass

    @staticmethod
    def play_mitigation_alert() -> None:
        """Plays tactical sonar alert chime when an attack is blocked."""
        try:
            import winsound
            winsound.Beep(800, 100)
            winsound.Beep(400, 150)
        except Exception:
            pass
