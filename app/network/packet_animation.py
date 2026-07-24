"""
app.network.packet_animation — Animated packet visual traveling between topology nodes.

PacketAnimationItem is a QGraphicsItem that:
  - Renders as a glowing colored circle
  - Moves from source node to destination node over a configurable duration
  - Auto-removes itself from the scene upon arrival
  - Operates at ~60 FPS via a QTimer
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QGraphicsItem, QGraphicsScene
from PySide6.QtCore import QPointF, QTimer, QRectF
from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QRadialGradient

logger = logging.getLogger("PacketAnimation")

# Animation parameters
_FRAME_INTERVAL_MS = 16      # ~60 FPS
_DEFAULT_DURATION_MS = 900   # Time to traverse source→destination
_PACKET_RADIUS = 5           # Dot radius in scene units


class PacketAnimationItem(QGraphicsItem):
    """
    Animated packet that travels from a source QPointF to a destination QPointF.

    Color codes:
      Green (#22C55E)  — normal traffic (Phase 2)
      Red   (#EF4444)  — attack traffic (Phase 3+)
      Amber (#FACC15)  — suspicious traffic (Phase 3+)
    """

    def __init__(
        self,
        src_pos: QPointF,
        dst_pos: QPointF,
        color: QColor = None,
        duration_ms: int = _DEFAULT_DURATION_MS,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._src = src_pos
        self._dst = dst_pos
        self._color = color or QColor("#22C55E")
        self._duration_ms = max(duration_ms, 200)
        self._elapsed_ms = 0
        self._progress = 0.0   # 0.0 = at source, 1.0 = at destination

        self.setZValue(10)     # Render above nodes and links
        self.setPos(src_pos)

        # Drive animation via a recurring QTimer
        self._timer = QTimer()
        self._timer.timeout.connect(self._step)
        self._timer.start(_FRAME_INTERVAL_MS)

    # ── QGraphicsItem overrides ──────────────────────────────────────────────

    def boundingRect(self) -> QRectF:
        r = _PACKET_RADIUS + 4  # Include glow margin
        return QRectF(-r, -r, r * 2, r * 2)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        painter.setRenderHint(QPainter.Antialiasing)

        # Outer glow
        glow_color = QColor(self._color)
        glow_color.setAlpha(60)
        painter.setPen(Qt_NoPen())
        painter.setBrush(QBrush(glow_color))
        painter.drawEllipse(QPointF(0, 0), _PACKET_RADIUS + 3, _PACKET_RADIUS + 3)

        # Core dot with radial gradient
        gradient = QRadialGradient(QPointF(0, 0), _PACKET_RADIUS)
        gradient.setColorAt(0.0, QColor("#FFFFFF"))
        gradient.setColorAt(0.4, self._color)
        gradient.setColorAt(1.0, self._color.darker(130))
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(self._color.darker(150), 0.5))
        painter.drawEllipse(QPointF(0, 0), _PACKET_RADIUS, _PACKET_RADIUS)

    # ── Animation Logic ──────────────────────────────────────────────────────

    def _step(self) -> None:
        """Advance animation one frame. Remove from scene when complete."""
        self._elapsed_ms += _FRAME_INTERVAL_MS
        self._progress = min(self._elapsed_ms / self._duration_ms, 1.0)

        # Linear interpolation src → dst
        x = self._src.x() + (self._dst.x() - self._src.x()) * self._progress
        y = self._src.y() + (self._dst.y() - self._src.y()) * self._progress
        self.setPos(x, y)
        self.update()

        if self._progress >= 1.0:
            self._timer.stop()
            scene = self.scene()
            if scene:
                scene.removeItem(self)


def Qt_NoPen():
    """Return a Qt NoPen-equivalent as a QPen."""
    from PySide6.QtCore import Qt
    return QPen(Qt.NoPen)
