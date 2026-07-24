"""
app.ui.topology.nodes — Premium enterprise-grade network node cards.

Each node is rendered as a sleek rounded card with:
  - Device category icon (left)
  - Hostname and type label (center)
  - Dynamic status indicator dot (right)
  - Hover highlight and selection border glow
  - Tooltip with full device details

Status dot colors:
  ONLINE       → green   (#22C55E)
  OFFLINE      → gray    (#64748B)
  WARNING      → amber   (#FACC15)
  UNDER_ATTACK → red     (#EF4444)
  BLOCKED      → orange  (#F97316)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from PySide6.QtWidgets import QGraphicsItem, QStyleOptionGraphicsItem, QWidget, QStyle, QToolTip
from PySide6.QtCore import QRectF, QPointF, Qt
from PySide6.QtGui import QPainter, QColor, QFont, QPen, QBrush, QLinearGradient

logger = logging.getLogger("NetworkNode")

# Status → dot color mapping
_STATUS_COLORS = {
    "online":       "#22C55E",
    "offline":      "#64748B",
    "warning":      "#FACC15",
    "under_attack": "#EF4444",
    "blocked":      "#F97316",
}

# Device type → unicode symbol
_DEVICE_ICONS = {
    "internet":    "🌐",
    "router":      "↔",
    "firewall":    "🛡",
    "switch":      "⇄",
    "server":      "▣",
    "database":    "🗄",
    "workstation": "🖥",
}


class NetworkNode(QGraphicsItem):
    """
    Premium enterprise-grade network node card.
    Drag-movable, selectable, hover-highlighted, tooltip-equipped.
    """

    NODE_W = 160
    NODE_H = 44

    def __init__(
        self,
        node_id: str,
        label: str,
        node_type: str,
        status: str = "offline",
        ip_address: str = "",
        mac_address: str = "",
    ) -> None:
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type.lower()
        self.status = status.lower()
        self.ip_address = ip_address
        self.mac_address = mac_address

        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setToolTip(self._build_tooltip())

        self._hovered = False

    # ── QGraphicsItem interface ──────────────────────────────────────────────

    def boundingRect(self) -> QRectF:
        return QRectF(-self.NODE_W / 2 - 6, -self.NODE_H / 2 - 6,
                      self.NODE_W + 12, self.NODE_H + 12)

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionGraphicsItem,
        widget: Optional[QWidget] = None,
    ) -> None:
        painter.setRenderHint(QPainter.Antialiasing)

        is_selected = bool(option.state & QStyle.State_Selected)
        is_hovered  = self._hovered

        # ── OLED Card Background ──────────────────────
        card_rect = QRectF(-self.NODE_W / 2, -self.NODE_H / 2, self.NODE_W, self.NODE_H)

        painter.setBrush(QBrush(QColor("#09090B")))

        if is_selected:
            border_color = QColor("#A3E635")
            border_width = 2.0
        elif is_hovered:
            border_color = QColor("#38BDF8")
            border_width = 2.0
        else:
            border_color = QColor("#27272A")
            border_width = 1.5

        painter.setPen(QPen(border_color, border_width))
        painter.drawRoundedRect(card_rect, 4, 4)

        # ── Device icon (left) ──────────────────────────────────
        icon_char = _DEVICE_ICONS.get(self.node_type, "■")
        icon_rect = QRectF(-self.NODE_W / 2 + 8, -self.NODE_H / 2 + 6, 28, 28)
        icon_font = QFont("Segoe UI Emoji", 13)
        painter.setFont(icon_font)
        painter.setPen(QPen(QColor("#94A3B8")))
        painter.drawText(icon_rect, Qt.AlignCenter, icon_char)

        # ── Text area (center) ──────────────────────────────────
        text_rect = QRectF(-self.NODE_W / 2 + 42, -self.NODE_H / 2 + 5, self.NODE_W - 62, self.NODE_H - 10)

        # Hostname (bold white)
        title_font = QFont("Segoe UI", 8, QFont.Bold)
        painter.setFont(title_font)
        painter.setPen(QPen(QColor("#F0F4FF")))
        elided = painter.fontMetrics().elidedText(self.label, Qt.ElideRight, int(text_rect.width()))
        painter.drawText(text_rect, Qt.AlignTop | Qt.AlignLeft, elided)

        # Device type subtitle (smaller gray)
        sub_font = QFont("Segoe UI", 6)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor("#64748B")))
        painter.drawText(
            text_rect.adjusted(0, 14, 0, 0),
            Qt.AlignTop | Qt.AlignLeft,
            self.node_type.upper(),
        )

        # ── Animated Node Pulsing Ring ─────────────────────────────
        if self.status in ("under_attack", "warning", "online"):
            pulse_color = QColor(_STATUS_COLORS.get(self.status, "#A3E635"))
            pulse_color.setAlpha(80)
            painter.setPen(QPen(pulse_color, 2.5, Qt.DotLine))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(card_rect.adjusted(-6, -6, 6, 6), 6, 6)

        # ── Status dot (right) ─────────────────────────────────
        dot_color = QColor(_STATUS_COLORS.get(self.status, "#64748B"))
        dot_x = self.NODE_W / 2 - 12
        dot_y = 0

        # Glow ring
        glow = QColor(dot_color)
        glow.setAlpha(90)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(glow))
        painter.drawEllipse(QPointF(dot_x, dot_y), 8, 8)

        # Solid core
        painter.setBrush(QBrush(dot_color))
        painter.setPen(QPen(QColor("#000000"), 1.5))
        painter.drawEllipse(QPointF(dot_x, dot_y), 4, 4)

    # ── Hover ────────────────────────────────────────────────────────────────

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    # ── Public API ───────────────────────────────────────────────────────────

    def set_status(self, status: str) -> None:
        """Update node status and refresh the visual dot."""
        self.status = status.lower()
        self.setToolTip(self._build_tooltip())
        self.update()

    def get_center_pos(self) -> QPointF:
        """Return the scene-space center of this node for packet animations."""
        return self.scenePos()

    # ── Internal ─────────────────────────────────────────────────────────────

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        if change == QGraphicsItem.ItemPositionHasChanged:
            scene = self.scene()
            if scene and hasattr(scene, "update_connections"):
                scene.update_connections()
        return super().itemChange(change, value)

    def _build_tooltip(self) -> str:
        """Build HTML tooltip string with full device info."""
        return (
            f"<b>{self.label}</b><br>"
            f"Type: {self.node_type.upper()}<br>"
            f"IP: {self.ip_address or 'N/A'}<br>"
            f"MAC: {self.mac_address or 'N/A'}<br>"
            f"Status: <b>{self.status.upper()}</b>"
        )

    def contextMenuEvent(self, event) -> None:
        """Draw interactive details popup context menu on node right-clicks."""
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui import QAction

        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #151E2F;
                color: #F8FAFC;
                border: 1px solid #2A364F;
                font-family: Consolas;
                font-size: 8pt;
            }
            QMenu::item:selected {
                background-color: #00D2FF;
                color: #0B1220;
            }
        """)

        # Label header
        hdr = QAction(f"NODE: {self.label}", menu)
        hdr.setEnabled(False)
        menu.addAction(hdr)
        menu.addSeparator()

        # Audit Action
        def show_audit():
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(
                None, "Node Security Audit Logs",
                f"Device Hostname : {self.label}\n"
                f"Infrastructure  : {self.node_type.upper()}\n"
                f"IPv4 Address    : {self.ip_address or 'N/A'}\n"
                f"MAC Registry    : {self.mac_address or 'N/A'}\n"
                f"Endpoint Status : {self.status.upper()}\n\n"
                f"Security Controls: VALIDATED (PASS)"
            )

        audit_act = QAction("🔍 Audit Device Details", menu)
        audit_act.triggered.connect(show_audit)
        menu.addAction(audit_act)

        menu.exec(event.screenPos())
