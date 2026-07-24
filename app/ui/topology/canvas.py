"""
app.ui.topology.canvas — Interactive QGraphicsView for the network topology.

Implements ITopologyRenderer so NetworkManager/TopologyRenderer can drive it
without importing Qt widgets in the business logic layer.

Features:
  - Zoom with mouse wheel
  - Pan with right/middle mouse drag
  - Premium node cards with hover and selection
  - Packet animation spawning
  - Dynamic topology loading from NetworkTopology model
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtWidgets import QGraphicsView, QSizePolicy
from PySide6.QtCore import Qt, QTimer, QRectF
from PySide6.QtGui import QWheelEvent, QMouseEvent, QPainter, QResizeEvent

from app.core.interfaces import ITopologyRenderer
from app.ui.topology.scene import TopologyScene

logger = logging.getLogger("TopologyCanvas")


class TopologyCanvas(QGraphicsView, ITopologyRenderer):
    """
    Interactive network topology canvas.

    Can be driven either by direct render_node/render_link calls (via ITopologyRenderer)
    or by load_topology(NetworkTopology) which delegates to TopologyRenderer.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.scene_obj = TopologyScene(self)
        self.setScene(self.scene_obj)

        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setDragMode(QGraphicsView.RubberBandDrag)
        self.setStyleSheet("background-color: #0B0F17; border: none;")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self._pan_active = False
        self._pan_start_x = 0.0
        self._pan_start_y = 0.0
        self._animation_duration_ms = 900
        self._has_topology = False

    def drawBackground(self, painter: QPainter, rect: QRectF) -> None:
        """Render 2.5D Tiered Layer Planes background bands."""
        super().drawBackground(painter, rect)
        painter.save()
        
        # 4 Tier Zones
        zones = [
            (-350, -220, "#050507", "ZONE 01: EXTERNAL PERIMETER & INTERNET GATEWAY"),
            (-220, -80,  "#0A0A0E", "ZONE 02: PERIMETER FIREWALL & SECURITY DMZ"),
            (-80,  100,  "#0F0F14", "ZONE 03: ENTERPRISE CORE INFRASTRUCTURE & LAN"),
            (100,  280,  "#030305", "ZONE 04: SECURE INTERNAL DATA VAULT"),
        ]

        from PySide6.QtGui import QFont, QPen, QColor, QBrush
        for top, bot, color_hex, label in zones:
            z_rect = QRectF(rect.left(), top, rect.width(), bot - top)
            painter.setBrush(QBrush(QColor(color_hex)))
            painter.setPen(QPen(QColor("#27272A"), 1, Qt.DashLine))
            painter.drawRect(z_rect)

            # Zone Tag Label
            painter.setFont(QFont("Consolas", 9, QFont.Bold))
            painter.setPen(QPen(QColor("#A1A1AA")))
            painter.drawText(QRectF(rect.left() + 20, top + 8, 400, 20), Qt.AlignLeft, label)

        painter.restore()

    # ── ITopologyRenderer ────────────────────────────────────────────────────

    def render_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        x: float = 0,
        y: float = 0,
        status: str = "offline",
        ip_address: str = "",
        mac_address: str = "",
    ) -> None:
        """Create or update a node on the canvas."""
        if node_id in self.scene_obj.nodes:
            node = self.scene_obj.nodes[node_id]
            node.label = label
            node.node_type = node_type.lower()
            node.setPos(x, y)
            node.set_status(status)
            node.ip_address = ip_address
            node.mac_address = mac_address
            node.update()
        else:
            self.scene_obj.add_network_node(
                node_id, label, node_type, x, y,
                status=status, ip_address=ip_address, mac_address=mac_address,
            )

    def render_link(self, node_a: str, node_b: str, status: str = "active") -> None:
        """Draw a connection between two nodes."""
        self.scene_obj.add_network_link(node_a, node_b)

    def clear(self) -> None:
        """Clear all topology items from the canvas."""
        self.scene_obj.clear_topology()

    # ── NetworkTopology integration ──────────────────────────────────────────

    def load_topology(self, topology) -> None:
        """
        Render a full NetworkTopology object by delegating to TopologyRenderer.
        Defers the fitInView call 50ms so the scene rect is fully computed first.
        """
        from app.network.topology_renderer import TopologyRenderer
        renderer = TopologyRenderer(self)
        renderer.render(topology)
        self._has_topology = True
        # Defer fit so Qt has time to compute the scene bounding rect
        QTimer.singleShot(50, self._fit_topology)

    def _fit_topology(self) -> None:
        """Fit the entire topology in view with a small margin."""
        rect = self.scene_obj.itemsBoundingRect()
        if not rect.isEmpty():
            self.fitInView(rect.adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Re-fit topology in view whenever the panel is resized."""
        super().resizeEvent(event)
        if self._has_topology:
            self._fit_topology()

    def animate_packet(self, packet_event) -> None:
        """Spawn a packet animation for the given PacketEvent."""
        color = "#22C55E" # Default Green (normal)
        if getattr(packet_event, "is_dangerous", False):
            color = "#EF4444" # Red (dangerous)
        elif getattr(packet_event, "is_suspicious", False):
            color = "#FACC15" # Yellow (suspicious)

        dst_id = packet_event.dst_id
        is_allowed = getattr(packet_event, "is_allowed", True)

        if not is_allowed:
            # Re-route to firewall card
            dst_id = "firewall"

        self.scene_obj.add_packet_animation(
            src_id=packet_event.src_id,
            dst_id=dst_id,
            color_hex=color,
            duration_ms=self._animation_duration_ms,
        )

        if getattr(packet_event, "is_dangerous", False) and dst_id:
            self.update_node_status(dst_id, "under_attack")
        elif getattr(packet_event, "is_suspicious", False) and dst_id:
            self.update_node_status(dst_id, "warning")

        if not is_allowed:
            # Flash the firewall node red when the packet reaches it
            from PySide6.QtCore import QTimer
            QTimer.singleShot(self._animation_duration_ms, self._flash_firewall_red)

    def _flash_firewall_red(self) -> None:
        """Flash firewall node in red error state, then revert to online status."""
        self.update_node_status("firewall", "under_attack")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(350, lambda: self.update_node_status("firewall", "online"))

    def update_node_status(self, node_id: str, status: str) -> None:
        """Update the visual status dot of a node."""
        self.scene_obj.update_node_status(node_id, status)

    def update_all_statuses(self, topology) -> None:
        """Sync all node status dots from a live NetworkTopology."""
        if not topology:
            return
        for device in topology.devices:
            self.update_node_status(device.id, device.status.value)

    def set_animation_duration(self, ms: int) -> None:
        self._animation_duration_ms = ms

    # ── Mouse interactions ───────────────────────────────────────────────────

    def wheelEvent(self, event: QWheelEvent) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() in (Qt.MiddleButton, Qt.RightButton):
            self._pan_active = True
            self._pan_start_x = event.position().x()
            self._pan_start_y = event.position().y()
            self.setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._pan_active:
            dx = event.position().x() - self._pan_start_x
            dy = event.position().y() - self._pan_start_y
            self.horizontalScrollBar().setValue(int(self.horizontalScrollBar().value() - dx))
            self.verticalScrollBar().setValue(int(self.verticalScrollBar().value() - dy))
            self._pan_start_x = event.position().x()
            self._pan_start_y = event.position().y()
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() in (Qt.MiddleButton, Qt.RightButton):
            self._pan_active = False
            self.setCursor(Qt.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)
