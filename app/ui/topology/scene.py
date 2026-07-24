"""
app.ui.topology.scene — QGraphicsScene for the network topology canvas.

Manages nodes, links, and packet animation items.
Provides methods for topology loading, status updates, and packet spawning.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from PySide6.QtWidgets import QGraphicsScene, QGraphicsLineItem
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QPen, QColor

from app.ui.topology.nodes import NetworkNode

logger = logging.getLogger("TopologyScene")


class NetworkLink(QGraphicsLineItem):
    """Connection line between two NetworkNodes. Updates when nodes move."""

    def __init__(self, node_a: NetworkNode, node_b: NetworkNode) -> None:
        super().__init__()
        self.node_a = node_a
        self.node_b = node_b
        self.setZValue(-1)
        self.update_position()

    def update_position(self) -> None:
        pos_a = self.node_a.scenePos()
        pos_b = self.node_b.scenePos()
        self.setLine(pos_a.x(), pos_a.y(), pos_b.x(), pos_b.y())
        self.setPen(QPen(QColor("#2A364F"), 1.5, Qt.SolidLine))


class TopologyScene(QGraphicsScene):
    """
    QGraphicsScene for the network topology.

    Maintains indexed collections of nodes and links.
    Provides packet animation injection and node status updates.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.nodes: Dict[str, NetworkNode] = {}
        self.links: List[NetworkLink] = []

    # ── Node Management ──────────────────────────────────────────────────────

    def add_network_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        x: float,
        y: float,
        status: str = "offline",
        ip_address: str = "",
        mac_address: str = "",
    ) -> NetworkNode:
        """Create and add a premium node card to the scene."""
        node = NetworkNode(
            node_id=node_id,
            label=label,
            node_type=node_type,
            status=status,
            ip_address=ip_address,
            mac_address=mac_address,
        )
        node.setPos(x, y)
        self.addItem(node)
        self.nodes[node_id] = node
        return node

    def update_node_status(self, node_id: str, status: str) -> None:
        """Update the visual status of a node by ID."""
        node = self.nodes.get(node_id)
        if node:
            node.set_status(status)

    # ── Link Management ──────────────────────────────────────────────────────

    def add_network_link(self, node_a_id: str, node_b_id: str) -> Optional[NetworkLink]:
        """Draw a connection line between two existing nodes."""
        node_a = self.nodes.get(node_a_id)
        node_b = self.nodes.get(node_b_id)

        if not node_a or not node_b:
            logger.warning(f"Cannot add link — node not found: {node_a_id} → {node_b_id}")
            return None

        link = NetworkLink(node_a, node_b)
        self.addItem(link)
        self.links.append(link)
        return link

    def update_connections(self) -> None:
        """Refresh all link line endpoints after node positions change."""
        for link in self.links:
            link.update_position()

    # ── Packet Animation ─────────────────────────────────────────────────────

    def add_packet_animation(
        self,
        src_id: str,
        dst_id: str,
        color_hex: str = "#22C55E",
        duration_ms: int = 900,
    ) -> None:
        """
        Spawn an animated packet item traveling from src node to dst node.
        The item self-destructs on arrival.
        """
        from app.network.packet_animation import PacketAnimationItem
        from PySide6.QtGui import QColor

        src_node = self.nodes.get(src_id)
        dst_node = self.nodes.get(dst_id)

        if not src_node or not dst_node:
            return

        src_pos = src_node.scenePos()
        dst_pos = dst_node.scenePos()

        packet = PacketAnimationItem(
            src_pos=src_pos,
            dst_pos=dst_pos,
            color=QColor(color_hex),
            duration_ms=duration_ms,
        )
        self.addItem(packet)

    # ── Topology Clear ───────────────────────────────────────────────────────

    def clear_topology(self) -> None:
        """Remove all nodes, links, and animation items from the scene."""
        self.clear()
        self.nodes.clear()
        self.links.clear()
