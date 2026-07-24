"""
app.network.topology_renderer — Translates NetworkTopology into canvas draw calls.

Implements a hierarchical top-down layout algorithm:
  - No coordinates are hardcoded
  - Devices are grouped by role (Internet → Router → Firewall → Switch → leaves)
  - Leaf nodes (servers, workstations, databases) are spread horizontally

The renderer calls ITopologyRenderer methods only — no direct Qt scene access.
"""

from __future__ import annotations

import logging
import math
from typing import List, Dict, Tuple

from app.network.topology_models import NetworkTopology, NetworkDevice, DeviceType
from app.core.interfaces import ITopologyRenderer

logger = logging.getLogger("TopologyRenderer")

# Vertical spacing between hierarchy levels (pixels in scene units)
_LEVEL_HEIGHT = 140
# Minimum horizontal spacing between sibling nodes
_NODE_SPACING = 180
# Canvas center offset
_CENTER_X = 0
_TOP_Y = -300


# Device type → hierarchy level (lower = higher on screen)
_HIERARCHY: Dict[DeviceType, int] = {
    DeviceType.INTERNET:    0,
    DeviceType.ROUTER:      1,
    DeviceType.FIREWALL:    2,
    DeviceType.SWITCH:      3,
    DeviceType.SERVER:      4,
    DeviceType.DATABASE:    5,
    DeviceType.WORKSTATION: 4,
}


class TopologyRenderer:
    """
    Renders a NetworkTopology onto an ITopologyRenderer (the canvas).

    Layout is computed dynamically each time render() is called.
    """

    def __init__(self, canvas: ITopologyRenderer) -> None:
        self._canvas = canvas

    def render(self, topology: NetworkTopology) -> None:
        """
        Clear the canvas and draw the topology with computed node positions.
        """
        self._canvas.clear()

        positions = self._compute_positions(topology)

        # Draw nodes
        for device in topology.devices:
            x, y = positions.get(device.id, (0, 0))
            self._canvas.render_node(
                node_id=device.id,
                label=device.hostname,
                node_type=device.device_type.value,
                x=x,
                y=y,
            )

        # Draw links
        for link in topology.links:
            self._canvas.render_link(link.source_id, link.target_id)

        logger.info(
            f"Topology rendered: {len(topology.devices)} nodes, {len(topology.links)} links."
        )

    def _compute_positions(
        self, topology: NetworkTopology
    ) -> Dict[str, Tuple[float, float]]:
        """
        Compute (x, y) scene positions for each device using hierarchical layout.

        Devices at the same level are distributed evenly across the horizontal axis.
        """
        # Group devices by their hierarchy level
        levels: Dict[int, List[NetworkDevice]] = {}
        for device in topology.devices:
            level = _HIERARCHY.get(device.device_type, 4)
            levels.setdefault(level, []).append(device)

        positions: Dict[str, Tuple[float, float]] = {}

        for level, devices in sorted(levels.items()):
            y = _TOP_Y + level * _LEVEL_HEIGHT
            count = len(devices)

            if count == 1:
                # Single device: center it
                positions[devices[0].id] = (_CENTER_X, y)
            else:
                # Multiple devices: spread symmetrically around center
                total_width = (count - 1) * _NODE_SPACING
                start_x = _CENTER_X - total_width / 2
                for i, device in enumerate(devices):
                    x = start_x + i * _NODE_SPACING
                    positions[device.id] = (x, y)

        return positions
