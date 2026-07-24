"""
app.network.mininet_controller — Mininet integration with transparent simulation fallback.

On Linux with Mininet installed: drives a real Mininet network.
On Windows or when Mininet is unavailable: enters a pure simulation mode.

The controller interface is identical in both cases — callers never need to
know which mode is active. The UI never displays an error for missing Mininet.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from app.network.topology_models import NetworkTopology, NetworkDevice, NodeStatus
from app.core.result import Result

logger = logging.getLogger("MininetController")

# Attempt real Mininet import — silently fallback if unavailable
_MININET_AVAILABLE = False
try:
    from mininet.net import Mininet           # type: ignore
    from mininet.topo import Topo             # type: ignore
    from mininet.node import Controller       # type: ignore
    from mininet.link import TCLink           # type: ignore
    from mininet.log import setLogLevel       # type: ignore
    _MININET_AVAILABLE = True
    logger.info("Mininet Python API detected — real network mode available.")
except ImportError:
    logger.info(
        "Mininet not available (expected on Windows). "
        "Operating in full simulation mode."
    )


class MininetController:
    """
    Manages the lifecycle of a Mininet network.

    In simulation mode (Mininet unavailable), all operations succeed
    and update the topology model in memory. The rest of the application
    sees no difference.
    """

    def __init__(self) -> None:
        self._running = False
        self._topology: Optional[NetworkTopology] = None
        self._net = None          # Real Mininet.net object when available
        self._sim_hosts: List[str] = []

    # ── Public API ──────────────────────────────────────────────────────────

    def start_network(self, topology: NetworkTopology) -> Result:
        """
        Start the network with the given topology.

        On Linux with Mininet: builds a real Mininet network.
        On Windows/no Mininet: marks all devices ONLINE and enters sim mode.
        """
        if self._running:
            return Result.ok("Network is already running.")

        self._topology = topology

        if _MININET_AVAILABLE:
            return self._start_mininet(topology)
        else:
            return self._start_simulation(topology)

    def stop_network(self) -> Result:
        """Stop the active network and mark all devices OFFLINE."""
        if not self._running:
            return Result.ok("Network is not running.")

        try:
            if _MININET_AVAILABLE and self._net is not None:
                self._net.stop()
                self._net = None
                logger.info("Mininet network stopped.")

            # Mark all devices offline
            if self._topology:
                for device in self._topology.devices:
                    device.status = NodeStatus.OFFLINE

            self._running = False
            self._sim_hosts.clear()
            return Result.ok("Network stopped successfully.")

        except Exception as exc:
            logger.error(f"Error stopping network: {exc}")
            self._running = False
            return Result.fail(f"Stop error: {exc}")

    def is_running(self) -> bool:
        """Return True if the network is currently active."""
        return self._running

    def get_active_hosts(self) -> List[str]:
        """Return list of active host IDs."""
        return list(self._sim_hosts)

    def get_topology(self) -> Optional[NetworkTopology]:
        """Return the currently managed topology, or None."""
        return self._topology

    # ── Real Mininet Mode ───────────────────────────────────────────────────

    def _start_mininet(self, topology: NetworkTopology) -> Result:
        """Start a real Mininet network from the topology model."""
        try:
            setLogLevel("warning")

            class DynamicTopo(Topo):
                def build(inner_self):
                    hosts = {}
                    for device in topology.devices:
                        h = inner_self.addHost(
                            device.hostname.replace("-", "_"),
                            ip=device.ip_address,
                        )
                        hosts[device.id] = h

                    for link in topology.links:
                        src = hosts.get(link.source_id)
                        dst = hosts.get(link.target_id)
                        if src and dst:
                            inner_self.addLink(src, dst,
                                               bw=link.bandwidth_mbps,
                                               delay=f"{link.latency_ms}ms")

            self._net = Mininet(topo=DynamicTopo(), controller=Controller, link=TCLink)
            self._net.start()

            # Mark devices online
            for device in topology.devices:
                device.status = NodeStatus.ONLINE
                self._sim_hosts.append(device.id)

            self._running = True
            logger.info("Mininet network started successfully.")
            return Result.ok("Mininet network started.")

        except Exception as exc:
            logger.error(f"Mininet start failed: {exc}. Falling back to simulation.")
            return self._start_simulation(topology)

    # ── Simulation Fallback Mode ─────────────────────────────────────────────

    def _start_simulation(self, topology: NetworkTopology) -> Result:
        """
        Activate simulation mode: mark all topology devices ONLINE
        without any real network infrastructure.
        """
        for device in topology.devices:
            device.status = NodeStatus.ONLINE
            self._sim_hosts.append(device.id)

        self._running = True
        mode = "simulation" if not _MININET_AVAILABLE else "simulation (Mininet fallback)"
        logger.info(f"Network started in {mode} mode with {len(topology.devices)} devices.")
        return Result.ok(f"Network started in {mode} mode.")
