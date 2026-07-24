"""
app.network.topology_builder — Constructs predefined enterprise network topologies.

The builder is the single authority for wiring up NetworkDevice and NetworkLink
objects into a coherent NetworkTopology. All addressing, naming, and structure
decisions live here.
"""

from __future__ import annotations

import logging
from app.network.topology_models import (
    NetworkDevice,
    NetworkLink,
    NetworkTopology,
    DeviceType,
    NodeStatus,
)

logger = logging.getLogger("TopologyBuilder")


class TopologyBuilder:
    """
    Constructs predefined enterprise network topologies.

    Topology: Enterprise Default
    ─────────────────────────────
    Internet
        │
    Router      (10.0.0.1)
        │
    Firewall    (10.0.0.2)
        │
    Core Switch (no IP — L2 device)
     ┌──┴──────────────┐──────────────┐
     │                 │              │
    Server          Workstation-1  Workstation-2
    (10.0.1.10)     (10.0.2.11)   (10.0.2.12)
     │
    Database
    (10.0.1.20)
    """

    @staticmethod
    def build_enterprise_default() -> NetworkTopology:
        """
        Build and return the default enterprise network topology.

        All devices start in OFFLINE status; they transition to ONLINE
        when the network manager starts the network.
        """
        logger.info("Building enterprise default topology...")

        topology = NetworkTopology(name="Enterprise Default")

        # ── Device Definitions ──────────────────────────────────────────────
        internet = NetworkDevice(
            id="internet",
            hostname="internet-gateway",
            ip_address="203.0.113.1",       # RFC 5737 documentation address
            mac_address="00:00:5E:00:53:01",
            device_type=DeviceType.INTERNET,
            status=NodeStatus.OFFLINE,
        )

        router = NetworkDevice(
            id="router",
            hostname="edge-router-01",
            ip_address="10.0.0.1",
            mac_address="00:1A:2B:3C:4D:01",
            device_type=DeviceType.ROUTER,
            status=NodeStatus.OFFLINE,
        )

        firewall = NetworkDevice(
            id="firewall",
            hostname="fw-perimeter-01",
            ip_address="10.0.0.2",
            mac_address="00:1A:2B:3C:4D:02",
            device_type=DeviceType.FIREWALL,
            status=NodeStatus.OFFLINE,
        )

        core_switch = NetworkDevice(
            id="core-switch",
            hostname="sw-core-01",
            ip_address="10.0.0.254",         # Management IP
            mac_address="00:1A:2B:3C:4D:03",
            device_type=DeviceType.SWITCH,
            status=NodeStatus.OFFLINE,
        )

        server = NetworkDevice(
            id="server",
            hostname="srv-app-01",
            ip_address="10.0.1.10",
            mac_address="00:1A:2B:3C:4D:10",
            device_type=DeviceType.SERVER,
            status=NodeStatus.OFFLINE,
        )

        database = NetworkDevice(
            id="database",
            hostname="db-prod-01",
            ip_address="10.0.1.20",
            mac_address="00:1A:2B:3C:4D:20",
            device_type=DeviceType.DATABASE,
            status=NodeStatus.OFFLINE,
        )

        workstation1 = NetworkDevice(
            id="ws-01",
            hostname="ws-user-01",
            ip_address="10.0.2.11",
            mac_address="00:1A:2B:3C:4D:11",
            device_type=DeviceType.WORKSTATION,
            status=NodeStatus.OFFLINE,
        )

        workstation2 = NetworkDevice(
            id="ws-02",
            hostname="ws-user-02",
            ip_address="10.0.2.12",
            mac_address="00:1A:2B:3C:4D:12",
            device_type=DeviceType.WORKSTATION,
            status=NodeStatus.OFFLINE,
        )

        topology.devices = [
            internet, router, firewall, core_switch,
            server, database, workstation1, workstation2,
        ]

        # ── Link Definitions ────────────────────────────────────────────────
        topology.links = [
            # WAN uplink — lower bandwidth, higher latency
            NetworkLink("internet", "router",      bandwidth_mbps=100.0,  latency_ms=20.0),
            # Core backbone — high bandwidth, low latency
            NetworkLink("router",   "firewall",    bandwidth_mbps=1000.0, latency_ms=0.5),
            NetworkLink("firewall", "core-switch", bandwidth_mbps=1000.0, latency_ms=0.5),
            # Distribution layer
            NetworkLink("core-switch", "server",   bandwidth_mbps=1000.0, latency_ms=0.3),
            NetworkLink("server",      "database", bandwidth_mbps=10000.0, latency_ms=0.1),
            NetworkLink("core-switch", "ws-01",    bandwidth_mbps=100.0,  latency_ms=1.0),
            NetworkLink("core-switch", "ws-02",    bandwidth_mbps=100.0,  latency_ms=1.0),
        ]

        logger.info(
            f"Enterprise topology built: {len(topology.devices)} devices, "
            f"{len(topology.links)} links."
        )
        return topology
