"""
app.network.topology_models — Core data models for network devices, links, and topology.

These are pure data structures with no UI or framework dependencies.
All enums and dataclasses defined here are the single source of truth
for device identity and network state throughout the application.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


class NodeStatus(Enum):
    """Operational status of a network device."""
    ONLINE = "online"
    OFFLINE = "offline"
    WARNING = "warning"
    UNDER_ATTACK = "under_attack"
    BLOCKED = "blocked"


class DeviceType(Enum):
    """Classification of network device roles."""
    INTERNET = "internet"
    ROUTER = "router"
    FIREWALL = "firewall"
    SWITCH = "switch"
    SERVER = "server"
    DATABASE = "database"
    WORKSTATION = "workstation"


@dataclass
class NetworkDevice:
    """
    Represents a single network device in the enterprise topology.

    Each device has a unique stable ID, human-readable hostname,
    network addressing, a role classification, and a live status.
    """
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    device_type: DeviceType
    status: NodeStatus = NodeStatus.OFFLINE

    @staticmethod
    def generate_id() -> str:
        """Generate a short, unique device identifier."""
        return str(uuid.uuid4())[:8]

    def to_dict(self) -> dict:
        """Serialize device to a plain dictionary for display / logging."""
        return {
            "id": self.id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "device_type": self.device_type.value,
            "status": self.status.value,
        }


@dataclass
class NetworkLink:
    """
    Represents a directional or bidirectional connection between two devices.

    The link carries metadata about bandwidth and latency for future
    quality-of-service simulation (Phase 3+).
    """
    source_id: str
    target_id: str
    bandwidth_mbps: float = 1000.0   # Default: 1 Gbps link
    latency_ms: float = 1.0          # Default: 1 ms latency
    is_active: bool = True

    def to_dict(self) -> dict:
        """Serialize link to a plain dictionary."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "bandwidth_mbps": self.bandwidth_mbps,
            "latency_ms": self.latency_ms,
            "is_active": self.is_active,
        }


@dataclass
class NetworkTopology:
    """
    Container for the complete network topology: devices and links.

    Provides lookup helpers used by the renderer and command parser.
    """
    name: str
    devices: List[NetworkDevice] = field(default_factory=list)
    links: List[NetworkLink] = field(default_factory=list)

    def get_device(self, device_id: str) -> Optional[NetworkDevice]:
        """Return a device by its unique ID, or None if not found."""
        for device in self.devices:
            if device.id == device_id:
                return device
        return None

    def get_device_by_hostname(self, hostname: str) -> Optional[NetworkDevice]:
        """Return a device by hostname, or None if not found."""
        for device in self.devices:
            if device.hostname == hostname:
                return device
        return None

    def get_device_by_ip(self, ip_address: str) -> Optional[NetworkDevice]:
        """Return a device by IP address, or None if not found."""
        for device in self.devices:
            if device.ip_address == ip_address:
                return device
        return None

    def get_links_for_device(self, device_id: str) -> List[NetworkLink]:
        """Return all links connected to the specified device."""
        return [
            link for link in self.links
            if link.source_id == device_id or link.target_id == device_id
        ]

    def set_device_status(self, device_id: str, status: NodeStatus) -> bool:
        """Update device status in place. Returns True if device was found."""
        for device in self.devices:
            if device.id == device_id:
                device.status = status
                return True
        return False

    def get_online_devices(self) -> List[NetworkDevice]:
        """Return only devices currently in ONLINE status."""
        return [d for d in self.devices if d.status == NodeStatus.ONLINE]

    def to_summary(self) -> str:
        """Return a human-readable summary string for terminal display."""
        lines = [
            f"Topology: {self.name}",
            f"Devices : {len(self.devices)}",
            f"Links   : {len(self.links)}",
            f"Online  : {len(self.get_online_devices())}",
        ]
        return "\n".join(lines)
