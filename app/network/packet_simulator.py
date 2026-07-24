"""
app.network.packet_simulator — Simulated enterprise network traffic generator.

Generates realistic PacketEvent objects representing legitimate enterprise
protocols: DNS, HTTP, HTTPS, SSH, FTP, ICMP.

Traffic distribution is weighted to approximate real-world enterprise ratios:
  HTTPS (40%), HTTP (20%), DNS (15%), ICMP (10%), SSH (10%), FTP (5%)
"""

from __future__ import annotations

import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from enum import Enum

from app.network.topology_models import NetworkTopology, NetworkDevice, DeviceType
from app.core.interfaces import ITrafficEmulator

logger = logging.getLogger("PacketSimulator")


class Protocol(Enum):
    """Simulated network protocol types."""
    DNS   = ("DNS",   53,  "udp",  15)   # (name, port, transport, weight)
    HTTP  = ("HTTP",  80,  "tcp",  20)
    HTTPS = ("HTTPS", 443, "tcp",  40)
    SSH   = ("SSH",   22,  "tcp",  10)
    FTP   = ("FTP",   21,  "tcp",   5)
    ICMP  = ("ICMP",  0,   "icmp", 10)
    ARP   = ("ARP",   0,   "arp",  0)
    DHCP  = ("DHCP",  67,  "udp",  0)

    def __init__(self, label: str, port: int, transport: str, weight: int) -> None:
        self.label = label
        self.port = port
        self.transport = transport
        self.weight = weight


@dataclass
class PacketEvent:
    """
    Represents a single simulated network packet traversal.

    Carries enough context for UI animation and log display.
    """
    packet_id: str
    src_id: str                # Source device ID
    dst_id: str                # Destination device ID
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size_bytes: int
    timestamp: float           # Unix epoch float
    is_allowed: bool = True    # Firewall decision
    is_suspicious: bool = False # Suspicious traffic marker
    is_dangerous: bool = False  # Dangerous traffic marker (Phase 4)
    attack_type: Optional[str] = None

    @property
    def label(self) -> str:
        """Short display label for log output."""
        if self.is_dangerous and self.attack_type:
            hdr = f"ATTACK: {self.attack_type}"
        elif self.is_suspicious and self.attack_type:
            hdr = f"SUSPICIOUS: {self.attack_type}"
        elif self.is_dangerous:
            hdr = "ATTACK STREAM"
        elif self.is_suspicious:
            hdr = f"SUSPICIOUS {self.protocol.label}"
        else:
            hdr = self.protocol.label

        return f"[{hdr}] {self.src_ip} -> {self.dst_ip} ({self.size_bytes}B)"


    @staticmethod
    def generate() -> "PacketEvent":
        """Generate a dummy PacketEvent — for testing only."""
        proto = random.choices(list(Protocol), weights=[p.weight for p in Protocol], k=1)[0]
        return PacketEvent(
            packet_id=str(uuid.uuid4())[:8],
            src_id="ws-01",
            dst_id="server",
            src_ip="10.0.2.11",
            dst_ip="10.0.1.10",
            protocol=proto,
            size_bytes=random.randint(64, 1500),
            timestamp=time.time(),
        )


class NormalTrafficSimulator(ITrafficEmulator):
    """
    Generates realistic legitimate enterprise network traffic.

    Selects random source/destination pairs from topology devices
    and emits weighted-random protocol packets via a registered callback.
    """

    def __init__(self) -> None:
        self._topology: Optional[NetworkTopology] = None
        self._running = False
        self._packet_callback: Optional[Callable[[PacketEvent], None]] = None
        self._stats = {"sent": 0, "delivered": 0, "lost": 0}

        # Protocol weight list for random selection
        self._protocols = list(Protocol)
        self._weights = [p.weight for p in self._protocols]

    # ── ITrafficEmulator Interface ───────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        logger.info("NormalTrafficSimulator started.")

    def stop(self) -> None:
        self._running = False
        logger.info("NormalTrafficSimulator stopped.")

    def get_status(self) -> str:
        return "RUNNING" if self._running else "STOPPED"

    def generate_normal_traffic(self) -> Optional[PacketEvent]:
        """
        Generate one legitimate packet event.
        Returns None if the simulator isn't ready.
        """
        if not self._running or not self._topology:
            return None

        # Pick eligible source and destination devices
        src, dst = self._pick_src_dst()
        if not src or not dst:
            return None

        proto = random.choices(self._protocols, weights=self._weights, k=1)[0]
        size = random.randint(64, 1500)

        event = PacketEvent(
            packet_id=str(uuid.uuid4())[:8],
            src_id=src.id,
            dst_id=dst.id,
            src_ip=src.ip_address,
            dst_ip=dst.ip_address,
            protocol=proto,
            size_bytes=size,
            timestamp=time.time(),
            is_allowed=True,
        )

        self._stats["sent"] += 1
        self._stats["delivered"] += 1

        if self._packet_callback:
            self._packet_callback(event)

        logger.debug(f"Packet generated: {event.label}")
        return event

    def generate_suspicious_traffic(self) -> None:
        """Not implemented in Phase 2 — deferred to Phase 3."""
        pass

    def generate_dangerous_traffic(self) -> None:
        """Not implemented in Phase 2 — deferred to Phase 3."""
        pass

    # ── Configuration ────────────────────────────────────────────────────────

    def set_topology(self, topology: NetworkTopology) -> None:
        """Configure the topology from which src/dst pairs are chosen."""
        self._topology = topology

    def set_packet_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        """Register a callback invoked each time a packet is generated."""
        self._packet_callback = callback

    def get_stats(self) -> dict:
        """Return cumulative traffic statistics."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset cumulative counters."""
        self._stats = {"sent": 0, "delivered": 0, "lost": 0}

    def is_running(self) -> bool:
        return self._running

    # ── Internal Helpers ─────────────────────────────────────────────────────

    def _pick_src_dst(self):
        """
        Pick a realistic source/destination pair.

        Traffic patterns:
          Workstations → Server (web requests)
          Workstations → Internet (external DNS/HTTPS)
          Server → Database (DB queries)
          Any host → Any host (ICMP ping)
        """
        online = self._topology.get_online_devices() if self._topology else []
        if len(online) < 2:
            return None, None

        # Weighted pattern selection
        pattern = random.choices(
            ["ws_to_server", "ws_to_internet", "srv_to_db", "random"],
            weights=[40, 25, 20, 15],
            k=1,
        )[0]

        def by_type(t: DeviceType):
            return [d for d in online if d.device_type == t]

        workstations = by_type(DeviceType.WORKSTATION)
        servers      = by_type(DeviceType.SERVER)
        databases    = by_type(DeviceType.DATABASE)
        internet     = by_type(DeviceType.INTERNET)

        if pattern == "ws_to_server" and workstations and servers:
            return random.choice(workstations), random.choice(servers)
        if pattern == "ws_to_internet" and workstations and internet:
            return random.choice(workstations), random.choice(internet)
        if pattern == "srv_to_db" and servers and databases:
            return random.choice(servers), random.choice(databases)

        # Random fallback
        choices = random.sample(online, 2)
        return choices[0], choices[1]


class SuspiciousTrafficSimulator(ITrafficEmulator):
    """
    Generates suspicious and malicious network traffic patterns.

    Cycles through standard attacks: SYN Flood, Port Scan, ICMP Flood, SSH Brute Force, Recon.
    Emits simulated packets with `is_suspicious=True` for visual classification.
    """

    def __init__(self, randomize_ip: bool = True) -> None:
        self._topology: Optional[NetworkTopology] = None
        self._running = False
        self._packet_callback: Optional[Callable[[PacketEvent], None]] = None
        self._stats = {"sent": 0, "delivered": 0, "lost": 0}

        self.attacks = ["Port Scan", "SSH Brute Force", "Reconnaissance", "Ping Sweep"]
        self.active_attack = "Port Scan"
        self._tick_counter = 0
        self._scan_port = 20
        self.randomize_ip = randomize_ip
        self._current_random_attacker_ip = self._generate_random_ip()

    def _generate_random_ip(self) -> str:
        subnets = ["198.51.100", "203.0.113", "45.33.32", "185.220.101", "103.21.244"]
        net = random.choice(subnets)
        return f"{net}.{random.randint(2, 254)}"

    def _get_attacker_ip(self, default_ip: str) -> str:
        if not self.randomize_ip:
            return default_ip
        return self._current_random_attacker_ip

    # ── ITrafficEmulator Interface ───────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._tick_counter = 0
        self.active_attack = random.choice(self.attacks)
        self._current_random_attacker_ip = self._generate_random_ip()
        logger.info(f"SuspiciousTrafficSimulator started. Initial attack: {self.active_attack} from {self._current_random_attacker_ip}")

    def stop(self) -> None:
        self._running = False
        logger.info("SuspiciousTrafficSimulator stopped.")

    def get_status(self) -> str:
        return "RUNNING" if self._running else "STOPPED"

    def generate_normal_traffic(self) -> Optional[PacketEvent]:
        """In suspicious mode, we don't generate normal traffic."""
        return None

    def generate_suspicious_traffic(self) -> Optional[PacketEvent]:
        """
        Generate burst stream representing active attack traffic.
        """
        if not self._running or not self._topology:
            return None

        # Cycle attacks every 25 ticks to simulate dynamic scenario
        self._tick_counter += 1
        if self._tick_counter % 25 == 0:
            current = self.active_attack
            while self.active_attack == current:
                self.active_attack = random.choice(self.attacks)
            self._current_random_attacker_ip = self._generate_random_ip()
            logger.info(f"Emulation switching attack signature to: {self.active_attack} (Attacker IP: {self._current_random_attacker_ip})")

        burst_count = 5 if self.active_attack in ("SYN Flood", "ICMP Flood", "Port Scan") else 3
        last_event: Optional[PacketEvent] = None

        for _ in range(burst_count):
            src, dst, proto, size = self._build_attack_packet()
            if not src or not dst:
                continue

            src_ip = self._get_attacker_ip(src.ip_address)

            event = PacketEvent(
                packet_id=str(uuid.uuid4())[:8],
                src_id=src.id,
                dst_id=dst.id,
                src_ip=src_ip,
                dst_ip=dst.ip_address,
                protocol=proto,
                size_bytes=size,
                timestamp=time.time(),
                is_allowed=True,
                is_suspicious=True,
                attack_type=self.active_attack,
            )


            self._stats["sent"] += 1
            self._stats["delivered"] += 1

            if self._packet_callback:
                self._packet_callback(event)
            last_event = event

        return last_event


    def generate_dangerous_traffic(self) -> None:
        pass

    # ── Configuration ────────────────────────────────────────────────────────

    def set_topology(self, topology: NetworkTopology) -> None:
        self._topology = topology

    def set_packet_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        self._packet_callback = callback

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset_stats(self) -> None:
        self._stats = {"sent": 0, "delivered": 0, "lost": 0}

    def is_running(self) -> bool:
        return self._running

    # ── Attack Builder ───────────────────────────────────────────────────────

    def _build_attack_packet(self) -> Tuple[Optional[NetworkDevice], Optional[NetworkDevice], Protocol, int]:
        """Constructs source, target, protocol, and size for active attack signature."""
        if not self._topology:
            return None, None, Protocol.HTTP, 64

        devices = {d.id: d for d in self._topology.devices}
        ws1 = devices.get("ws-01")
        ws2 = devices.get("ws-02")
        server = devices.get("server")
        db = devices.get("database")
        fw = devices.get("firewall")
        internet = devices.get("internet")

        # Fallbacks if IDs don't match
        ws_node = ws1 or ws2 or list(devices.values())[0]
        srv_node = server or list(devices.values())[0]

        if self.active_attack == "SYN Flood":
            # ws-02 floods server with tiny SYN TCP packets
            src = ws2 or ws_node
            dst = srv_node
            proto = Protocol.HTTP
            size = 40  # Minimal TCP header size
            # Override Protocol port temporarily to represent high SYN target
            proto.port = 80
            return src, dst, proto, size

        elif self.active_attack == "Port Scan":
            # ws-01 scans server ports
            src = ws1 or ws_node
            dst = srv_node
            proto = Protocol.HTTPS
            # Increment port
            self._scan_port = (self._scan_port + 27) % 65535
            proto.port = self._scan_port
            return src, dst, proto, 54

        elif self.active_attack == "ICMP Flood":
            # internet floods firewall with ICMP ping
            src = internet or ws_node
            dst = fw or srv_node
            proto = Protocol.ICMP
            return src, dst, proto, 64

        elif self.active_attack == "SSH Brute Force":
            # ws-01 runs dictionary attack against server on port 22
            src = ws1 or ws_node
            dst = srv_node
            proto = Protocol.SSH
            proto.port = 22
            return src, dst, proto, random.randint(120, 300)

        else: # Reconnaissance
            # ws-01 queries database or firewall
            src = ws_node
            dst = db or srv_node
            proto = Protocol.DNS
            proto.port = 53
            return src, dst, proto, 72


class DangerousTrafficSimulator(ITrafficEmulator):
    """
    Generates high-impact, malicious attack simulations for Phase 4.

    Attacks: SYN Flood, ICMP Flood, ARP Spoof, DHCP Starvation, Malware Beacon.
    All packets generated are marked as is_dangerous=True (visualized in Red).
    """

    def __init__(self, randomize_ip: bool = True) -> None:
        self._topology: Optional[NetworkTopology] = None
        self._running = False
        self._packet_callback: Optional[Callable[[PacketEvent], None]] = None
        self._stats = {"sent": 0, "delivered": 0, "lost": 0}

        self.attacks = ["SYN Flood", "ICMP Flood", "ARP Spoof", "DHCP Starvation", "Malware Beacon"]
        self.active_attack = "SYN Flood"
        self._tick_counter = 0
        self._starving_mac_idx = 0
        self.randomize_ip = randomize_ip
        self._current_random_attacker_ip = self._generate_random_ip()

    def _generate_random_ip(self) -> str:
        subnets = ["198.51.100", "203.0.113", "45.33.32", "185.220.101", "103.21.244"]
        net = random.choice(subnets)
        return f"{net}.{random.randint(2, 254)}"

    def _get_attacker_ip(self, default_ip: str) -> str:
        if not self.randomize_ip:
            return default_ip
        return self._current_random_attacker_ip

    # ── ITrafficEmulator Interface ───────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._tick_counter = 0
        self.active_attack = random.choice(self.attacks)
        self._current_random_attacker_ip = self._generate_random_ip()
        logger.info(f"DangerousTrafficSimulator started. Initial attack: {self.active_attack} from {self._current_random_attacker_ip}")

    def stop(self) -> None:
        self._running = False
        logger.info("DangerousTrafficSimulator stopped.")

    def get_status(self) -> str:
        return "RUNNING" if self._running else "STOPPED"

    def generate_normal_traffic(self) -> Optional[PacketEvent]:
        return None

    def generate_suspicious_traffic(self) -> Optional[PacketEvent]:
        return None

    def generate_dangerous_traffic(self) -> Optional[PacketEvent]:
        """
        Generate burst stream representing active dangerous attack traffic.
        """
        if not self._running or not self._topology:
            return None

        # Cycle attacks every 20 ticks to showcase variety
        self._tick_counter += 1
        if self._tick_counter % 20 == 0:
            current = self.active_attack
            while self.active_attack == current:
                self.active_attack = random.choice(self.attacks)
            self._current_random_attacker_ip = self._generate_random_ip()
            logger.info(f"Dangerous emulation switching attack signature to: {self.active_attack} (Attacker IP: {self._current_random_attacker_ip})")

        burst_count = 35 if self.active_attack in ("SYN Flood", "ICMP Flood", "Port Scan", "DHCP Starvation") else 10
        last_event: Optional[PacketEvent] = None

        for _ in range(burst_count):
            src, dst, proto, size = self._build_dangerous_packet()
            if not src or not dst:
                continue

            src_ip = self._get_attacker_ip(src.ip_address)

            event = PacketEvent(
                packet_id=str(uuid.uuid4())[:8],
                src_id=src.id,
                dst_id=dst.id,
                src_ip=src_ip,
                dst_ip=dst.ip_address,
                protocol=proto,
                size_bytes=size,
                timestamp=time.time(),
                is_allowed=True,
                is_suspicious=False,
                is_dangerous=True,
                attack_type=self.active_attack,
            )


            self._stats["sent"] += 1
            self._stats["delivered"] += 1

            if self._packet_callback:
                self._packet_callback(event)
            last_event = event

        return last_event


    # ── Configuration ────────────────────────────────────────────────────────

    def set_topology(self, topology: NetworkTopology) -> None:
        self._topology = topology

    def set_packet_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        self._packet_callback = callback

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset_stats(self) -> None:
        self._stats = {"sent": 0, "delivered": 0, "lost": 0}

    def is_running(self) -> bool:
        return self._running

    # ── Attack Builder ───────────────────────────────────────────────────────

    def _build_dangerous_packet(self) -> Tuple[Optional[NetworkDevice], Optional[NetworkDevice], Protocol, int]:
        """Constructs source, target, protocol, and size for active dangerous attack signature."""
        if not self._topology:
            return None, None, Protocol.HTTP, 64

        devices = {d.id: d for d in self._topology.devices}
        ws1 = devices.get("ws-01")
        ws2 = devices.get("ws-02")
        server = devices.get("server")
        db = devices.get("database")
        fw = devices.get("firewall")
        internet = devices.get("internet")

        ws_node = ws1 or ws2 or list(devices.values())[0]
        srv_node = server or list(devices.values())[0]

        if self.active_attack == "SYN Flood":
            # Attacker Internet host floods server with SYN packets
            src = internet or ws_node
            dst = srv_node
            proto = Protocol.HTTP
            proto.port = 80
            return src, dst, proto, 40

        elif self.active_attack == "ICMP Flood":
            # Volumetric ping flood from local ws-02 to firewall
            src = ws2 or ws_node
            dst = fw or srv_node
            proto = Protocol.ICMP
            return src, dst, proto, 1200  # Large packet size for volumetric flood

        elif self.active_attack == "ARP Spoof":
            # ws-01 poisons database's mapping of server
            src = ws1 or ws_node
            dst = db or srv_node
            proto = Protocol.ARP
            return src, dst, proto, 60

        elif self.active_attack == "DHCP Starvation":
            # ws-02 requests DHCP addresses using dynamic fake MACs
            src = ws2 or ws_node
            dst = fw or srv_node  # Switch/router gateway
            proto = Protocol.DHCP
            proto.port = 67
            return src, dst, proto, 300

        else: # Malware Beacon
            # Infected server beaconing outbound to malicious C2 controller
            src = srv_node
            dst = internet or ws_node
            proto = Protocol.HTTPS
            proto.port = 8080
            return src, dst, proto, 250

