"""
app.capture.flow_manager — Groups parsed packets into active bi-directional flows.

Calculates flow statistics: packet counts, byte counts, duration, and inter-arrival times.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from app.capture.packet_parser import ParsedPacket

logger = logging.getLogger("FlowManager")

# Clean key structure: (low_ip, high_ip, low_port, high_port, protocol)
FlowKey = Tuple[str, str, int, int, str]


@dataclass
class NetworkFlow:
    """Represents an active bi-directional flow between two endpoints."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    last_packet_time: Optional[float] = None
    inter_arrival_times: List[float] = field(default_factory=list)
    ttl_values: List[int] = field(default_factory=list)
    window_sizes: List[int] = field(default_factory=list)
    connection_state: str = "ESTABLISHED"

    @property
    def duration(self) -> float:
        """Returns active flow duration in seconds."""
        d = self.end_time - self.start_time
        return max(d, 0.0001)

    @property
    def avg_packet_size(self) -> float:
        """Returns average packet size in bytes."""
        if self.packet_count == 0:
            return 0.0
        return self.byte_count / self.packet_count

    @property
    def avg_inter_arrival(self) -> float:
        """Returns average time between arrivals in seconds."""
        if not self.inter_arrival_times:
            return 0.0
        return sum(self.inter_arrival_times) / len(self.inter_arrival_times)

    @property
    def avg_ttl(self) -> float:
        """Returns average Time To Live."""
        if not self.ttl_values:
            return 64.0
        return sum(self.ttl_values) / len(self.ttl_values)

    @property
    def avg_window_size(self) -> float:
        """Returns average TCP window size."""
        if not self.window_sizes:
            return 0.0
        return sum(self.window_sizes) / len(self.window_sizes)

    def update(self, packet: ParsedPacket) -> None:
        """Add a packet's statistics to this flow."""
        self.end_time = packet.timestamp
        self.packet_count += 1
        self.byte_count += packet.length

        # Inter-arrival time
        if self.last_packet_time is not None:
            iat = packet.timestamp - self.last_packet_time
            self.inter_arrival_times.append(max(iat, 0.0))
        self.last_packet_time = packet.timestamp

        # TTL & Window
        if packet.ttl is not None:
            self.ttl_values.append(packet.ttl)
        if packet.window_size is not None:
            self.window_sizes.append(packet.window_size)

        # TCP flags
        if packet.protocol == "TCP":
            if packet.tcp_flags.get("SYN"):
                self.syn_count += 1
                self.connection_state = "SYN_SENT"
            if packet.tcp_flags.get("ACK"):
                self.ack_count += 1
                if self.connection_state == "SYN_SENT":
                    self.connection_state = "ESTABLISHED"
            if packet.tcp_flags.get("RST"):
                self.rst_count += 1
                self.connection_state = "RESET"
            if packet.tcp_flags.get("FIN"):
                self.fin_count += 1
                self.connection_state = "CLOSED"


class FlowManager:
    """Tracks active connections, groups packets, and ages out stale sessions."""

    def __init__(self, idle_timeout_sec: float = 15.0) -> None:
        self.idle_timeout_sec = idle_timeout_sec
        self.active_flows: Dict[FlowKey, NetworkFlow] = {}

    def get_flow_key(self, packet: ParsedPacket) -> FlowKey:
        """Construct direction-independent flow key (bi-directional)."""
        src = packet.src_ip
        dst = packet.dst_ip
        sport = packet.src_port or 0
        dport = packet.dst_port or 0

        # Sort IP and Port pairs for symmetry
        if src > dst:
            src, dst = dst, src
            sport, dport = dport, sport

        return (src, dst, sport, dport, packet.protocol)

    def process_packet(self, packet: ParsedPacket) -> NetworkFlow:
        """Groups packet into an existing or new bi-directional flow."""
        key = self.get_flow_key(packet)

        if key in self.active_flows:
            flow = self.active_flows[key]
            flow.update(packet)
        else:
            flow = NetworkFlow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port or 0,
                dst_port=packet.dst_port or 0,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
            )
            flow.update(packet)
            self.active_flows[key] = flow

        return flow

    def cleanup_stale_flows(self, current_time: float) -> List[NetworkFlow]:
        """Flushes flows that haven't received traffic inside idle_timeout_sec or are closed."""
        stale_keys = []
        stale_flows = []

        for key, flow in self.active_flows.items():
            if flow.last_packet_time is not None:
                is_idle = (current_time - flow.last_packet_time > self.idle_timeout_sec)
                is_finished = (flow.connection_state in ("CLOSED", "RESET") and (current_time - flow.last_packet_time > 5.0))
                if is_idle or is_finished:
                    stale_keys.append(key)
                    stale_flows.append(flow)

        for key in stale_keys:
            del self.active_flows[key]

        return stale_flows

    def clear(self) -> None:
        """Reset internal flow tracker."""
        self.active_flows.clear()
