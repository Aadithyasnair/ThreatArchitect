"""
app.capture.feature_buffer — Computes 16 numerical features from flows and buffers sequences.

Prepares sliding-window inputs of shape (sequence_length, 16) for the PyTorch LSTM.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Tuple, Set, Optional
from collections import deque
from app.capture.flow_manager import NetworkFlow

logger = logging.getLogger("FeatureBuffer")


class FeatureBuffer:
    """
    Maintains a rolling buffer of computed feature vectors from active flows.

    Extracts:
    1. PPS (Packets Per Second)
    2. BPS (Bytes Per Second)
    3. Average Packet Size
    4. SYN Count
    5. ACK Count
    6. RST Count
    7. FIN Count
    8. Protocol (TCP=1, UDP=2, ICMP=3, Other=0)
    9. Destination Port
    10. Source Port
    11. TTL
    12. Window Size
    13. Flow Duration
    14. Inter-arrival Time
    15. Unique Destination Count (in window)
    16. Unique Source Count (in window)
    """

    def __init__(self, window_size_sec: int = 10, stride_sec: int = 2, seq_length: int = 5) -> None:
        self.window_size_sec = window_size_sec
        self.stride_sec = stride_sec
        self.seq_length = seq_length

        # Deque of historic feature vectors to build sequences of length `seq_length`
        self.history = deque(maxlen=seq_length)

    def extract_features(self, flows: List[NetworkFlow]) -> List[float]:
        """
        Extracts aggregated 16-dimensional feature vector from a list of active flows.
        Returns a 16-element float list.
        """
        if not flows:
            # Return baseline clean/quiet zero-flow features
            return [0.0] * 16

        total_pkts = sum(f.packet_count for f in flows)
        total_bytes = sum(f.byte_count for f in flows)
        max_duration = max((f.duration for f in flows), default=1.0)
        eff_duration = max(max_duration, 0.5)

        # Basic rates bounded to realistic dataset scale
        pps = min(total_pkts / eff_duration, 3500.0)
        bps = min(total_bytes / eff_duration, 5000000.0)
        avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0

        # TCP flags
        syn = float(sum(f.syn_count for f in flows))
        ack = float(sum(f.ack_count for f in flows))
        rst = float(sum(f.rst_count for f in flows))
        fin = float(sum(f.fin_count for f in flows))

        # Protocol code mapping
        proto_map = {"TCP": 1.0, "UDP": 2.0, "ICMP": 3.0, "ARP": 0.0, "DHCP": 2.0, "IP": 1.0}
        protocols = [proto_map.get(f.protocol, 1.0) for f in flows]
        avg_proto = sum(protocols) / len(protocols) if protocols else 1.0

        # Ports, TTL, Window
        dports = [float(f.dst_port) for f in flows]
        sports = [float(f.src_port) for f in flows]
        avg_dport = sum(dports) / len(dports) if dports else 0.0
        avg_sport = sum(sports) / len(sports) if sports else 0.0

        ttls = [f.avg_ttl for f in flows]
        avg_ttl = sum(ttls) / len(ttls) if ttls else 64.0

        windows = [f.avg_window_size for f in flows]
        avg_window = sum(windows) / len(windows) if windows else 0.0

        # Flow duration & IAT
        avg_duration = sum(f.duration for f in flows) / len(flows)
        valid_iats = [iat for f in flows for iat in f.inter_arrival_times if iat > 0]
        if valid_iats:
            avg_iat = sum(valid_iats) / len(valid_iats)
        else:
            avg_iat = eff_duration / max(total_pkts, 1)

        # Unique addresses and ports
        src_ips: Set[str] = set()
        dst_ips: Set[str] = set()
        dst_ports_set: Set[int] = set()
        for f in flows:
            src_ips.add(f.src_ip)
            dst_ips.add(f.dst_ip)
            if f.dst_port > 0:
                dst_ports_set.add(f.dst_port)

        unique_dst = float(max(len(dst_ips), len(dst_ports_set)))
        unique_src = float(len(src_ips))

        return [
            pps, bps, avg_pkt_size, syn, ack, rst, fin,
            avg_proto, avg_dport, avg_sport, avg_ttl, avg_window,
            avg_duration, avg_iat, unique_dst, unique_src
        ]

    def add_vector(self, vector: List[float]) -> None:
        """Appends a new feature vector to the rolling history buffer."""
        self.history.append(vector)

    def get_sequence(self) -> List[List[float]]:
        """
        Returns a sequence of shape (seq_length, 16) for PyTorch.
        If history is not full, pads the start with zero-vectors.
        """
        seq = list(self.history)
        while len(seq) < self.seq_length:
            seq.insert(0, [0.0] * 16)
        return seq



    def clear(self) -> None:
        """Reset sequence history buffer."""
        self.history.clear()
