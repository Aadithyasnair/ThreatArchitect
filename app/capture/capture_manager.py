"""
app.capture.capture_manager — Coordinates sniffing, flow reconstruction, and feature windowing.

Provides a unified interface for starting/stopping capture, feeding packets,
and periodically yielding feature sequences via Qt Signals.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional, Callable
from PySide6.QtCore import QObject, Signal, QTimer

from app.capture.packet_parser import PacketParser, ParsedPacket
from app.capture.flow_manager import FlowManager, NetworkFlow
from app.capture.feature_buffer import FeatureBuffer
from app.capture.packet_listener import PacketListener
from app.core.interfaces import IPacketCapture

logger = logging.getLogger("CaptureManager")


class CaptureManager(QObject):
    """
    Manages the complete network capture pipeline.

    Emits:
    - packet_parsed(ParsedPacket): When a raw packet is successfully parsed.
    - flow_updated(NetworkFlow): When a flow state changes.
    - sequence_ready(list): Extracted sequence of shape (seq_length, 16) ready for LSTM.
    """
    packet_parsed = Signal(object)
    flow_updated = Signal(object)
    sequence_ready = Signal(list)
    stats_updated = Signal(dict)

    def __init__(
        self,
        interface: str = "eth0",
        window_size_sec: int = 10,
        stride_sec: int = 2,
        seq_length: int = 5,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.interface = interface
        self.window_size_sec = window_size_sec
        self.stride_sec = stride_sec
        self.seq_length = seq_length

        self._status = "STOPPED"
        self._total_packets_captured = 0

        # Pipeline components
        self.flow_manager = FlowManager(idle_timeout_sec=15.0)
        self.feature_buffer = FeatureBuffer(
            window_size_sec=window_size_sec,
            stride_sec=stride_sec,
            seq_length=seq_length,
        )
        self.listener: Optional[PacketListener] = None

        # Timer for stride feature extraction
        self.stride_timer = QTimer(self)
        self.stride_timer.timeout.connect(self._on_stride_tick)

    # ── IPacketCapture Interface ─────────────────────────────────────────────

    def start(self) -> None:
        """Start the capture manager and default interface listening."""
        self.start_capture(self.interface)

    def stop(self) -> None:
        """Stop the capture manager and interface listening."""
        self.stop_capture()

    def get_status(self) -> str:
        """Return the current capture status."""
        return self._status

    def start_capture(self, interface: str, filter_exp: Optional[str] = None) -> None:
        if self._status == "RUNNING":
            logger.warning("Capture is already running.")
            return

        self.interface = interface
        self.flow_manager.clear()
        self.feature_buffer.clear()
        self._total_packets_captured = 0

        # Start the background sniffer thread
        self.listener = PacketListener(
            interface=interface,
            packet_callback=self.on_raw_packet_received,
        )
        self.listener.start()

        # Start the stride interval feature extraction timer
        self.stride_timer.start(self.stride_sec * 1000)

        self._status = "RUNNING"
        logger.info(f"Capture pipeline started on interface '{interface}'")

    def stop_capture(self) -> None:
        if self._status != "RUNNING":
            return

        # Stop stride timer
        self.stride_timer.stop()

        # Stop listener thread
        if self.listener:
            self.listener.stop()
            self.listener = None

        self._status = "STOPPED"
        logger.info("Capture pipeline stopped.")

    # ── Packet Processing ────────────────────────────────────────────────────

    def on_raw_packet_received(self, scapy_pkt) -> None:
        """Callback invoked whenever the listener thread captures a raw packet."""
        parsed = PacketParser.parse(scapy_pkt)
        if parsed is None:
            return

        self._total_packets_captured += 1

        # Feed into flow manager
        flow = self.flow_manager.process_packet(parsed)

        # Emit updates for live console / dashboard
        self.packet_parsed.emit(parsed)
        self.flow_updated.emit(flow)

    def feed_emulated_packet(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        protocol_str: str,
        size: int,
        is_suspicious: bool = False,
        is_dangerous: bool = False,
    ) -> None:
        """
        Windows / Fallback mode: Manually serialize an emulated packet event
        into a Scapy structure and push it to the capture pipeline.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.l2 import Ether
            import random

            # Build mock layer 2 / 3
            pkt = Ether(src="00:11:22:33:44:55", dst="55:44:33:22:11:00")
            pkt /= IP(src=src_ip, dst=dst_ip, ttl=64)

            # Build layer 4 based on protocol
            p_upper = protocol_str.upper()
            
            # For persistent flows (SSH, HTTPS beacon, normal sessions), keep source port stable
            if port in (22, 443, 80, 5432) and not (is_suspicious and port != 22):
                sport = 40000 + (abs(hash((src_ip, dst_ip, port))) % 20000)
            else:
                sport = random.randint(1024, 65535)

            if p_upper == "TCP":
                if is_suspicious or is_dangerous:
                    if port == 22:
                        tcp_flags = "S" if random.random() > 0.4 else "PA"
                        win = 16384
                    elif port in (443, 8080, 8443, 6667, 4444, 9001, 1337) and size > 200:
                        tcp_flags = "PA"
                        win = 65535
                    else:
                        tcp_flags = "S"
                        win = 1024
                else:
                    tcp_flags = "PA" if random.random() > 0.05 else "S"
                    win = 65535

                pkt /= TCP(sport=sport, dport=port, flags=tcp_flags, window=win)

            elif p_upper == "UDP":
                if port == 67:
                    pkt /= UDP(sport=68, dport=67)
                else:
                    pkt /= UDP(sport=sport, dport=port)
            elif p_upper == "ICMP":
                pkt /= ICMP()
            elif p_upper in ("ARP", "NON-IP"):
                from scapy.layers.l2 import ARP
                pkt /= ARP(psrc=src_ip, pdst=dst_ip)
            else:
                pkt /= TCP(sport=sport, dport=port, flags="PA", window=65535)

            # Simulate timestamp
            pkt.time = time.time()

            # Push packet into listener queue
            if self.listener and (getattr(self.listener, "is_running", lambda: False)() or getattr(self.listener, "isRunning", lambda: False)()):
                self.listener.push_emulated_packet(pkt)

        except Exception as exc:
            logger.error(f"Failed to generate mock scapy packet: {exc}")


    # ── Feature Extraction Stride Timer ──────────────────────────────────────

    def _on_stride_tick(self) -> None:
        """Runs every `stride_sec` to compute and emit feature window updates."""
        try:
            # 1. Clean up stale idle connections
            now = time.time()
            self.flow_manager.cleanup_stale_flows(now)

            # 2. Get active flows
            active = list(self.flow_manager.active_flows.values())

            # 3. Extract feature vector & add to sliding window
            vector = self.feature_buffer.extract_features(active)
            self.feature_buffer.add_vector(vector)

            # 4. Generate sequences & emit for AI models
            sequence = self.feature_buffer.get_sequence()
            self.sequence_ready.emit(sequence)

            # 5. Emit updated stats
            stats = {
                "packets_captured": self._total_packets_captured,
                "active_flows": len(active),
            }
            self.stats_updated.emit(stats)

        except Exception as exc:
            logger.error(f"Error during feature stride execution: {exc}")
