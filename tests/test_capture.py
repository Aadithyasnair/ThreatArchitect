"""
tests/test_capture — Verifies packet parser, flow reconstruction, and feature buffering.
"""

import time
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from app.capture.packet_parser import PacketParser, ParsedPacket
from app.capture.flow_manager import FlowManager, NetworkFlow
from app.capture.feature_buffer import FeatureBuffer


def test_packet_parser_tcp() -> None:
    """Verifies that PacketParser correctly decodes Layer 3 and Layer 4 TCP fields."""
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkt /= IP(src="10.0.2.11", dst="10.0.1.10", ttl=64)
    pkt /= TCP(sport=12345, dport=80, flags="S", window=8192)
    pkt.time = time.time()

    parsed = PacketParser.parse(pkt)
    assert parsed is not None
    assert parsed.src_ip == "10.0.2.11"
    assert parsed.dst_ip == "10.0.1.10"
    assert parsed.protocol == "TCP"
    assert parsed.src_port == 12345
    assert parsed.dst_port == 80
    assert parsed.ttl == 64
    assert parsed.window_size == 8192
    assert parsed.tcp_flags["SYN"] is True
    assert parsed.tcp_flags["ACK"] is False
    assert parsed.app_protocol == "HTTP"


def test_packet_parser_udp_dns() -> None:
    """Verifies that PacketParser decodes UDP/DNS fields."""
    pkt = Ether()
    pkt /= IP(src="10.0.2.11", dst="8.8.8.8")
    pkt /= UDP(sport=43210, dport=53)
    pkt.time = time.time()

    parsed = PacketParser.parse(pkt)
    assert parsed is not None
    assert parsed.protocol == "UDP"
    assert parsed.dst_port == 53
    assert parsed.app_protocol == "DNS"


def test_flow_manager_grouping() -> None:
    """Verifies that FlowManager aggregates packet sizes and TCP flags symmetrically."""
    mgr = FlowManager()

    # Packet A: Client -> Server
    p1 = ParsedPacket(
        timestamp=100.0,
        length=100,
        src_ip="10.0.2.11",
        dst_ip="10.0.1.10",
        protocol="TCP",
        src_port=50000,
        dst_port=80,
        ttl=64,
        tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False},
        window_size=1024,
    )

    # Packet B: Server -> Client (Reply)
    p2 = ParsedPacket(
        timestamp=100.2,
        length=200,
        src_ip="10.0.1.10",
        dst_ip="10.0.2.11",
        protocol="TCP",
        src_port=80,
        dst_port=50000,
        ttl=128,
        tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False},
        window_size=2048,
    )

    # Group both packets into same flow
    f1 = mgr.process_packet(p1)
    f2 = mgr.process_packet(p2)

    assert f1 is f2  # Symmetrical flow match
    assert f1.packet_count == 2
    assert f1.byte_count == 300
    assert f1.syn_count == 1
    assert f1.ack_count == 1
    assert f1.duration == pytest.approx(0.2)
    assert f1.avg_packet_size == 150.0
    assert f1.avg_inter_arrival == pytest.approx(0.2)


def test_feature_buffer_extraction() -> None:
    """Verifies feature extraction outputs valid 16-dimensional vectors."""
    buffer = FeatureBuffer(window_size_sec=10, stride_sec=2, seq_length=3)

    # Mock flow representing normal active web connection
    flow = NetworkFlow(
        src_ip="10.0.2.11",
        dst_ip="10.0.1.10",
        src_port=55555,
        dst_port=443,
        protocol="TCP",
        start_time=10.0,
        end_time=12.0,
        packet_count=10,
        byte_count=5000,
        syn_count=1,
        ack_count=9,
    )

    vec = buffer.extract_features([flow])
    assert len(vec) == 16
    # PPS = 10 pkts / 2 sec = 5.0
    assert vec[0] == pytest.approx(5.0)
    # BPS = 5000 bytes / 2 sec = 2500.0
    assert vec[1] == pytest.approx(2500.0)
    # Avg Packet Size = 500.0
    assert vec[2] == pytest.approx(500.0)
    # Protocol (TCP=1.0)
    assert vec[7] == 1.0
    # Unique dsts/srcs
    assert vec[14] == 1.0
    assert vec[15] == 1.0


def test_feature_buffer_sequencing() -> None:
    """Verifies that sliding window sequences are padded properly to seq_length."""
    buffer = FeatureBuffer(window_size_sec=10, stride_sec=2, seq_length=3)
    
    # Empty history sequence should be padded with zeros
    seq1 = buffer.get_sequence()
    assert len(seq1) == 3
    assert seq1[0] == [0.0] * 16

    # Add one vector
    buffer.add_vector([1.0] * 16)
    seq2 = buffer.get_sequence()
    assert len(seq2) == 3
    assert seq2[0] == [0.0] * 16
    assert seq2[2] == [1.0] * 16
