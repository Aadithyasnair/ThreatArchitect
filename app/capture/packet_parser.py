"""
app.capture.packet_parser — Decodes raw Scapy packets into structural representations.

Supports extracting layer-specific fields: Ethernet, IP, TCP, UDP, ICMP, DNS,
and standard application protocols.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# Delay importing scapy layers internally where possible to prevent startup lag
logger = logging.getLogger("PacketParser")


@dataclass
class ParsedPacket:
    """Standardized internal representation of a parsed network packet."""
    timestamp: float
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "UNKNOWN"       # TCP, UDP, ICMP, etc.
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    ttl: Optional[int] = None
    tcp_flags: Dict[str, bool] = field(default_factory=lambda: {
        "SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False
    })
    window_size: Optional[int] = None
    payload_size: int = 0
    app_protocol: str = "UNKNOWN"   # DNS, HTTP, HTTPS, SSH, FTP, etc.


class PacketParser:
    """Parses raw Scapy packets into type-safe ParsedPacket objects."""

    @staticmethod
    def parse(packet) -> Optional[ParsedPacket]:
        """
        Parses a Scapy packet. Returns ParsedPacket or None if parsing fails
        or if the packet does not contain IP or basic layers.
        """
        try:
            # Avoid crashes if scapy is not fully loaded/supported
            from scapy.layers.l2 import Ether, ARP
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6

            # Timestamp and raw length
            timestamp = float(getattr(packet, "time", 0.0))
            length = len(packet)

            parsed = ParsedPacket(timestamp=timestamp, length=length)

            # ── Layer 2: Ethernet ──────────────────────────────────────────
            if packet.haslayer(Ether):
                eth = packet[Ether]
                parsed.src_mac = eth.src
                parsed.dst_mac = eth.dst

            # ── Layer 3: IPv4 / IPv6 / ARP ──────────────────────────────────
            if packet.haslayer(IP):
                ip = packet[IP]
                parsed.src_ip = ip.src
                parsed.dst_ip = ip.dst
                parsed.ttl = ip.ttl
                parsed.protocol = "IP"
            elif packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                parsed.src_ip = ip6.src
                parsed.dst_ip = ip6.dst
                parsed.ttl = ip6.hlim
                parsed.protocol = "IPv6"
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                parsed.src_ip = arp.psrc
                parsed.dst_ip = arp.pdst
                parsed.protocol = "ARP"
                parsed.app_protocol = "ARP"
            else:
                # We prioritize IP and ARP traffic for security flow reconstruction
                return None

            # ── Layer 4: TCP / UDP / ICMP ───────────────────────────────────
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                parsed.protocol = "TCP"
                parsed.src_port = tcp.sport
                parsed.dst_port = tcp.dport
                parsed.window_size = tcp.window
                parsed.payload_size = len(tcp.payload)

                # Decode TCP flags
                flags_str = str(tcp.flags)
                parsed.tcp_flags = {
                    "SYN": "S" in flags_str,
                    "ACK": "A" in flags_str,
                    "FIN": "F" in flags_str,
                    "RST": "R" in flags_str,
                    "PSH": "P" in flags_str,
                }
                # Determine App protocol from ports
                parsed.app_protocol = PacketParser._detect_app_protocol(
                    tcp.sport, tcp.dport, packet, is_tcp=True
                )

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                parsed.protocol = "UDP"
                parsed.src_port = udp.sport
                parsed.dst_port = udp.dport
                parsed.payload_size = len(udp.payload)
                parsed.app_protocol = PacketParser._detect_app_protocol(
                    udp.sport, udp.dport, packet, is_tcp=False
                )

            elif packet.haslayer(ICMP):
                parsed.protocol = "ICMP"
                parsed.app_protocol = "ICMP"
                parsed.payload_size = len(packet[ICMP].payload)

            return parsed

        except Exception as exc:
            logger.error(f"Failed to parse packet: {exc}", exc_info=True)
            return None

    @staticmethod
    def _detect_app_protocol(sport: int, dport: int, packet, is_tcp: bool) -> str:
        """Helper to classify standard application-layer protocols by port/signatures."""
        ports = {sport, dport}

        # DNS (UDP/TCP 53)
        if 53 in ports:
            return "DNS"
        # HTTP (TCP 80)
        if is_tcp and 80 in ports:
            return "HTTP"
        # HTTPS (TCP 443)
        if is_tcp and 443 in ports:
            return "HTTPS"
        # SSH (TCP 22)
        if is_tcp and 22 in ports:
            return "SSH"
        # FTP (TCP 20, 21)
        if is_tcp and (20 in ports or 21 in ports):
            return "FTP"

        # Check Scapy protocol layer definitions if present
        try:
            from scapy.layers.dns import DNS
            if packet.haslayer(DNS):
                return "DNS"
        except ImportError:
            pass

        return "UNKNOWN"
