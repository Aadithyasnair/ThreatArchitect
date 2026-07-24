"""
app.network.rule_engine — Deterministic rule-based threat classification.

Computes baseline heuristics on flow features to support the machine learning pipelines.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Set
from app.capture.flow_manager import NetworkFlow

logger = logging.getLogger("RuleEngine")


class RuleAlert:
    """Heuristic rule trigger detail."""

    def __init__(self, rule_name: str, message: str, severity: str) -> None:
        self.rule_name = rule_name
        self.message = message
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL


class RuleEngine:
    """Evaluates deterministic network security rule logic on active flows."""

    def __init__(self) -> None:
        pass

    def evaluate(self, flows: List[NetworkFlow]) -> List[RuleAlert]:
        """
        Check flows against baseline signature rules.
        Returns a list of matching RuleAlert objects.
        """
        alerts: List[RuleAlert] = []
        if not flows:
            return alerts

        # Group metrics by Source IP to trace host-specific volumetric behavior
        by_src: Dict[str, List[NetworkFlow]] = {}
        for flow in flows:
            by_src.setdefault(flow.src_ip, []).append(flow)

        for src_ip, src_flows in by_src.items():
            total_pkts = sum(f.packet_count for f in src_flows)
            total_syn = sum(f.syn_count for f in src_flows)
            total_tcp = sum(f.packet_count for f in src_flows if f.protocol == "TCP")
            total_icmp = sum(f.packet_count for f in src_flows if f.protocol == "ICMP")
            total_non_ip = sum(f.packet_count for f in src_flows if f.protocol not in ("TCP", "UDP", "ICMP"))

            max_duration = max((f.duration for f in src_flows), default=1.0)
            pps = total_pkts / max_duration

            # ── 1. High SYN Rate Rule (SYN Flood Indicator) ───────────────────
            if total_tcp > 15 and total_syn > 10 and (total_syn / total_tcp) > 0.75:
                alerts.append(
                    RuleAlert(
                        rule_name="HIGH_SYN_RATE",
                        message=f"Host {src_ip} exhibits abnormal SYN/TCP ratio ({(total_syn/total_tcp)*100:.1f}%).",
                        severity="HIGH",
                    )
                )

            # ── 2. Repeated Port Access Rule (Port Scan Indicator) ────────────
            dst_ports: Set[int] = set()
            for f in src_flows:
                if f.dst_port > 0:
                    dst_ports.add(f.dst_port)
            if len(dst_ports) > 10:
                alerts.append(
                    RuleAlert(
                        rule_name="REPEATED_PORT_ACCESS",
                        message=f"Host {src_ip} queried {len(dst_ports)} different target ports in window.",
                        severity="MEDIUM",
                    )
                )

            # ── 3. High Connection Count (Recon / Connection Enumeration) ─────
            if len(src_flows) > 80:
                alerts.append(
                    RuleAlert(
                        rule_name="Reconnaissance",
                        message=f"Host {src_ip} initiated {len(src_flows)} concurrent flows.",
                        severity="LOW",
                    )
                )

            # ── 4. ICMP Flood Rule ───────────────────────────────────────────
            icmp_pps = total_icmp / max_duration
            if total_icmp > 40 and icmp_pps > 50:
                alerts.append(
                    RuleAlert(
                        rule_name="ICMP Flood",
                        message=f"Host {src_ip} sending ICMP packets at {icmp_pps:.1f} packets/sec.",
                        severity="HIGH",
                    )
                )

            # ── 5. ARP / Non-IP Spoofing Rule ────────────────────────────────
            arp_pps = total_non_ip / max_duration
            if total_non_ip > 5 and arp_pps > 2:
                alerts.append(
                    RuleAlert(
                        rule_name="ARP Spoof",
                        message=f"Host {src_ip} emitting non-IP frames at {arp_pps:.1f} frames/sec.",
                        severity="HIGH",
                    )
                )

            # ── 6. DHCP Starvation Rule ─────────────────────────────────────
            dhcp_pkts = sum(f.packet_count for f in src_flows if f.dst_port == 67 or f.protocol == "DHCP")
            if dhcp_pkts > 5:
                alerts.append(
                    RuleAlert(
                        rule_name="DHCP Starvation",
                        message=f"Host {src_ip} emitting high volume DHCP broadcast requests.",
                        severity="HIGH",
                    )
                )

            # ── 7. Malware Beacon Rule ────────────────────────────────────────
            beacon_pkts = sum(f.packet_count for f in src_flows if f.dst_port in (8080, 8443, 6667, 9001, 4444, 1337))
            if beacon_pkts > 5:
                alerts.append(
                    RuleAlert(
                        rule_name="Malware Beacon",
                        message=f"Host {src_ip} active persistent outbound C2 malware beacon.",
                        severity="HIGH",
                    )
                )

        return alerts
