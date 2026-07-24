"""
app.network.firewall — Firewall abstraction layer.

Maintains allow/deny rules, tracks packet statistics, and provides
the policy enforcement interface used by the simulation engine.

Note: Intelligent/dynamic blocking is intentionally deferred to Phase 3.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

logger = logging.getLogger("Firewall")


class FirewallAction(Enum):
    """The enforcement outcome for a matched firewall rule."""
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class FirewallRule:
    """
    A single firewall policy entry.

    Fields use '*' as a wildcard to match any value.
    """
    src_ip: str = "*"
    dst_ip: str = "*"
    port: int = 0               # 0 = any port
    protocol: str = "*"         # tcp, udp, icmp, *
    action: FirewallAction = FirewallAction.ALLOW
    description: str = ""

    def matches(self, src_ip: str, dst_ip: str, port: int, protocol: str) -> bool:
        """Return True if this rule applies to the given packet parameters."""
        src_match = self.src_ip == "*" or self.src_ip == src_ip
        dst_match = self.dst_ip == "*" or self.dst_ip == dst_ip
        port_match = self.port == 0 or self.port == port
        proto_match = self.protocol == "*" or self.protocol.lower() == protocol.lower()
        return src_match and dst_match and port_match and proto_match


@dataclass
class FirewallStats:
    """Running counters for firewall traffic decisions."""
    packets_allowed: int = 0
    packets_blocked: int = 0

    @property
    def total(self) -> int:
        return self.packets_allowed + self.packets_blocked

    @property
    def block_rate_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return round(self.packets_blocked / self.total * 100, 2)


class FirewallComponent:
    """
    Stateful firewall policy engine.

    Rules are evaluated top-down (first match wins).
    If no rule matches, the default policy is applied (configurable).
    """

    def __init__(self, default_action: FirewallAction = FirewallAction.ALLOW) -> None:
        self._rules: List[FirewallRule] = []
        self._default_action = default_action
        self._stats = FirewallStats()
        self._blocked_log: List[dict] = []   # Last 100 blocked packets

        # Install default enterprise baseline rules
        self._install_default_rules()

    def _install_default_rules(self) -> None:
        """Install baseline enterprise firewall rules."""
        self._rules = [
            FirewallRule(protocol="icmp",  action=FirewallAction.ALLOW,
                         description="Allow ICMP ping/traceroute"),
            FirewallRule(port=53,  protocol="udp", action=FirewallAction.ALLOW,
                         description="Allow DNS resolution"),
            FirewallRule(port=80,  protocol="tcp", action=FirewallAction.ALLOW,
                         description="Allow HTTP"),
            FirewallRule(port=443, protocol="tcp", action=FirewallAction.ALLOW,
                         description="Allow HTTPS"),
            FirewallRule(port=22,  protocol="tcp", action=FirewallAction.ALLOW,
                         description="Allow SSH from trusted hosts"),
            FirewallRule(port=21,  protocol="tcp", action=FirewallAction.ALLOW,
                         description="Allow FTP control"),
            FirewallRule(port=5432, protocol="tcp", action=FirewallAction.ALLOW,
                         description="Allow PostgreSQL internal"),
        ]
        logger.debug(f"Installed {len(self._rules)} default firewall rules.")

    def load_persisted_rules(self, rules: List[FirewallRule]) -> None:
        """Load persisted custom firewall rules from database, placing them before default rules."""
        for rule in reversed(rules):
            # Avoid duplicate rules
            if not any(r.src_ip == rule.src_ip and r.dst_ip == rule.dst_ip and r.port == rule.port and r.protocol == rule.protocol and r.action == rule.action for r in self._rules):
                self._rules.insert(0, rule)
        logger.info(f"Loaded {len(rules)} persisted firewall rules into policy engine.")

    def allow(self, rule: FirewallRule) -> None:
        """Prepend an allow rule (evaluated before existing rules)."""
        rule.action = FirewallAction.ALLOW
        self._rules.insert(0, rule)
        logger.info(f"Firewall ALLOW rule added: {rule.description or rule}")

    def deny(self, rule: FirewallRule) -> None:
        """Prepend a deny rule (evaluated before existing rules)."""
        rule.action = FirewallAction.DENY
        self._rules.insert(0, rule)
        logger.info(f"Firewall DENY rule added: {rule.description or rule}")

    def check_packet(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        protocol: str,
    ) -> bool:
        """
        Evaluate a packet against the rule set.

        Returns True (allowed) or False (blocked).
        Updates internal statistics.
        """
        for rule in self._rules:
            if rule.matches(src_ip, dst_ip, port, protocol):
                if rule.action == FirewallAction.ALLOW:
                    self._stats.packets_allowed += 1
                    return True
                else:
                    self._stats.packets_blocked += 1
                    self._blocked_log.append({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "port": port, "protocol": protocol,
                    })
                    # Keep log bounded
                    if len(self._blocked_log) > 100:
                        self._blocked_log.pop(0)
                    return False

        # Default action
        if self._default_action == FirewallAction.ALLOW:
            self._stats.packets_allowed += 1
            return True
        else:
            self._stats.packets_blocked += 1
            return False

    def evaluate(
        self,
        src_ip: str = "*",
        dst_ip: str = "*",
        dport: int = 0,
        protocol: str = "*",
        port: int = 0,
    ) -> bool:
        """Alias for check_packet supporting dport parameter."""
        target_port = dport if dport != 0 else port
        return self.check_packet(src_ip=src_ip, dst_ip=dst_ip, port=target_port, protocol=protocol)


    def get_stats(self) -> dict:
        """Return firewall traffic statistics as a plain dictionary."""
        return {
            "packets_allowed": self._stats.packets_allowed,
            "packets_blocked": self._stats.packets_blocked,
            "total": self._stats.total,
            "block_rate_pct": self._stats.block_rate_pct,
        }

    def get_rules(self) -> List[FirewallRule]:
        """Return the current ordered rule list (read-only view)."""
        return list(self._rules)

    def reset_stats(self) -> None:
        """Reset counters without touching rules."""
        self._stats = FirewallStats()
        self._blocked_log.clear()

    def format_rules_table(self) -> str:
        """Return a formatted string table of current rules for terminal display."""
        lines = [
            f"{'#':<4} {'Protocol':<10} {'Port':<8} {'Src IP':<20} {'Dst IP':<20} {'Action':<8} Description",
            "-" * 90,
        ]

        for i, rule in enumerate(self._rules, 1):
            port_str = str(rule.port) if rule.port != 0 else "any"
            lines.append(
                f"{i:<4} {rule.protocol:<10} {port_str:<8} {rule.src_ip:<20} "
                f"{rule.dst_ip:<20} {rule.action.value:<8} {rule.description}"
            )
        return "\n".join(lines)
