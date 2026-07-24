"""
tests.test_firewall — Unit tests for FirewallComponent.

Verifies rule matching, allow/deny enforcement, and statistics tracking.
"""

import pytest
from app.network.firewall import FirewallComponent, FirewallRule, FirewallAction


def _make_fw() -> FirewallComponent:
    """Create a fresh FirewallComponent with default rules."""
    return FirewallComponent()


def test_default_rules_installed():
    """Default firewall must have at least one rule."""
    fw = _make_fw()
    assert len(fw.get_rules()) > 0


def test_allow_https():
    """HTTPS (port 443 TCP) must be allowed by default."""
    fw = _make_fw()
    allowed = fw.check_packet("10.0.2.11", "10.0.1.10", 443, "tcp")
    assert allowed is True


def test_allow_dns():
    """DNS (port 53 UDP) must be allowed by default."""
    fw = _make_fw()
    allowed = fw.check_packet("10.0.2.11", "203.0.113.1", 53, "udp")
    assert allowed is True


def test_allow_icmp():
    """ICMP must be allowed by default."""
    fw = _make_fw()
    allowed = fw.check_packet("10.0.2.11", "10.0.1.10", 0, "icmp")
    assert allowed is True


def test_deny_rule_blocks_packet():
    """An explicitly added deny rule must block matching packets."""
    fw = _make_fw()
    rule = FirewallRule(port=9999, protocol="tcp", action=FirewallAction.DENY,
                        description="Block test port")
    fw.deny(rule)
    blocked = fw.check_packet("10.0.2.11", "10.0.1.10", 9999, "tcp")
    assert blocked is False


def test_allow_rule_overrides_deny():
    """An allow rule added before a deny rule must take precedence."""
    fw = FirewallComponent(default_action=FirewallAction.DENY)
    allow_rule = FirewallRule(port=8080, protocol="tcp", action=FirewallAction.ALLOW)
    fw.allow(allow_rule)
    result = fw.check_packet("10.0.0.1", "10.0.1.10", 8080, "tcp")
    assert result is True


def test_stats_increment_on_allow():
    """Allowed packets must increment packets_allowed counter."""
    fw = _make_fw()
    fw.reset_stats()
    fw.check_packet("10.0.2.11", "10.0.1.10", 443, "tcp")
    stats = fw.get_stats()
    assert stats["packets_allowed"] >= 1


def test_stats_increment_on_block():
    """Blocked packets must increment packets_blocked counter."""
    fw = _make_fw()
    fw.reset_stats()
    deny_rule = FirewallRule(port=1234, protocol="tcp", action=FirewallAction.DENY)
    fw.deny(deny_rule)
    fw.check_packet("10.0.2.11", "10.0.1.10", 1234, "tcp")
    stats = fw.get_stats()
    assert stats["packets_blocked"] >= 1


def test_stats_total_is_sum():
    """Total must equal allowed + blocked."""
    fw = _make_fw()
    fw.reset_stats()
    fw.check_packet("10.0.2.11", "10.0.1.10", 443, "tcp")
    stats = fw.get_stats()
    assert stats["total"] == stats["packets_allowed"] + stats["packets_blocked"]


def test_reset_stats():
    """reset_stats() must zero all counters."""
    fw = _make_fw()
    fw.check_packet("10.0.2.11", "10.0.1.10", 443, "tcp")
    fw.reset_stats()
    stats = fw.get_stats()
    assert stats["packets_allowed"] == 0
    assert stats["packets_blocked"] == 0


def test_format_rules_table_returns_string():
    """format_rules_table() must return a non-empty string."""
    fw = _make_fw()
    table = fw.format_rules_table()
    assert isinstance(table, str)
    assert len(table) > 0


def test_wildcard_rule_matches_all():
    """A wildcard rule must match any packet."""
    fw = FirewallComponent(default_action=FirewallAction.ALLOW)
    deny_all = FirewallRule(src_ip="*", dst_ip="*", port=0, protocol="*",
                            action=FirewallAction.DENY, description="Deny all")
    fw.deny(deny_all)
    # Any packet should now be blocked
    result = fw.check_packet("1.2.3.4", "5.6.7.8", 12345, "tcp")
    assert result is False
