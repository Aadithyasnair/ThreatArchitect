"""
tests.test_command_parser — Unit tests for CommandParser.

Tests each supported command returns expected CommandResult structure.
Uses a stub NetworkManager to isolate parser logic.
"""

import pytest
from unittest.mock import MagicMock
from app.network.command_parser import CommandParser, CommandResult
from app.network.topology_builder import TopologyBuilder
from app.network.topology_models import NodeStatus


def _make_parser(started: bool = False) -> CommandParser:
    """Create a CommandParser with a stub NetworkManager."""
    mock_manager = MagicMock()

    # Configure mock returns
    mock_manager.start_network.return_value = "Network started in simulation mode."
    mock_manager.stop_network.return_value = "Network stopped successfully."
    mock_manager.start_emulate_normal.return_value = "Normal traffic emulation started."
    mock_manager.get_topology.return_value = (
        TopologyBuilder.build_enterprise_default() if started else None
    )
    mock_manager.get_firewall.return_value = MagicMock(
        get_stats=lambda: {
            "packets_allowed": 42, "packets_blocked": 3,
            "total": 45, "block_rate_pct": 6.67,
        },
        format_rules_table=lambda: "Rule table",
        get_rules=lambda: [],
    )
    mock_manager.get_stats.return_value = {
        "network_status": "ONLINE" if started else "OFFLINE",
        "simulation_mode": "emulate normal" if started else "IDLE",
        "active_devices": 8 if started else 0,
        "packets_sent": 100,
        "packets_delivered": 98,
        "packets_lost": 2,
        "firewall": {"packets_allowed": 42, "packets_blocked": 3},
    }

    return CommandParser(mock_manager)


def test_help_returns_success():
    parser = _make_parser()
    result = parser.parse_and_execute("help")
    assert result.success is True
    assert "help" in result.output.lower()


def test_help_case_insensitive():
    parser = _make_parser()
    result = parser.parse_and_execute("HELP")
    assert result.success is True


def test_start_network():
    parser = _make_parser()
    result = parser.parse_and_execute("start network")
    assert result.success is True
    assert result.action == "start_network"


def test_stop_network():
    parser = _make_parser()
    result = parser.parse_and_execute("stop network")
    assert result.success is True
    assert result.action == "stop_network"


def test_emulate_normal():
    parser = _make_parser()
    result = parser.parse_and_execute("emulate normal")
    assert result.success is True
    assert result.action == "emulate_normal"


def test_show_topology_when_started():
    parser = _make_parser(started=True)
    result = parser.parse_and_execute("show topology")
    assert result.success is True
    assert "Topology" in result.output


def test_show_topology_when_not_started():
    parser = _make_parser(started=False)
    result = parser.parse_and_execute("show topology")
    assert result.success is False
    assert "start network" in result.output.lower()


def test_show_nodes_when_started():
    parser = _make_parser(started=True)
    result = parser.parse_and_execute("show nodes")
    assert result.success is True
    assert "Hostname" in result.output


def test_show_firewall():
    parser = _make_parser()
    result = parser.parse_and_execute("show firewall")
    assert result.success is True
    assert "Firewall" in result.output


def test_status():
    parser = _make_parser()
    result = parser.parse_and_execute("status")
    assert result.success is True
    assert "Network" in result.output


def test_clear_command():
    parser = _make_parser()
    result = parser.parse_and_execute("clear")
    assert result.success is True
    assert result.action == "clear"


def test_unknown_command():
    parser = _make_parser()
    result = parser.parse_and_execute("foobarxyz")
    assert result.success is False
    assert "not recognized" in result.output.lower() or "unknown" in result.output.lower()


def test_whitespace_trimmed():
    """Leading/trailing whitespace must not break parsing."""
    parser = _make_parser()
    result = parser.parse_and_execute("  help  ")
    assert result.success is True


def test_result_dataclass_fields():
    """CommandResult must expose success, output, data, action fields."""
    r = CommandResult(success=True, output="OK", data={"x": 1}, action="test")
    assert r.success is True
    assert r.output == "OK"
    assert r.data == {"x": 1}
    assert r.action == "test"
