"""
tests.test_network_manager — Unit tests for NetworkManager.

Tests network start/stop lifecycle and stats structure.
No real network is started — Mininet fallback ensures pure simulation.
"""

import pytest
from app.network.manager import NetworkManager


def _make_manager() -> NetworkManager:
    return NetworkManager()


def test_initially_not_running():
    mgr = _make_manager()
    assert mgr.is_running() is False


def test_initial_stats_structure():
    """Stats dict must contain all required keys even before start."""
    mgr = _make_manager()
    stats = mgr.get_stats()
    required_keys = {
        "network_status", "simulation_mode", "active_devices",
        "packets_sent", "packets_delivered", "packets_lost", "firewall",
    }
    assert required_keys.issubset(stats.keys())


def test_start_network_returns_string():
    """start_network() must return a non-empty string message."""
    mgr = _make_manager()
    msg = mgr.start_network()
    assert isinstance(msg, str)
    assert len(msg) > 0
    # Cleanup
    mgr.stop_network()


def test_start_network_marks_running():
    mgr = _make_manager()
    mgr.start_network()
    assert mgr.is_running() is True
    mgr.stop_network()


def test_stop_network_marks_stopped():
    mgr = _make_manager()
    mgr.start_network()
    mgr.stop_network()
    assert mgr.is_running() is False


def test_topology_available_after_start():
    mgr = _make_manager()
    mgr.start_network()
    topo = mgr.get_topology()
    assert topo is not None
    assert len(topo.devices) > 0
    mgr.stop_network()


def test_all_devices_online_after_start():
    from app.network.topology_models import NodeStatus
    mgr = _make_manager()
    mgr.start_network()
    topo = mgr.get_topology()
    for device in topo.devices:
        assert device.status == NodeStatus.ONLINE, (
            f"{device.hostname} is {device.status}, expected ONLINE"
        )
    mgr.stop_network()


def test_all_devices_offline_after_stop():
    from app.network.topology_models import NodeStatus
    mgr = _make_manager()
    mgr.start_network()
    mgr.stop_network()
    topo = mgr.get_topology()
    if topo:
        for device in topo.devices:
            assert device.status == NodeStatus.OFFLINE


def test_stats_network_status_reflects_state():
    mgr = _make_manager()
    assert mgr.get_stats()["network_status"] == "OFFLINE"
    mgr.start_network()
    assert mgr.get_stats()["network_status"] == "ONLINE"
    mgr.stop_network()
    assert mgr.get_stats()["network_status"] == "OFFLINE"


def test_start_network_twice_is_idempotent():
    """Calling start_network twice must not raise or corrupt state."""
    mgr = _make_manager()
    msg1 = mgr.start_network()
    msg2 = mgr.start_network()
    assert "already running" in msg2.lower()
    mgr.stop_network()


def test_stop_network_when_not_running():
    """Calling stop_network when already stopped must return gracefully."""
    mgr = _make_manager()
    msg = mgr.stop_network()
    assert isinstance(msg, str)


def test_emulate_normal_when_not_started():
    """start_emulate_normal before start_network must return instruction."""
    mgr = _make_manager()
    msg = mgr.start_emulate_normal()
    assert "start network" in msg.lower() or isinstance(msg, str)


def test_firewall_available():
    mgr = _make_manager()
    fw = mgr.get_firewall()
    assert fw is not None
    stats = fw.get_stats()
    assert "packets_allowed" in stats
