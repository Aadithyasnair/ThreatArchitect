"""
tests.test_simulation — Unit tests for Simulation engine.

Tests NormalSimulation lifecycle and PacketEvent generation.
"""

import pytest
from app.network.simulation import NormalSimulation
from app.network.topology_builder import TopologyBuilder
from app.network.topology_models import NodeStatus
from app.network.packet_simulator import PacketEvent


def _started_simulation() -> NormalSimulation:
    """Return a running NormalSimulation with a loaded topology."""
    sim = NormalSimulation()
    topo = TopologyBuilder.build_enterprise_default()
    # Mark all devices online so traffic can flow
    for device in topo.devices:
        device.status = NodeStatus.ONLINE
    sim.set_topology(topo)
    sim.start()
    return sim


def test_simulation_starts():
    sim = _started_simulation()
    assert sim.is_running() is True
    sim.stop()


def test_simulation_stops():
    sim = _started_simulation()
    sim.stop()
    assert sim.is_running() is False


def test_tick_returns_packet_event_when_running():
    sim = _started_simulation()
    event = sim.tick()
    sim.stop()
    assert event is not None
    assert isinstance(event, PacketEvent)


def test_tick_returns_none_when_stopped():
    sim = _started_simulation()
    sim.stop()
    event = sim.tick()
    assert event is None


def test_packet_event_has_required_fields():
    sim = _started_simulation()
    event = sim.tick()
    sim.stop()
    assert event is not None
    assert event.packet_id
    assert event.src_id
    assert event.dst_id
    assert event.src_ip
    assert event.dst_ip
    assert event.protocol is not None
    assert event.size_bytes > 0
    assert event.timestamp > 0


def test_packet_src_dst_are_different():
    """Packets must not be sent from a device to itself."""
    sim = _started_simulation()
    events = [sim.tick() for _ in range(20)]
    sim.stop()
    for event in events:
        if event:
            assert event.src_id != event.dst_id


def test_reset_clears_stats():
    sim = _started_simulation()
    # Generate some packets
    for _ in range(5):
        sim.tick()
    sim.reset()
    stats = sim.get_stats()
    assert stats["sent"] == 0
    sim.stop()


def test_simulation_name():
    sim = NormalSimulation()
    assert "normal" in sim.name.lower()


def test_simulation_tick_before_start_returns_none():
    """tick() before start() must return None."""
    sim = NormalSimulation()
    topo = TopologyBuilder.build_enterprise_default()
    sim.set_topology(topo)
    # Don't call start()
    result = sim.tick()
    assert result is None


def test_callback_is_called_on_tick():
    """If a packet callback is set, it must be called during tick."""
    events_received = []
    sim = _started_simulation()
    sim.set_packet_callback(lambda e: events_received.append(e))
    for _ in range(5):
        sim.tick()
    sim.stop()
    assert len(events_received) > 0


def test_packet_event_protocols_are_valid():
    """All generated packets must use known Protocol values."""
    from app.network.packet_simulator import Protocol
    sim = _started_simulation()
    events = [sim.tick() for _ in range(30)]
    sim.stop()
    valid_protocols = set(Protocol)
    for event in events:
        if event:
            assert event.protocol in valid_protocols
