"""
tests.test_topology_builder — Unit tests for TopologyBuilder.

Verifies device counts, types, IP assignments, and link structure
of the enterprise default topology without any UI dependencies.
"""

import pytest
from app.network.topology_builder import TopologyBuilder
from app.network.topology_models import DeviceType, NodeStatus


def test_enterprise_default_has_correct_device_count():
    """Enterprise topology must contain exactly 8 devices."""
    topo = TopologyBuilder.build_enterprise_default()
    assert len(topo.devices) == 8


def test_enterprise_default_has_correct_link_count():
    """Enterprise topology must contain exactly 7 links."""
    topo = TopologyBuilder.build_enterprise_default()
    assert len(topo.links) == 7


def test_enterprise_default_has_all_required_device_types():
    """All required device types must be present."""
    topo = TopologyBuilder.build_enterprise_default()
    device_types = {d.device_type for d in topo.devices}
    required = {
        DeviceType.INTERNET,
        DeviceType.ROUTER,
        DeviceType.FIREWALL,
        DeviceType.SWITCH,
        DeviceType.SERVER,
        DeviceType.DATABASE,
        DeviceType.WORKSTATION,
    }
    # WORKSTATION appears twice, so check subset
    assert required.issubset(device_types)


def test_all_devices_start_offline():
    """All devices must begin with OFFLINE status."""
    topo = TopologyBuilder.build_enterprise_default()
    for device in topo.devices:
        assert device.status == NodeStatus.OFFLINE, (
            f"Device {device.hostname} expected OFFLINE, got {device.status}"
        )


def test_device_ids_are_unique():
    """All device IDs must be unique."""
    topo = TopologyBuilder.build_enterprise_default()
    ids = [d.id for d in topo.devices]
    assert len(ids) == len(set(ids)), "Duplicate device IDs found"


def test_device_ips_are_assigned():
    """All devices must have non-empty IP addresses."""
    topo = TopologyBuilder.build_enterprise_default()
    for device in topo.devices:
        assert device.ip_address, f"Device {device.id} has no IP address"


def test_links_reference_valid_device_ids():
    """All link source/target IDs must reference existing devices."""
    topo = TopologyBuilder.build_enterprise_default()
    device_ids = {d.id for d in topo.devices}
    for link in topo.links:
        assert link.source_id in device_ids, f"Unknown source: {link.source_id}"
        assert link.target_id in device_ids, f"Unknown target: {link.target_id}"


def test_topology_name():
    """Topology must have a non-empty name."""
    topo = TopologyBuilder.build_enterprise_default()
    assert topo.name


def test_get_device_by_id():
    """get_device() must return correct device."""
    topo = TopologyBuilder.build_enterprise_default()
    firewall = topo.get_device("firewall")
    assert firewall is not None
    assert firewall.device_type == DeviceType.FIREWALL


def test_set_device_status():
    """set_device_status() must update in place."""
    topo = TopologyBuilder.build_enterprise_default()
    result = topo.set_device_status("router", NodeStatus.ONLINE)
    assert result is True
    router = topo.get_device("router")
    assert router.status == NodeStatus.ONLINE


def test_get_online_devices_initially_empty():
    """get_online_devices() must return empty list before network starts."""
    topo = TopologyBuilder.build_enterprise_default()
    assert topo.get_online_devices() == []
