"""
app.network.router — Router device abstraction (Phase 3+ extension stub).
"""
from app.network.topology_models import NetworkDevice, DeviceType, NodeStatus


class RouterDevice:
    """Wrapper around NetworkDevice for router-specific behaviour."""

    def __init__(self, device: NetworkDevice) -> None:
        assert device.device_type == DeviceType.ROUTER
        self._device = device

    @property
    def device(self) -> NetworkDevice:
        return self._device

    def route(self, src_ip: str, dst_ip: str) -> str:
        """Stub: return next hop for destination IP (Phase 3)."""
        return "10.0.0.2"  # Default next hop: firewall
