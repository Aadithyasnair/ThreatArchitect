"""
app.network.host — Host/Workstation device abstraction (Phase 3+ extension stub).
"""
from app.network.topology_models import NetworkDevice, DeviceType


class HostDevice:
    """Wrapper around NetworkDevice for host-specific behaviour."""

    def __init__(self, device: NetworkDevice) -> None:
        self._device = device

    @property
    def device(self) -> NetworkDevice:
        return self._device

    def ping(self, target_ip: str) -> bool:
        """Stub: simulate ping (Phase 3 Mininet integration)."""
        return True
