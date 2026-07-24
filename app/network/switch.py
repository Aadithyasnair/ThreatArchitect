"""
app.network.switch — Switch device abstraction (Phase 3+ extension stub).
"""
from app.network.topology_models import NetworkDevice, DeviceType


class SwitchDevice:
    """Wrapper around NetworkDevice for switch-specific behaviour."""

    def __init__(self, device: NetworkDevice) -> None:
        assert device.device_type == DeviceType.SWITCH
        self._device = device
        self._mac_table: dict = {}

    @property
    def device(self) -> NetworkDevice:
        return self._device

    def learn(self, mac: str, port: int) -> None:
        """Learn a MAC address on a port (stub for Phase 3 forwarding logic)."""
        self._mac_table[mac] = port

    def lookup(self, mac: str) -> int:
        """Return the port for a known MAC or -1 for flood."""
        return self._mac_table.get(mac, -1)
