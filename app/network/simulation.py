"""
app.network.simulation — Abstract simulation framework and concrete NormalSimulation.

Provides the base Simulation interface that all simulation modes must implement.
NormalSimulation drives NormalTrafficSimulator to produce legitimate traffic.

Future simulations (SuspiciousSimulation, DangerousSimulation) will subclass Simulation.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional, Callable

from app.network.packet_simulator import NormalTrafficSimulator, SuspiciousTrafficSimulator, DangerousTrafficSimulator, PacketEvent
from app.network.topology_models import NetworkTopology

logger = logging.getLogger("Simulation")



class Simulation(ABC):
    """
    Abstract base for all simulation modes.

    Subclasses override tick() to emit packet events.
    """

    def __init__(self) -> None:
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """Activate the simulation."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Deactivate the simulation."""
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset internal state without stopping."""
        ...

    @abstractmethod
    def tick(self) -> Optional[PacketEvent]:
        """
        Produce one packet event (called by SimulationTickWorker on each timer tick).
        Returns None if nothing should be emitted this tick.
        """
        ...

    def is_running(self) -> bool:
        """Return True if the simulation is active."""
        return self._running

    @property
    def name(self) -> str:
        """Human-readable simulation mode name."""
        return self.__class__.__name__


class NormalSimulation(Simulation):
    """
    Drives NormalTrafficSimulator to produce realistic enterprise traffic.

    Each tick() call asks the simulator for one packet event.
    The simulation is stateless between ticks — no ordering is enforced.
    """

    def __init__(self) -> None:
        super().__init__()
        self._simulator = NormalTrafficSimulator()

    def start(self) -> None:
        self._running = True
        self._simulator.start()
        logger.info("NormalSimulation started.")

    def stop(self) -> None:
        self._running = False
        self._simulator.stop()
        logger.info("NormalSimulation stopped.")

    def reset(self) -> None:
        self._simulator.reset_stats()
        logger.info("NormalSimulation stats reset.")

    def tick(self) -> Optional[PacketEvent]:
        """Generate one legitimate packet event, or None if not running."""
        if not self._running:
            return None
        return self._simulator.generate_normal_traffic()

    def set_topology(self, topology: NetworkTopology) -> None:
        """Provide the topology from which traffic sources/destinations are chosen."""
        self._simulator.set_topology(topology)

    def set_packet_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        """Wire a callback for every generated packet event."""
        self._simulator.set_packet_callback(callback)

    def get_stats(self) -> dict:
        """Return underlying traffic statistics."""
        return self._simulator.get_stats()

    @property
    def name(self) -> str:
        return "emulate normal"


class SuspiciousSimulation(Simulation):
    """
    Drives SuspiciousTrafficSimulator to produce attack network signatures.
    """

    def __init__(self) -> None:
        super().__init__()
        self._simulator = SuspiciousTrafficSimulator()

    def start(self) -> None:
        self._running = True
        self._simulator.start()
        logger.info("SuspiciousSimulation started.")

    def stop(self) -> None:
        self._running = False
        self._simulator.stop()
        logger.info("SuspiciousSimulation stopped.")

    def reset(self) -> None:
        self._simulator.reset_stats()
        logger.info("SuspiciousSimulation stats reset.")

    def tick(self) -> Optional[PacketEvent]:
        """Generate one malicious packet event."""
        if not self._running:
            return None
        return self._simulator.generate_suspicious_traffic()

    def set_topology(self, topology: NetworkTopology) -> None:
        self._simulator.set_topology(topology)

    def set_packet_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        self._simulator.set_packet_callback(callback)

    def get_stats(self) -> dict:
        return self._simulator.get_stats()

    @property
    def name(self) -> str:
        return "emulate suspicious"


class DangerousSimulation(Simulation):
    """
    Drives DangerousTrafficSimulator to produce volumetric and exploit signatures.
    """

    def __init__(self) -> None:
        super().__init__()
        self._simulator = DangerousTrafficSimulator()

    def start(self) -> None:
        self._running = True
        self._simulator.start()
        logger.info("DangerousSimulation started.")

    def stop(self) -> None:
        self._running = False
        self._simulator.stop()
        logger.info("DangerousSimulation stopped.")

    def reset(self) -> None:
        self._simulator.reset_stats()
        logger.info("DangerousSimulation stats reset.")

    def tick(self) -> Optional[PacketEvent]:
        """Generate one dangerous exploit packet event."""
        if not self._running:
            return None
        return self._simulator.generate_dangerous_traffic()

    def set_topology(self, topology: NetworkTopology) -> None:
        self._simulator.set_topology(topology)

    def set_packet_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        self._simulator.set_packet_callback(callback)

    def get_stats(self) -> dict:
        return self._simulator.get_stats()

    @property
    def name(self) -> str:
        return "emulate dangerous"

