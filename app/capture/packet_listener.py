"""
app.capture.packet_listener — Background thread listener for packet capture.

Uses native Scapy sniff on Linux, and consumes in-memory emulated Scapy packets on Windows.
Backed by standard Python threading for reliability and clean test teardown.
"""

from __future__ import annotations

import logging
import queue
import sys
import threading
from typing import Callable, Optional

logger = logging.getLogger("PacketListener")


class PacketListener(threading.Thread):
    """
    Background worker thread that listens for and captures raw packets.

    Can sniff network interfaces natively or consume emulated packets
    pushed from our traffic simulators.
    """

    def __init__(
        self,
        interface: str = "eth0",
        packet_callback: Optional[Callable[[any], None]] = None,
    ) -> None:
        super().__init__()
        self.interface = interface
        self.packet_callback = packet_callback
        self.running = False
        self.daemon = True  # Daemon thread so it never blocks main process exit

        # In-memory queue to feed emulated packets (e.g. on Windows)
        self.emulated_queue: queue.Queue = queue.Queue()

    def run(self) -> None:
        """Background loop."""
        self.running = True
        logger.info(f"PacketListener started on interface '{self.interface}'")

        is_linux = sys.platform.startswith("linux")

        if is_linux:
            # We run native Scapy sniff inside the Thread
            try:
                from scapy.sendrecv import sniff

                def process_scapy_packet(pkt):
                    if not self.running:
                        return
                    if self.packet_callback:
                        self.packet_callback(pkt)

                # sniff runs its own blocking loop, check running flag periodically
                sniff(
                    iface=self.interface,
                    prn=process_scapy_packet,
                    store=False,
                    stop_filter=lambda x: not self.running,
                )
                logger.info("Native Scapy sniffing loop stopped.")
                return
            except Exception as exc:
                logger.warning(f"Native sniffing failed ({exc}). Falling back to emulated queue.")

        # Fallback / Windows loop: Consume from in-memory queue
        while self.running:
            try:
                pkt = self.emulated_queue.get(timeout=0.05)
                if self.packet_callback and pkt is not None:
                    self.packet_callback(pkt)
                self.emulated_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error(f"Error in listener fallback loop: {exc}")

        logger.info("PacketListener background loop stopped.")

    def stop(self) -> None:
        """Signals the background loop to stop and blocks until finished."""
        self.running = False
        self.join(timeout=1.0) # Safe join with timeout

    def is_running(self) -> bool:
        """Return True if background loop is active and thread is alive."""
        return self.running and self.is_alive()

    def isRunning(self) -> bool:
        """Alias for Qt / QThread isRunning compatibility."""
        return self.is_running()

    def push_emulated_packet(self, scapy_pkt) -> None:
        """Safely queue an in-memory Scapy packet for listener processing."""
        self.emulated_queue.put(scapy_pkt)

