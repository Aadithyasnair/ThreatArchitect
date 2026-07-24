"""
app.ui.widgets.osi_visualizer — OSI 7-layer stack visualizer.

Displays the vertical stack of network layers. Highlights the affected layer
(e.g., Transport for SYN floods) with a neon warning/critical glow and explanation.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

logger = logging.getLogger("OSIVisualizer")


class OSIVisualizer(QWidget):
    """
    HUD widget showing the vertical 7-layer OSI model stack.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.layer_widgets: dict[str, QFrame] = {}
        self.layer_lbls: dict[str, QLabel] = {}
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(3)

        # Title Label
        title_lbl = QLabel("OSI 7-LAYER TARGET STACK")
        title_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        title_lbl.setStyleSheet("color: #4F8EF7; background: transparent;")
        layout.addWidget(title_lbl)

        # Vertical stack of layers (Top down: Application -> Physical)
        layers = [
            ("L7", "Application", "DNS, HTTP, HTTPS, SSH, DHCP, Malware Beacons"),
            ("L6", "Presentation", "SSL/TLS Encryption & Encoding"),
            ("L5", "Session", "RPC, NetBIOS, Session Establishment"),
            ("L4", "Transport", "TCP Handshakes, UDP Ports, SYN flow segmenting"),
            ("L3", "Network", "IP Addresses, Routing, ICMP packets"),
            ("L2", "Data Link", "MAC Addresses, ARP resolution cache"),
            ("L1", "Physical", "Cables, NIC hardware transceivers"),
        ]

        for code, name, desc in layers:
            frame = QFrame()
            frame.setFrameStyle(QFrame.StyledPanel)
            frame.setFixedHeight(22)
            
            f_layout = QHBoxLayout(frame)
            f_layout.setContentsMargins(8, 0, 8, 0)
            f_layout.setSpacing(8)

            code_lbl = QLabel(code)
            code_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
            code_lbl.setStyleSheet("color: #4A6080;")
            code_lbl.setFixedWidth(20)

            name_lbl = QLabel(name)
            name_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
            name_lbl.setStyleSheet("color: #E2E8F0;")

            desc_lbl = QLabel(f"({desc})")
            desc_lbl.setFont(QFont("Consolas", 7))
            desc_lbl.setStyleSheet("color: #4A6080;")
            desc_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

            f_layout.addWidget(code_lbl)
            f_layout.addWidget(name_lbl)
            f_layout.addWidget(desc_lbl, 1)

            layout.addWidget(frame)
            
            # Map index/name
            self.layer_widgets[name] = frame
            self.layer_lbls[name] = name_lbl

            # Default style
            frame.setStyleSheet("""
                QFrame {
                    background-color: #0F172A;
                    border: 1px solid #1E2D45;
                    border-radius: 3px;
                }
            """)

        # Bottom explanation block
        self.explanation_lbl = QLabel("No active layers affected. Network is running in normal baseline.")
        self.explanation_lbl.setWordWrap(True)
        self.explanation_lbl.setFont(QFont("Consolas", 8))
        self.explanation_lbl.setStyleSheet("color: #4A6080; padding: 4px; border: 1px dashed #1E2D45; border-radius: 3px; margin-top: 4px;")
        layout.addWidget(self.explanation_lbl)

        self.reset_stack()

    def highlight_layer(self, layer_name: str, explanation: str, level: str = "CRITICAL") -> None:
        """
        Highlights a specific layer with red/yellow glow borders and text explanation.
        """
        self.reset_stack()
        
        target = layer_name.title()
        if target not in self.layer_widgets:
            return

        # Determine color
        border_color = "#EF4444" if level in ("CRITICAL", "HIGH") else "#FACC15"
        bg_color = "#200A10" if level in ("CRITICAL", "HIGH") else "#201B05"

        self.layer_widgets[target].setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border: 2px solid {border_color};
                border-radius: 3px;
            }}
        """)
        self.layer_lbls[target].setStyleSheet(f"color: {border_color}; font-weight: bold;")
        self.explanation_lbl.setText(f"⚠ [{target.upper()} LAYER AFFECTED] {explanation}")
        self.explanation_lbl.setStyleSheet(f"color: {border_color}; padding: 4px; border: 1px solid {border_color}; border-radius: 3px; margin-top: 4px; background-color: #0A0F1D;")

    def reset_stack(self) -> None:
        """Resets all layers to their default dark-slate states."""
        for name, frame in self.layer_widgets.items():
            frame.setStyleSheet("""
                QFrame {
                    background-color: #090F1C;
                    border: 1px solid #1E2D45;
                    border-radius: 3px;
                }
            """)
            self.layer_lbls[name].setStyleSheet("color: #E2E8F0;")

        self.explanation_lbl.setText("All layers normal. Running enterprise traffic baseline.")
        self.explanation_lbl.setStyleSheet("color: #4A6080; padding: 4px; border: 1px dashed #1E2D45; border-radius: 3px; margin-top: 4px;")
