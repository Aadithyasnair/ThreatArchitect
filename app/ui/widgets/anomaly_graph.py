"""
app.ui.widgets.anomaly_graph — Real-time pyqtgraph anomaly score timeline.

Displays current LSTM anomaly score, classification threshold, and historic trend.
Fits the dark cyber-security HUD aesthetic.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
import pyqtgraph as pg

logger = logging.getLogger("AnomalyGraph")


class AnomalyGraph(QWidget):
    """
    Live line graph displaying LSTM anomaly scores over time.

    Styled with neon line accents and a custom threshold line.
    """

    def __init__(self, threshold: float = 0.65, history_len: int = 40, parent=None) -> None:
        super().__init__(parent)
        self.threshold = threshold
        self.history_len = history_len

        # Rolling data buffer
        self.x_data = list(range(history_len))
        self.y_data = [0.0] * history_len

        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Small HUD title
        self.title_lbl = QLabel("LIVE ANOMALY TIMELINE (LSTM)")
        self.title_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        self.title_lbl.setStyleSheet("color: #4F8EF7; background: transparent;")
        layout.addWidget(self.title_lbl)

        # Initialize pyqtgraph plot
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground("#050B14")
        self.plot_widget.setMouseEnabled(x=False, y=False) # Disable zoom/pan
        self.plot_widget.setMenuEnabled(False)             # Disable context menu
        self.plot_widget.hideButtons()
        self.plot_widget.setYRange(0.0, 1.05, padding=0)

        # Style axes
        styles = {"color": "#4A6080", "font-family": "Consolas", "font-size": "7pt"}
        self.plot_widget.getAxis("left").setPen("#1E2D45")
        self.plot_widget.getAxis("bottom").setPen("#1E2D45")
        self.plot_widget.getAxis("left").setTextPen("#4A6080")
        self.plot_widget.getAxis("bottom").setTextPen("#4A6080")

        # Disable bottom axis ticks
        self.plot_widget.getAxis("bottom").setStyle(showValues=False)

        # Add grid lines
        self.plot_widget.showGrid(x=True, y=True, alpha=0.15)

        # Score line (neon cyan)
        pen_score = pg.mkPen(color="#00D2FF", width=2)
        self.score_curve = self.plot_widget.plot(self.x_data, self.y_data, pen=pen_score)

        # Threshold line (dotted red)
        pen_thresh = pg.mkPen(color="#EF4444", width=1.5, style=Qt.DashLine)
        self.thresh_line = pg.InfiniteLine(
            pos=self.threshold,
            angle=0,
            pen=pen_thresh,
            label=f"THRESH: {self.threshold:.2f}",
            labelOpts={
                "color": "#EF4444",
                "position": 0.9,
                "anchors": [(1, 1)],
            }
        )
        self.plot_widget.addItem(self.thresh_line)

        layout.addWidget(self.plot_widget)

    def add_score(self, score: float) -> None:
        """Pushes a new anomaly score into the rolling graph buffer and redraws."""
        self.y_data.pop(0)
        self.y_data.append(score)
        self.score_curve.setData(self.x_data, self.y_data)

    def set_threshold(self, threshold: float) -> None:
        """Update threshold limit line position dynamically."""
        self.threshold = threshold
        self.thresh_line.setValue(threshold)
        self.thresh_line.label.setText(f"THRESH: {threshold:.2f}")

    def clear(self) -> None:
        """Reset score history timeline."""
        self.y_data = [0.0] * self.history_len
        self.score_curve.setData(self.x_data, self.y_data)
