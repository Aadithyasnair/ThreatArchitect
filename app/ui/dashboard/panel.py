"""
app.ui.dashboard.panel — Live network stats dashboard strip.

Fully responsive: all font sizes, card padding, and log area height
are recomputed each time on_resize(height) is called from MainWindow.

Cards stretch horizontally to fill available width.
No fixed pixel sizes anywhere.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QSizePolicy,
)
from PySide6.QtCore import Qt, QDateTime, QSize
from PySide6.QtGui import QFont

logger = logging.getLogger("DashboardPanel")


class _StatCard(QFrame):
    """
    A single live metric card.
    Title is a small dimmed label; value is large bold text with an accent color.
    Both font sizes scale dynamically when set_scale(height) is called.
    """

    def __init__(self, title: str, value: str, accent: str) -> None:
        super().__init__()
        self._accent = accent
        self.setMinimumWidth(110)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.setStyleSheet(f"""
            _StatCard, QFrame {{
                background-color: #09090B;
                border: 1px solid #27272A;
                border-left: 3px solid {accent};
                border-radius: 6px;
            }}
        """)

        self._layout = QVBoxLayout(self)
        self._layout.setSpacing(2)
        self._layout.setContentsMargins(10, 8, 10, 8)

        self._title_lbl = QLabel(title.upper())
        self._title_lbl.setStyleSheet("color: #A1A1AA; border: none; background: transparent; font-weight: 700; font-size: 10px;")
        self._title_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self._val_lbl = QLabel(value)
        self._val_lbl.setStyleSheet(f"color: {accent}; border: none; background: transparent; font-weight: 800; font-size: 14px;")
        self._val_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._val_lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)

        self._layout.addWidget(self._title_lbl)
        self._layout.addWidget(self._val_lbl)

    def set_value(self, text: str) -> None:
        self._val_lbl.setText(text)

    def set_accent(self, accent: str) -> None:
        self._accent = accent
        self._val_lbl.setStyleSheet(f"color: {accent}; border: none; background: transparent; font-weight: 800; font-size: 14px;")

    def set_scale(self, panel_height: int) -> None:
        pass


class DashboardPanel(QWidget):
    """
    Bottom stats strip — 7 metric cards + a one-line live event log.
    All sizes are recomputed on every resize via on_resize().
    """

    _CARDS = [
        ("Threat Level",   "INFO",     "#94A3B8"),
        ("Threat Score",   "0",        "#A3E635"),
        ("Anomaly Score",  "0.00",     "#A3E635"),
        ("Classifier Conf", "0%",      "#38BDF8"),
        ("Pkt Sniffed",    "0",        "#38BDF8"),
        ("Active Flows",   "0",        "#38BDF8"),
        ("Active Attack",  "Normal",   "#A3E635"),
        ("Attack Target",  "N/A",      "#94A3B8"),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyleSheet("background-color: #0B0F17;")
        self._log_lines: list = []
        self._init_ui()

    def _init_ui(self) -> None:
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(0)

        # ── Stat cards row ────────────────────────────────────────────────────
        cards_wrap = QWidget()
        cards_wrap.setStyleSheet("background-color: #000000;")
        self._cards_layout = QHBoxLayout(cards_wrap)
        self._cards_layout.setContentsMargins(8, 6, 8, 4)
        self._cards_layout.setSpacing(6)

        self._cards: dict[str, _StatCard] = {}
        for title, default, accent in self._CARDS:
            card = _StatCard(title, default, accent)
            self._cards[title] = card
            self._cards_layout.addWidget(card, 1)

        self._root.addWidget(cards_wrap, 1)

        # ── Live log strip (1 line, very slim) ───────────────────────────────
        self._log_lbl = QLabel("  ▸ network idle")
        self._log_lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        self._log_lbl.setStyleSheet(
            "color: #A3E635; background-color: #09090B; "
            "padding: 4px 12px; border-top: 1px solid #27272A; font-weight: 700; font-family: 'Consolas', monospace;"
        )
        self._log_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._root.addWidget(self._log_lbl)

    # ── Public API ────────────────────────────────────────────────────────────

    def on_resize(self, panel_height: int) -> None:
        """Called by MainWindow whenever the panel height changes."""
        # Cards occupy 80% of panel height, log strip is 20%
        card_h = max(60, int(panel_height * 0.78))
        log_h  = max(18, panel_height - card_h)

        self._log_lbl.setFixedHeight(log_h)

        # Scale log font
        log_pt = max(7, min(9, log_h // 3))
        self._log_lbl.setFont(QFont("Consolas", log_pt))

        # Scale every card
        for card in self._cards.values():
            card.set_scale(card_h)

    def update_stats(self, stats: dict) -> None:
        """Push live values into each card."""
        level = stats.get("threat_level", "INFO")
        score = stats.get("threat_score", 0)

        # Color map for severity
        level_colors = {
            "INFO": "#94A3B8",
            "LOW": "#22C55E",
            "MEDIUM": "#FACC15",
            "HIGH": "#F97316",
            "CRITICAL": "#EF4444"
        }
        level_color = level_colors.get(level, "#94A3B8")

        # Color map for threat score warning thresholds
        score_color = "#22C55E"
        if score > 75:
            score_color = "#EF4444"
        elif score > 45:
            score_color = "#FACC15"

        anomaly = stats.get("anomaly_score", 0.0)
        anomaly_color = "#EF4444" if anomaly > 0.65 else "#22C55E"

        conf = stats.get("classifier_confidence", 0.0)

        attack = stats.get("current_attack", "Normal")
        if attack == "Normal":
            attack_color = "#A3E635"
        elif score > 70 or level in ("HIGH", "CRITICAL"):
            attack_color = "#EF4444"
        else:
            attack_color = "#FACC15"

        updates = {
            "Threat Level":    (level, level_color),
            "Threat Score":    (str(score), score_color),
            "Anomaly Score":   (f"{anomaly:.2f}", anomaly_color),
            "Classifier Conf": (f"{int(conf * 100)}%", "#38BDF8"),
            "Pkt Sniffed":     (str(stats.get("packets_captured", 0)), "#4F8EF7"),
            "Active Flows":    (str(stats.get("active_flows", 0)), "#4F8EF7"),
            "Active Attack":   (attack, attack_color),
            "Attack Target":   (stats.get("current_target", "N/A"), "#94A3B8"),
        }
        for title, (value, accent) in updates.items():
            card = self._cards.get(title)
            if card:
                card.set_value(value)
                card.set_accent(accent)

    def append_log(self, message: str) -> None:
        """Update the live log strip with the latest event."""
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        self._log_lines.append(f"[{timestamp}] {message}")
        if len(self._log_lines) > 200:
            self._log_lines = self._log_lines[-200:]
        # Show only the last line in the strip; terminal has the full log
        last = self._log_lines[-1] if self._log_lines else ""
        self._log_lbl.setText(f"  ▸  {last}")


class AIRecommendationPanel(QWidget):
    """Placeholder — implemented in Phase 5."""
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        lbl = QLabel("AI recommendations will appear here in Phase 5.")
        lbl.setStyleSheet("color: #64748B;")
        layout = QVBoxLayout(self)
        layout.addWidget(lbl)
        self.setStyleSheet("background-color: #151E2F; border: 1px solid #2A364F; border-radius: 8px;")
