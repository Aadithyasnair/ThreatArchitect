"""
app.ui.widgets.timeline_widget — Interactive, scrollable threat incident timeline.

Displays chronological updates: traffic status, classifications, rules matching,
firewall blocking, and AI recommendations.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextBrowser, QFrame
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

logger = logging.getLogger("TimelineWidget")


class TimelineWidget(QWidget):
    """
    HUD timeline logger showing sequence of historical incident events.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._events: list[dict] = []
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Title Label
        title_lbl = QLabel("INTERACTIVE INCIDENT TIMELINE")
        title_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        title_lbl.setStyleSheet("color: #4F8EF7; background: transparent;")
        layout.addWidget(title_lbl)

        # Display Browser
        self.browser = QTextBrowser()
        self.browser.setFrameStyle(QFrame.NoFrame)
        self.browser.setStyleSheet("""
            QTextBrowser {
                background-color: #050B14;
                color: #A9B2C3;
                font-family: Consolas, monospace;
                font-size: 8pt;
                line-height: 1.4;
                border: 1px solid #1E2D45;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        layout.addWidget(self.browser)

        self.clear()

    def update_events(self, events: list[dict]) -> None:
        """
        Accepts a list of dictionaries with keys: 'event_time', 'message', 'event_type'.
        """
        self._events = events
        self.render_html()

    def render_html(self) -> None:
        """Build and render timeline nodes as styled HTML."""
        if not self._events:
            self.clear()
            return

        type_colors = {
            "TRAFFIC_START": "#38BDF8",  # Light Blue
            "DETECTED":      "#F97316",  # Orange
            "ELEVATED":      "#EC4899",  # Pink
            "BLOCKED":       "#EF4444",  # Red
            "AI_RECOMMENDATION": "#22C55E", # Green
            "COMPLIANCE":    "#FACC15",  # Yellow
        }

        html = '<div style="font-family: Consolas, monospace; font-size: 8pt;">'

        # Loop through events in reverse chronological order (newest on top) or chronological?
        # Chronological is usually standard for timelines, but newest on top makes it easy to read
        # Let's display chronological (oldest at top, scroll down to see newest)
        for idx, evt in enumerate(self._events):
            t = evt.get("event_time", "00:00:00")
            msg = evt.get("message", "")
            etype = evt.get("event_type", "INFO")
            color = type_colors.get(etype, "#94A3B8")

            # Draw timeline connectors
            html += f"""
            <div style="margin-bottom: 6px; line-height: 1.3;">
                <span style="color: #4A6080; font-weight: bold;">[{t}]</span>
                <span style="background-color: {color}20; color: {color}; border: 1px solid {color}; border-radius: 3px; padding: 1px 4px; font-size: 7.5pt; font-weight: bold; margin: 0 4px;">
                    {etype}
                </span>
                <span style="color: #E2E8F0; margin-left: 2px;">{msg}</span>
            </div>
            """

        html += "</div>"
        self.browser.setHtml(html)
        
        # Scroll to bottom automatically to focus on latest events
        self.browser.verticalScrollBar().setValue(
            self.browser.verticalScrollBar().maximum()
        )

    def clear(self) -> None:
        """Resets timeline display to idle."""
        self._events = []
        self.browser.setHtml("""
            <div style="font-family: Consolas, monospace; font-size: 8pt; color: #4A6080; text-align: center; margin-top: 20px;">
                Timeline empty.<br/>
                Activate a simulation stream to view events.
            </div>
        """)
