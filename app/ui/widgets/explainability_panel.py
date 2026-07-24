"""
app.ui.widgets.explainability_panel — Explains security decisions made by the threat engine.

Renders threat details, classifier confidence, evidence list, and the reasoning chain.
Uses clean HTML formatting for readability.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextBrowser, QFrame
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from app.network.threat_engine import ThreatModel

logger = logging.getLogger("ExplainabilityPanel")


class ExplainabilityPanel(QWidget):
    """
    Renders structured audit details explaining active security threat verdicts.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header Title
        title_lbl = QLabel("DECISION EXPLAINABILITY & AUDIT")
        title_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        title_lbl.setStyleSheet("color: #4F8EF7; background: transparent;")
        layout.addWidget(title_lbl)

        # Detail text browser (Scrollable, HTML support, borderless)
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

    def update_threat_model(self, model: ThreatModel) -> None:
        """Parse a ThreatModel report and render explainable HTML content."""
        # Color code severity
        color_map = {
            "INFO": "#94A3B8",
            "LOW": "#22C55E",
            "MEDIUM": "#FACC15",
            "HIGH": "#F97316",
            "CRITICAL": "#EF4444"
        }
        level_color = color_map.get(model.threat_level, "#A9B2C3")

        html = f"""
        <div style="font-family: Consolas, monospace; font-size: 8pt;">
            <!-- Severity Summary -->
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 8px;">
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">THREAT LEVEL:</td>
                    <td style="color:{level_color}; font-weight:bold; text-align:right;">{model.threat_level} ({model.threat_score}/100)</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">ATTACK TYPE:</td>
                    <td style="color:#F8FAFC; text-align:right;">{model.attack_category} ({(model.confidence*100):.1f}%)</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">TARGET IP:</td>
                    <td style="color:#EF4444; text-align:right;">{model.affected_host}</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">ATTACKER IP:</td>
                    <td style="color:#FACC15; text-align:right;">{model.attacker_host}</td>
                </tr>
                <tr>
                    <td style="color:#4A6080; font-weight:bold;">AFFECTED PORT:</td>
                    <td style="color:#38BDF8; text-align:right;">{model.affected_service}</td>
                </tr>
            </table>

            <hr style="border: 0; border-top: 1px solid #1E2D45; margin: 6px 0;">

            <!-- Reasoning Chain -->
            <div style="color: #00D2FF; font-weight: bold; margin-bottom: 4px;">REASONING CHAIN:</div>
            <div style="padding-left: 6px; border-left: 2px solid #00D2FF; margin-bottom: 8px;">
        """

        # Generate reasoning step arrows
        for i, step in enumerate(model.reasoning_chain):
            if i > 0:
                html += f'<div style="color:#4A6080; padding: 2px 0;">  &nbsp;&nbsp;▼</div>'
            html += f'<div style="color:#E2E8F0;">• {step}</div>'

        html += """
            </div>

            <hr style="border: 0; border-top: 1px solid #1E2D45; margin: 6px 0;">

            <!-- Evidence / Rules triggered -->
            <div style="color: #EF4444; font-weight: bold; margin-bottom: 4px;">EVIDENCE LOG:</div>
            <ul style="margin: 0; padding-left: 14px; color: #A9B2C3;">
        """

        for item in model.evidence:
            html += f'<li style="margin-bottom: 2px;">{item}</li>'

        if not model.evidence:
            html += "<li>No alerts or anomalies triggered.</li>"

        html += """
            </ul>

            <hr style="border: 0; border-top: 1px solid #1E2D45; margin: 6px 0;">

            <!-- Top features -->
            <div style="color: #FACC15; font-weight: bold; margin-bottom: 4px;">TOP CONTRIBUTING FEATURES:</div>
        """
        feats = ", ".join(model.top_features) if model.top_features else "None"
        html += f'<div style="color:#A9B2C3;">{feats}</div>'

        html += "</div>"

        self.browser.setHtml(html)

    def clear(self) -> None:
        """Reset panel text."""
        self.browser.setHtml("""
            <div style="font-family: Consolas, monospace; font-size: 8pt; color: #4A6080; text-align: center; margin-top: 20px;">
                No active threats detected.<br>
                Emulate suspicious traffic or run pings to trigger analysis.
            </div>
        """)
