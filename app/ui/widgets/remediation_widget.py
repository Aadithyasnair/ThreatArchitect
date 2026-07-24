"""
app.ui.widgets.remediation_widget — Renders AI mitigation analysis and commands.

Allows copy-to-clipboard for recommended shell or firewall commands.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser, QPushButton, QFrame, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication

from app.ai.ollama.response_parser import RemediationReport

logger = logging.getLogger("RemediationWidget")


class RemediationWidget(QWidget):
    """
    Renders strongly-typed LLM remediation plans with copyable commands.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._accumulated_text = ""
        self._status_text = "Idle"
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Title / Status layout
        title_box = QHBoxLayout()
        title_lbl = QLabel("AI REMEDIATION PLAYBOOK")
        title_lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        title_lbl.setStyleSheet("color: #4F8EF7; background: transparent;")
        title_box.addWidget(title_lbl)

        title_box.addStretch()

        self.status_lbl = QLabel("")
        self.status_lbl.setFont(QFont("Consolas", 7.5, QFont.Bold))
        self.status_lbl.setStyleSheet("color: #4A6080;")
        title_box.addWidget(self.status_lbl)
        
        layout.addLayout(title_box)

        # Main scrollable area
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameStyle(QFrame.NoFrame)
        self.scroll.setStyleSheet("background-color: #050B14; border: 1px solid #1E2D45; border-radius: 4px;")

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: #050B14;")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(6, 6, 6, 6)
        self.scroll_layout.setSpacing(8)

        # Summary Browser
        self.browser = QTextBrowser()
        self.browser.setFrameStyle(QFrame.NoFrame)
        self.browser.setMinimumHeight(150)
        self.browser.setStyleSheet("""
            QTextBrowser {
                background-color: #050B14;
                color: #A9B2C3;
                font-family: Consolas, monospace;
                font-size: 8pt;
                line-height: 1.4;
            }
        """)
        self.scroll_layout.addWidget(self.browser)

        # Container for commands
        self.cmd_container = QWidget()
        self.cmd_layout = QVBoxLayout(self.cmd_container)
        self.cmd_layout.setContentsMargins(0, 0, 0, 0)
        self.cmd_layout.setSpacing(4)
        self.scroll_layout.addWidget(self.cmd_container)

        self.scroll.setWidget(self.scroll_content)
        layout.addWidget(self.scroll)

        self.clear()

    def update_status(self, status: str) -> None:
        """Updates the status text tag at the top of the playbook."""
        self._status_text = status
        self.status_lbl.setText(status.upper())
        if status == "Analyzing...":
            self.clear_commands()
            self._accumulated_text = ""
            self.status_lbl.setStyleSheet("color: #FACC15;")
            self.browser.setHtml("""
                <div style="font-family: Consolas, monospace; font-size: 8.5pt; color: #FACC15; text-align: center; margin-top: 20px;">
                    [Analyzing threat vector and compiling context...]
                </div>
            """)
        elif status == "Streaming response...":
            self.status_lbl.setStyleSheet("color: #00D2FF;")
        elif status == "Completed":
            self.status_lbl.setStyleSheet("color: #22C55E;")
            self.status_lbl.setText("")

    def append_token(self, token: str) -> None:
        """Appends a new streaming word token and updates the log screen in real time."""
        self._accumulated_text += token
        
        # Display the raw accumulating stream
        html = f"""
        <div style="font-family: Consolas, monospace; font-size: 8pt; color: #38BDF8; font-weight: bold; margin-bottom: 4px;">
            SEC-GPT STREAMING RESPONSE:
        </div>
        <pre style="font-family: Consolas, monospace; font-size: 8pt; color: #A9B2C3; white-space: pre-wrap; margin: 0;">
{self._accumulated_text}
        </pre>
        """
        self.browser.setHtml(html)
        
        # Scroll to bottom
        self.browser.verticalScrollBar().setValue(
            self.browser.verticalScrollBar().maximum()
        )

    def update_remediation(self, report: RemediationReport) -> None:
        """Populates fields and builds action lists and command copy rows."""
        self.clear_commands()

        # Build basic details html
        color = "#EF4444" if report.risk_level in ("CRITICAL", "HIGH") else "#FACC15"
        
        html = f"""
        <div style="font-family: Consolas, monospace; font-size: 8.5pt;">
            <div style="color: {color}; font-weight: bold; font-size: 9pt; margin-bottom: 4px;">
                RISK LEVEL: {report.risk_level}
            </div>
            <div style="color: #E2E8F0; font-weight: bold; margin-bottom: 2px;">Threat Analysis Summary:</div>
            <div style="color: #A9B2C3; margin-bottom: 8px;">{report.threat_summary}</div>
            
            <div style="color: #E2E8F0; font-weight: bold; margin-bottom: 2px;">AI Reasoning:</div>
            <div style="color: #A9B2C3; margin-bottom: 8px;">{report.reasoning}</div>
        """

        if report.recommended_actions:
            html += """
            <div style="color: #38BDF8; font-weight: bold; margin-bottom: 2px;">Recommended Actions:</div>
            <ul style="margin: 0; padding-left: 14px; color: #A9B2C3; margin-bottom: 8px;">
            """
            for action in report.recommended_actions:
                html += f"<li>{action}</li>"
            html += "</ul>"

        if report.additional_notes:
            html += f"""
            <div style="color: #4A6080; font-style: italic; margin-top: 4px;">
                *Note: {report.additional_notes}
            </div>
            """

        html += "</div>"
        self.browser.setHtml(html)

        # Build mitigation commands list
        if report.linux_commands:
            self._add_header_label("RECOMMENDED MITIGATION COMMANDS:")
            for cmd in report.linux_commands:
                self._add_copyable_command_row(cmd)

        if report.rollback_commands:
            self._add_header_label("ROLLBACK COMMANDS:")
            for cmd in report.rollback_commands:
                self._add_copyable_command_row(cmd)

    def _add_header_label(self, text: str) -> None:
        lbl = QLabel(text)
        lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        lbl.setStyleSheet("color: #E2E8F0; margin-top: 6px;")
        self.cmd_layout.addWidget(lbl)

    def _add_copyable_command_row(self, cmd_text: str) -> None:
        """Creates a row containing the command and a Copy button."""
        row = QFrame()
        row.setStyleSheet("background-color: #0B1220; border: 1px solid #1E2D45; border-radius: 3px;")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(6, 4, 6, 4)
        row_layout.setSpacing(6)

        cmd_lbl = QLabel(cmd_text)
        cmd_lbl.setFont(QFont("Courier", 8))
        cmd_lbl.setStyleSheet("color: #E2E8F0; border: none; background: transparent;")
        cmd_lbl.setWordWrap(True)
        row_layout.addWidget(cmd_lbl, 1)

        copy_btn = QPushButton("Copy")
        copy_btn.setFont(QFont("Consolas", 7, QFont.Bold))
        copy_btn.setFixedWidth(42)
        copy_btn.setFixedHeight(18)
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E2D45;
                color: #A9B2C3;
                border: 1px solid #2A364F;
                border-radius: 2px;
            }
            QPushButton:hover {
                background-color: #2A364F;
                color: #F8FAFC;
            }
            QPushButton:pressed {
                background-color: #0F172A;
            }
        """)
        
        # Clipboard copy lambda
        copy_btn.clicked.connect(lambda: self._copy_to_clipboard(cmd_text, copy_btn))
        row_layout.addWidget(copy_btn)

        self.cmd_layout.addWidget(row)

    def _copy_to_clipboard(self, text: str, button: QPushButton) -> None:
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(text)
        button.setText("Copied!")
        button.setStyleSheet("background-color: #22C55E; color: #0F172A; border: none; border-radius: 2px;")
        
        # Revert text after delay
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1500, lambda: self._revert_copy_button(button))

    def _revert_copy_button(self, button: QPushButton) -> None:
        button.setText("Copy")
        button.setStyleSheet("""
            QPushButton {
                background-color: #1E2D45;
                color: #A9B2C3;
                border: 1px solid #2A364F;
                border-radius: 2px;
            }
            QPushButton:hover {
                background-color: #2A364F;
                color: #F8FAFC;
            }
        """)

    def clear_commands(self) -> None:
        """Removes all copyable command boxes."""
        while self.cmd_layout.count():
            item = self.cmd_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def clear(self) -> None:
        """Resets layout to idle description."""
        self.clear_commands()
        self.browser.setHtml("""
            <div style="font-family: Consolas, monospace; font-size: 8pt; color: #4A6080; text-align: center; margin-top: 20px;">
                Playbook is empty.<br/>
                LLM recommendations will display when a high threat is active.
            </div>
        """)
