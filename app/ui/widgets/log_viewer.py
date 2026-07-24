"""
app.ui.widgets.log_viewer — Enterprise Logging Audit Explorer.

Allows search, keyword filter, log domain switches, logs clearing, exporting,
and directory opening directly from the PySide6 UI.
"""

from __future__ import annotations

import os
import logging
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QTextBrowser, QPushButton, QFrame, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QDesktopServices, QUrl

logger = logging.getLogger("LogViewer")


class LogViewerDialog(QDialog):
    """
    Log Explorer Dialog form for audits and runtime diagnostics tracing.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("System Logs Explorer")
        self.resize(720, 520)
        self.setStyleSheet("background-color: #0B1220; color: #F8FAFC;")

        self._log_mapping = {
            "Application Logs": "logs/application.log",
            "Networking Logs": "logs/networking.log",
            "AI Subsystem Logs": "logs/ai.log",
            "Threat Engine Logs": "logs/threat_detection.log",
            "Compliance Audit Logs": "logs/compliance.log",
            "Error & Crash Logs": "logs/errors.log"
        }

        self._init_ui()
        self._load_log_file()

        # Update reader automatically every 3 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._load_log_file)
        self._timer.start(3000)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Top Control Bar
        control_bar = QFrame()
        control_bar.setStyleSheet("background-color: #151E2F; border: 1px solid #2A364F; border-radius: 4px;")
        bar_layout = QHBoxLayout(control_bar)
        bar_layout.setContentsMargins(8, 6, 8, 6)
        bar_layout.setSpacing(10)

        # 1. Log domain combobox
        self.log_combo = QComboBox()
        self.log_combo.addItems(list(self._log_mapping.keys()))
        self.log_combo.currentTextChanged.connect(self._load_log_file)
        self._style_widget(self.log_combo)
        bar_layout.addWidget(QLabel("Domain:"), 0)
        bar_layout.addWidget(self.log_combo, 1)

        # 2. Search keyword filter
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter lines by keyword...")
        self.search_input.textChanged.connect(self._filter_changed)
        self._style_widget(self.search_input)
        bar_layout.addWidget(QLabel("Search:"), 0)
        bar_layout.addWidget(self.search_input, 2)

        # 3. Severity filter
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["ALL", "DEBUG", "INFO", "WARNING", "ERROR"])
        self.severity_combo.currentTextChanged.connect(self._load_log_file)
        self._style_widget(self.severity_combo)
        bar_layout.addWidget(QLabel("Severity:"), 0)
        bar_layout.addWidget(self.severity_combo, 0)

        layout.addWidget(control_bar)

        # Browser View
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
                padding: 8px;
            }
        """)
        layout.addWidget(self.browser)

        # Action Buttons footer
        footer_layout = QHBoxLayout()
        footer_layout.setSpacing(8)

        clear_btn = QPushButton("Clear File")
        self._style_btn(clear_btn, "#EF4444", "#F8FAFC")
        clear_btn.clicked.connect(self._clear_logs)
        footer_layout.addWidget(clear_btn)

        open_folder_btn = QPushButton("Open Logs Folder")
        self._style_btn(open_folder_btn, "#1E2D45", "#A9B2C3")
        open_folder_btn.clicked.connect(self._open_folder)
        footer_layout.addWidget(open_folder_btn)

        export_btn = QPushButton("Export Logs...")
        self._style_btn(export_btn, "#1E2D45", "#A9B2C3")
        export_btn.clicked.connect(self._export_logs)
        footer_layout.addWidget(export_btn)

        footer_layout.addStretch()

        close_btn = QPushButton("Close")
        self._style_btn(close_btn, "#00D2FF", "#0B1220")
        close_btn.clicked.connect(self.accept)
        footer_layout.addWidget(close_btn)

        layout.addLayout(footer_layout)

    def _style_widget(self, w) -> None:
        w.setFont(QFont("Consolas", 8))
        w.setStyleSheet("""
            QWidget {
                background-color: #0B1220;
                color: #F8FAFC;
                border: 1px solid #2A364F;
                border-radius: 2px;
                padding: 3px;
            }
        """)

    def _style_btn(self, btn: QPushButton, bg: str, fg: str) -> None:
        btn.setFont(QFont("Consolas", 8, QFont.Bold))
        btn.setFixedHeight(24)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {fg};
                border: 1px solid #2A364F;
                border-radius: 2px;
                padding: 0 10px;
            }}
            QPushButton:hover {{
                background-color: {bg}D0;
            }}
        """)

    def _filter_changed(self) -> None:
        # Debounce or simple immediate load
        self._load_log_file()

    def _load_log_file(self) -> None:
        domain = self.log_combo.currentText()
        path = self._log_mapping.get(domain)

        if not path or not os.path.exists(path):
            self.browser.setText(f"[EMPTY] Log file '{path}' does not exist yet. Perform operations to populate.")
            return

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            search_q = self.search_input.text().lower()
            severity_q = self.severity_combo.currentText()

            filtered = []
            for line in lines:
                # 1. Search keyword filter
                if search_q and search_q not in line.lower():
                    continue

                # 2. Severity levels check
                if severity_q != "ALL":
                    # Logs format contains level e.g. "[INFO]", "[ERROR]"
                    if f"[{severity_q}]" not in line:
                        continue

                filtered.append(line.replace("<", "&lt;").replace(">", "&gt;"))

            if not filtered:
                self.browser.setHtml("<span style='color:#4A6080;'>No log matching filter criteria.</span>")
            else:
                self.browser.setHtml(f"<pre style='margin: 0; white-space: pre-wrap;'>{''.join(filtered)}</pre>")
                
                # Auto scroll to bottom
                self.browser.verticalScrollBar().setValue(
                    self.browser.verticalScrollBar().maximum()
                )
        except Exception as exc:
            self.browser.setText(f"ERROR reading logs: {exc}")

    def _clear_logs(self) -> None:
        domain = self.log_combo.currentText()
        path = self._log_mapping.get(domain)
        if not path or not os.path.exists(path):
            return

        ret = QMessageBox.question(
            self, "Clear Log File?",
            f"Are you sure you want to truncate the log file for '{domain}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if ret == QMessageBox.Yes:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.truncate(0)
                self._load_log_file()
            except Exception as exc:
                QMessageBox.critical(self, "Write Error", f"Could not clear logs: {exc}")

    def _open_folder(self) -> None:
        log_dir = os.path.abspath("logs")
        if os.path.exists(log_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(log_dir))
        else:
            QMessageBox.warning(self, "Directory Missing", "Logs directory not initialized yet.")

    def _export_logs(self) -> None:
        domain = self.log_combo.currentText()
        path = self._log_mapping.get(domain)
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Empty Log File", "No log file found to export.")
            return

        dest, _ = QFileDialog.getSaveFileName(
            self, "Export Log File",
            f"export_{os.path.basename(path)}.txt",
            "Text Files (*.txt);;Log Files (*.log)"
        )
        if dest:
            try:
                import shutil
                shutil.copy2(path, dest)
                QMessageBox.information(self, "Export Successful", f"Log successfully saved to {dest}")
            except Exception as exc:
                QMessageBox.critical(self, "Export Error", f"Could not export file: {exc}")
