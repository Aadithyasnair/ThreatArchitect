"""
app.ui.widgets.diagnostics_window — Diagnostic verification sequence widget.

Validates core environment parameters before launching the main window.
Displays progressive status checks with PASS/WARNING/FAIL badges.
"""

from __future__ import annotations

import os
import sys
import logging
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QPushButton, QFrame
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

logger = logging.getLogger("Diagnostics")


class DiagnosticsWindow(QDialog):
    """
    Diagnostics startup sequence checks validation dashboard.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("ThreatArchitect Diagnostics HUD")
        self.resize(480, 360)
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint)
        self.setStyleSheet("background-color: #0B1220; color: #F8FAFC;")

        self._check_index = 0
        self._results: list[tuple[str, str, str]] = [] # (label, status, details)

        self._steps = [
            ("Python Runtime Version Check", self._check_python_version),
            ("Core Package Dependencies Check", self._check_packages),
            ("Database Schema & Connection", self._check_database),
            ("Configuration Settings YAML Validity", self._check_config),
            ("Ollama Local Endpoint Reachability", self._check_ollama),
            ("Llama Model Registration check", self._check_llama_model),
            ("Report & Logs Directory Permissions", self._check_write_permissions)
        ]

        self._init_ui()
        # Start diagnostic sequence after delay
        QTimer.singleShot(500, self._run_next_check)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # Header Title
        title_lbl = QLabel("SYSTEM BOOT DIAGNOSTICS")
        title_lbl.setFont(QFont("Consolas", 11, QFont.Bold))
        title_lbl.setStyleSheet("color: #00D2FF; letter-spacing: 1px;")
        layout.addWidget(title_lbl)

        sub_lbl = QLabel("Performing environment security checks before starting main console...")
        sub_lbl.setFont(QFont("Consolas", 8))
        sub_lbl.setStyleSheet("color: #4A6080;")
        layout.addWidget(sub_lbl)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background-color: #1E2D45; max-height: 1px; border: none;")
        layout.addWidget(sep)

        # Container for check rows
        self.rows_container = QFrame()
        self.rows_layout = QVBoxLayout(self.rows_container)
        self.rows_layout.setContentsMargins(0, 4, 0, 4)
        self.rows_layout.setSpacing(6)

        self.scroll_frame = QFrame()
        layout.addWidget(self.scroll_frame)
        self.scroll_frame.setLayout(self.rows_layout)

        # Spacer to push progress down
        layout.addStretch()

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, len(self._steps))
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #151E2F;
                border: 1px solid #2A364F;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #00D2FF;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Bottom actions
        self.actions_layout = QHBoxLayout()
        self.status_lbl = QLabel("Initializing validator...")
        self.status_lbl.setFont(QFont("Consolas", 8))
        self.status_lbl.setStyleSheet("color: #E2E8F0;")
        self.actions_layout.addWidget(self.status_lbl)
        
        self.actions_layout.addStretch()

        self.launch_btn = QPushButton("LAUNCH SYSTEM")
        self.launch_btn.setFont(QFont("Consolas", 8, QFont.Bold))
        self.launch_btn.setFixedWidth(120)
        self.launch_btn.setFixedHeight(26)
        self.launch_btn.setEnabled(False)
        self.launch_btn.clicked.connect(self.accept)
        self.launch_btn.setStyleSheet("""
            QPushButton {
                background-color: #151E2F;
                color: #4A6080;
                border: 1px solid #2A364F;
                border-radius: 3px;
            }
            QPushButton:enabled {
                background-color: #00D2FF;
                color: #0B1220;
                border: none;
            }
            QPushButton:enabled:hover {
                background-color: #38BDF8;
            }
        """)
        self.actions_layout.addWidget(self.launch_btn)
        layout.addLayout(self.actions_layout)

    def _run_next_check(self) -> None:
        if self._check_index >= len(self._steps):
            self._finalize_diagnostics()
            return

        label, check_func = self._steps[self._check_index]
        self.status_lbl.setText(f"Running: {label}...")
        
        # Execute diagnostic check
        status, details = check_func()
        self._results.append((label, status, details))

        # Add row to interface
        self._add_row_ui(label, status, details)

        self._check_index += 1
        self.progress_bar.setValue(self._check_index)

        # Trigger next check after animation delay
        QTimer.singleShot(150, self._run_next_check)

    def _add_row_ui(self, label: str, status: str, details: str) -> None:
        row = QFrame()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(6, 4, 6, 4)
        row_layout.setSpacing(8)

        lbl = QLabel(label)
        lbl.setFont(QFont("Consolas", 8))
        lbl.setStyleSheet("color: #E2E8F0;")
        row_layout.addWidget(lbl)

        det_lbl = QLabel(f"({details})")
        det_lbl.setFont(QFont("Consolas", 7))
        det_lbl.setStyleSheet("color: #4A6080;")
        row_layout.addWidget(det_lbl, 1)

        badge = QLabel(status)
        badge.setFont(QFont("Consolas", 7, QFont.Bold))
        badge.setAlignment(Qt.AlignCenter)
        badge.setFixedWidth(54)
        badge.setFixedHeight(16)

        if status == "PASS":
            badge.setStyleSheet("background-color: #10B981; color: #0B1220; border-radius: 2px;")
        elif status == "WARNING":
            badge.setStyleSheet("background-color: #F59E0B; color: #0B1220; border-radius: 2px;")
        else:
            badge.setStyleSheet("background-color: #EF4444; color: #F8FAFC; border-radius: 2px;")

        row_layout.addWidget(badge)
        self.rows_layout.addWidget(row)

    def _finalize_diagnostics(self) -> None:
        """Processes validation results to decide on boot or warning lock."""
        failures = [lbl for lbl, status, _ in self._results if status == "FAIL"]
        
        if failures:
            self.status_lbl.setText("Critical checks failed. Resolve configuration errors.")
            self.status_lbl.setStyleSheet("color: #EF4444; font-weight: bold;")
            
            # Change launch button to close button
            self.launch_btn.setText("EXIT BOOT")
            self.launch_btn.setEnabled(True)
            self.launch_btn.clicked.disconnect()
            self.launch_btn.clicked.connect(self.reject)
            self.launch_btn.setStyleSheet("""
                QPushButton {
                    background-color: #EF4444;
                    color: #F8FAFC;
                    border: none;
                    border-radius: 3px;
                }
            """)
        else:
            warnings = [lbl for lbl, status, _ in self._results if status == "WARNING"]
            if warnings:
                self.status_lbl.setText("Boot ready (degraded performance).")
                self.status_lbl.setStyleSheet("color: #F59E0B;")
            else:
                self.status_lbl.setText("All checks passed successfully.")
                self.status_lbl.setStyleSheet("color: #10B981;")

            self.launch_btn.setEnabled(True)
            # Auto-accept after 1 second if no warnings/failures
            if not warnings:
                QTimer.singleShot(800, self.accept)

    # ── Diagnostic check implementations ─────────────────────────────────────

    def _check_python_version(self) -> tuple[str, str]:
        v = sys.version_info
        details = f"v{v.major}.{v.minor}.{v.micro}"
        if v.major == 3 and v.minor >= 8:
            return "PASS", details
        return "FAIL", f"Required: Python 3.8+, Found: {details}"

    def _check_packages(self) -> tuple[str, str]:
        missing = []
        packages = ["PySide6", "reportlab", "sklearn", "yaml"]
        for p in packages:
            try:
                __import__(p)
            except (ImportError, OSError):
                missing.append(p)

        if not missing:
            return "PASS", "All packages verified"
        return "FAIL", f"Missing packages: {', '.join(missing)}"

    def _check_database(self) -> tuple[str, str]:
        try:
            from app.config.loader import ConfigLoader
            db_path = ConfigLoader.load().database.db_path
            
            import sqlite3
            conn = sqlite3.connect(db_path, timeout=1.0)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return "PASS", f"Connected to {os.path.basename(db_path)}"
        except Exception as exc:
            return "FAIL", f"SQL Error: {exc}"

    def _check_config(self) -> tuple[str, str]:
        try:
            from app.config.loader import ConfigLoader
            config = ConfigLoader.load(force_reload=True)
            return "PASS", "settings.yaml valid"
        except Exception as exc:
            return "FAIL", f"YAML Error: {exc}"

    def _check_ollama(self) -> tuple[str, str]:
        try:
            from app.ai.ollama.client import OllamaClient
            client = OllamaClient()
            if client.is_available():
                return "PASS", "Service active"
            return "WARNING", "Ollama unreachable"
        except Exception:
            return "WARNING", "Ollama unreachable"

    def _check_llama_model(self) -> tuple[str, str]:
        try:
            from app.ai.ollama.client import OllamaClient
            client = OllamaClient()
            if not client.is_available():
                return "WARNING", "Ollama offline"
                
            model_name = client.config.model
            # tags check
            import requests
            response = requests.get(f"{client.base_url}/api/tags", timeout=1.0)
            if response.status_code == 200:
                models = [m.get("name") for m in response.json().get("models", [])]
                if any(model_name in m for m in models):
                    return "PASS", f"{model_name} loaded"
                return "WARNING", f"Model '{model_name}' missing"
            return "WARNING", "Tags check failed"
        except Exception:
            return "WARNING", "Registry check skipped"

    def _check_write_permissions(self) -> tuple[str, str]:
        try:
            from app.config.loader import ConfigLoader
            config = ConfigLoader.load()
            
            # Check log folder write access
            log_dir = os.path.dirname(config.logging.file_path) or "."
            os.makedirs(log_dir, exist_ok=True)
            log_test = os.path.join(log_dir, ".test_perm")
            with open(log_test, "w") as f:
                f.write("test")
            os.remove(log_test)

            # Check report folder write access
            os.makedirs("reports", exist_ok=True)
            report_test = os.path.join("reports", ".test_perm")
            with open(report_test, "w") as f:
                f.write("test")
            os.remove(report_test)

            return "PASS", "Log & reports folders writable"
        except Exception as exc:
            return "FAIL", f"Permission error: {exc}"
