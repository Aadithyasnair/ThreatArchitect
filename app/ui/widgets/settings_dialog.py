"""
app.ui.widgets.settings_dialog — Dynamic Settings Configuration Editor.

Provides visual form components to edit application thresholds, speeds, theme,
and Ollama models tags. Saves to settings.yaml and notifies MainWindow to hot-reload.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QDoubleSpinBox, QSpinBox, QPushButton, QFrame, QFormLayout
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from app.config.loader import ConfigLoader
from app.config.models import (
    AppConfig, ThemeConfig, OllamaConfig, NetworkConfig,
    LoggingConfig, DatabaseConfig, ThresholdConfig, SimulationConfig,
    DetectionConfig
)

logger = logging.getLogger("SettingsDialog")


class SettingsDialog(QDialog):
    """
    Settings Editor Modal Dialog for ThreatArchitect configuration hot-reloads.
    """
    settings_changed = Signal(object)  # Emits new AppConfig copy

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("System Settings Configuration")
        self.resize(440, 480)
        self.setStyleSheet("background-color: #0B1220; color: #F8FAFC;")
        
        self.config = ConfigLoader.load()
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Title
        title = QLabel("SYSTEM CONFIGURATION EDITOR")
        title.setFont(QFont("Consolas", 10, QFont.Bold))
        title.setStyleSheet("color: #00D2FF;")
        layout.addWidget(title)

        form_frame = QFrame()
        form_frame.setStyleSheet("background-color: #151E2F; border: 1px solid #2A364F; border-radius: 4px;")
        form_layout = QFormLayout(form_frame)
        form_layout.setContentsMargins(10, 10, 10, 10)
        form_layout.setSpacing(8)

        # 1. Theme Selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark", "light"])
        self.theme_combo.setCurrentText(self.config.theme.active)
        self._style_widget(self.theme_combo)
        form_layout.addRow(self._make_label("Active UI Theme:"), self.theme_combo)

        # 2. Packet Speed
        self.packet_speed_spin = QSpinBox()
        self.packet_speed_spin.setRange(200, 5000)
        self.packet_speed_spin.setSingleStep(100)
        self.packet_speed_spin.setSuffix(" ms")
        self.packet_speed_spin.setValue(self.config.simulation.packet_speed_ms)
        self._style_widget(self.packet_speed_spin)
        form_layout.addRow(self._make_label("Packet Speed Rate:"), self.packet_speed_spin)

        # 3. Animation Speed Multiplier
        self.anim_speed_spin = QDoubleSpinBox()
        self.anim_speed_spin.setRange(0.1, 4.0)
        self.anim_speed_spin.setSingleStep(0.1)
        self.anim_speed_spin.setSuffix(" x")
        self.anim_speed_spin.setValue(self.config.network.animation_speed)
        self._style_widget(self.anim_speed_spin)
        form_layout.addRow(self._make_label("Animation Speed:"), self.anim_speed_spin)

        # 4. Topology selection
        self.top_combo = QComboBox()
        self.top_combo.addItems(["enterprise_default", "datacenter_spine", "custom_workstation"])
        self.top_combo.setCurrentText(self.config.simulation.default_topology)
        self._style_widget(self.top_combo)
        form_layout.addRow(self._make_label("Default Topology:"), self.top_combo)

        # 5. LSTM Anomaly Threshold
        self.lstm_spin = QDoubleSpinBox()
        self.lstm_spin.setRange(0.05, 1.0)
        self.lstm_spin.setSingleStep(0.05)
        self.lstm_spin.setValue(self.config.detection.anomaly_threshold)
        self._style_widget(self.lstm_spin)
        form_layout.addRow(self._make_label("LSTM Anomaly Limit:"), self.lstm_spin)

        # 6. Classifier Confidence limit
        self.classifier_spin = QDoubleSpinBox()
        self.classifier_spin.setRange(0.05, 1.0)
        self.classifier_spin.setSingleStep(0.05)
        self.classifier_spin.setValue(self.config.thresholds.classifier_confidence_limit)
        self._style_widget(self.classifier_spin)
        form_layout.addRow(self._make_label("Classifier Confidence limit:"), self.classifier_spin)

        # 7. Ollama Model Tags name
        self.model_input = QLineEdit()
        self.model_input.setText(self.config.ollama.model)
        self._style_widget(self.model_input)
        form_layout.addRow(self._make_label("Ollama Model Tag:"), self.model_input)

        # 8. Logging severity level
        self.log_combo = QComboBox()
        self.log_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_combo.setCurrentText(self.config.logging.level)
        self._style_widget(self.log_combo)
        form_layout.addRow(self._make_label("System Log Severity:"), self.log_combo)

        # 9. Database Path
        self.db_path_input = QLineEdit()
        self.db_path_input.setText(self.config.database.db_path)
        self._style_widget(self.db_path_input)
        form_layout.addRow(self._make_label("Database Path:"), self.db_path_input)

        layout.addWidget(form_frame)

        # Actions buttons
        actions = QHBoxLayout()
        actions.setSpacing(10)
        
        actions.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFont(QFont("Consolas", 8, QFont.Bold))
        cancel_btn.setFixedSize(70, 24)
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
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
        actions.addWidget(cancel_btn)

        save_btn = QPushButton("Save Settings")
        save_btn.setFont(QFont("Consolas", 8, QFont.Bold))
        save_btn.setFixedSize(110, 24)
        save_btn.clicked.connect(self._save_settings)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #00D2FF;
                color: #0B1220;
                border: none;
                border-radius: 2px;
            }
            QPushButton:hover {
                background-color: #38BDF8;
            }
        """)
        actions.addWidget(save_btn)

        layout.addLayout(actions)

    def _make_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setFont(QFont("Consolas", 8, QFont.Bold))
        lbl.setStyleSheet("color: #A9B2C3; border: none; background: transparent;")
        return lbl

    def _style_widget(self, w) -> None:
        w.setFont(QFont("Consolas", 8))
        w.setStyleSheet("""
            QWidget {
                background-color: #0B1220;
                color: #F8FAFC;
                border: 1px solid #2A364F;
                border-radius: 2px;
                padding: 2px;
            }
        """)

    def _save_settings(self) -> None:
        """Create new config structures, save to YAML, and emit signal."""
        try:
            # Build structures maintaining visual palette values
            theme_config = ThemeConfig(
                active=self.theme_combo.currentText(),
                background=self.config.theme.background,
                surface=self.config.theme.surface,
                primary_accent=self.config.theme.primary_accent,
                green=self.config.theme.green,
                yellow=self.config.theme.yellow,
                red=self.config.theme.red,
                text=self.config.theme.text,
                border=self.config.theme.border,
                hover=self.config.theme.hover
            )

            ollama_config = OllamaConfig(
                host=self.config.ollama.host,
                port=self.config.ollama.port,
                model=self.model_input.text(),
                timeout_seconds=self.config.ollama.timeout_seconds
            )

            network_config = NetworkConfig(
                animation_speed=self.anim_speed_spin.value(),
                capture_interface=self.config.network.capture_interface,
                mininet_ip=self.config.network.mininet_ip,
                mininet_port=self.config.network.mininet_port
            )

            logging_config = LoggingConfig(
                level=self.log_combo.currentText(),
                file_path=self.config.logging.file_path
            )

            database_config = DatabaseConfig(
                db_path=self.db_path_input.text()
            )

            threshold_config = ThresholdConfig(
                anomaly_score_limit=self.config.thresholds.anomaly_score_limit,
                classifier_confidence_limit=self.classifier_spin.value()
            )

            simulation_config = SimulationConfig(
                packet_speed_ms=self.packet_speed_spin.value(),
                animation_duration_ms=self.config.simulation.animation_duration_ms,
                refresh_interval_ms=self.config.simulation.refresh_interval_ms,
                default_topology=self.top_combo.currentText()
            )

            detection_config = DetectionConfig(
                window_size_seconds=self.config.detection.window_size_seconds,
                stride_seconds=self.config.detection.stride_seconds,
                anomaly_threshold=self.lstm_spin.value(),
                model_dir=self.config.detection.model_dir
            )

            new_config = AppConfig(
                theme=theme_config,
                ollama=ollama_config,
                network=network_config,
                logging=logging_config,
                database=database_config,
                thresholds=threshold_config,
                simulation=simulation_config,
                detection=detection_config
            )

            # Write file changes
            ConfigLoader.save(new_config)
            
            # Emit changes custom signal
            self.settings_changed.emit(new_config)
            logger.info("Configuration successfully written and cached.")
            self.accept()
        except Exception as exc:
            logger.error(f"Failed to compile configurations: {exc}", exc_info=True)
            self.reject()
