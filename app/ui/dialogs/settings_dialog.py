from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QMessageBox
from PySide6.QtCore import Qt
from app.config.loader import ConfigLoader
from app.config.models import AppConfig, ThemeConfig, OllamaConfig, NetworkConfig, LoggingConfig, DatabaseConfig, ThresholdConfig

class SettingsDialog(QDialog):
    """Tabbed dialog for managing local application settings (saves to settings.yaml)."""
    
    def __init__(self, current_config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = current_config
        self.setWindowTitle("ThreatArchitect Configurations")
        self.resize(500, 400)
        self._init_ui()
        self._load_values()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # General/Theme Tab
        self.tab_general = QWidget()
        gen_lay = QVBoxLayout(self.tab_general)
        
        gen_lay.addWidget(QLabel("Theme Active:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark", "light"])
        gen_lay.addWidget(self.theme_combo)
        
        gen_lay.addWidget(QLabel("Database Path:"))
        self.db_path_input = QLineEdit()
        gen_lay.addWidget(self.db_path_input)
        
        gen_lay.addStretch()
        self.tabs.addTab(self.tab_general, "General & Theme")
        
        # Ollama Tab
        self.tab_ollama = QWidget()
        oll_lay = QVBoxLayout(self.tab_ollama)
        
        oll_lay.addWidget(QLabel("Ollama API Host:"))
        self.ollama_host = QLineEdit()
        oll_lay.addWidget(self.ollama_host)
        
        oll_lay.addWidget(QLabel("Ollama Port:"))
        self.ollama_port = QLineEdit()
        oll_lay.addWidget(self.ollama_port)
        
        oll_lay.addWidget(QLabel("Ollama Local Model Name:"))
        self.ollama_model = QLineEdit()
        oll_lay.addWidget(self.ollama_model)
        
        oll_lay.addStretch()
        self.tabs.addTab(self.tab_ollama, "Ollama LLM")
        
        # Network Emulation Tab
        self.tab_network = QWidget()
        net_lay = QVBoxLayout(self.tab_network)
        
        net_lay.addWidget(QLabel("Capture Network Interface:"))
        self.net_iface = QLineEdit()
        net_lay.addWidget(self.net_iface)
        
        net_lay.addWidget(QLabel("Mininet Controller IP:"))
        self.net_ip = QLineEdit()
        net_lay.addWidget(self.net_ip)
        
        net_lay.addWidget(QLabel("Mininet Controller Port:"))
        self.net_port = QLineEdit()
        net_lay.addWidget(self.net_port)
        
        net_lay.addStretch()
        self.tabs.addTab(self.tab_network, "Network Engine")
        
        # Logging Tab
        self.tab_logging = QWidget()
        log_lay = QVBoxLayout(self.tab_logging)
        
        log_lay.addWidget(QLabel("System Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        log_lay.addWidget(self.log_level_combo)
        
        log_lay.addWidget(QLabel("Log File Path:"))
        self.log_file_input = QLineEdit()
        log_lay.addWidget(self.log_file_input)
        
        log_lay.addStretch()
        self.tabs.addTab(self.tab_logging, "Logging System")
        
        layout.addWidget(self.tabs)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.clicked.connect(self._on_save_clicked)
        btn_layout.addWidget(self.save_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(btn_layout)

    def _load_values(self) -> None:
        """Populate settings widgets with current loaded configurations."""
        # General
        self.theme_combo.setCurrentText(self.config.theme.active)
        self.db_path_input.setText(self.config.database.db_path)
        
        # Ollama
        self.ollama_host.setText(self.config.ollama.host)
        self.ollama_port.setText(str(self.config.ollama.port))
        self.ollama_model.setText(self.config.ollama.model)
        
        # Network
        self.net_iface.setText(self.config.network.capture_interface)
        self.net_ip.setText(self.config.network.mininet_ip)
        self.net_port.setText(str(self.config.network.mininet_port))
        
        # Logging
        self.log_level_combo.setCurrentText(self.config.logging.level)
        self.log_file_input.setText(self.config.logging.file_path)

    def _on_save_clicked(self) -> None:
        """Validate, map, save, and overwrite configurations."""
        try:
            # Build new AppConfig object
            new_theme = ThemeConfig(
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
            new_ollama = OllamaConfig(
                host=self.ollama_host.text().strip(),
                port=int(self.ollama_port.text().strip()),
                model=self.ollama_model.text().strip(),
                timeout_seconds=self.config.ollama.timeout_seconds
            )
            new_network = NetworkConfig(
                animation_speed=self.config.network.animation_speed,
                capture_interface=self.net_iface.text().strip(),
                mininet_ip=self.net_ip.text().strip(),
                mininet_port=int(self.net_port.text().strip())
            )
            new_logging = LoggingConfig(
                level=self.log_level_combo.currentText(),
                file_path=self.log_file_input.text().strip()
            )
            new_db = DatabaseConfig(
                db_path=self.db_path_input.text().strip()
            )
            
            updated_config = AppConfig(
                theme=new_theme,
                ollama=new_ollama,
                network=new_network,
                logging=new_logging,
                database=new_db,
                thresholds=self.config.thresholds
            )
            
            # Save settings.yaml
            ConfigLoader.save(updated_config)
            self.config = updated_config # Cache updated configuration state
            
            QMessageBox.information(
                self,
                "Settings Saved",
                "Application configuration updated. Some properties may require restart to apply fully."
            )
            self.accept()
        except ValueError as ve:
            QMessageBox.critical(self, "Invalid Inputs", f"Please check integer format for ports: {ve}")
        except Exception as e:
            QMessageBox.critical(self, "Error Saving Settings", f"Failed to persist configuration to YAML: {e}")
