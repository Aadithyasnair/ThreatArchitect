import sys
import logging
from pathlib import Path
from PySide6.QtWidgets import QApplication
from app.config.loader import ConfigLoader
from app.utils.logging_manager import LoggingManager
from app.database.connection import DatabaseConnection
from app.container import ServiceContainer
from app.core.interfaces import ILLMClient
from app.ai.ollama.client import OllamaClient
from app.ui.themes.loader import ThemeLoader
from app.ui.main_window import MainWindow
from app.network.manager import NetworkManager

logger = logging.getLogger("Bootstrap")

class ApplicationBootstrap:
    """Orchestrates sequential startup of configuration, logging, database, DI and MainWindow."""
    
    @classmethod
    def start_application(cls) -> MainWindow:
        logger.info("Initializing ThreatArchitect bootstrap sequence...")
        
        # Launch diagnostics check if not running unit tests
        if "pytest" not in sys.modules:
            from PySide6.QtWidgets import QDialog
            from app.ui.widgets.diagnostics_window import DiagnosticsWindow
            diag = DiagnosticsWindow()
            if diag.exec() != QDialog.Accepted:
                sys.exit(0)

        # 1. Load configuration
        try:
            config = ConfigLoader.load()
        except FileNotFoundError:
            # Fallback/Write default config if settings.yaml does not exist
            logger.warning("Configuration settings.yaml not found. Generating default settings.")
            # Default loading will create setting defaults
            config = ConfigLoader.from_dict({})
            ConfigLoader.save(config)
            
        # 2. Setup system-wide structured logging
        LoggingManager(
            log_level=config.logging.level,
            file_path=config.logging.file_path
        )
        
        logger.info("Configuration loaded. Logging manager initialized.")
        
        # 3. Setup local database
        db_conn = DatabaseConnection(config.database.db_path)
        # Establish connection to check/run table migrations immediately
        db_conn.connect()
        
        # 4. Wire Dependency Injection container
        container = ServiceContainer()
        container.register(DatabaseConnection, db_conn)
        
        # Register Ollama LLM client implementation
        ollama_client = OllamaClient(config.ollama)
        container.register(ILLMClient, ollama_client)
        
        # 5. Apply selected visual theme styles to QApplication
        app = QApplication.instance()
        if app is None:
            # Create QApplication if it does not exist (useful for testing stubs)
            app = QApplication(sys.argv)
            
        ThemeLoader.apply(app, config)
        
        # 6. Build and show main dashboard window
        logger.info("Building MainWindow dashboard...")
        network_manager = NetworkManager()
        main_window = MainWindow(config, network_manager=network_manager)
        main_window.show()
        
        logger.info("ThreatArchitect bootstrap sequence complete.")
        return main_window
