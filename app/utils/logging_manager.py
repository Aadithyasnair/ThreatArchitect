import logging
import sys
from pathlib import Path
from typing import Optional
from app.utils.log_handler import UILogHandler

class LoggingManager:
    """Manages system-wide logging. Integrates UI stream handler."""
    
    _instance: Optional['LoggingManager'] = None
    _ui_handler: Optional[UILogHandler] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, log_level: str = "INFO", file_path: Optional[str] = None) -> None:
        # Avoid re-initialization if already initialized
        if hasattr(self, "_initialized"):
            return
            
        self._initialized = True
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Configure root logger
        self.root_logger = logging.getLogger()
        self.root_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        self.root_logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] (%(name)s:%(funcName)s:%(lineno)d) - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Console handler — force UTF-8 so Unicode chars (→, ✔, etc.) never
        # crash on Windows cp1252 terminals.
        import io
        utf8_stdout = io.TextIOWrapper(
            sys.stdout.buffer,
            encoding="utf-8",
            errors="replace",
            line_buffering=True,
        ) if hasattr(sys.stdout, "buffer") else sys.stdout

        console_handler = logging.StreamHandler(utf8_stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(self.log_level)
        self.root_logger.addHandler(console_handler)
        
        # Rotating partitioned File Handlers
        import os
        from logging.handlers import RotatingFileHandler
        
        os.makedirs("logs", exist_ok=True)
        
        def make_rotating_handler(filename: str, handler_level) -> RotatingFileHandler:
            h = RotatingFileHandler(
                os.path.join("logs", filename),
                maxBytes=5 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8"
            )
            h.setFormatter(formatter)
            h.setLevel(handler_level)
            return h

        # 1. Error logs (global errors)
        err_handler = make_rotating_handler("errors.log", logging.ERROR)
        self.root_logger.addHandler(err_handler)

        # 2. Application logs (fallback write)
        app_handler = make_rotating_handler("application.log", self.log_level)
        self.root_logger.addHandler(app_handler)

        # 3. Domain Specific loggers
        # Networking
        net_handler = make_rotating_handler("networking.log", self.log_level)
        for nl_name in ["Simulation", "NetworkManager", "TopologyScene"]:
            nl = logging.getLogger(nl_name)
            nl.addHandler(net_handler)

        # AI
        ai_handler = make_rotating_handler("ai.log", self.log_level)
        for al_name in ["OllamaClient", "RemediationWidget", "Workers"]:
            al = logging.getLogger(al_name)
            al.addHandler(ai_handler)

        # Threat Detection
        threat_handler = make_rotating_handler("threat_detection.log", self.log_level)
        for tl_name in ["ThreatModelingEngine", "RuleEngine"]:
            tl = logging.getLogger(tl_name)
            tl.addHandler(threat_handler)

        # Compliance
        comp_handler = make_rotating_handler("compliance.log", self.log_level)
        logging.getLogger("Compliance").addHandler(comp_handler)
            
        # UI Handler
        self.__class__._ui_handler = UILogHandler()
        self.__class__._ui_handler.setFormatter(formatter)
        self.__class__._ui_handler.setLevel(self.log_level)
        self.root_logger.addHandler(self.__class__._ui_handler)

    @classmethod
    def get_ui_handler(cls) -> UILogHandler:
        """Retrieve the active UILogHandler for Qt UI subscriptions."""
        if cls._ui_handler is None:
            # Fallback if LoggingManager is not yet instantiated
            cls._ui_handler = UILogHandler()
        return cls._ui_handler
