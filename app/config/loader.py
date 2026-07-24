import os
import yaml
from pathlib import Path
from typing import Any, Dict
from app.config.models import (
    AppConfig,
    ThemeConfig,
    OllamaConfig,
    NetworkConfig,
    LoggingConfig,
    DatabaseConfig,
    ThresholdConfig,
    SimulationConfig,
    DetectionConfig,
)

class ConfigLoader:
    """Loader to parse settings.yaml and instantiate AppConfig."""
    _cached_config: AppConfig | None = None
    
    @staticmethod
    def get_default_path() -> Path:
        """Get default path to settings.yaml."""
        return Path(__file__).parent / "settings.yaml"

    @classmethod
    def load(cls, path: Path = None, force_reload: bool = False) -> AppConfig:
        """Load configuration from YAML file. If path is None, use default."""
        if path is None and cls._cached_config is not None and not force_reload:
            return cls._cached_config

        if path is None:
            path = cls.get_default_path()
            
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found at {path}")
            
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            
        config = cls.from_dict(data)
        if path == cls.get_default_path():
            cls._cached_config = config
        return config

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AppConfig:
        """Convert raw dict data to type-safe AppConfig."""
        theme_data = data.get("theme", {})
        palette = theme_data.get("palette", {})
        
        theme_config = ThemeConfig(
            active=theme_data.get("active", "dark"),
            background=palette.get("background", "#0B1220"),
            surface=palette.get("surface", "#151E2F"),
            primary_accent=palette.get("primary_accent", "#4F8EF7"),
            green=palette.get("green", "#22C55E"),
            yellow=palette.get("yellow", "#FACC15"),
            red=palette.get("red", "#EF4444"),
            text=palette.get("text", "#F8FAFC"),
            border=palette.get("border", "#2A364F"),
            hover=palette.get("hover", "#1D2A44")
        )
        
        ollama_data = data.get("ollama", {})
        ollama_config = OllamaConfig(
            host=ollama_data.get("host", "localhost"),
            port=ollama_data.get("port", 11434),
            model=ollama_data.get("model", "llama3.2:latest"),
            timeout_seconds=float(ollama_data.get("timeout_seconds", 5))
        )
        
        network_data = data.get("network", {})
        network_config = NetworkConfig(
            animation_speed=float(network_data.get("animation_speed", 1.0)),
            capture_interface=network_data.get("capture_interface", "eth0"),
            mininet_ip=network_data.get("mininet_ip", "127.0.0.1"),
            mininet_port=network_data.get("mininet_port", 8000)
        )
        
        logging_data = data.get("logging", {})
        logging_config = LoggingConfig(
            level=logging_data.get("level", "INFO"),
            file_path=logging_data.get("file_path", "threat_architect.log")
        )
        
        database_data = data.get("database", {})
        database_config = DatabaseConfig(
            db_path=database_data.get("db_path", "threat_architect.db")
        )
        
        thresholds_data = data.get("thresholds", {})
        threshold_config = ThresholdConfig(
            anomaly_score_limit=float(thresholds_data.get("anomaly_score_limit", 0.85)),
            classifier_confidence_limit=float(thresholds_data.get("classifier_confidence_limit", 0.75))
        )
        
        simulation_data = data.get("simulation", {})
        simulation_config = SimulationConfig(
            packet_speed_ms=int(simulation_data.get("packet_speed_ms", 800)),
            animation_duration_ms=int(simulation_data.get("animation_duration_ms", 900)),
            refresh_interval_ms=int(simulation_data.get("refresh_interval_ms", 2000)),
            default_topology=simulation_data.get("default_topology", "enterprise_default"),
        )
        
        detection_data = data.get("detection", {})
        detection_config = DetectionConfig(
            window_size_seconds=int(detection_data.get("window_size_seconds", 10)),
            stride_seconds=int(detection_data.get("stride_seconds", 2)),
            anomaly_threshold=float(detection_data.get("anomaly_threshold", 0.65)),
            model_dir=detection_data.get("model_dir", "models"),
        )
        
        return AppConfig(
            theme=theme_config,
            ollama=ollama_config,
            network=network_config,
            logging=logging_config,
            database=database_config,
            thresholds=threshold_config,
            simulation=simulation_config,
            detection=detection_config,
        )

    @classmethod
    def save(cls, config: AppConfig, path: Path = None) -> None:
        """Save configuration back to YAML file."""
        if path is None:
            path = cls.get_default_path()
            
        data = {
            "theme": {
                "active": config.theme.active,
                "palette": {
                    "background": config.theme.background,
                    "surface": config.theme.surface,
                    "primary_accent": config.theme.primary_accent,
                    "green": config.theme.green,
                    "yellow": config.theme.yellow,
                    "red": config.theme.red,
                    "text": config.theme.text,
                    "border": config.theme.border,
                    "hover": config.theme.hover
                }
            },
            "ollama": {
                "host": config.ollama.host,
                "port": config.ollama.port,
                "model": config.ollama.model,
                "timeout_seconds": config.ollama.timeout_seconds
            },
            "network": {
                "animation_speed": config.network.animation_speed,
                "capture_interface": config.network.capture_interface,
                "mininet_ip": config.network.mininet_ip,
                "mininet_port": config.network.mininet_port
            },
            "logging": {
                "level": config.logging.level,
                "file_path": config.logging.file_path
            },
            "database": {
                "db_path": config.database.db_path
            },
            "thresholds": {
                "anomaly_score_limit": config.thresholds.anomaly_score_limit,
                "classifier_confidence_limit": config.thresholds.classifier_confidence_limit
            },
            "simulation": {
                "packet_speed_ms": config.simulation.packet_speed_ms,
                "animation_duration_ms": config.simulation.animation_duration_ms,
                "refresh_interval_ms": config.simulation.refresh_interval_ms,
                "default_topology": config.simulation.default_topology
            },
            "detection": {
                "window_size_seconds": config.detection.window_size_seconds,
                "stride_seconds": config.detection.stride_seconds,
                "anomaly_threshold": config.detection.anomaly_threshold,
                "model_dir": config.detection.model_dir
            }
        }
        
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False)

        if path == cls.get_default_path():
            cls._cached_config = config
