from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass(frozen=True)
class ThemeConfig:
    active: str
    background: str
    surface: str
    primary_accent: str
    green: str
    yellow: str
    red: str
    text: str
    border: str
    hover: str

@dataclass(frozen=True)
class OllamaConfig:
    host: str
    port: int
    model: str
    timeout_seconds: float

@dataclass(frozen=True)
class NetworkConfig:
    animation_speed: float
    capture_interface: str
    mininet_ip: str
    mininet_port: int

@dataclass(frozen=True)
class LoggingConfig:
    level: str
    file_path: str

@dataclass(frozen=True)
class DatabaseConfig:
    db_path: str

@dataclass(frozen=True)
class ThresholdConfig:
    anomaly_score_limit: float
    classifier_confidence_limit: float

@dataclass(frozen=True)
class SimulationConfig:
    """Configuration for simulation tick rate and animation parameters."""
    packet_speed_ms: int         # Milliseconds between simulated packets
    animation_duration_ms: int   # Milliseconds for packet to traverse a link
    refresh_interval_ms: int     # Dashboard stats refresh rate
    default_topology: str        # Name of default topology to load

@dataclass(frozen=True)
class DetectionConfig:
    """Configuration for AI anomaly detection and classification."""
    window_size_seconds: int
    stride_seconds: int
    anomaly_threshold: float
    model_dir: str

@dataclass(frozen=True)
class AppConfig:
    theme: ThemeConfig
    ollama: OllamaConfig
    network: NetworkConfig
    logging: LoggingConfig
    database: DatabaseConfig
    thresholds: ThresholdConfig
    simulation: SimulationConfig
    detection: DetectionConfig
