import pytest
import os
from pathlib import Path
from app.config.loader import ConfigLoader
from app.ai.ollama.health import OllamaHealthChecker, OllamaStatus
from app.config.models import OllamaConfig

def test_config_loader_default():
    """Verify config loader loads and populates default fields."""
    config = ConfigLoader.from_dict({})
    assert config.theme.active == "dark"
    assert config.ollama.port == 11434
    assert config.logging.level == "INFO"

def test_ollama_health_offline():
    """Verify health checker handles unreachable endpoint correctly."""
    config = OllamaConfig(
        host="localhost",
        port=99999, # invalid port
        model="llama3.2",
        timeout_seconds=0.1
    )
    checker = OllamaHealthChecker(config)
    status = checker.check_health()
    assert status == OllamaStatus.UNREACHABLE or status == OllamaStatus.NOT_RUNNING
