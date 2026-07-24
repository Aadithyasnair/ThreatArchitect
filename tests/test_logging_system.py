import os
import pytest
import logging
from app.utils.logging_manager import LoggingManager


def test_logging_partitioning():
    """Verify logger separates logs into correct domain log files."""
    # Ensure logs exist/init
    LoggingManager(log_level="INFO")

    logger_net = logging.getLogger("Simulation")
    logger_ai = logging.getLogger("OllamaClient")
    logger_threat = logging.getLogger("ThreatModelingEngine")

    # Clear previous logs if they exist to start fresh
    for filename in ["networking.log", "ai.log", "threat_detection.log"]:
        path = os.path.join("logs", filename)
        if os.path.exists(path):
            try:
                open(path, "w").close()
            except Exception:
                pass

    logger_net.info("LOGGING_TEST_NET_PACKET")
    logger_ai.info("LOGGING_TEST_AI_REMEDIATION")
    logger_threat.info("LOGGING_TEST_THREAT_SIGNATURE")

    # Verify matching file contents
    assert os.path.exists("logs/networking.log")
    with open("logs/networking.log", "r", encoding="utf-8") as f:
        content_net = f.read()
        assert "LOGGING_TEST_NET_PACKET" in content_net
        assert "LOGGING_TEST_AI_REMEDIATION" not in content_net

    assert os.path.exists("logs/ai.log")
    with open("logs/ai.log", "r", encoding="utf-8") as f:
        content_ai = f.read()
        assert "LOGGING_TEST_AI_REMEDIATION" in content_ai
        assert "LOGGING_TEST_NET_PACKET" not in content_ai

    assert os.path.exists("logs/threat_detection.log")
    with open("logs/threat_detection.log", "r", encoding="utf-8") as f:
        content_threat = f.read()
        assert "LOGGING_TEST_THREAT_SIGNATURE" in content_threat
