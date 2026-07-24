import logging
import requests
from enum import Enum
from app.config.models import OllamaConfig

logger = logging.getLogger("OllamaHealth")

class OllamaStatus(Enum):
    RUNNING = "RUNNING"
    NOT_RUNNING = "NOT_RUNNING"
    UNREACHABLE = "UNREACHABLE"

class OllamaHealthChecker:
    """Checks the status of the local Ollama service without attempting to launch it."""
    
    def __init__(self, config: OllamaConfig) -> None:
        self.config = config
        self.url = f"http://{config.host}:{config.port}/api/tags"
        
    def check_health(self) -> OllamaStatus:
        """Passive health check: verify if the local Ollama API endpoint is responsive."""
        logger.info(f"Checking Ollama health at {self.url}...")
        try:
            response = requests.get(self.url, timeout=self.config.timeout_seconds)
            if response.status_code == 200:
                logger.info("Ollama local service is running and responsive.")
                return OllamaStatus.RUNNING
            else:
                logger.warning(f"Ollama returned unexpected status code: {response.status_code}")
                return OllamaStatus.NOT_RUNNING
        except requests.exceptions.ConnectionError:
            logger.warning("Connection refused. Ollama is likely not running on localhost.")
            return OllamaStatus.NOT_RUNNING
        except requests.exceptions.Timeout:
            logger.warning("Ollama connection timed out.")
            return OllamaStatus.UNREACHABLE
        except Exception as e:
            logger.error(f"Unexpected error checking Ollama status: {e}")
            return OllamaStatus.UNREACHABLE
