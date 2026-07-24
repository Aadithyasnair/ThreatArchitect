"""
app.ai.ollama.client — Client connection manager for local Ollama HTTP API.

Integrates with local LLM models (e.g., Llama 3.2) to fetch structured incident remediation plans.
"""

from __future__ import annotations

import json
import logging
import requests
from typing import Optional, Dict, Any, Iterator

from app.core.interfaces import ILLMClient
from app.config.loader import ConfigLoader

logger = logging.getLogger("OllamaClient")


class OllamaNotAvailableError(Exception):
    """Exception raised when local Ollama service is not running or unreachable."""
    pass


class OllamaClient(ILLMClient):
    """
    HTTP client for querying local Ollama instances. Complies with ILLMClient.
    """

    def __init__(self, config: Optional[Any] = None) -> None:
        self.config = config or ConfigLoader.load().ollama
        self.base_url = f"http://{self.config.host}:{self.config.port}"
        self._session = requests.Session()

    def is_available(self) -> bool:
        """Verify connection to local Ollama API."""
        try:
            response = self._session.get(f"{self.base_url}/api/tags", timeout=1.5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def query_stream(self, prompt: str, system_prompt: Optional[str] = None) -> Iterator[str]:
        """
        Send a generation request to the Ollama endpoint and yield text tokens in real time.
        """
        if not self.is_available():
            logger.warning("Local AI unavailable (Ollama offline).")
            yield '{"threat_summary": "Local AI temporarily unavailable."}'
            return

        url = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": True,
            "format": "json"
        }

        if system_prompt:
            payload["system"] = system_prompt

        timeout = max(15.0, self.config.timeout_seconds)

        try:
            logger.info(f"Initiating streaming prompt query to Ollama ({self.config.model})...")
            response = self._session.post(url, json=payload, timeout=timeout, stream=True)
            if response.status_code != 200:
                logger.error(f"Ollama returned HTTP error status: {response.status_code}")
                yield '{"threat_summary": "Ollama error response."}'
                return

            for line in response.iter_lines():
                if line:
                    decoded = line.decode("utf-8")
                    data = json.loads(decoded)
                    chunk = data.get("response", "")
                    if chunk:
                        yield chunk
        except requests.Timeout:
            logger.error("Ollama streaming query timed out.")
            yield '{"threat_summary": "Ollama connection timeout."}'
        except requests.RequestException as exc:
            logger.error(f"Ollama connection error: {exc}")
            yield f'{{"threat_summary": "Ollama request error: {exc}"}}'
        except Exception as exc:
            logger.error(f"Unexpected error streaming Ollama: {exc}")
            yield f'{{"threat_summary": "Ollama unexpected error: {exc}"}}'

    def query(self, prompt: str, system_prompt: Optional[str] = None, format_json: bool = True, timeout: Optional[float] = None) -> Optional[str]:
        """
        Send a generation request to the Ollama endpoint.
        """
        if not self.is_available():
            logger.warning("Local AI unavailable (Ollama offline).")
            return None

        url = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if format_json:
            payload["format"] = "json"

        effective_timeout = timeout if timeout is not None else max(15.0, self.config.timeout_seconds)

        try:
            logger.info(f"Sending prompt query to Ollama ({self.config.model})...")
            response = requests.post(url, json=payload, timeout=effective_timeout)
            if response.status_code != 200:
                logger.error(f"Ollama returned HTTP error status: {response.status_code}")
                return None

            data = response.json()
            return data.get("response")
        except requests.Timeout:
            logger.warning(f"Ollama query timed out after {effective_timeout}s.")
            return None
        except requests.RequestException as exc:
            logger.error(f"Ollama connection error: {exc}")
            return None
        except Exception as exc:
            logger.error(f"Unexpected error querying Ollama: {exc}")
            return None

    def generate_remediation(self, threat_model: Any) -> str:
        """
        Compatibility method implementing ILLMClient.
        """
        if not self.is_available():
            raise OllamaNotAvailableError("Ollama is not running.")
            
        # Basic raw format helper
        prompt = f"Threat: {getattr(threat_model, 'attack_category', 'Unknown')}. Threat Score: {getattr(threat_model, 'threat_score', 50)}. Please provide mitigation commands."
        res = self.query(prompt, format_json=False)
        return res if res else "# [REMEDIATION] Offline remediation placeholder."
