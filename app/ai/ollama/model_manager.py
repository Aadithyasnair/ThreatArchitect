"""
app.ai.ollama.model_manager — Verifies local model installation status.
"""

from __future__ import annotations

import logging
import requests
from app.config.loader import ConfigLoader

logger = logging.getLogger("OllamaModelManager")


class OllamaModelManager:
    """Manages check status for configured model on local Ollama service."""

    def __init__(self) -> None:
        self.config = ConfigLoader.load().ollama
        self.base_url = f"http://{self.config.host}:{self.config.port}"

    def check_model_loaded(self) -> bool:
        """Query tags endpoint to see if the target model is installed locally."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=1.5)
            if response.status_code != 200:
                return False
            
            data = response.json()
            models_list = data.get("models", [])
            
            # Extract names from lists
            installed_names = []
            for item in models_list:
                name = item.get("name")
                if name:
                    installed_names.append(name)
                    # Also match base name (e.g. without ':latest')
                    if ":" in name:
                        installed_names.append(name.split(":")[0])

            target = self.config.model
            # Match directly or by base name
            target_base = target.split(":")[0] if ":" in target else target

            is_loaded = target in installed_names or target_base in installed_names
            if is_loaded:
                logger.info(f"Ollama model '{target}' is verified and loaded.")
            else:
                logger.warning(f"Ollama model '{target}' is NOT present in local tags.")
            return is_loaded

        except Exception as exc:
            logger.warning(f"Failed checking model loaded status: {exc}")
            return False
