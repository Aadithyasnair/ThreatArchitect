"""
app.ai.ollama.remediation_engine — Orchestrates AI threat mitigation analysis.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

from app.ai.ollama.client import OllamaClient
from app.ai.ollama.prompt_builder import PromptBuilder
from app.ai.ollama.response_parser import ResponseParser, RemediationReport

logger = logging.getLogger("RemediationEngine")


class RemediationEngine:
    """
    Triggers local LLM queries to produce parsed incident remediation reports.
    """

    def __init__(self, client: Optional[OllamaClient] = None) -> None:
        self.client = client or OllamaClient()

    def generate_remediation(self, context: Dict[str, Any]) -> RemediationReport:
        """
        Assembles structured prompt, queries Ollama, and parses the response.
        """
        if not self.client.is_available():
            logger.warning("RemediationEngine aborted: Ollama service is unreachable.")
            return RemediationReport(
                threat_summary="Local AI Service (Ollama) is offline.",
                reasoning="Ensure Ollama is running and Llama 3.2 model is pulled."
            )

        prompt = PromptBuilder.build_remediation_prompt(context)
        system_prompt = PromptBuilder.SYSTEM_INSTRUCTIONS

        raw_response = self.client.query(prompt, system_prompt=system_prompt, format_json=True)
        if not raw_response:
            return RemediationReport(
                threat_summary="Local AI returned no response or timed out.",
                reasoning="The model failed to execute inference. Check local server resources."
            )

        return ResponseParser.parse_response(raw_response)
