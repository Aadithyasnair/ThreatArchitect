"""
app.ai.ollama.explanation_engine — Explains the nature of cyber threats via local LLM.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

from app.ai.ollama.client import OllamaClient
from app.ai.ollama.remediation_engine import RemediationEngine
from app.ai.ollama.response_parser import RemediationReport

logger = logging.getLogger("ExplanationEngine")


class ExplanationEngine:
    """
    Translates technical security logs into explainable summaries.
    """

    def __init__(self, remediation_engine: Optional[RemediationEngine] = None) -> None:
        self._remediation = remediation_engine or RemediationEngine()

    def explain_threat(self, context: Dict[str, Any]) -> RemediationReport:
        """
        Produce a full RemediationReport containing detailed threat explanation.
        """
        return self._remediation.generate_remediation(context)
