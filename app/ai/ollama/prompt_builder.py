"""
app.ai.ollama.prompt_builder — Constructs structured prompts for local Ollama analysis.

Ensures no raw packet dump is sent to the LLM, but rather aggregated threat metadata,
MITRE techniques, and compliance check failures.
"""

from __future__ import annotations

import json
from typing import Dict, Any

class PromptBuilder:
    """
    Builder utility to synthesize structured, safety-bounded markdown/text prompts.
    """

    SYSTEM_INSTRUCTIONS = (
        "You are Antigravity-SecGPT, an expert cybersecurity assistant for ThreatArchitect.\n"
        "Your task is to analyze the structured network threat context provided by the user\n"
        "and generate a clear explanation, risk evaluation, recommended actions, copyable commands,\n"
        "and corresponding rollback commands.\n\n"
        "CRITICAL RULES:\n"
        "1. You MUST NEVER classify or detect threats. That detection is handled by deterministic engines.\n"
        "   Only trust and explain the threat detected in the context.\n"
        "2. Do NOT execute or try to run anything. You are purely advising.\n"
        "3. You must return your output strictly in JSON format matching the schema below.\n"
        "4. Do NOT wrap the JSON output in markdown blocks (e.g. do not use ```json ... ```).\n\n"
        "EXPECTED JSON SCHEMA:\n"
        "{\n"
        "  \"threat_summary\": \"Short paragraph summarizing the active threat and its main characteristics.\",\n"
        "  \"reasoning\": \"A concise explanation of why this was identified (correlating features, rules, anomalies).\",\n"
        "  \"recommended_actions\": [\n"
        "     \"Detailed human action item 1\",\n"
        "     \"Detailed human action item 2\"\n"
        "  ],\n"
        "  \"linux_commands\": [\n"
        "     \"Precise Linux CLI shell commands for mitigation (e.g. systemctl, ip route, iptables)\"\n"
        "  ],\n"
        "  \"rollback_commands\": [\n"
        "     \"Commands to undo the mitigation steps exactly if needed\"\n"
        "  ],\n"
        "  \"risk_level\": \"CRITICAL, HIGH, MEDIUM, or LOW\",\n"
        "  \"additional_notes\": \"Any relevant security advice or operational notes.\"\n"
        "}"
    )

    @staticmethod
    def build_remediation_prompt(context: Dict[str, Any]) -> str:
        """
        Formats security threat context into a clean prompt.
        """
        # Convert dictionary metrics into formatted YAML/text block
        lines = [
            "--- DETECTED THREAT CONTEXT ---",
            f"Threat Type: {context.get('threat_type', 'N/A')}",
            f"Threat Score: {context.get('threat_score', 0)} / 100",
            f"Anomaly Score (LSTM): {context.get('anomaly_score', 0.0):.4f}",
            f"Classifier Confidence: {context.get('classifier_confidence', 0.0):.2f}",
            f"Affected Host: {context.get('affected_host', 'N/A')}",
            f"Affected Service / Port: {context.get('affected_service', 'N/A')}",
            f"Attacker Host IP: {context.get('attacker_host', 'N/A')}",
            f"Detected Heuristics / Rules: {', '.join(context.get('triggered_rules', [])) or 'None'}",
            f"Top Contributing Features: {', '.join(context.get('top_features', [])) or 'None'}",
            f"Firewall Status: {context.get('firewall_status', 'N/A')}",
            f"Compliance Violations: {', '.join(context.get('compliance_violations', [])) or 'None'}",
            f"MITRE ATT&CK Mapping: {context.get('mitre_mapping', 'N/A')}",
            "--------------------------------",
            "Please analyze this data, fill in the JSON schema fields, and return only the raw JSON string."
        ]
        return "\n".join(lines)
