"""
tests/test_ollama — Unit tests for Ollama integration, clients, and response parsers.
"""

import pytest
from app.ai.ollama.client import OllamaClient
from app.ai.ollama.prompt_builder import PromptBuilder
from app.ai.ollama.response_parser import ResponseParser, RemediationReport


def test_prompt_builder() -> None:
    """Verifies that prompt builder structures keys cleanly without raw packet details."""
    context = {
        "threat_type": "SYN Flood",
        "threat_score": 88,
        "anomaly_score": 0.85,
        "classifier_confidence": 0.92,
        "affected_host": "10.0.1.10",
        "affected_service": "80",
        "attacker_host": "10.0.2.12",
        "triggered_rules": ["HIGH_SYN_RATE"],
        "top_features": ["PPS", "SYN Count"],
        "firewall_status": "ACTIVE",
        "compliance_violations": ["NIST CSF - PR.AC-3"],
        "mitre_mapping": "T1498.001"
    }

    prompt = PromptBuilder.build_remediation_prompt(context)
    assert "SYN Flood" in prompt
    assert "10.0.1.10" in prompt
    assert "10.0.2.12" in prompt
    assert "HIGH_SYN_RATE" in prompt
    assert "NIST CSF - PR.AC-3" in prompt
    # System instructions
    assert "Antigravity-SecGPT" in PromptBuilder.SYSTEM_INSTRUCTIONS
    assert "linux_commands" in PromptBuilder.SYSTEM_INSTRUCTIONS


def test_response_parser_valid_json() -> None:
    """Verifies response parser handles clean, standard JSON formats."""
    raw = """
    {
      "threat_summary": "Active SYN Flood targeting port 80.",
      "reasoning": "Spike in anomaly score and SYN count.",
      "recommended_actions": ["Block attacker IP via iptables."],
      "linux_commands": ["sudo iptables -A INPUT -s 10.0.2.12 -j DROP"],
      "rollback_commands": ["sudo iptables -D INPUT -s 10.0.2.12 -j DROP"],
      "risk_level": "CRITICAL",
      "additional_notes": "Monitor server socket counters."
    }
    """
    report = ResponseParser.parse_response(raw)
    assert report.threat_summary == "Active SYN Flood targeting port 80."
    assert report.reasoning == "Spike in anomaly score and SYN count."
    assert len(report.recommended_actions) == 1
    assert report.linux_commands == ["sudo iptables -A INPUT -s 10.0.2.12 -j DROP"]
    assert report.rollback_commands == ["sudo iptables -D INPUT -s 10.0.2.12 -j DROP"]
    assert report.risk_level == "CRITICAL"
    assert "Monitor server socket counters." in report.additional_notes


def test_response_parser_markdown_wrapped_json() -> None:
    """Verifies response parser extracts JSON correctly even if wrapped in markdown blocks."""
    raw = """
    Some random text output.
    ```json
    {
      "threat_summary": "Port Scan warning.",
      "reasoning": "Sequential connection queries.",
      "recommended_actions": [],
      "linux_commands": [],
      "rollback_commands": [],
      "risk_level": "MEDIUM",
      "additional_notes": ""
    }
    ```
    Footer text.
    """
    report = ResponseParser.parse_response(raw)
    assert report.threat_summary == "Port Scan warning."
    assert report.reasoning == "Sequential connection queries."
    assert report.risk_level == "MEDIUM"


def test_response_parser_malformed_json_fallback() -> None:
    """Verifies that response parser falls back gracefully on malformed JSON without crashing."""
    raw = "This is not JSON at all, it's just raw text recommendations."
    report = ResponseParser.parse_response(raw)
    assert "Failed to parse" in report.threat_summary
    assert "JSON parsing error" in report.reasoning
    assert raw[:20] in report.additional_notes
