"""
tests/test_pdf — Unit tests for PDF generation using ReportLab.
"""

import os
import pytest
from app.utils.pdf_generator import PDFIncidentReportGenerator


def test_pdf_report_compilation(tmp_path) -> None:
    """Verifies that PDF generator builds a non-empty file with correct margins/styles."""
    output_pdf = os.path.join(tmp_path, "incident_report_test.pdf")

    incident_data = {
        "timestamp": "2026-07-21 12:00:00",
        "attack_category": "SYN Flood",
        "anomaly_score": 0.82,
        "classifier_confidence": 0.94,
        "threat_score": 90,
        "threat_level": "CRITICAL",
        "attacker_host": "10.0.2.12",
        "affected_host": "10.0.1.10",
        "affected_service": "80"
    }

    timeline_events = [
        {"event_time": "12:00:00", "event_type": "TRAFFIC_START", "message": "Emulation active."},
        {"event_time": "12:00:02", "event_type": "DETECTED", "message": "SYN Flood anomaly spikes."}
    ]

    compliance_results = [
        {
            "framework": "NIST CSF",
            "control": "PR.AC-3",
            "status": "PASS",
            "reason": "Firewall active.",
            "improvement": "None"
        }
    ]

    mitre_info = {
        "id": "T1498.001",
        "name": "Network Denial of Service: Reflection/Amplification",
        "tactic": "Impact",
        "description": "Adversaries flood server."
    }

    ai_remediation = {
        "threat_summary": "SYN Flood mitigation summary advice.",
        "reasoning": "LSTM score exceeded threshold limits.",
        "risk_level": "CRITICAL",
        "recommended_actions": ["Block attacker MAC.", "Configure TCP Syncookies."],
        "linux_commands": ["sysctl -w net.ipv4.tcp_syncookies=1"],
        "rollback_commands": ["sysctl -w net.ipv4.tcp_syncookies=0"]
    }

    # Run PDF generation
    PDFIncidentReportGenerator.generate_report(
        output_path=output_pdf,
        incident_data=incident_data,
        timeline_events=timeline_events,
        compliance_results=compliance_results,
        mitre_info=mitre_info,
        ai_remediation=ai_remediation
    )

    # Check file exists and is not empty
    assert os.path.exists(output_pdf)
    assert os.path.getsize(output_pdf) > 1000  # ReportLab output should be multiple KB
