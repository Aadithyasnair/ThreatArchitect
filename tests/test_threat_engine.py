"""
tests/test_threat_engine — Verifies signature rules and Threat Modeling Engine output.
"""

import pytest
from app.capture.flow_manager import NetworkFlow
from app.network.rule_engine import RuleEngine, RuleAlert
from app.network.threat_engine import ThreatModelingEngine


def test_rule_engine_syn_flood() -> None:
    """Verifies that high SYN rate flag triggers signature rules."""
    engine = RuleEngine()

    # Flow with 20 packets, 18 of which are SYNs (SYN Flood)
    flow = NetworkFlow(
        src_ip="10.0.2.12",
        dst_ip="10.0.1.10",
        src_port=55000,
        dst_port=80,
        protocol="TCP",
        start_time=100.0,
        end_time=102.0,
        packet_count=20,
        byte_count=800,
        syn_count=18,
    )

    alerts = engine.evaluate([flow])
    assert len(alerts) >= 1
    assert any(a.rule_name == "HIGH_SYN_RATE" for a in alerts)


def test_rule_engine_port_scan() -> None:
    """Verifies that multiple destination ports query triggers scanning rules."""
    engine = RuleEngine()

    # Initiate flows from workstation ws-01 to multiple different ports on target
    flows = []
    for port in range(20, 32):  # 12 different ports
        f = NetworkFlow(
            src_ip="10.0.2.11",
            dst_ip="10.0.1.10",
            src_port=12345,
            dst_port=port,
            protocol="TCP",
            start_time=100.0,
            end_time=101.0,
            packet_count=1,
            byte_count=40,
            syn_count=1,
        )
        flows.append(f)

    alerts = engine.evaluate(flows)
    assert any(a.rule_name == "REPEATED_PORT_ACCESS" for a in alerts)


def test_threat_engine_decision_fusion() -> None:
    """Verifies that threat modeling aggregates LSTM, ML, and Rules correctly."""
    engine = ThreatModelingEngine()

    # Test case A: Clean normal traffic
    model_normal = engine.evaluate(
        anomaly_score=0.15,
        predicted_class="Normal",
        confidence=0.98,
        rule_alerts=[],
        flows=[],
        top_features=["TTL", "Window Size"],
    )
    assert model_normal.threat_level == "INFO"
    assert model_normal.threat_score <= 30
    assert any("Normal" in step for step in model_normal.reasoning_chain)

    # Test case B: Heavy attack (High LSTM + SYN Flood ML + Rule matches)
    alerts = [RuleAlert(rule_name="HIGH_SYN_RATE", message="SYN rate warning", severity="HIGH")]
    flow = NetworkFlow(
        src_ip="10.0.2.12",
        dst_ip="10.0.1.10",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        start_time=100.0,
        end_time=100.5,
        packet_count=50,
        byte_count=2000,
    )

    model_attack = engine.evaluate(
        anomaly_score=0.88,
        predicted_class="SYN Flood",
        confidence=0.92,
        rule_alerts=alerts,
        flows=[flow],
        top_features=["PPS", "SYN Count"],
    )

    assert model_attack.threat_level == "CRITICAL"
    assert model_attack.threat_score >= 85
    assert model_attack.affected_host == "10.0.1.10"
    assert model_attack.attacker_host == "10.0.2.12"
    assert any("Verdict: Calculated CRITICAL" in step for step in model_attack.reasoning_chain)
    assert len(model_attack.evidence) >= 2
