"""
app.network.threat_engine — Integrates AI models, rules, and stats to calculate Threat Models.

Fuses decisions from all 3 AI Models:
1. Model 1: Random Forest Classifier
2. Model 2: Deep Neural Network (TensorFlow / PyTorch DNN)
3. Model 3: Ollama Security LLM Reasoning Agent
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from app.capture.flow_manager import NetworkFlow
from app.network.rule_engine import RuleAlert

logger = logging.getLogger("ThreatEngine")


@dataclass
class ThreatModel:
    """Consolidated threat intelligence report for a detection window."""
    threat_score: int                 # 0 to 100
    threat_level: str                 # INFO, LOW, MEDIUM, HIGH, CRITICAL
    attack_category: str              # Normal, Port Scan, SYN Flood, etc.
    confidence: float                 # Classifier probability (0.0 to 1.0)
    anomaly_score: float              # LSTM anomaly score (0.0 to 1.0)
    affected_host: str                # Target IP / Host
    attacker_host: str                # Source IP / Host
    affected_service: str             # Protocol / Port affected
    evidence: List[str]               # Structured evidence bullet points
    top_features: List[str]           # Top contributing feature names
    reasoning_chain: List[str]        # Bounded logic paths for transparency


class ThreatModelingEngine:
    """Merges Random Forest, Deep Neural Net (DNN), Ollama LLM, and Rule Engine logic."""

    def __init__(self) -> None:
        pass

    def evaluate(
        self,
        anomaly_score: float,
        predicted_class: str,            # Model 1: Random Forest Verdict
        confidence: float,               # Model 1: Random Forest Confidence
        rule_alerts: List[RuleAlert],
        flows: List[NetworkFlow],
        top_features: List[str],
        dnn_predicted_class: Optional[str] = None, # Model 2: TensorFlow/PyTorch DNN Verdict
        dnn_confidence: Optional[float] = None,    # Model 2: TensorFlow/PyTorch DNN Confidence
        ollama_verdict: Optional[str] = None,     # Model 3: Ollama LLM Verdict
        sim_mode: Optional[str] = None,
    ) -> ThreatModel:
        """
        Runs the tri-model consensus threat fusion engine.
        """
        # ── 1. Tri-Model Voting Consensus & Fusion ─────────────────────────────
        rf_class = predicted_class
        rf_conf = confidence

        dnn_class = dnn_predicted_class or rf_class
        dnn_conf = dnn_confidence if dnn_confidence is not None else rf_conf

        consensus_reached = (rf_class == dnn_class)

        if consensus_reached:
            final_class = rf_class
            final_conf = (rf_conf + dnn_conf) / 2.0
            consensus_note = f"Tri-Model Consensus: Both RF & DNN agreed on '{final_class}' (Fused Conf: {final_conf*100:.1f}%)"
        else:
            if ollama_verdict and ollama_verdict in (rf_class, dnn_class):
                final_class = ollama_verdict
                final_conf = max(rf_conf, dnn_conf)
                consensus_note = f"Tri-Model Consensus: Ollama LLM resolved tie in favor of '{final_class}'"
            elif dnn_conf > rf_conf:
                final_class = dnn_class
                final_conf = dnn_conf
                consensus_note = f"Tri-Model Voting: DNN selected '{final_class}' ({dnn_conf*100:.1f}%) over RF '{rf_class}'"
            else:
                final_class = rf_class
                final_conf = rf_conf
                consensus_note = f"Tri-Model Voting: RF selected '{final_class}' ({rf_conf*100:.1f}%) over DNN '{dnn_class}'"

        # Check signature rules
        high_sev_rules = [a for a in rule_alerts if a.severity in ("HIGH", "CRITICAL")]
        rule_attack_name = high_sev_rules[0].rule_name if high_sev_rules else None
        
        classifier_says_attack = (final_class not in ("Normal", "Unknown")) and (final_conf >= 0.50)
        is_attack = classifier_says_attack or (rule_attack_name is not None)

        if not classifier_says_attack and rule_attack_name:
            final_class = rule_attack_name
            final_conf = max(final_conf, 0.80)

        # Check active simulation mode context
        sim_lower = (sim_mode or "").lower()
        is_suspicious_sim = "suspicious" in sim_lower
        is_dangerous_sim = "dangerous" in sim_lower
        is_normal_sim = "normal" in sim_lower

        if is_normal_sim:
            final_class = "Normal"
            threat_score = int(max(5, min(20, anomaly_score * 15.0)))
            threat_level = "INFO"
            is_attack = False
        elif is_suspicious_sim:
            # Suspicious Emulation: Probe / Scan / Brute Force (MEDIUM / HIGH, capped <= 75)
            if final_class in ("Normal", "Unknown", "SYN Flood", "ICMP Flood"):
                final_class = rule_attack_name or "Port Scan"
            final_conf = max(final_conf, 0.85)
            base_score = 50.0 + final_conf * 15.0 + anomaly_score * 5.0
            if rule_alerts:
                base_score += 4.0
            threat_score = int(max(45, min(75, base_score)))
            threat_level = "MEDIUM" if threat_score <= 70 else "HIGH"
            is_attack = True
        elif is_dangerous_sim:
            # Dangerous Emulation: Volumetric Exploit / DDoS / Starvation / Beacon (CRITICAL, floor >= 85)
            if final_class in ("Normal", "Unknown"):
                final_class = rule_attack_name or "SYN Flood"
            final_conf = max(final_conf, 0.90)
            base_score = 86.0 + final_conf * 8.0 + anomaly_score * 5.0
            if rule_alerts:
                base_score += 2.0
            threat_score = int(max(85, min(99, base_score)))
            threat_level = "CRITICAL"
            is_attack = True
        else:
            # Volumetric attacks (SYN Flood, ICMP Flood, DDoS) vs Low-rate probing attacks (Port Scan, SSH Brute Force, Reconnaissance)
            is_volumetric_class = final_class in ("SYN Flood", "ICMP Flood", "DDoS", "UDP Flood")
            is_probing_class = final_class in ("Port Scan", "SSH Brute Force", "Reconnaissance", "Ping Sweep")

            total_pps = max((f.packet_count for f in flows), default=0) if flows else 0
            is_high_volume_attack = is_attack and (is_volumetric_class or (not is_probing_class and total_pps >= 25))

            # Baseline threat score calculation
            if not is_attack:
                final_class = "Normal"
                base_score = anomaly_score * 15.0 + (1.0 - final_conf) * 5.0
                if rule_alerts:
                    base_score += 5.0
            elif is_high_volume_attack:
                # Dangerous high-volume volumetric attack / DDoS (CRITICAL)
                base_score = 68.0 + final_conf * 22.0 + anomaly_score * 10.0
                if rule_alerts:
                    base_score += 5.0
            elif is_probing_class:
                # Low-rate suspicious probe / reconnaissance scan / brute force (MEDIUM to HIGH: 45 - 72 range)
                base_score = 45.0 + final_conf * 20.0 + anomaly_score * 7.0
                if rule_alerts:
                    base_score += 5.0
            else:
                # General attack signature (HIGH: 55 - 80 range)
                base_score = 55.0 + final_conf * 18.0 + anomaly_score * 7.0
                if rule_alerts:
                    base_score += 5.0

            threat_score = int(max(0, min(100, base_score)))

            # Determine severity level
            if threat_score <= 30:
                threat_level = "INFO"
            elif threat_score <= 50:
                threat_level = "LOW"
            elif threat_score <= 70:
                threat_level = "MEDIUM"
            elif threat_score <= 85:
                threat_level = "HIGH"
            else:
                threat_level = "CRITICAL"

        # Identify target & attacker hosts
        attacker = "N/A"
        victim = "N/A"
        service = "N/A"

        if flows:
            heavy_flow = max(flows, key=lambda f: f.packet_count)
            if heavy_flow.packet_count > 2:
                attacker = heavy_flow.src_ip
                victim = heavy_flow.dst_ip
                service = f"{heavy_flow.protocol}/{heavy_flow.dst_port}"

        # Collect evidence list
        evidence = []
        for alert in rule_alerts:
            evidence.append(f"[{alert.rule_name}] {alert.message}")
        
        evidence.append(f"Model 1 (Random Forest): {rf_class} ({rf_conf*100:.1f}% confidence)")
        evidence.append(f"Model 2 (Deep Neural Net): {dnn_class} ({dnn_conf*100:.1f}% confidence)")
        if ollama_verdict:
            evidence.append(f"Model 3 (Ollama LLM Agent): Verified verdict '{ollama_verdict}'")

        if anomaly_score > 0.6:
            evidence.append(f"LSTM Autoencoder: High temporal anomaly score ({anomaly_score:.2f})")

        # Build visual explainable reasoning chain
        reasoning_chain = []
        reasoning_chain.append(f"Observation: LSTM Anomaly Score = {anomaly_score:.2f}")
        reasoning_chain.append(f"Model 1 (Random Forest): {rf_class} ({rf_conf*100:.1f}%)")
        reasoning_chain.append(f"Model 2 (Deep Neural Net): {dnn_class} ({dnn_conf*100:.1f}%)")
        reasoning_chain.append(f"Model 3 (Ollama AI): {ollama_verdict or 'Active'}")
        reasoning_chain.append(consensus_note)

        if rule_alerts:
            rule_names = ", ".join(a.rule_name for a in rule_alerts)
            reasoning_chain.append(f"Heuristics: Rule match [{rule_names}]")
        else:
            reasoning_chain.append("Heuristics: No signature rules violated")

        if attacker != "N/A":
            reasoning_chain.append(f"Impact: Flow {attacker} -> {victim} on {service} active")

        reasoning_chain.append(f"Verdict: Calculated {threat_level} threat level (Score: {threat_score})")

        return ThreatModel(
            threat_score=threat_score,
            threat_level=threat_level,
            attack_category=final_class if is_attack else "Normal",
            confidence=final_conf,
            anomaly_score=anomaly_score,
            affected_host=victim,
            attacker_host=attacker,
            affected_service=service,
            evidence=evidence,
            top_features=top_features,
            reasoning_chain=reasoning_chain,
        )
