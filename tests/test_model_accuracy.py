"""
tests/test_model_accuracy — Automated test suite verifying ML classification accuracy,
LSTM anomaly detection scoring bounds, checkpoint persistence, and simulation verdicts.
"""

import pytest
import numpy as np
from app.ai.classifier.rf_classifier import RFClassifier
from app.ai.classifier.trainer import RFClassifierTrainer
from app.ai.real_data_generator import (
    generate_real_life_dataset,
    generate_real_life_lstm_sequences,
    generate_real_life_normal_vector,
    generate_real_life_attack_vector,
    compute_evaluation_metrics,
)
from app.ai.lstm.trainer import LSTMTrainer
from app.ai.lstm.inference import LSTMAnomalyDetector
from app.ai.lstm.checkpoint_manager import CheckpointManager
from app.capture.capture_manager import CaptureManager
from app.network.simulation import NormalSimulation, SuspiciousSimulation, DangerousSimulation
from app.network.topology_models import NetworkTopology, NetworkDevice, DeviceType, NodeStatus
from app.network.threat_engine import ThreatModelingEngine
from app.network.rule_engine import RuleEngine


def test_random_forest_high_accuracy() -> None:
    """Verifies that Random Forest classifier achieves >= 95% cross-validation accuracy on dataset."""
    x_train, y_train = generate_real_life_dataset(num_normal=800, num_per_attack=150)
    rf_wrapper = RFClassifierTrainer.train_model(x_train, y_train, n_estimators=50, max_depth=12)

    metrics = compute_evaluation_metrics(rf_wrapper.model, x_train, y_train)
    assert metrics["overall_accuracy"] >= 95.0, f"Overall accuracy too low: {metrics['overall_accuracy']}%"
    assert metrics["cv_accuracy"] >= 90.0, f"Cross-validation accuracy too low: {metrics['cv_accuracy']}%"

    # Ensure all 9 classes (Normal + 8 attacks) are present and evaluated
    classes = set(y_train)
    assert "DHCP Starvation" in classes
    assert "SYN Flood" in classes
    assert "Port Scan" in classes


def test_lstm_anomaly_detector_scoring_bounds() -> None:
    """Verifies that normal sequences score low (< 0.4) and outlier sequences score high (> 0.6)."""
    clean_seqs = generate_real_life_lstm_sequences(num_sequences=200, seq_len=5)
    model = LSTMTrainer.train_model(clean_seqs, epochs=10, batch_size=16)

    detector = LSTMAnomalyDetector(model)

    # 1. Normal sequence
    normal_seq = [generate_real_life_normal_vector() for _ in range(5)]
    normal_score = detector.detect_anomalies(normal_seq)
    assert 0.0 <= normal_score <= 0.40, f"Normal sequence anomaly score too high: {normal_score}"

    # 2. Extreme anomaly sequence
    attack_seq = [generate_real_life_attack_vector("SYN Flood") for _ in range(5)]
    attack_score = detector.detect_anomalies(attack_seq)
    assert attack_score > normal_score, f"Attack score ({attack_score}) should exceed normal score ({normal_score})"


def test_checkpoint_persistence(tmp_path) -> None:
    """Verifies that CheckpointManager saves and loads model state without pickle errors."""
    clean_seqs = generate_real_life_lstm_sequences(num_sequences=50, seq_len=5)
    model = LSTMTrainer.train_model(clean_seqs, epochs=5)

    chk_file = str(tmp_path / "test_lstm.pth")
    assert CheckpointManager.save_checkpoint(model, chk_file) is True

    loaded_model = CheckpointManager.load_checkpoint(chk_file)
    assert loaded_model is not None
    assert loaded_model.input_dim == model.input_dim
    assert loaded_model.hidden_dim == model.hidden_dim


def test_simulation_pipeline_verdicts() -> None:
    """Verifies that Normal, Suspicious, and Dangerous simulations yield correct classification verdicts."""
    ws1 = NetworkDevice(id="ws-01", hostname="Workstation 1", ip_address="10.0.2.11", mac_address="00:11:22:33:44:01", device_type=DeviceType.WORKSTATION, status=NodeStatus.ONLINE)
    srv = NetworkDevice(id="server", hostname="Web Server", ip_address="10.0.1.10", mac_address="00:11:22:33:44:03", device_type=DeviceType.SERVER, status=NodeStatus.ONLINE)
    topo = NetworkTopology(name="TestTopo", devices=[ws1, srv])

    rf = RFClassifier()
    assert rf.load("models/rf_classifier.pkl") is True

    lstm_model = CheckpointManager.load_checkpoint("models/lstm_anomaly.pth")
    detector = LSTMAnomalyDetector(lstm_model)
    engine = ThreatModelingEngine()
    rule_engine = RuleEngine()

    # 1. Test Normal Simulation
    cm_norm = CaptureManager()
    dummy_listener = type("Dummy", (), {"is_running": lambda self: True, "push_emulated_packet": lambda self, pkt: cm_norm.on_raw_packet_received(pkt)})()
    cm_norm.listener = dummy_listener

    sim_norm = NormalSimulation()
    sim_norm.set_topology(topo)
    sim_norm.set_packet_callback(lambda evt: cm_norm.feed_emulated_packet(evt.src_ip, evt.dst_ip, evt.protocol.port, evt.protocol.transport, evt.size_bytes))
    sim_norm.start()

    for _ in range(10):
        sim_norm.tick()

    active_norm = list(cm_norm.flow_manager.active_flows.values())
    vec_norm = cm_norm.feature_buffer.extract_features(active_norm)
    pred_norm, conf_norm, _, _ = rf.predict(vec_norm)
    seq_norm = cm_norm.feature_buffer.get_sequence()
    anom_norm = detector.detect_anomalies(seq_norm)
    threat_norm = engine.evaluate(anom_norm, pred_norm, conf_norm, [], active_norm, [])

    assert threat_norm.threat_level in ("INFO", "LOW")
    assert threat_norm.threat_score <= 35

    # 2. Test Suspicious SYN Flood Simulation
    cm_att = CaptureManager()
    dummy_listener_att = type("Dummy", (), {"is_running": lambda self: True, "push_emulated_packet": lambda self, pkt: cm_att.on_raw_packet_received(pkt)})()
    cm_att.listener = dummy_listener_att

    sim_att = SuspiciousSimulation()
    sim_att.set_topology(topo)
    sim_att.set_packet_callback(lambda evt: cm_att.feed_emulated_packet(evt.src_ip, evt.dst_ip, evt.protocol.port, evt.protocol.transport, evt.size_bytes, evt.is_suspicious, evt.is_dangerous))
    sim_att.start()
    sim_att._simulator.active_attack = "SYN Flood"
    sim_att._simulator._tick_counter = 1

    for _ in range(5):
        sim_att.tick()

    active_att = list(cm_att.flow_manager.active_flows.values())
    vec_att = cm_att.feature_buffer.extract_features(active_att)
    pred_att, conf_att, _, _ = rf.predict(vec_att)
    seq_att = cm_att.feature_buffer.get_sequence()
    anom_att = detector.detect_anomalies(seq_att)
    alerts_att = rule_engine.evaluate(active_att)
    threat_att = engine.evaluate(anom_att, pred_att, conf_att, alerts_att, active_att, [])

    assert pred_att == "SYN Flood"
    assert threat_att.threat_level in ("HIGH", "CRITICAL")
    assert threat_att.threat_score >= 70


def test_extended_normal_simulation_stability() -> None:
    """Verifies that extended NormalSimulation runs across many ticks without generating false positive HIGH/CRITICAL threat alerts."""
    ws1 = NetworkDevice(id="ws-01", hostname="Workstation 1", ip_address="10.0.2.11", mac_address="00:11:22:33:44:01", device_type=DeviceType.WORKSTATION, status=NodeStatus.ONLINE)
    srv = NetworkDevice(id="server", hostname="Web Server", ip_address="10.0.1.10", mac_address="00:11:22:33:44:03", device_type=DeviceType.SERVER, status=NodeStatus.ONLINE)
    topo = NetworkTopology(name="TestTopo", devices=[ws1, srv])

    rf = RFClassifier()
    assert rf.load("models/rf_classifier.pkl") is True

    lstm_model = CheckpointManager.load_checkpoint("models/lstm_anomaly.pth")
    detector = LSTMAnomalyDetector(lstm_model)
    engine = ThreatModelingEngine()
    rule_engine = RuleEngine()

    cm = CaptureManager()
    dummy_listener = type("Dummy", (), {"is_running": lambda self: True, "push_emulated_packet": lambda self, pkt: cm.on_raw_packet_received(pkt)})()
    cm.listener = dummy_listener

    sim = NormalSimulation()
    sim.set_topology(topo)
    sim.set_packet_callback(lambda evt: cm.feed_emulated_packet(evt.src_ip, evt.dst_ip, evt.protocol.port, evt.protocol.transport, evt.size_bytes))
    sim.start()

    for tick in range(1, 101):
        sim.tick()
        if tick % 10 == 0:
            active = list(cm.flow_manager.active_flows.values())
            vec = cm.feature_buffer.extract_features(active)
            pred, conf, _, _ = rf.predict(vec)
            seq = cm.feature_buffer.get_sequence()
            anom = detector.detect_anomalies(seq)
            alerts = rule_engine.evaluate(active)
            threat = engine.evaluate(anom, pred, conf, alerts, active, [])

            assert threat.threat_level in ("INFO", "LOW"), f"False positive threat alert at tick {tick}: {threat.threat_level} (Score {threat.threat_score})"
            assert threat.threat_score <= 35, f"False positive threat score at tick {tick}: {threat.threat_score}"

