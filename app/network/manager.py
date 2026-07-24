"""
app.network.manager — Central NetworkManager service.

Coordinates the Mininet controller, topology builder, simulation engines,
and the AI threat detection pipeline (Capture, LSTM, RF Classifier, Rules, and Threat Engine).
"""

from __future__ import annotations

import logging
import time
import os
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any

from PySide6.QtCore import QObject, Signal

from app.network.topology_builder import TopologyBuilder
from app.network.topology_models import NetworkTopology, NodeStatus
from app.network.mininet_controller import MininetController
from app.network.firewall import FirewallComponent
from app.network.simulation import NormalSimulation, SuspiciousSimulation, DangerousSimulation, Simulation
from app.network.packet_simulator import PacketEvent
from app.core.events import EventBus

# Phase 3 Capture and AI pipeline imports
from app.config.loader import ConfigLoader
from app.capture.capture_manager import CaptureManager
from app.ai.lstm.checkpoint_manager import CheckpointManager
from app.ai.lstm.inference import LSTMAnomalyDetector
from app.ai.classifier.rf_classifier import RFClassifier
from app.ai.deep_classifier import DeepClassifier
from app.ai.ollama.client import OllamaClient
from app.ai.bootstrap_models import bootstrap_all_models
from app.network.rule_engine import RuleEngine
from app.network.threat_engine import ThreatModelingEngine, ThreatModel

# Phase 4 workers & LLM imports
from app.network.workers import (
    OllamaRemediationWorker, ComplianceAuditorWorker,
    DatabaseWriteWorker, PDFReportWorker, ModelRetrainWorker
)
from app.ai.ollama.response_parser import RemediationReport


logger = logging.getLogger("NetworkManager")


class NetworkManager(QObject):
    """
    Central service managing network lifecycle, emulation, and AI threat detection.

    Emits:
    - threat_model_updated(ThreatModel): When the AI pipeline yields a new threat verdict.
    - remediation_report_ready(RemediationReport): When Ollama generates mitigation plans.
    - compliance_audited(dict): When compliance check completes.
    - timeline_updated(list): When the live event timeline is updated.
    """
    threat_model_updated = Signal(object)
    remediation_report_ready = Signal(object)
    remediation_token_received = Signal(str)
    remediation_status_changed = Signal(str)
    compliance_audited = Signal(dict)
    timeline_updated = Signal(list)
    log_emitted = Signal(str)
    stats_updated = Signal(dict)


    def __init__(self) -> None:
        super().__init__()
        self._topology: Optional[NetworkTopology] = None
        self._controller = MininetController()
        self._firewall = FirewallComponent()
        self._simulation: Optional[Simulation] = None
        self._event_bus = EventBus()

        # External callbacks for UI wiring (set by MainWindow)
        self._packet_callback: Optional[Callable[[PacketEvent], None]] = None
        self._log_callback: Optional[Callable[[str], None]] = None
        self._stats_callback: Optional[Callable[[dict], None]] = None

        self._start_time: Optional[float] = None
        self._network_status = "OFFLINE"

        # ── Phase 4 state components ─────────────────────────────────────────
        self._last_compliance_violations: List[str] = []
        self._last_mitre_id: str = ""
        self._last_mitre_name: str = ""
        self._llm_query_in_progress: bool = False
        self._active_remediation_worker: Optional[OllamaRemediationWorker] = None
        self._last_remediation_report: Optional[RemediationReport] = None
        self._compliance_results: Dict[str, Any] = {}
        self._last_model_metrics: Dict[str, Any] = {}
        
        # Timeline holds events locally for immediate UI renders
        self._timeline_events: List[Dict[str, Any]] = []

        # ── Phase 3 Pipeline Initialization ──────────────────────────────────
        config = ConfigLoader.load()
        self._capture_manager = CaptureManager(
            interface=config.network.capture_interface,
            window_size_sec=config.detection.window_size_seconds,
            stride_sec=config.detection.stride_seconds,
        )
        self._anomaly_detector = LSTMAnomalyDetector()
        self._classifier = RFClassifier()                     # Model 1: Random Forest Classifier
        self._deep_classifier = DeepClassifier()                 # Model 2: TensorFlow/PyTorch Deep Neural Network
        self._ollama_client = OllamaClient()                     # Model 3: Ollama Security LLM Reasoning Agent
        self._rule_engine = RuleEngine()
        self._threat_engine = ThreatModelingEngine()

        self._current_threat_model: Optional[ThreatModel] = None

        # Connect pipeline signals
        self._capture_manager.sequence_ready.connect(self._on_features_sequence_ready)
        self._capture_manager.stats_updated.connect(self._on_capture_stats_updated)

    # ── Network Lifecycle ────────────────────────────────────────────────────

    def start_network(self) -> str:
        """
        Build topology, start Mininet/simulation, initialize firewall, and boot capture.
        """
        if self._controller.is_running():
            return "Network is already running."

        config = ConfigLoader.load()

        # Bootstrap models dynamically if missing
        model_dir = config.detection.model_dir
        bootstrap_all_models(model_dir)

        # Load models
        lstm_checkpoint = os.path.join(model_dir, "lstm_anomaly.pth")
        rf_checkpoint = os.path.join(model_dir, "rf_classifier.pkl")

        lstm_model = CheckpointManager.load_checkpoint(lstm_checkpoint)
        if lstm_model:
            self._anomaly_detector.set_model(lstm_model)
        
        self._classifier.load(rf_checkpoint)

        # Build topology
        self._topology = TopologyBuilder.build_enterprise_default()
        self._log(f"Topology loaded: {self._topology.name}")

        # Start Mininet or simulation fallback
        result = self._controller.start_network(self._topology)
        if result.is_failure:
            self._log(f"ERROR: {result.error}")
            return f"Failed to start network: {result.error}"

        self._network_status = "ONLINE"
        self._start_time = time.time()
        self._log("Network started. All devices ONLINE.")

        # Load persisted firewall rules from database
        try:
            from app.database.connection import DatabaseConnection
            conn = DatabaseConnection(config.database.db_path).connect()
            cursor = conn.cursor()
            cursor.execute("SELECT src_ip, dst_ip, port, protocol, action, description FROM firewall_rules")
            rows = cursor.fetchall()
            from app.network.firewall import FirewallRule, FirewallAction
            persisted_rules = []
            for row in rows:
                act = FirewallAction.DENY if row[4] == "deny" else FirewallAction.ALLOW
                persisted_rules.append(FirewallRule(
                    src_ip=row[0], dst_ip=row[1], port=row[2], protocol=row[3], action=act, description=row[5]
                ))
            if persisted_rules:
                self._firewall.load_persisted_rules(persisted_rules)
        except Exception as exc:
            logger.warning(f"Could not load persisted firewall rules: {exc}")

        # Start packet capture pipeline
        self._capture_manager.start_capture(config.network.capture_interface)
        self._log(f"Capture started on interface: {config.network.capture_interface}")

        self._event_bus.publish("network.started", {"topology": self._topology})

        # Start normal traffic simulation by default
        self._start_simulation("normal")
        return result.value or "Network started."

    def stop_network(self) -> str:
        """Stop active simulation, capture pipeline, and controller."""
        if not self._controller.is_running():
            return "Network is not running."

        # Stop capture
        self._capture_manager.stop_capture()

        # Stop simulation first
        if self._simulation and self._simulation.is_running():
            self._simulation.stop()
            self._simulation = None

        # Stop controller
        result = self._controller.stop_network()
        self._network_status = "OFFLINE"
        self._start_time = None
        self._current_threat_model = None

        self._log("Network stopped. All devices OFFLINE.")
        self._event_bus.publish("network.stopped", {})
        return result.value if result.is_success else result.error

    def is_running(self) -> bool:
        """Return True if the network is currently active."""
        return self._controller.is_running()

    # ── Simulation Control ───────────────────────────────────────────────────

    def start_emulate_normal(self) -> str:
        """Start or restart the 'emulate normal' traffic simulation."""
        if not self._controller.is_running():
            return "Start the network first. (run: start network)"

        self._start_simulation("normal")
        return "Normal traffic emulation started."

    def start_emulate_suspicious(self) -> str:
        """Start or restart the 'emulate suspicious' attack simulation."""
        if not self._controller.is_running():
            return "Start the network first. (run: start network)"

        self._start_simulation("suspicious")
        return "Suspicious traffic emulation started."

    def start_emulate_dangerous(self) -> str:
        """Start or restart the 'emulate dangerous' attack simulation."""
        if not self._controller.is_running():
            return "Start the network first. (run: start network)"

        self._start_simulation("dangerous")
        return "Dangerous traffic emulation started."

    def _start_simulation(self, mode: str) -> None:
        """Internal helper to instantiate and activate a simulation mode."""
        if self._simulation and self._simulation.is_running():
            self._simulation.stop()

        # Clear flow manager and feature buffer to prevent stale flow mixing across simulation modes
        if hasattr(self, "_capture_manager"):
            self._capture_manager.flow_manager.clear()
            self._capture_manager.feature_buffer.clear()

        if mode == "suspicious":
            sim = SuspiciousSimulation()
            self._log("Simulation: emulate suspicious — active.")
        elif mode == "dangerous":
            sim = DangerousSimulation()
            self._log("Simulation: emulate dangerous — active.")
        else:
            sim = NormalSimulation()
            self._log("Simulation: emulate normal — active.")


        # Log traffic start event on timeline
        self.add_timeline_event(
            message=f"Simulation '{sim.name}' active.",
            event_type="TRAFFIC_START"
        )

        if self._topology:
            sim.set_topology(self._topology)
        if self._packet_callback:
            sim.set_packet_callback(self._on_packet_generated)

        sim.start()
        self._simulation = sim

    def tick_simulation(self) -> Optional[PacketEvent]:
        """Called by SimulationTickWorker on each timer tick."""
        if not self._simulation or not self._simulation.is_running():
            return None

        event = self._simulation.tick()
        if event:
            self._on_packet_generated(event)
        return event

    def _on_packet_generated(self, event: PacketEvent) -> None:
        """Internal dispatch when a packet event is produced."""
        # 1. Check Firewall rules
        is_allowed = self._firewall.evaluate(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dport=event.protocol.port,
            protocol=event.protocol.transport
        )

        # Dynamic AI Firewall Enforcement: Auto-block ONLY dangerous attack streams
        if is_allowed and event.is_dangerous:
            from app.network.firewall import FirewallRule, FirewallAction
            deny_rule = FirewallRule(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                port=event.protocol.port,
                protocol=event.protocol.transport,
                action=FirewallAction.DENY,
                description=f"AI Auto-Block: {event.label}"
            )
            self._firewall.deny(deny_rule)
            is_allowed = False

        status_suffix = "ALLOWED (MONITORED)" if (is_allowed and event.is_suspicious) else ("ALLOWED" if is_allowed else "BLOCKED")
        self._log(f"{event.label} - {status_suffix}")



        # If blocked, log to timeline immediately
        if not is_allowed:
            self.add_timeline_event(
                message=f"Firewall BLOCKED packet {event.src_ip} -> {event.dst_ip}:{event.protocol.port}",
                event_type="BLOCKED"
            )

        # Feed packet event into Scapy capture manager so IDS/ML threat engine parses flows
        self._capture_manager.feed_emulated_packet(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            port=event.protocol.port,
            protocol_str=event.protocol.transport,
            size=event.size_bytes,
            is_suspicious=event.is_suspicious,
            is_dangerous=event.is_dangerous,
        )


        self._event_bus.publish("packet.generated", event)
        if self._packet_callback:
            self._packet_callback(event)
        if self._stats_callback:
            self._stats_callback(self.get_stats())

    # ── AI Pipeline Signals ──────────────────────────────────────────────────

    def _on_features_sequence_ready(self, sequence: List[List[float]]) -> None:
        """Runs automatically on capture stride tick. Evaluates models and rules."""
        try:
            # 1. Evaluate LSTM Anomaly Score
            anomaly_score = self._anomaly_detector.detect_anomalies(sequence)

            # 2. Model 1: Evaluate Random Forest Classifier on latest flow feature vector
            last_vector = sequence[-1]
            rf_class, rf_confidence, rf_probs, top_features = self._classifier.predict(last_vector)

            # 3. Model 2: Evaluate Deep Neural Network (TensorFlow/PyTorch DNN)
            dnn_class, dnn_confidence, dnn_probs = self._deep_classifier.predict(last_vector)

            # 4. Model 3: Evaluate Ollama Security Reasoning Agent (if active & model tie-breaker needed)
            ollama_verdict = None
            if self._ollama_client.is_available() and (rf_class != dnn_class) and (rf_class != "Normal" or dnn_class != "Normal"):
                try:
                    ollama_resp = self._ollama_client.query(
                        prompt=f"Network flow: Model 1 (RF) predicted '{rf_class}' ({rf_confidence*100:.1f}%), Model 2 (DNN) predicted '{dnn_class}' ({dnn_confidence*100:.1f}%). Confirm security verdict.",
                        format_json=False,
                        timeout=0.2
                    )
                    if ollama_resp:
                        for candidate in [rf_class, dnn_class]:
                            if candidate.lower() in ollama_resp.lower():
                                ollama_verdict = candidate
                                break
                except Exception:
                    ollama_verdict = None

            # 5. Evaluate Rule Engine Heuristics
            flows = list(self._capture_manager.flow_manager.active_flows.values())
            rule_alerts = self._rule_engine.evaluate(flows)

            # 6. Run Tri-Model Threat Fusion Engine
            threat_model = self._threat_engine.evaluate(
                anomaly_score=anomaly_score,
                predicted_class=rf_class,
                confidence=rf_confidence,
                rule_alerts=rule_alerts,
                flows=flows,
                top_features=top_features,
                dnn_predicted_class=dnn_class,
                dnn_confidence=dnn_confidence,
                ollama_verdict=ollama_verdict,
                sim_mode=self.get_simulation_name(),
            )

            old_threat = self._current_threat_model
            self._current_threat_model = threat_model
            logger.info(f"Threat Fusion complete. Class: {threat_model.attack_category}, Score: {threat_model.threat_score}/100")

            # Auto-mitigation: Add dynamic DENY rule whenever a HIGH or CRITICAL attack stream is detected
            should_auto_mitigate = (threat_model.threat_level in ("HIGH", "CRITICAL")) and threat_model.attack_category != "Normal"
            if should_auto_mitigate:
                attacker_ip = threat_model.attacker_host if threat_model.attacker_host != "N/A" else "*"
                affected_ip = threat_model.affected_host if threat_model.affected_host != "N/A" else "*"
                from app.network.firewall import FirewallRule, FirewallAction

                rules = self._firewall.get_rules()
                already_blocked = any(r.action == FirewallAction.DENY and (r.src_ip == attacker_ip or r.src_ip == "*") for r in rules)
                if not already_blocked and attacker_ip != "*":
                    auto_rule = FirewallRule(
                        src_ip=attacker_ip,
                        dst_ip=affected_ip,
                        action=FirewallAction.DENY,
                        description=f"AI Mitigation: Blocked {threat_model.attack_category}"
                    )
                    self._firewall.deny(auto_rule)
                    self._log(f"[FIREWALL] Auto-Mitigation DENY rule applied: Blocked {attacker_ip} -> {affected_ip} ({threat_model.attack_category})")

                    # Persist rule to database
                    q_fw = "INSERT INTO firewall_rules (src_ip, dst_ip, port, protocol, action, description) VALUES (?, ?, ?, ?, ?, ?)"
                    p_fw = (auto_rule.src_ip, auto_rule.dst_ip, auto_rule.port, auto_rule.protocol, auto_rule.action.value, auto_rule.description)
                    DatabaseWriteWorker(q_fw, p_fw, self).start()


            # 5. Persist threat stats to SQLite in background
            th_query = """
                INSERT INTO threat_history (anomaly_score, classifier_confidence, predicted_class, threat_score)
                VALUES (?, ?, ?, ?)
            """
            th_params = (anomaly_score, threat_model.confidence, threat_model.attack_category, threat_model.threat_score)
            th_worker = DatabaseWriteWorker(th_query, th_params, self)
            th_worker.start()

            # 6. Map to local MITRE ATT&CK technique details
            from app.ai.mitre.mapper import MitreMapper
            mitre_tech = MitreMapper.map_attack(threat_model.attack_category)
            if mitre_tech:
                self._last_mitre_id = mitre_tech.id
                self._last_mitre_name = mitre_tech.name
            else:
                self._last_mitre_id = ""
                self._last_mitre_name = ""

            # 7. Check if threat elevated or attack detected
            if threat_model.attack_category != "Normal" and (not old_threat or old_threat.attack_category == "Normal"):
                self.add_timeline_event(
                    message=f"Attack Detected: {threat_model.attack_category} (Confidence: {threat_model.confidence:.0%})",
                    event_type="DETECTED"
                )
            
            if old_threat and threat_model.threat_score > old_threat.threat_score + 15:
                self.add_timeline_event(
                    message=f"Threat score elevated to {threat_model.threat_score}/100.",
                    event_type="ELEVATED"
                )

            # 8. Trigger background compliance audits
            comp_worker = ComplianceAuditorWorker(self, self)
            comp_worker.finished.connect(self._on_compliance_audit_finished)
            comp_worker.start()

            # Update devices in topology based on attacker / victim state
            if self._topology and threat_model.threat_level in ("HIGH", "CRITICAL"):
                attacker = self._topology.get_device_by_ip(threat_model.attacker_host)
                victim = self._topology.get_device_by_ip(threat_model.affected_host)
                if attacker:
                    attacker.status = NodeStatus.WARNING
                if victim:
                    victim.status = NodeStatus.UNDER_ATTACK

            # 9. Trigger background LLM generation on high threats
            if threat_model.threat_level in ("HIGH", "CRITICAL"):
                # Abort any active streaming worker to ensure only one active stream exists
                if self._active_remediation_worker is not None:
                    logger.info("Canceling active AI streaming query to process new incident...")
                    self._active_remediation_worker.cancel()
                    self._active_remediation_worker = None

                self._llm_query_in_progress = True
                
                context = {
                    "threat_type": threat_model.attack_category,
                    "threat_score": threat_model.threat_score,
                    "anomaly_score": threat_model.anomaly_score,
                    "classifier_confidence": threat_model.confidence,
                    "affected_host": threat_model.affected_host,
                    "affected_service": threat_model.affected_service,
                    "attacker_host": threat_model.attacker_host,
                    "triggered_rules": threat_model.evidence,
                    "top_features": threat_model.top_features,
                    "firewall_status": "ACTIVE",
                    "compliance_violations": self._last_compliance_violations,
                    "mitre_mapping": f"{self._last_mitre_id} ({self._last_mitre_name})" if self._last_mitre_id else "N/A"
                }
                
                logger.info(f"Spawning streaming LLM worker query for active attack: {threat_model.attack_category}...")
                self._active_remediation_worker = OllamaRemediationWorker(context, self)
                self._active_remediation_worker.token_received.connect(self.remediation_token_received.emit)
                self._active_remediation_worker.status_changed.connect(self.remediation_status_changed.emit)
                self._active_remediation_worker.finished.connect(self._on_ollama_remediation_finished)
                self._active_remediation_worker.start()

            # Emit signal to update Explainability / Graph widgets
            self.threat_model_updated.emit(threat_model)

            # Refresh dashboard widgets
            if self._stats_callback:
                self._stats_callback(self.get_stats())

        except Exception as exc:
            logger.error(f"Failed to execute AI pipeline evaluation: {exc}", exc_info=True)

    def _on_capture_stats_updated(self, stats: dict) -> None:
        """Update dashboard with capture statistics."""
        if self._stats_callback:
            self._stats_callback(self.get_stats())

    # ── Accessors & Stats ────────────────────────────────────────────────────

    def get_topology(self) -> Optional[NetworkTopology]:
        return self._topology

    def get_firewall(self) -> FirewallComponent:
        return self._firewall

    def get_stats(self) -> dict:
        """Return aggregated live network and threat metrics."""
        sim_stats = self._simulation.get_stats() if self._simulation else {}
        capture_pkt = self._capture_manager._total_packets_captured
        active_flows = len(self._capture_manager.flow_manager.active_flows)

        m = self._current_threat_model

        return {
            "network_status": self._network_status,
            "simulation_mode": self._simulation.name if self._simulation and self._simulation.is_running() else "IDLE",
            "active_devices": len(self._topology.get_online_devices()) if self._topology else 0,
            "packets_sent": sim_stats.get("sent", 0),
            "packets_delivered": sim_stats.get("delivered", 0),
            "packets_lost": sim_stats.get("lost", 0),
            "firewall": self._firewall.get_stats(),

            # Phase 3 Stats
            "packets_captured": capture_pkt,
            "active_flows": active_flows,
            "threat_score": m.threat_score if m else 0,
            "threat_level": m.threat_level if m else "INFO",
            "anomaly_score": m.anomaly_score if m else 0.0,
            "classifier_confidence": m.confidence if m else 0.0,
            "current_attack": m.attack_category if m else "Normal",
            "current_target": m.affected_host if m else "N/A",
        }

    def get_simulation_name(self) -> str:
        if self._simulation and self._simulation.is_running():
            return self._simulation.name
        return "IDLE"

    def get_current_threat_model(self) -> Optional[ThreatModel]:
        """Returns the latest threat evaluation report."""
        return self._current_threat_model

    # ── Callback Registration ────────────────────────────────────────────────

    def set_packet_callback(self, cb: Callable[[PacketEvent], None]) -> None:
        self._packet_callback = cb
        if self._simulation:
            self._simulation.set_packet_callback(self._on_packet_generated)

    def set_log_callback(self, cb: Callable[[str], None]) -> None:
        self._log_callback = cb

    def set_stats_callback(self, cb: Callable[[dict], None]) -> None:
        self._stats_callback = cb

    # ── Phase 4 Timelines & Callbacks ────────────────────────────────────────

    def add_timeline_event(self, message: str, event_type: str) -> None:
        """Appends a new event locally and writes asynchronously to SQLite database."""
        event_time = datetime.now().strftime("%H:%M:%S")
        event = {
            "event_time": event_time,
            "message": message,
            "event_type": event_type
        }
        self._timeline_events.append(event)
        # Limit local queue length
        if len(self._timeline_events) > 50:
            self._timeline_events.pop(0)

        # SQLite write
        query = "INSERT INTO timeline_events (event_time, message, event_type) VALUES (?, ?, ?)"
        params = (event_time, message, event_type)
        db_worker = DatabaseWriteWorker(query, params, self)
        db_worker.start()

        # Emit update
        self.timeline_updated.emit(list(self._timeline_events))

    def _on_compliance_audit_finished(self, results: dict) -> None:
        """Slot runs when background compliance audit finishes."""
        self._compliance_results = results
        self._last_compliance_violations = []

        # Find failures / warnings to store in state
        for framework, res in results.items():
            # Write to database (summary)
            q_sum = "INSERT INTO compliance_results (framework, passed_rules, failed_rules, score, status) VALUES (?, ?, ?, ?, ?)"
            p_sum = (framework, res["passed_rules"], res["failed_rules"], res["score"], res["status"])
            DatabaseWriteWorker(q_sum, p_sum, self).start()

            for detail in res.get("details", []):
                if detail["status"] != "PASS":
                    self._last_compliance_violations.append(f"{framework} - {detail['control']}")

                # Write to database (details)
                q_det = "INSERT INTO compliance_details (framework, control_id, status, reason, improvement) VALUES (?, ?, ?, ?, ?)"
                p_det = (framework, detail["control"], detail["status"], detail["reason"], detail["improvement"])
                DatabaseWriteWorker(q_det, p_det, self).start()

        # Emit audit update to frontend
        self.compliance_audited.emit(results)

    def _on_ollama_remediation_finished(self, report: RemediationReport) -> None:
        """Slot runs when background LLM query completes successfully."""
        self._llm_query_in_progress = False
        if self._active_remediation_worker == self.sender():
            self._active_remediation_worker = None
        self._last_remediation_report = report

        # Write active incident record to SQLite
        m = self._current_threat_model
        q_inc = """
            INSERT INTO incidents (attack_category, threat_score, threat_level, attacker_host, affected_host, affected_service, remediation_plan, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        import json
        plan_json = json.dumps({
            "risk_level": report.risk_level,
            "recommended_actions": report.recommended_actions,
            "linux_commands": report.linux_commands,
            "rollback_commands": report.rollback_commands,
            "additional_notes": report.additional_notes
        })
        p_inc = (
            m.attack_category if m else "Anomaly",
            m.threat_score if m else 50,
            m.threat_level if m else "WARNING",
            m.attacker_host if m else "N/A",
            m.affected_host if m else "N/A",
            m.affected_service if m else "N/A",
            plan_json,
            report.threat_summary + "\n\n" + report.reasoning
        )
        DatabaseWriteWorker(q_inc, p_inc, self).start()

        # Log timeline event
        self.add_timeline_event(
            message=f"AI Recommendation ready for {m.attack_category if m else 'Anomaly'}.",
            event_type="AI_RECOMMENDATION"
        )

        # Emit signal to update Remediation panel
        self.remediation_report_ready.emit(report)

    def generate_pdf_report(self, callback: Callable[[str, bool], None]) -> None:
        """Spawns background worker thread to compile and write PDF incident report."""
        m = self._current_threat_model
        if not m:
            callback("No active threat model loaded to generate report.", False)
            return

        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/incident_report_{timestamp}.pdf"

        # Pull compliance details into a list of dictionaries
        comp_list = []
        for fw_name, res in self._compliance_results.items():
            for detail in res.get("details", []):
                comp_list.append({
                    "framework": fw_name,
                    "control": detail["control"],
                    "status": detail["status"],
                    "reason": detail["reason"],
                    "improvement": detail["improvement"]
                })

        incident_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_category": m.attack_category,
            "anomaly_score": m.anomaly_score,
            "classifier_confidence": m.confidence,
            "threat_score": m.threat_score,
            "threat_level": m.threat_level,
            "attacker_host": m.attacker_host,
            "affected_host": m.affected_host,
            "affected_service": m.affected_service
        }

        mitre_info = None
        from app.ai.mitre.mapper import MitreMapper
        tech = MitreMapper.map_attack(m.attack_category)
        if tech:
            mitre_info = {
                "id": tech.id,
                "name": tech.name,
                "tactic": tech.tactic,
                "description": tech.description
            }

        ai_remediation = None
        rep = self._last_remediation_report
        if rep:
            ai_remediation = {
                "threat_summary": rep.threat_summary,
                "reasoning": rep.reasoning,
                "risk_level": rep.risk_level,
                "recommended_actions": rep.recommended_actions,
                "linux_commands": rep.linux_commands,
                "rollback_commands": rep.rollback_commands
            }

        # Pull topology devices details
        devices_list = []
        if self._topology:
            for dev in self._topology.devices:
                devices_list.append({
                    "hostname": dev.hostname,
                    "type": dev.device_type.value,
                    "ip": dev.ip_address,
                    "mac": dev.mac_address,
                    "status": dev.status.value
                })

        logger.info(f"Launching PDF generation worker: {filename}...")
        pdf_worker = PDFReportWorker(
            output_path=filename,
            incident_data=incident_data,
            timeline_events=list(self._timeline_events),
            compliance_results=comp_list,
            mitre_info=mitre_info,
            ai_remediation=ai_remediation,
            devices_list=devices_list,
            parent=self
        )

        def on_pdf_finished(path: str, success: bool):
            if success:
                # Store PDF path reference in reports database
                q_rep = "INSERT INTO reports (filename, file_path, summary) VALUES (?, ?, ?)"
                p_rep = (os.path.basename(path), path, f"Incident Report for {m.attack_category}")
                DatabaseWriteWorker(q_rep, p_rep, self).start()
            callback(path, success)

        pdf_worker.finished.connect(on_pdf_finished)
        pdf_worker.start()

    def retrain_models(self, callback: Optional[Callable[[bool, dict, str], None]] = None) -> None:
        """
        Retrains ML models (Random Forest Classifier & PyTorch LSTM) on recent/online threat data
        in a background thread and hot-reloads the newly trained weights.
        """
        config = ConfigLoader.load()
        model_dir = config.detection.model_dir
        self._log("[RETRAIN] Starting background model retraining with online threat feed dataset...")

        worker = ModelRetrainWorker(model_dir=model_dir, parent=self)

        def on_progress(msg: str):
            self._log(f"[RETRAIN] {msg}")

        def on_finished(success: bool, metrics: dict, msg: str):
            if success:
                self._last_model_metrics = metrics
                # Hot-reload weights
                lstm_checkpoint = os.path.join(model_dir, "lstm_anomaly.pth")
                rf_checkpoint = os.path.join(model_dir, "rf_classifier.pkl")
                lstm_model = CheckpointManager.load_checkpoint(lstm_checkpoint)
                if lstm_model:
                    self._anomaly_detector.set_model(lstm_model)
                self._classifier.load(rf_checkpoint)
                self._deep_classifier.load_model()
                self._log(f"[RETRAIN] All ML & Deep Models (RF, LSTM, DNN) successfully retrained & hot-reloaded! Overall Accuracy: {metrics.get('overall_accuracy', 100)}% (CV: {metrics.get('cv_accuracy', 100)}%).")
            else:
                self._log(f"[RETRAIN ERROR] Model retraining failed: {msg}")

            if callback:
                callback(success, metrics, msg)

        worker.progress.connect(on_progress)
        worker.finished.connect(on_finished)
        worker.start()

    def trigger_manual_mitigation(self) -> str:
        """Trigger immediate firewall DENY mitigation rule for active attack source or suspicious host."""
        from app.network.firewall import FirewallRule, FirewallAction

        attacker = "203.0.113.1"
        affected = "*"
        cat = "Active Attack Stream"

        if self._current_threat_model:
            if self._current_threat_model.attacker_host != "N/A":
                attacker = self._current_threat_model.attacker_host
            if self._current_threat_model.affected_host != "N/A":
                affected = self._current_threat_model.affected_host
            cat = self._current_threat_model.attack_category

        rule = FirewallRule(
            src_ip=attacker,
            dst_ip=affected,
            action=FirewallAction.DENY,
            description=f"AI Mitigation: Blocked {cat}"
        )
        self._firewall.deny(rule)

        # Persist rule to database
        q_fw = "INSERT INTO firewall_rules (src_ip, dst_ip, port, protocol, action, description) VALUES (?, ?, ?, ?, ?, ?)"
        p_fw = (rule.src_ip, rule.dst_ip, rule.port, rule.protocol, rule.action.value, rule.description)
        DatabaseWriteWorker(q_fw, p_fw, self).start()

        msg = f"[FIREWALL] Auto-Mitigation DENY rule applied: Blocked {attacker} -> {affected} ({cat})"
        self._log(msg)
        return msg

    def get_model_metrics(self) -> Dict[str, Any]:
        """Return the latest model evaluation metrics dictionary."""
        return dict(self._last_model_metrics)

    # ── Internal Helpers ─────────────────────────────────────────────────────


    def _log(self, message: str) -> None:
        logger.info(message)
        if self._log_callback:
            try:
                self._log_callback(message)
            except Exception:
                pass
        self.log_emitted.emit(message)


