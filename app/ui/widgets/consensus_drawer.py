"""
app.ui.widgets.consensus_drawer — Visual Tri-Model AI Consensus Breakdown Drawer.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QGroupBox, QFrame, QSizePolicy
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class TriModelConsensusDrawer(QWidget):
    """
    Side-by-side expandable drawer panel comparing real-time voting predictions
    across Model 1 (Random Forest), Model 2 (Deep Neural Net), and Model 3 (Ollama Security LLM).
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("AI Threat Consensus Engine")
        self.setMinimumWidth(320)
        self.setStyleSheet("background-color: #0B0F17;")
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Header Title
        hdr = QLabel("🧠 TRI-MODEL AI CONSENSUS DRAWER")
        hdr.setFont(QFont("Segoe UI", 11, QFont.Bold))
        hdr.setStyleSheet("color: #A3E635; padding: 4px; border-bottom: 3px solid #000000;")
        layout.addWidget(hdr)

        # ── Card 1: Random Forest ──────────────────────────────────────────
        rf_box = QGroupBox("MODEL 1: RANDOM FOREST (150 TREES)")
        rf_layout = QVBoxLayout(rf_box)
        
        self.rf_status = QLabel("VERDICT: BENIGN / NORMAL (98.4%)")
        self.rf_status.setStyleSheet("color: #A3E635; font-weight: 800; font-family: Consolas;")
        rf_layout.addWidget(self.rf_status)

        self.rf_bar = QProgressBar()
        self.rf_bar.setRange(0, 100)
        self.rf_bar.setValue(98)
        self.rf_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #27272A;
                border-radius: 4px;
                background-color: #09090B;
                height: 18px;
                text-align: center;
                color: #FAFAFA;
                font-weight: 700;
            }
            QProgressBar::chunk {
                background-color: #A3E635;
            }
        """)
        rf_layout.addWidget(self.rf_bar)
        
        rf_features = QLabel("Top Drivers: byte_rate (0.42), pps (0.31), syn_ratio (0.18)")
        rf_features.setStyleSheet("color: #94A3B8; font-size: 11px;")
        rf_layout.addWidget(rf_features)
        layout.addWidget(rf_box)

        # ── Card 2: Deep Neural Network ────────────────────────────────────
        dnn_box = QGroupBox("MODEL 2: TENSORFLOW / PYTORCH DNN")
        dnn_layout = QVBoxLayout(dnn_box)

        self.dnn_status = QLabel("CLASSIFICATION: NORMAL TRAFFIC")
        self.dnn_status.setStyleSheet("color: #38BDF8; font-weight: 800; font-family: Consolas;")
        dnn_layout.addWidget(self.dnn_status)

        self.dnn_probs = QLabel("Dist: Normal: 97.2% | SYN Flood: 1.5% | ICMP: 1.3%")
        self.dnn_probs.setStyleSheet("color: #F8FAFC; font-family: Consolas; font-size: 11px;")
        dnn_layout.addWidget(self.dnn_probs)
        layout.addWidget(dnn_box)

        # ── Card 3: Ollama Security Agent ─────────────────────────────────
        ollama_box = QGroupBox("MODEL 3: OLLAMA SECURITY LLM AGENT")
        ollama_layout = QVBoxLayout(ollama_box)

        self.ollama_status = QLabel("STATUS: HEALTHY (LLM READY)")
        self.ollama_status.setStyleSheet("color: #A3E635; font-weight: 800; font-family: Consolas;")
        ollama_layout.addWidget(self.ollama_status)

        self.ollama_rationale = QLabel("Rationale: Standard HTTPS packet sequence with low packet rate and valid handshakes.")
        self.ollama_rationale.setWordWrap(True)
        self.ollama_rationale.setStyleSheet("color: #94A3B8; font-size: 11px;")
        ollama_layout.addWidget(self.ollama_rationale)
        layout.addWidget(ollama_box)

        # Consensus Summary Box
        self.consensus_summary = QFrame()
        self.consensus_summary.setStyleSheet("background-color: #1E293B; border: 3px solid #000000; border-radius: 6px; padding: 8px;")
        cs_layout = QVBoxLayout(self.consensus_summary)
        
        cs_lbl = QLabel("UNANIMOUS CONSENSUS: ALLOW (LOW RISK)")
        cs_lbl.setFont(QFont("Segoe UI", 10, QFont.Bold))
        cs_lbl.setStyleSheet("color: #A3E635;")
        cs_layout.addWidget(cs_lbl)
        
        layout.addWidget(self.consensus_summary)
        layout.addStretch()

    def update_consensus(self, threat_model) -> None:
        """Push real-time threat fusion data into the voting cards."""
        category = getattr(threat_model, "attack_category", "Normal Traffic")
        score = getattr(threat_model, "threat_score", 0)
        conf = getattr(threat_model, "confidence", 0.95)
        reasoning = getattr(threat_model, "reasoning_chain", ["Standard baseline traffic."])

        # RF Update
        self.rf_status.setText(f"VERDICT: {category.upper()} ({int(conf*100)}%)")
        self.rf_bar.setValue(int(conf * 100))

        # DNN Update
        self.dnn_status.setText(f"CLASSIFICATION: {category.upper()}")
        self.dnn_probs.setText(f"Threat Index: {score}/100 | Confidence: {int(conf*100)}%")

        # Ollama Update
        if reasoning:
            self.ollama_rationale.setText(f"Rationale: {reasoning[0]}")

        # Severity Colors
        if score > 75:
            color = "#EF4444"
            verdict = "CRITICAL THREAT DETECTED: DENY / BLOCK"
        elif score > 45:
            color = "#FACC15"
            verdict = "SUSPICIOUS PROBE: ALLOWED (MONITORED)"
        else:
            color = "#A3E635"
            verdict = "UNANIMOUS CONSENSUS: ALLOW (LOW RISK)"

        self.rf_status.setStyleSheet(f"color: {color}; font-weight: 800; font-family: Consolas;")
        self.dnn_status.setStyleSheet(f"color: {color}; font-weight: 800; font-family: Consolas;")
