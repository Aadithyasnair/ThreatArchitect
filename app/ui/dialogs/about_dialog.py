from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class AboutDialog(QDialog):
    """About dialog showing application details, authoring, and architectural mission statements."""
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About ThreatArchitect")
        self.resize(400, 220)
        self._init_ui()
        
    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # Title/Subtitle
        title_lbl = QLabel("ThreatArchitect")
        title_lbl.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title_lbl.setStyleSheet("color: #4F8EF7;")
        layout.addWidget(title_lbl)
        
        sub_lbl = QLabel("An AI-Powered Local Threat Modeling & Compliance Agent")
        sub_lbl.setFont(QFont("Segoe UI", 10, QFont.Bold))
        sub_lbl.setStyleSheet("color: #F8FAFC;")
        layout.addWidget(sub_lbl)
        
        # Details
        details_lbl = QLabel(
            "Version: 1.0 (Phase 1 Application Shell)\n"
            "Execution: 100% Local (Offline Safe)\n"
            "UI Framework: PySide6 (Qt for Python)\n\n"
            "This application emulates networks, sniffs network packets, detects anomalies, "
            "evaluates industry compliance, and generates remediation commands using local AI."
        )
        details_lbl.setFont(QFont("Segoe UI", 9))
        details_lbl.setStyleSheet("color: #94A3B8;")
        details_lbl.setWordWrap(True)
        layout.addWidget(details_lbl)
        
        # Close button row
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        close_btn = QPushButton("OK")
        close_btn.clicked.connect(self.accept)
        close_btn.setMinimumWidth(80)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
