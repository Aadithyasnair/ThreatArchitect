from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QCheckBox, QLabel, QComboBox, QFileDialog, QMessageBox
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from app.ui.widgets.status_badge import SectionHeader

class ReportsPanel(QWidget):
    """UI panel controlling compilation, formatting, and generation of PDF/HTML reports."""
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._init_ui()
        
    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        
        header = SectionHeader("REPORT GENERATOR (PHASE 5 STUB)")
        layout.addWidget(header)
        
        info_lbl = QLabel("Configure parameters below to generate deterministic security reports locally.")
        info_lbl.setFont(QFont("Segoe UI", 9))
        info_lbl.setStyleSheet("color: #94A3B8; background: transparent;")
        info_lbl.setWordWrap(True)
        layout.addWidget(info_lbl)
        
        # Report format selection
        fmt_lbl = QLabel("Report Format:")
        fmt_lbl.setFont(QFont("Segoe UI", 9, QFont.Bold))
        fmt_lbl.setStyleSheet("color: #F8FAFC; background: transparent;")
        layout.addWidget(fmt_lbl)
        
        self.fmt_combo = QComboBox()
        self.fmt_combo.addItems(["PDF Security Report (Recommended)", "HTML Compliance Sheet", "JSON Raw Telemetry Log"])
        self.fmt_combo.setStyleSheet("""
            QComboBox {
                background-color: #0B1220;
                color: #F8FAFC;
                border: 1px solid #2A364F;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        layout.addWidget(self.fmt_combo)
        
        # Modules inclusion checkboxes
        opts_lbl = QLabel("Include Sections:")
        opts_lbl.setFont(QFont("Segoe UI", 9, QFont.Bold))
        opts_lbl.setStyleSheet("color: #F8FAFC; background: transparent;")
        layout.addWidget(opts_lbl)
        
        self.cb_topology = QCheckBox("Virtual Topology Map Layout")
        self.cb_topology.setChecked(True)
        self.cb_topology.setStyleSheet("color: #F8FAFC; background: transparent;")
        
        self.cb_threats = QCheckBox("Deep Learning Telemetry & ML Threat Analysis")
        self.cb_threats.setChecked(True)
        self.cb_threats.setStyleSheet("color: #F8FAFC; background: transparent;")
        
        self.cb_compliance = QCheckBox("Industry Framework Compliance Audit Checklist")
        self.cb_compliance.setChecked(True)
        self.cb_compliance.setStyleSheet("color: #F8FAFC; background: transparent;")
        
        self.cb_remedy = QCheckBox("AI Remediation Generated Commands list")
        self.cb_remedy.setChecked(True)
        self.cb_remedy.setStyleSheet("color: #F8FAFC; background: transparent;")
        
        layout.addWidget(self.cb_topology)
        layout.addWidget(self.cb_threats)
        layout.addWidget(self.cb_compliance)
        layout.addWidget(self.cb_remedy)
        
        # Action button
        self.gen_btn = QPushButton("Generate Local Report")
        self.gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #4F8EF7;
                color: #FFFFFF;
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3B7AD4;
            }
        """)
        self.gen_btn.clicked.connect(self._on_generate_clicked)
        layout.addWidget(self.gen_btn)
        
        layout.addStretch()
        self.setStyleSheet("background-color: #151E2F; border: 1px solid #2A364F; border-radius: 8px;")

    def _on_generate_clicked(self) -> None:
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save ThreatArchitect Report",
            "ThreatArchitect_Security_Report.pdf",
            "PDF Files (*.pdf);;HTML Files (*.html);;JSON Files (*.json)"
        )
        if save_path:
            QMessageBox.information(
                self,
                "Report Generation Successful",
                f"Report saved to:\n{save_path}\n\nNote: This is a design mock. Full local ReportLab processing triggers in Phase 5."
            )
            # Future hooks for report generation logic will trigger here.
