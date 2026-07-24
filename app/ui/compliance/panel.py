from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from app.ui.widgets.status_badge import SectionHeader, StatusBadge

class ComplianceFrameworkRow(QWidget):
    """Row widget representing compliance coverage status for a single framework standard."""
    
    def __init__(self, name: str, percentage: int, status: str, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(6)
        
        info_layout = QHBoxLayout()
        
        lbl_name = QLabel(name)
        lbl_name.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl_name.setStyleSheet("color: #F8FAFC; background: transparent;")
        info_layout.addWidget(lbl_name)
        
        info_layout.addStretch()
        
        self.badge = StatusBadge(status, status)
        info_layout.addWidget(self.badge)
        
        layout.addLayout(info_layout)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setValue(percentage)
        self.progress.setTextVisible(True)
        self.progress.setFormat("%p% Coverage")
        self.progress.setFixedHeight(16)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #0B1220;
                border: 1px solid #2A364F;
                border-radius: 4px;
                text-align: center;
                color: #F8FAFC;
                font-weight: bold;
                font-size: 10px;
            }
            QProgressBar::chunk {
                background-color: #4F8EF7;
                border-radius: 3px;
            }
        """)
        if status.lower() == "success" or status.lower() == "green":
            self.progress.setStyleSheet(self.progress.styleSheet() + " QProgressBar::chunk { background-color: #22C55E; }")
        elif status.lower() == "warning" or status.lower() == "yellow":
            self.progress.setStyleSheet(self.progress.styleSheet() + " QProgressBar::chunk { background-color: #FACC15; }")
            
        layout.addWidget(self.progress)
        
        # Bottom light separator
        separator = QWidget()
        separator.setFixedHeight(1)
        separator.setStyleSheet("background-color: #2A364F;")
        layout.addWidget(separator)

class CompliancePanel(QWidget):
    """Right-side panel evaluating current network configs against industry standards."""
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._init_ui()
        
    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        
        header = SectionHeader("STANDARDS COMPLIANCE")
        layout.addWidget(header)
        
        # Frameworks stack
        self.nist_row = ComplianceFrameworkRow("NIST SP 800-53", 92, "success")
        self.iso_row = ComplianceFrameworkRow("ISO/IEC 27001", 85, "success")
        self.pci_row = ComplianceFrameworkRow("PCI-DSS v4.0", 68, "warning")
        self.soc_row = ComplianceFrameworkRow("SOC 2 Type II", 90, "success")
        
        layout.addWidget(self.nist_row)
        layout.addWidget(self.iso_row)
        layout.addWidget(self.pci_row)
        layout.addWidget(self.soc_row)
        
        # Compliance summary card
        summary_widget = QWidget()
        summary_widget.setStyleSheet("""
            QWidget {
                background-color: #0B1220;
                border: 1px solid #2A364F;
                border-radius: 6px;
            }
        """)
        summary_layout = QVBoxLayout(summary_widget)
        summary_layout.setContentsMargins(8, 8, 8, 8)
        
        summary_title = QLabel("COMPLIANCE HIGHLIGHTS")
        summary_title.setFont(QFont("Segoe UI", 9, QFont.Bold))
        summary_title.setStyleSheet("color: #4F8EF7; border: none; background: transparent;")
        summary_layout.addWidget(summary_title)
        
        summary_txt = QLabel("PCI-DSS alert: Database cluster 'db_prod' lacks port firewall policy restricts. Generate firewall configuration recommendations to fix.")
        summary_txt.setFont(QFont("Segoe UI", 9))
        summary_txt.setStyleSheet("color: #F8FAFC; border: none; background: transparent;")
        summary_txt.setWordWrap(True)
        summary_layout.addWidget(summary_txt)
        
        layout.addWidget(summary_widget)
        
        layout.addStretch()
        self.setStyleSheet("background-color: #151E2F; border-left: 1px solid #2A364F;")
