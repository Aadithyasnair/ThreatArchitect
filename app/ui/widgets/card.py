from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class MetricCard(QFrame):
    """Reusable metric card component matching visual requirements (rounded, surface colors)."""
    
    def __init__(self, title: str, value: str, trend: str = "", parent = None) -> None:
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.setFrameShape(QFrame.StyledPanel)
        self._init_ui(title, value, trend)
        
    def _init_ui(self, title: str, value: str, trend: str) -> None:
        # Layouts
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        
        # Header (Title)
        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Segoe UI", 10, QFont.Medium))
        self.title_label.setStyleSheet("color: #94A3B8; background: transparent;") # soft text
        layout.addWidget(self.title_label)
        
        # Content Row (Value + Trend)
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        
        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self.value_label.setStyleSheet("color: #F8FAFC; background: transparent;")
        content_layout.addWidget(self.value_label)
        
        content_layout.addStretch()
        
        if trend:
            self.trend_label = QLabel(trend)
            self.trend_label.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
            if "+" in trend or "Normal" in trend or "Green" in trend:
                self.trend_label.setStyleSheet("color: #22C55E; background: transparent; padding: 2px 6px; border-radius: 4px;")
            elif "-" in trend or "Warning" in trend:
                self.trend_label.setStyleSheet("color: #FACC15; background: transparent; padding: 2px 6px; border-radius: 4px;")
            else:
                self.trend_label.setStyleSheet("color: #EF4444; background: transparent; padding: 2px 6px; border-radius: 4px;")
            content_layout.addWidget(self.trend_label)
            
        layout.addLayout(content_layout)
        
        # Style sheet override for rounded panel glassmorphism look
        self.setStyleSheet("""
            QFrame#MetricCard {
                background-color: #151E2F;
                border: 1px solid #2A364F;
                border-radius: 8px;
            }
            QFrame#MetricCard:hover {
                border-color: #4F8EF7;
            }
        """)

    def update_value(self, value: str, trend: str = None) -> None:
        """Update value and optionally trend label."""
        self.value_label.setText(value)
        if trend and hasattr(self, 'trend_label'):
            self.trend_label.setText(trend)
            if "+" in trend or "Normal" in trend or "Green" in trend:
                self.trend_label.setStyleSheet("color: #22C55E; background: transparent;")
            elif "-" in trend or "Warning" in trend:
                self.trend_label.setStyleSheet("color: #FACC15; background: transparent;")
            else:
                self.trend_label.setStyleSheet("color: #EF4444; background: transparent;")
