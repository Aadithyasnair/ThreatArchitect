from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class StatusBadge(QLabel):
    """Pill badge showing statuses like Success, Warning, or Critical."""
    
    def __init__(self, text: str, status_level: str = "neutral", parent = None) -> None:
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.set_status(text, status_level)
        
    def set_status(self, text: str, status_level: str) -> None:
        """Update text and colors of status badge."""
        self.setText(text.upper())
        status_level = status_level.lower()
        
        # Style mapping
        if status_level == "success" or status_level == "green":
            bg = "#1B3A24"
            fg = "#22C55E"
            border = "#2E5D3A"
        elif status_level == "warning" or status_level == "yellow":
            bg = "#3A351B"
            fg = "#FACC15"
            border = "#5D542E"
        elif status_level == "critical" or status_level == "danger" or status_level == "red":
            bg = "#3A1B1B"
            fg = "#EF4444"
            border = "#5D2E2E"
        else: # neutral / blue
            bg = "#1B2A3A"
            fg = "#4F8EF7"
            border = "#2E475D"
            
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {border};
                border-radius: 12px;
                padding: 4px 10px;
                min-width: 80px;
            }}
        """)
        self.adjustSize()
class SectionHeader(QLabel):
    """Bold title widget with a clean divider rule."""
    
    def __init__(self, text: str, parent = None) -> None:
        super().__init__(text, parent)
        self.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.setStyleSheet("color: #4F8EF7; padding-bottom: 4px; border-bottom: 1px solid #2A364F;")
