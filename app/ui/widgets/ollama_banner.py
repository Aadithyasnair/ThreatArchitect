from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class OllamaBanner(QFrame):
    """Warning banner displayed when local Ollama instance is not detected."""
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("OllamaBanner")
        self._init_ui()
        
    def _init_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(12)
        
        # Warning icon/text
        self.msg_label = QLabel("⚠️  <b>Ollama is not running locally.</b> AI features will be disabled. Please start Ollama (`ollama serve`) to enable threat model explaining.")
        self.msg_label.setFont(QFont("Segoe UI", 10))
        self.msg_label.setStyleSheet("color: #000000; background: transparent;")
        layout.addWidget(self.msg_label)
        
        layout.addStretch()
        
        # Close button
        self.close_btn = QPushButton("Dismiss")
        self.close_btn.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 0, 0, 0.15);
                border: 1px solid rgba(0, 0, 0, 0.3);
                border-radius: 4px;
                color: #000000;
                padding: 4px 10px;
            }
            QPushButton:hover {
                background-color: rgba(0, 0, 0, 0.25);
            }
        """)
        self.close_btn.clicked.connect(self.close)
        layout.addWidget(self.close_btn)
        
        # Styled warning look
        self.setStyleSheet("""
            QFrame#OllamaBanner {
                background-color: #FACC15; /* Warning yellow */
                border-bottom: 1px solid #D9A406;
            }
        """)
        self.setFixedHeight(40)
        
    def show_alert(self) -> None:
        self.show()
        
    def hide_alert(self) -> None:
        self.hide()
