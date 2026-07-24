import logging
from PySide6.QtWidgets import QPlainTextEdit
from PySide6.QtGui import QColor, QTextCharFormat, QFont
from app.utils.logging_manager import LoggingManager

class LogView(QPlainTextEdit):
    """Real-time scrolling event log viewer. Color-coded log levels."""
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0B1220;
                color: #F8FAFC;
                border: 1px solid #2A364F;
                border-radius: 6px;
            }
        """)
        
        # Subscribe to logging records
        self._ui_handler = LoggingManager.get_ui_handler()
        self._ui_handler.emitter.log_emitted.connect(self.append_log_record)

    def append_log_record(self, record: logging.LogRecord) -> None:
        """Process log records and append formatted colored text."""
        formatted_message = self._ui_handler.format(record)
        
        # Save character format
        orig_fmt = self.currentCharFormat()
        
        # Apply color based on log level
        new_fmt = QTextCharFormat()
        if record.levelno >= logging.ERROR:
            new_fmt.setForeground(QColor("#EF4444")) # Red
        elif record.levelno >= logging.WARNING:
            new_fmt.setForeground(QColor("#FACC15")) # Yellow
        elif record.levelno >= logging.INFO:
            new_fmt.setForeground(QColor("#F8FAFC")) # White/Soft White
        else:
            new_fmt.setForeground(QColor("#5A6A85")) # Muted Blue/Gray for debug
            
        self.setCurrentCharFormat(new_fmt)
        self.appendPlainText(formatted_message)
        
        # Restore character format
        self.setCurrentCharFormat(orig_fmt)
        
        # Auto-scroll to bottom
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
