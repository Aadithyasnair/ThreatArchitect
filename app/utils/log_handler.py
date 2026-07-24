import logging
from PySide6.QtCore import QObject, Signal

class LogSignalEmitter(QObject):
    """QObject to safely emit log records to the Qt UI main loop."""
    log_emitted = Signal(logging.LogRecord)

class UILogHandler(logging.Handler):
    """Custom logging handler that forwards records to a Qt Signal."""
    
    def __init__(self) -> None:
        super().__init__()
        self.emitter = LogSignalEmitter()
        
    def emit(self, record: logging.LogRecord) -> None:
        # Format message if not already formatted
        if record.msg and not record.message:
            try:
                record.message = record.getMessage()
            except Exception:
                record.message = str(record.msg)
        self.emitter.log_emitted.emit(record)
