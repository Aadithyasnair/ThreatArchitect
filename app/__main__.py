import sys
from PySide6.QtWidgets import QApplication
from app.bootstrap import ApplicationBootstrap

def main() -> None:
    """Application entry point."""
    app = QApplication(sys.argv)
    
    # Launch bootstrap sequence
    _main_win = ApplicationBootstrap.start_application()
    
    # Start Qt Event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
