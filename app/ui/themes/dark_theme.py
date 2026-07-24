from PySide6.QtGui import QPalette, QColor
from app.ui.themes.palette import ThemePalette

class DarkTheme:
    """Builds QPalette and Ultra OLED Dark stylesheet for ThreatArchitect."""
    
    @staticmethod
    def get_q_palette(palette: ThemePalette) -> QPalette:
        """Create a standard QPalette for system dialogs / base fallbacks."""
        qp = QPalette()
        bg = QColor("#000000")
        surf = QColor("#09090B")
        text = QColor("#FAFAFA")
        accent = QColor("#A3E635")
        
        qp.setColor(QPalette.Window, bg)
        qp.setColor(QPalette.WindowText, text)
        qp.setColor(QPalette.Base, surf)
        qp.setColor(QPalette.AlternateBase, bg)
        qp.setColor(QPalette.ToolTipBase, surf)
        qp.setColor(QPalette.ToolTipText, text)
        qp.setColor(QPalette.Text, text)
        qp.setColor(QPalette.Button, surf)
        qp.setColor(QPalette.ButtonText, text)
        qp.setColor(QPalette.Highlight, accent)
        qp.setColor(QPalette.HighlightedText, QColor("#000000"))
        
        return qp

    @staticmethod
    def get_stylesheet(palette: ThemePalette) -> str:
        """Build full Ultra OLED Cyber Dark enterprise QSS stylesheet."""
        return """
        /* ── Base Application & Ultra OLED Dark Global Styling ── */
        QWidget {
            background-color: #000000;
            color: #FAFAFA;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            font-size: 13px;
        }

        QMainWindow {
            background-color: #000000;
        }

        /* ── Splitters ── */
        QSplitter::handle {
            background-color: #18181B;
        }
        QSplitter::handle:horizontal {
            width: 3px;
        }
        QSplitter::handle:vertical {
            height: 3px;
        }
        QSplitter::handle:hover {
            background-color: #A3E635;
        }

        /* ── Scrollbars ── */
        QScrollBar:vertical {
            border: 1px solid #27272A;
            background-color: #000000;
            width: 10px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background-color: #27272A;
            min-height: 24px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #A3E635;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            border: none;
            background: none;
            height: 0px;
        }
        QScrollBar:horizontal {
            border: 1px solid #27272A;
            background-color: #000000;
            height: 10px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background-color: #27272A;
            min-width: 24px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal:hover {
            background-color: #A3E635;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            border: none;
            background: none;
            width: 0px;
        }

        /* ── ToolBar ── */
        QToolBar {
            background-color: #09090B;
            border-bottom: 1px solid #27272A;
            padding: 6px 12px;
            spacing: 8px;
        }
        QToolButton {
            background-color: #18181B;
            border: 1px solid #27272A;
            border-radius: 6px;
            padding: 6px 14px;
            font-weight: 700;
            font-size: 12px;
            color: #FAFAFA;
        }
        QToolButton:hover {
            background-color: #27272A;
            border-color: #A3E635;
            color: #A3E635;
        }
        QToolButton:pressed {
            background-color: #A3E635;
            color: #000000;
        }

        /* ── Menu Bar ── */
        QMenuBar {
            background-color: #09090B;
            border-bottom: 1px solid #27272A;
            padding: 4px;
            font-weight: 600;
        }
        QMenuBar::item {
            background-color: transparent;
            padding: 6px 12px;
            border-radius: 4px;
        }
        QMenuBar::item:selected {
            background-color: #18181B;
            color: #A3E635;
            border: 1px solid #27272A;
        }
        QMenu {
            background-color: #09090B;
            border: 1px solid #27272A;
            border-radius: 6px;
            padding: 6px;
        }
        QMenu::item {
            padding: 8px 24px;
            border-radius: 4px;
            font-weight: 500;
        }
        QMenu::item:selected {
            background-color: #18181B;
            color: #38BDF8;
        }

        /* ── Dock Widgets ── */
        QDockWidget {
            border: 1px solid #27272A;
            background-color: #09090B;
        }
        QDockWidget::title {
            background-color: #09090B;
            padding: 10px;
            border-bottom: 1px solid #27272A;
            font-weight: 800;
            font-size: 12px;
            color: #A3E635;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* ── GroupBox / Cards ── */
        QGroupBox {
            background-color: #09090B;
            border: 1px solid #27272A;
            border-radius: 8px;
            margin-top: 16px;
            padding: 16px;
            font-weight: 700;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 14px;
            padding: 2px 8px;
            background-color: #18181B;
            color: #A3E635;
            border: 1px solid #27272A;
            border-radius: 4px;
            font-weight: 800;
        }

        /* ── OLED PushButtons ── */
        QPushButton {
            background-color: #18181B;
            border: 1px solid #27272A;
            border-radius: 6px;
            padding: 8px 18px;
            color: #FAFAFA;
            font-weight: 700;
            font-size: 13px;
        }
        QPushButton:hover {
            background-color: #27272A;
            border-color: #A3E635;
            color: #A3E635;
        }
        QPushButton:pressed {
            background-color: #A3E635;
            color: #000000;
        }
        QPushButton:disabled {
            color: #52525B;
            background-color: #09090B;
            border-color: #18181B;
        }

        /* ── Input Fields ── */
        QLineEdit, QPlainTextEdit, QTextEdit {
            background-color: #09090B;
            border: 1px solid #27272A;
            border-radius: 6px;
            padding: 8px;
            color: #FAFAFA;
            font-family: 'Consolas', 'Fira Code', monospace;
            font-size: 13px;
            selection-background-color: #A3E635;
            selection-color: #000000;
        }
        QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {
            border: 1px solid #A3E635;
        }

        /* ── Status Bar ── */
        QStatusBar {
            background-color: #09090B;
            border-top: 1px solid #27272A;
            color: #A1A1AA;
            font-weight: 600;
        }
        
        /* ── Tab Widget ── */
        QTabWidget::panel {
            border: 1px solid #27272A;
            border-radius: 6px;
            background-color: #09090B;
        }
        QTabBar::tab {
            background-color: #09090B;
            border: 1px solid #27272A;
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            padding: 8px 18px;
            margin-right: 4px;
            color: #A1A1AA;
            font-weight: 700;
        }
        QTabBar::tab:selected {
            background-color: #18181B;
            color: #A3E635;
            border: 1px solid #27272A;
            border-bottom: 2px solid #A3E635;
        }
        QTabBar::tab:hover:!selected {
            background-color: #18181B;
            color: #FAFAFA;
        }

        /* ── Table & Tree Headers ── */
        QHeaderView::section {
            background-color: #09090B;
            color: #A3E635;
            font-weight: 800;
            padding: 8px;
            border: 1px solid #27272A;
            text-transform: uppercase;
        }
        QTableWidget {
            background-color: #09090B;
            border: 1px solid #27272A;
            gridline-color: #18181B;
        }
        """
