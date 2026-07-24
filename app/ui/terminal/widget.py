"""
app.ui.terminal.widget — Interactive terminal console widget.

Wires CommandParser for real command execution.
Features:
  - Black background, blue-tinted text (enterprise hacker aesthetic)
  - Command history with Up/Down arrow navigation
  - Real CommandParser dispatching (no inline mock logic)
  - Output color-coded: blue for normal, green for success, red for errors
"""

from __future__ import annotations

import logging
from typing import List, Optional

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit, QLineEdit, QLabel, QSizePolicy
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QKeyEvent, QResizeEvent

logger = logging.getLogger("TerminalWidget")

_BANNER = """\
╔═══════════════════════════════════════════════════════════════╗
║          ThreatArchitect  —  Network Emulation Shell          ║
║                    Phase 2  |  v2.0.0                         ║
╚═══════════════════════════════════════════════════════════════╝
  Type  help  for commands   •   Ctrl+R start   •   Ctrl+C stop
"""


class TerminalWidget(QWidget):
    """
    Interactive command-line terminal console.

    Forwards commands to an injected CommandParser and renders output.
    Supports command history via Up/Down arrow keys.
    """

    def __init__(self, command_parser=None, parent=None) -> None:
        super().__init__(parent)
        self._parser = command_parser
        self._history: List[str] = []
        self._history_idx: int = -1
        self._init_ui()
        self._print_banner()

    # ── Construction ─────────────────────────────────────────────────────────

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(3)

        # Output area — expands to fill all available space
        self.output_area = QPlainTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.output_area.setStyleSheet("""
            QPlainTextEdit {
                background-color: #000000;
                color: #38BDF8;
                border: 1px solid #27272A;
                border-radius: 6px;
                selection-background-color: #A3E635;
                selection-color: #000000;
                font-family: 'Consolas', 'Fira Code', monospace;
                font-size: 13px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.output_area, 1)

        # Input row — sits at the bottom, auto-height
        input_row = QHBoxLayout()
        input_row.setContentsMargins(4, 4, 4, 4)
        input_row.setSpacing(6)

        self._prompt_lbl = QLabel("threat@architect:~$")
        self._prompt_lbl.setStyleSheet("color: #A3E635; background: transparent; font-weight: 800;")
        self._prompt_lbl.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.cmd_input = _HistoryLineEdit(self)
        self.cmd_input.setStyleSheet("""
            QLineEdit {
                background-color: #09090B;
                color: #FAFAFA;
                border: 1px solid #27272A;
                border-radius: 6px;
                padding: 6px 12px;
                font-family: 'Consolas', 'Fira Code', monospace;
                font-weight: 600;
            }
            QLineEdit:focus {
                border: 1px solid #A3E635;
            }
        """)
        self.cmd_input.returnPressed.connect(self._on_enter)
        self.cmd_input.history_up.connect(self._history_up)
        self.cmd_input.history_down.connect(self._history_down)

        input_row.addWidget(self._prompt_lbl)
        input_row.addWidget(self.cmd_input, 1)
        layout.addLayout(input_row)

        self.setStyleSheet("background-color: #0B0F17; border: 3px solid #000000;")
        self._font_pt = 9   # Current font size in pt
        self._update_fonts(self._font_pt)

    def _print_banner(self) -> None:
        self.output_area.appendPlainText(_BANNER)

    # ── Command Execution ─────────────────────────────────────────────────────

    def set_command_parser(self, parser) -> None:
        """Inject or replace the CommandParser at runtime."""
        self._parser = parser

    def _on_enter(self) -> None:
        raw = self.cmd_input.text().strip()
        self.cmd_input.clear()
        if not raw:
            return

        # Echo the command
        self._print_line(f"threat@architect:~$ {raw}", color="#22C55E")

        # Record history
        if raw not in self._history:
            self._history.append(raw)
        self._history_idx = -1

        # Dispatch
        if self._parser:
            result = self._parser.parse_and_execute(raw)

            if result.action == "clear":
                self.output_area.clear()
                self._print_banner()
                return

            color = "#4F8EF7" if result.success else "#EF4444"
            if result.output:
                self._print_line(result.output, color=color)
        else:
            # Fallback if parser not yet injected
            self._print_line(f"No command parser connected. Command: {raw}", color="#FACC15")

        self._print_line("")
        self._scroll_to_bottom()

    # ── Public API ────────────────────────────────────────────────────────────

    def print_log(self, message: str) -> None:
        """Print a log message from the network layer to the terminal."""
        line = message.strip() if (message.startswith("▸") or message.startswith("  ▸")) else f"  ▸ {message}"
        color = "#94A3B8"
        if "BLOCKED" in message:
            color = "#EF4444"
        elif "MONITORED" in message:
            color = "#FACC15"
        elif "ALLOWED" in message:
            color = "#22C55E"
        elif message.startswith("Simulation:") or message.startswith("Topology"):
            color = "#38BDF8"

        self._print_line(line, color=color)
        self._scroll_to_bottom()


    def print_success(self, message: str) -> None:
        self._print_line(f"  ✔ {message}", color="#22C55E")
        self._scroll_to_bottom()

    def print_error(self, message: str) -> None:
        self._print_line(f"  ✖ {message}", color="#EF4444")
        self._scroll_to_bottom()

    # ── History ───────────────────────────────────────────────────────────────

    def _history_up(self) -> None:
        if not self._history:
            return
        if self._history_idx == -1:
            self._history_idx = len(self._history) - 1
        elif self._history_idx > 0:
            self._history_idx -= 1
        self.cmd_input.setText(self._history[self._history_idx])

    def _history_down(self) -> None:
        if self._history_idx == -1:
            return
        self._history_idx += 1
        if self._history_idx >= len(self._history):
            self._history_idx = -1
            self.cmd_input.clear()
        else:
            self.cmd_input.setText(self._history[self._history_idx])

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _print_line(self, text: str, color: str = "#4F8EF7") -> None:
        """Append a colored HTML line. Font size tracks self._font_pt."""
        escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        formatted = escaped.replace("\n", "<br>")
        pt = self._font_pt
        html = (
            f'<span style="color:{color}; font-family:Consolas,monospace; '
            f'font-size:{pt}pt;">{formatted}</span>'
        )
        self.output_area.appendHtml(html)

    def _scroll_to_bottom(self) -> None:
        sb = self.output_area.verticalScrollBar()
        sb.setValue(sb.maximum())

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Scale terminal font relative to the panel width."""
        super().resizeEvent(event)
        w = event.size().width()
        # Font: 9pt at 400px wide, scales up to 10pt at 600px, down to 8pt at 280px
        pt = max(7, min(10, 7 + (w - 240) // 120))
        if pt != self._font_pt:
            self._font_pt = pt
            self._update_fonts(pt)

    def _update_fonts(self, pt: int) -> None:
        f = QFont("Consolas", pt)
        self.output_area.setFont(f)
        self.cmd_input.setFont(f)
        self._prompt_lbl.setFont(QFont("Consolas", pt, QFont.Bold))

    def focusInEvent(self, event) -> None:
        self.cmd_input.setFocus()
        super().focusInEvent(event)


class _HistoryLineEdit(QLineEdit):
    """QLineEdit that emits Up/Down signals for history navigation."""

    from PySide6.QtCore import Signal
    history_up   = Signal()
    history_down = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key_Up:
            self.history_up.emit()
        elif event.key() == Qt.Key_Down:
            self.history_down.emit()
        else:
            super().keyPressEvent(event)
