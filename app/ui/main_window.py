"""
app.ui.main_window — Main application window. Fully responsive layout.

Layout:
  ┌─────────────────────────────────────────────────────────┐
  │  Left (Terminal, 30%)  │  Right (Topology Canvas, 70%)  │
  │                        │                                 │
  │  Black shell console   │  Network topology diagram       │
  │  CommandParser-wired   │  Premium node cards             │
  │                        │  Live packet animations         │
  ├────────────────────────┴─────────────────────────────────┤
  │  Dashboard stats strip (height = 13% of window)          │
  └─────────────────────────────────────────────────────────┘
  │  Status bar (1 line, auto-height)                        │
  └─────────────────────────────────────────────────────────┘

Everything scales when the window is resized.
"""

from __future__ import annotations

import logging
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QSplitter, QStatusBar, QLabel, QDialog, QDockWidget, QToolBar,
)
from PySide6.QtCore import Qt, QTimer, QSize
from PySide6.QtGui import QFont, QResizeEvent, QShortcut, QKeySequence, QAction

from app.config.models import AppConfig
from app.ui.topology.canvas import TopologyCanvas
from app.ui.dashboard.panel import DashboardPanel
from app.ui.terminal.widget import TerminalWidget
from app.ui.widgets.detection_panel import DetectionPanel
from app.ui.widgets.consensus_drawer import TriModelConsensusDrawer
from app.ui.widgets.cyber_fx import CRTScanlineOverlay, TacticalAudioEngine

from app.network.manager import NetworkManager
from app.network.command_parser import CommandParser
from app.network.workers import SimulationTickWorker

from app.ai.ollama.health import OllamaHealthChecker, OllamaStatus

logger = logging.getLogger("MainWindow")


class MainWindow(QMainWindow):
    """
    Main application shell — fully responsive to window size.
    All proportions are percentage-based, no fixed pixel sizes.
    """

    # Proportions (fractions of window dimensions)
    _TERMINAL_RATIO  = 0.30   # 30% of width
    _TOPOLOGY_RATIO  = 0.70   # 70% of width
    _DASH_HEIGHT_PCT = 0.13   # 13% of height for stats bar

    def __init__(
        self,
        config: AppConfig,
        network_manager: NetworkManager = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.config = config
        self._net_manager = network_manager or NetworkManager()

        self.setWindowTitle("ThreatArchitect — Network Emulation & Threat Modeling")
        self.resize(1400, 820)
        self.setMinimumSize(900, 540)
        self.setStyleSheet("background-color: #0B0F17;")

        self._init_services()
        self._init_ui()
        self._wire_signals()
        self._start_timers()

        logger.info("Main Window layout components initialized.")

    # ── Service Init ──────────────────────────────────────────────────────────

    def _init_services(self) -> None:
        self._command_parser = CommandParser(self._net_manager)
        self._net_manager.set_log_callback(self._on_network_log)
        self._net_manager.set_stats_callback(self._on_stats_update)
        self._net_manager.set_packet_callback(self._on_packet_generated)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _init_ui(self) -> None:
        self._build_toolbar()

        root = QWidget()
        self.setCentralWidget(root)

        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Horizontal splitter: Terminal | Topology ──────────────────────────
        self._main_splitter = QSplitter(Qt.Horizontal)
        self._main_splitter.setStyleSheet(
            "QSplitter::handle { background-color: #000000; width: 3px; }"
        )

        self.terminal = TerminalWidget(command_parser=self._command_parser)
        self.terminal.setMinimumWidth(240)
        self._main_splitter.addWidget(self.terminal)

        self.topology_canvas = TopologyCanvas()
        self._main_splitter.addWidget(self.topology_canvas)

        # Right: AI Threat Detection & Explainability Panel (collapsible)
        self.detection_panel = DetectionPanel()
        self.detection_panel.setVisible(False)
        self._main_splitter.addWidget(self.detection_panel)

        self._main_splitter.setCollapsible(0, False)
        self._main_splitter.setCollapsible(1, False)
        self._main_splitter.setCollapsible(2, True)
        self._main_splitter.setSizes([400, 1000, 0])

        root_layout.addWidget(self._main_splitter, 1)

        # ── Tri-Model AI Consensus Dockable Panel ─────────────────────────────
        self.consensus_drawer = TriModelConsensusDrawer()
        self.consensus_dock = QDockWidget("AI Consensus Engine", self)
        self.consensus_dock.setWidget(self.consensus_drawer)
        self.consensus_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        self.addDockWidget(Qt.RightDockWidgetArea, self.consensus_dock)
        self.consensus_dock.setVisible(False)

        # ── Dashboard strip (no fixed height — percentage set in resizeEvent) ─
        self.dashboard = DashboardPanel()
        root_layout.addWidget(self.dashboard)

        # ── Status bar ────────────────────────────────────────────────────────
        self._build_status_bar()

        # ── Keyboard shortcuts ────────────────────────────────────────────────
        self._register_shortcuts()

    def _build_toolbar(self) -> None:
        """Construct Neo-Brutalist quick action control toolbar."""
        tb = QToolBar("Emulation Controls", self)
        tb.setMovable(False)
        tb.setFloatable(False)

        # 🟢 Start Normal Emulation
        act_normal = QAction("🟢 Normal Traffic", self)
        act_normal.setStatusTip("Emulate legitimate HTTP/HTTPS/DNS traffic stream")
        act_normal.triggered.connect(self._shortcut_emulate_normal)
        tb.addAction(act_normal)

        # 🟡 Emulate Suspicious Probes
        act_susp = QAction("🟡 Emulate Suspicious", self)
        act_susp.setStatusTip("Emulate low-rate suspicious probes (Port scans / Ping sweeps)")
        act_susp.triggered.connect(lambda: self._command_parser.parse_and_execute("emulate suspicious"))
        tb.addAction(act_susp)

        # 🔴 Emulate Dangerous DDoS
        act_dang = QAction("🔴 Emulate Dangerous (DDoS)", self)
        act_dang.setStatusTip("Emulate high-impact volumetric attack (SYN Flood / ICMP Flood)")
        act_dang.triggered.connect(lambda: self._command_parser.parse_and_execute("emulate dangerous"))
        tb.addAction(act_dang)

        tb.addSeparator()

        # 🛑 Stop Network
        act_stop = QAction("🛑 Stop Simulation", self)
        act_stop.setStatusTip("Halt current emulation stream")
        act_stop.triggered.connect(self._shortcut_stop_network)
        tb.addAction(act_stop)

        # 🛡️ Auto-Mitigate
        act_mit = QAction("🛡️ Auto-Mitigate", self)
        act_mit.setStatusTip("Apply automatic firewall mitigation rule")
        act_mit.triggered.connect(lambda: self._command_parser.parse_and_execute("mitigate"))
        tb.addAction(act_mit)

        tb.addSeparator()

        # 🧠 Toggle AI Consensus
        act_ai = QAction("🧠 AI Consensus Engine", self)
        act_ai.setStatusTip("Toggle AI Consensus Voting Panel")
        act_ai.triggered.connect(lambda: self.consensus_dock.setVisible(not self.consensus_dock.isVisible()))
        tb.addAction(act_ai)

        # 🖥️ Compact / SOC Mode Toggle
        act_compact = QAction("🖥️ Toggle Simple/SOC View", self)
        act_compact.setStatusTip("Switch between clean focus view and detailed SOC panel view")
        act_compact.triggered.connect(self._toggle_compact_mode)
        tb.addAction(act_compact)

        self.addToolBar(Qt.TopToolBarArea, tb)

    def _toggle_compact_mode(self) -> None:
        """Toggle between clean focus mode and detailed SOC view."""
        is_visible = self.consensus_dock.isVisible() or self.detection_panel.isVisible()
        self.consensus_dock.setVisible(not is_visible)
        self.detection_panel.setVisible(False)

    def _register_shortcuts(self) -> None:
        """Register global keyboard shortcuts."""
        # Ctrl+C — stop network (mirrors 'stop network' command)
        sc_stop = QShortcut(QKeySequence("Ctrl+C"), self)
        sc_stop.setContext(Qt.ApplicationShortcut)
        sc_stop.activated.connect(self._shortcut_stop_network)

        # Ctrl+R — start/restart network
        sc_start = QShortcut(QKeySequence("Ctrl+R"), self)
        sc_start.setContext(Qt.ApplicationShortcut)
        sc_start.activated.connect(self._shortcut_start_network)

        # Ctrl+E — emulate normal
        sc_emulate = QShortcut(QKeySequence("Ctrl+E"), self)
        sc_emulate.setContext(Qt.ApplicationShortcut)
        sc_emulate.activated.connect(self._shortcut_emulate_normal)

        # Ctrl+L — clear terminal
        sc_clear = QShortcut(QKeySequence("Ctrl+L"), self)
        sc_clear.setContext(Qt.ApplicationShortcut)
        sc_clear.activated.connect(self._shortcut_clear)

        # Ctrl+G — toggle graph / detection panel
        sc_graph = QShortcut(QKeySequence("Ctrl+G"), self)
        sc_graph.setContext(Qt.ApplicationShortcut)
        sc_graph.activated.connect(self._toggle_detection_panel)

        # Ctrl+S — show settings configuration editor
        sc_settings = QShortcut(QKeySequence("Ctrl+S"), self)
        sc_settings.setContext(Qt.ApplicationShortcut)
        sc_settings.activated.connect(self._show_settings_dialog)

        # Ctrl+Shift+L — show partitioned rotating logs explorer dialog
        sc_logs = QShortcut(QKeySequence("Ctrl+Shift+L"), self)
        sc_logs.setContext(Qt.ApplicationShortcut)
        sc_logs.activated.connect(self._show_logs_dialog)

    def _toggle_detection_panel(self) -> None:
        """Toggle right-side threat graph and explainability panel."""
        is_visible = self.detection_panel.isVisible()
        self.detection_panel.setVisible(not is_visible)
        
        # Trigger resize adjustment manually
        w = self.width()
        terminal_w = int(w * self._TERMINAL_RATIO)
        remaining_w = w - terminal_w
        if not is_visible:
            self._main_splitter.setSizes([terminal_w, remaining_w - 340, 340])
        else:
            self._main_splitter.setSizes([terminal_w, remaining_w, 0])

    def _shortcut_stop_network(self) -> None:
        """Ctrl+C — stop the running network and simulation."""
        result = self._command_parser.parse_and_execute("stop network")
        self.terminal.print_log(f"[Ctrl+C] {result.output}")

    def _shortcut_start_network(self) -> None:
        """Ctrl+R — start the network."""
        result = self._command_parser.parse_and_execute("start network")
        self.terminal.print_log(f"[Ctrl+R] {result.output}")
        if result.action == "start_network":
            self.refresh_topology()

    def _shortcut_emulate_normal(self) -> None:
        """Ctrl+E — start emulate normal simulation."""
        result = self._command_parser.parse_and_execute("emulate normal")
        self.terminal.print_log(f"[Ctrl+E] {result.output}")

    def _shortcut_clear(self) -> None:
        """Ctrl+L — clear terminal."""
        self._command_parser.parse_and_execute("clear")
        self.terminal.output_area.clear()
        self.terminal._print_banner()

    def _build_status_bar(self) -> None:
        sb = QStatusBar()
        sb.setSizeGripEnabled(False)
        sb.setStyleSheet("""
            QStatusBar {
                background-color: #050B14;
                border-top: 1px solid #1E2D45;
                color: #4A6080;
                font-family: Consolas;
                font-size: 8pt;
                padding: 2px 0;
            }
        """)
        self.setStatusBar(sb)

        self._sb_network = QLabel("● OFFLINE")
        self._sb_network.setStyleSheet("color: #64748B; padding: 0 14px;")

        self._sb_sim = QLabel("SIM: IDLE")
        self._sb_sim.setStyleSheet("color: #4A6080; padding: 0 14px;")

        self._sb_packets = QLabel("PKT: 0 sent")
        self._sb_packets.setStyleSheet("color: #4A6080; padding: 0 14px;")

        self._sb_fw = QLabel("FW: 0 blocked")
        self._sb_fw.setStyleSheet("color: #4A6080; padding: 0 14px;")

        self._sb_mode = QLabel("ThreatArchitect v2.0  |  Phase 2  |  Simulation Mode")
        self._sb_mode.setStyleSheet("color: #1E3A5F; padding: 0 14px;")

        sb.addWidget(self._sb_network)
        sb.addWidget(self._sb_sim)
        sb.addWidget(self._sb_packets)
        sb.addWidget(self._sb_fw)
        sb.addPermanentWidget(self._sb_mode)

    # ── Responsive resize ─────────────────────────────────────────────────────

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Recalculate all proportional sizes when window is resized."""
        super().resizeEvent(event)
        w = event.size().width()
        h = event.size().height()

        # Splitter: Terminal 30% | Topology / Detection 70%
        terminal_w = int(w * self._TERMINAL_RATIO)
        remaining_w = w - terminal_w

        if self.detection_panel.isVisible():
            panel_w = 340
            topology_w = remaining_w - panel_w
            self._main_splitter.setSizes([terminal_w, topology_w, panel_w])
        else:
            self._main_splitter.setSizes([terminal_w, remaining_w, 0])

        # Dashboard height: 13% of window height, clamped between 90 and 160px
        dash_h = max(90, min(160, int(h * self._DASH_HEIGHT_PCT)))
        self.dashboard.setFixedHeight(dash_h)

        # Tell dashboard its new height so it can scale fonts
        self.dashboard.on_resize(dash_h)

    # ── NetworkManager Callbacks ──────────────────────────────────────────────

    def _on_network_log(self, message: str) -> None:
        self.terminal.print_log(message)
        self.dashboard.append_log(message)

    def _on_stats_update(self, stats: dict) -> None:
        self.dashboard.update_stats(stats)
        self._update_status_bar(stats)
        self.detection_panel.update_firewall_stats(stats)

    def _on_packet_generated(self, packet_event) -> None:
        self.topology_canvas.animate_packet(packet_event)

    # ── Status Bar ────────────────────────────────────────────────────────────

    def _update_status_bar(self, stats: dict) -> None:
        net_status = stats.get("network_status", "OFFLINE")
        sim_mode   = stats.get("simulation_mode", "IDLE")
        sent       = stats.get("packets_sent", 0)
        fw_blocked = stats.get("firewall", {}).get("packets_blocked", 0)

        if net_status == "ONLINE":
            self._sb_network.setText("● ONLINE")
            self._sb_network.setStyleSheet("color: #22C55E; padding: 0 14px;")
        else:
            self._sb_network.setText("● OFFLINE")
            self._sb_network.setStyleSheet("color: #64748B; padding: 0 14px;")

        color = "#4F8EF7" if sim_mode != "IDLE" else "#4A6080"
        self._sb_sim.setText(f"SIM: {sim_mode}")
        self._sb_sim.setStyleSheet(f"color: {color}; padding: 0 14px;")
        self._sb_packets.setText(f"PKT: {sent} sent")
        self._sb_fw.setText(f"FW: {fw_blocked} blocked")

    # ── Topology Refresh ──────────────────────────────────────────────────────

    def refresh_topology(self) -> None:
        topology = self._net_manager.get_topology()
        if topology:
            self.topology_canvas.load_topology(topology)
            self.topology_canvas.update_all_statuses(topology)

    # ── Timers ────────────────────────────────────────────────────────────────

    def _wire_signals(self) -> None:
        interval_ms = getattr(self.config.simulation, "packet_speed_ms", 800)
        self._tick_worker = SimulationTickWorker(
            self._net_manager, interval_ms=interval_ms,
        )
        self._tick_worker.packet_generated.connect(self._on_packet_generated)
        
        self._net_manager.log_emitted.connect(self._on_network_log)
        self._net_manager.stats_updated.connect(self._on_stats_update)
        self._net_manager.threat_model_updated.connect(self._on_threat_model_updated)

        # Wire Phase 4 Console Updates
        self._net_manager.timeline_updated.connect(self.detection_panel.update_timeline)
        self._net_manager.remediation_report_ready.connect(self.detection_panel.update_remediation)
        self._net_manager.remediation_token_received.connect(self.detection_panel.update_remediation_token)
        self._net_manager.remediation_status_changed.connect(self.detection_panel.update_remediation_status)
        self._net_manager.compliance_audited.connect(self.detection_panel.update_compliance)


    def _on_threat_model_updated(self, model) -> None:
        """Slot triggered when the network manager threat analysis updates."""
        # 1. Update Detection Panel widgets
        self.detection_panel.update_threat_model(model)
        
        # 2. If threat level is high/critical, auto-expand panel to draw attention
        if model.threat_level in ("HIGH", "CRITICAL") and not self.detection_panel.isVisible():
            self._toggle_detection_panel()
            
        # 3. Refresh topology nodes color state visually
        self.refresh_topology()


    def _start_timers(self) -> None:
        self._tick_worker.start()

        refresh_ms = getattr(self.config.simulation, "refresh_interval_ms", 2000)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._periodic_refresh)
        self._refresh_timer.start(refresh_ms)

        QTimer.singleShot(1500, self._check_ollama_status)

    def _periodic_refresh(self) -> None:
        topology = self._net_manager.get_topology()
        if topology and self._net_manager.is_running():
            self.topology_canvas.update_all_statuses(topology)
        self._on_stats_update(self._net_manager.get_stats())

    # ── Ollama ────────────────────────────────────────────────────────────────

    def _check_ollama_status(self) -> None:
        checker = OllamaHealthChecker(self.config.ollama)
        if checker.check_health() != OllamaStatus.RUNNING:
            self._show_ollama_popup()

    def _show_ollama_popup(self) -> None:
        self.popup = QDialog(self)
        self.popup.setWindowTitle("Ollama Offline")
        self.popup.resize(360, 80)
        self.popup.setStyleSheet(
            "background-color: #0B1220; border: 1px solid #2A364F; border-radius: 6px;"
        )
        layout = QVBoxLayout(self.popup)
        lbl = QLabel("⚠  Ollama is not running locally.\n   AI features disabled. Run: ollama serve")
        lbl.setFont(QFont("Consolas", 9))
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("color: #FACC15; border: none; background: transparent;")
        layout.addWidget(lbl)

        t = QTimer(self.popup)
        t.setSingleShot(True)
        t.timeout.connect(self.popup.close)
        t.start(5000)
        self.popup.show()

    # ── Settings Dialog Hot-Reload ───────────────────────────────────────────

    def _show_settings_dialog(self) -> None:
        """Trigger Settings Dialog modal form."""
        from app.ui.widgets.settings_dialog import SettingsDialog
        dialog = SettingsDialog(self)
        dialog.settings_changed.connect(self._on_settings_changed)
        dialog.exec()

    def _on_settings_changed(self, new_config) -> None:
        """Update running system constraints dynamically without restarts."""
        self.config = new_config
        
        # 1. Update simulation speeds
        self._tick_worker.set_interval(new_config.simulation.packet_speed_ms)
        self.topology_canvas.set_animation_duration(new_config.simulation.animation_duration_ms)
        
        # 2. Re-apply theme configuration
        from app.ui.theme.loader import ThemeLoader
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app:
            ThemeLoader.apply(app, new_config)

        self.terminal.print_log("[SETTINGS] Configuration file updated and hot-reloaded successfully.")

    def _show_logs_dialog(self) -> None:
        """Trigger Logs Dialog modal form."""
        from app.ui.widgets.log_viewer import LogViewerDialog
        dialog = LogViewerDialog(self)
        dialog.exec()
