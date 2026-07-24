"""
app.network.command_parser — Terminal command dispatcher.

Parses raw text commands and delegates to NetworkManager service methods.
Returns structured CommandResult objects. Never touches widgets directly.

Supported commands:
  help, start network, stop network, show topology, show nodes,
  show firewall, clear, status, emulate normal
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Any, Callable, Dict

logger = logging.getLogger("CommandParser")


@dataclass
class CommandResult:
    """Structured result returned by every command execution."""
    success: bool
    output: str
    data: Any = None
    action: Optional[str] = None   # Special UI actions: "clear", "start_network", etc.


class CommandParser:
    """
    Parses and dispatches terminal commands to the NetworkManager.

    The parser holds a reference to the NetworkManager and calls its
    service-layer methods. It returns CommandResult for the terminal to display.
    """

    HELP_TEXT = """\

ThreatArchitect — Available Commands
========================================================
  help                  Show this help message
  start network         Start the network (Mininet / simulation)
  stop network          Stop the active network
  emulate normal        Start normal enterprise traffic emulation
  emulate suspicious    Start suspicious/attack emulation (SYN flood, scan, etc.)
  emulate dangerous     Start high-impact dangerous emulation (DDoS, MitM, beacons)
  retrain               Retrain ML models with online/recent threat data
  show metrics          Display ML classification accuracy, precision, recall & F1 scores
  generate report       Compile and export the current incident report to PDF
  show topology         Display topology summary and device tree
  show nodes            List all devices with IP, MAC, and status
  show firewall         Show firewall rules and traffic statistics
  status                Show live network and simulation statistics
  clear                 Clear the terminal screen
========================================================
  Keyboard Shortcuts
  Ctrl+R                start network
  Ctrl+C                stop network
  Ctrl+E                emulate normal
  Ctrl+L                clear terminal
========================================================
"""

    def __init__(self, network_manager) -> None:
        """
        Args:
            network_manager: NetworkManager instance providing service methods.
        """
        self._manager = network_manager
        self._dispatch: Dict[str, Callable[[], CommandResult]] = {
            "help":               self._cmd_help,
            "start network":      self._cmd_start_network,
            "stop network":       self._cmd_stop_network,
            "emulate normal":     self._cmd_emulate_normal,
            "emulate suspicious": self._cmd_emulate_suspicious,
            "emulate dangerous":  self._cmd_emulate_dangerous,
            "mitigate":           self._cmd_mitigate,
            "auto mitigate":      self._cmd_mitigate,
            "automitigate":       self._cmd_mitigate,
            "retrain":            self._cmd_retrain,
            "retrain model":      self._cmd_retrain,
            "show metrics":       self._cmd_show_metrics,
            "model info":         self._cmd_show_metrics,
            "generate report":    self._cmd_generate_report,
            "show topology":      self._cmd_show_topology,
            "show nodes":         self._cmd_show_nodes,
            "show firewall":      self._cmd_show_firewall,
            "status":             self._cmd_status,
            "clear":              self._cmd_clear,
        }

    def _cmd_mitigate(self) -> CommandResult:
        msg = self._manager.trigger_manual_mitigation()
        return CommandResult(success=True, output=msg, action="mitigate")

    def parse_and_execute(self, raw_input: str) -> CommandResult:
        """
        Parse a raw text command and execute the matching handler.

        Commands are case-insensitive and trimmed. Unknown commands return
        a helpful error message pointing back to 'help'.
        """
        cmd = raw_input.strip().lower()
        handler = self._dispatch.get(cmd)

        if handler:
            try:
                result = handler()
                logger.debug(f"Command executed: '{cmd}' → success={result.success}")
                return result
            except Exception as exc:
                logger.error(f"Command '{cmd}' raised exception: {exc}")
                return CommandResult(
                    success=False,
                    output=f"Command error: {exc}",
                )
        else:
            # Fuzzy suggestion for near-matches
            suggestion = self._suggest(cmd)
            msg = f"Unknown command: '{raw_input}'"
            if suggestion:
                msg += f"\n  Did you mean: {suggestion}?"
            msg += "\n  Type 'help' for available commands."
            return CommandResult(success=False, output=msg)

    # ── Command Handlers ─────────────────────────────────────────────────────

    def _cmd_help(self) -> CommandResult:
        return CommandResult(success=True, output=self.HELP_TEXT)

    def _cmd_start_network(self) -> CommandResult:
        msg = self._manager.start_network()
        return CommandResult(success=True, output=msg, action="start_network")

    def _cmd_stop_network(self) -> CommandResult:
        msg = self._manager.stop_network()
        return CommandResult(success=True, output=msg, action="stop_network")

    def _cmd_emulate_normal(self) -> CommandResult:
        msg = self._manager.start_emulate_normal()
        return CommandResult(success=True, output=msg, action="emulate_normal")

    def _cmd_emulate_suspicious(self) -> CommandResult:
        msg = self._manager.start_emulate_suspicious()
        return CommandResult(success=True, output=msg, action="emulate_suspicious")

    def _cmd_emulate_dangerous(self) -> CommandResult:
        msg = self._manager.start_emulate_dangerous()
        return CommandResult(success=True, output=msg, action="emulate_dangerous")

    def _cmd_retrain(self) -> CommandResult:
        """Triggers model retraining with recent/online threat dataset feeds in a background thread."""
        def on_complete(success: bool, metrics: dict, msg: str):
            if not success:
                self._manager._log(f"[RETRAIN FAILED] {msg}")

        self._manager.retrain_models(on_complete)
        return CommandResult(
            success=True,
            output="[ML ENGINE] Initiated model retraining with online dataset feeds in the background...\n  Progress logs will display in the console terminal."
        )

    def _cmd_show_metrics(self) -> CommandResult:
        """Displays active model classification metrics (Accuracy, Precision, Recall, F1 Scores)."""
        metrics = self._manager.get_model_metrics()
        if not metrics:
            # Generate metrics on the spot if not cached
            try:
                from app.ai.real_data_generator import generate_real_life_dataset, compute_evaluation_metrics
                rf = self._manager._classifier
                if hasattr(rf, 'model') and rf.model is not None:
                    x_test, y_test = generate_real_life_dataset(1500, 250)
                    metrics = compute_evaluation_metrics(rf.model, x_test, y_test)
                    metrics["dataset_source"] = "Active Real-Life Benchmark (CIC-IDS2017 Profiles)"
            except Exception as exc:
                return CommandResult(success=False, output=f"Failed to calculate metrics: {exc}")

        if not metrics:
            return CommandResult(success=False, output="No model evaluation metrics available. Run 'retrain' command first.")

        out = self._format_metrics(metrics)
        return CommandResult(success=True, output=out)

    def _format_metrics(self, metrics: dict) -> str:
        """Formats evaluation metrics dictionary into a clean terminal report."""
        lines = [
            "=== ThreatArchitect ML Model Evaluation Metrics ===",
            f"  Model Architecture  : Random Forest (100 Estimators) + PyTorch LSTM",
            f"  Dataset Feed Source : {metrics.get('dataset_source', 'Real-Life Benchmark Profiles')}",
            f"  Total Test Samples  : {metrics.get('total_samples', 0):,}",
            f"  Overall Accuracy    : {metrics.get('overall_accuracy', 0.0):.2f}%",
            f"  5-Fold CV Accuracy  : {metrics.get('cv_accuracy', 0.0):.2f}%",
            "",
            "--- Per-Class Classification Performance ---",
            f"  {'Class Name':<18} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Samples'}",
            "  " + "-" * 65,
        ]

        per_class = metrics.get("per_class", {})
        for cls_name, vals in per_class.items():
            lines.append(
                f"  {cls_name:<18} {vals['precision']:>8.1f}%   {vals['recall']:>8.1f}%   {vals['f1_score']:>8.1f}%   {vals['support']:>7}"
            )

        top_feats = metrics.get("top_features", [])
        if top_feats:
            lines.extend([
                "",
                "--- Top Feature Importance Ranks ---",
            ])
            for i, (feat, imp) in enumerate(top_feats, 1):
                lines.append(f"  {i}. {feat:<20} : {imp*100:6.2f}% importance")

        lines.append("==========================================================")
        return "\n".join(lines)

    def _cmd_generate_report(self) -> CommandResult:
        # Define a callback print function
        def on_pdf_finished(path_or_err: str, success: bool):
            if success:
                self._manager._log(f"[REPORT] Incident report compiled successfully: {path_or_err}")
            else:
                self._manager._log(f"[REPORT] ERROR generating report: {path_or_err}")

        self._manager.generate_pdf_report(on_pdf_finished)
        return CommandResult(
            success=True,
            output="Starting PDF incident report compilation in the background..."
        )

    def _cmd_show_topology(self) -> CommandResult:
        topology = self._manager.get_topology()
        if not topology:
            return CommandResult(
                success=False,
                output="No topology loaded. Run 'start network' first.",
            )

        lines = [topology.to_summary(), "", "Device Tree:"]
        # Build a simple text tree
        type_order = ["internet", "router", "firewall", "switch", "server", "database", "workstation"]
        sorted_devices = sorted(
            topology.devices,
            key=lambda d: type_order.index(d.device_type.value)
            if d.device_type.value in type_order else 99
        )
        for device in sorted_devices:
            status_icon = {
                "online":       "[+] ",
                "offline":      "[-] ",
                "warning":      "[!] ",
                "under_attack": "[X] ",
                "blocked":      "[B] ",
            }.get(device.status.value, "[?] ")
            lines.append(f"  {status_icon}{device.hostname:<22} [{device.device_type.value.upper()}]  {device.ip_address}")

        return CommandResult(success=True, output="\n".join(lines))

    def _cmd_show_nodes(self) -> CommandResult:
        topology = self._manager.get_topology()
        if not topology:
            return CommandResult(
                success=False,
                output="No topology loaded. Run 'start network' first.",
            )

        lines = [
            f"{'Hostname':<24} {'IP Address':<16} {'MAC Address':<20} {'Type':<14} {'Status'}",
            "-" * 90,
        ]
        for device in topology.devices:
            lines.append(
                f"{device.hostname:<24} {device.ip_address:<16} {device.mac_address:<20} "
                f"{device.device_type.value:<14} {device.status.value.upper()}"
            )
        return CommandResult(success=True, output="\n".join(lines))

    def _cmd_show_firewall(self) -> CommandResult:
        fw = self._manager.get_firewall()
        stats = fw.get_stats()
        lines = [
            "Firewall Status: ACTIVE",
            f"  Allowed  : {stats['packets_allowed']}",
            f"  Blocked  : {stats['packets_blocked']}",
            f"  Total    : {stats['total']}",
            f"  Block %  : {stats['block_rate_pct']}%",
            "",
            "Active Rules:",
            fw.format_rules_table(),
        ]
        return CommandResult(success=True, output="\n".join(lines))

    def _cmd_status(self) -> CommandResult:
        stats = self._manager.get_stats()
        lines = [
            "=== Network Status ===",
            f"  Network     : {stats['network_status']}",
            f"  Simulation  : {stats['simulation_mode']}",
            f"  Active Devs : {stats['active_devices']}",
            "",
            "--- Traffic Statistics ---",
            f"  Packets Sent      : {stats['packets_sent']}",
            f"  Packets Delivered : {stats['packets_delivered']}",
            f"  Packets Lost      : {stats['packets_lost']}",
            f"  Packets Captured  : {stats.get('packets_captured', 0)} (Scapy)",
            f"  Active Flows      : {stats.get('active_flows', 0)} (Reconstructed)",
            "",
            "--- AI Threat Engine ---",
            f"  Threat Level      : {stats.get('threat_level', 'INFO')}",
            f"  Threat Score      : {stats.get('threat_score', 0)} / 100",
            f"  Anomaly Score     : {stats.get('anomaly_score', 0.0):.4f} (LSTM)",
            f"  ML Classification : {stats.get('current_attack', 'Normal')} ({(stats.get('classifier_confidence', 0.0)*100):.1f}%)",
            f"  Target Host       : {stats.get('current_target', 'N/A')}",
            "",
            "--- Firewall ---",
            f"  Allowed : {stats['firewall']['packets_allowed']}",
            f"  Blocked : {stats['firewall']['packets_blocked']}",
        ]
        return CommandResult(success=True, output="\n".join(lines))

    def _cmd_clear(self) -> CommandResult:

        return CommandResult(success=True, output="", action="clear")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _suggest(self, cmd: str) -> Optional[str]:
        """Return the closest known command if edit distance is small."""
        for known in self._dispatch:
            # Simple substring check for suggestions
            if known.startswith(cmd[:4]) or cmd in known:
                return known
        return None
