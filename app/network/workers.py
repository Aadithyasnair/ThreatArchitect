"""
app.network.workers — Qt-threaded worker classes for background network operations.

All heavy operations (network start/stop, simulation ticking) run off the
main thread. Workers use Qt signals to communicate results back to the UI.
Uses standard Python threading internally for QObject-compliant workers to guarantee
safe pytest cleanup and prevent PySide6 thread locks.
"""

from __future__ import annotations

import logging
import threading
from PySide6.QtCore import QThread, Signal, QTimer, QObject

logger = logging.getLogger("Workers")


class NetworkStartWorker(QThread):
    """
    Runs NetworkManager.start_network() in a background thread.
    Emits finished(success, message) when done.
    """
    finished = Signal(bool, str)

    def __init__(self, network_manager, parent=None) -> None:
        super().__init__(parent)
        self._manager = network_manager

    def run(self) -> None:
        try:
            message = self._manager.start_network()
            self.finished.emit(True, message)
        except Exception as exc:
            logger.error(f"NetworkStartWorker error: {exc}")
            self.finished.emit(False, str(exc))


class NetworkStopWorker(QThread):
    """
    Runs NetworkManager.stop_network() in a background thread.
    Emits finished(success, message) when done.
    """
    finished = Signal(bool, str)

    def __init__(self, network_manager, parent=None) -> None:
        super().__init__(parent)
        self._manager = network_manager

    def run(self) -> None:
        try:
            message = self._manager.stop_network()
            self.finished.emit(True, message)
        except Exception as exc:
            logger.error(f"NetworkStopWorker error: {exc}")
            self.finished.emit(False, str(exc))


class ModelRetrainWorker(QThread):
    """
    Runs model retraining in a background thread using recent/online data.
    Emits progress(str) and finished(bool, dict, str) when complete.
    """
    progress = Signal(str)
    finished = Signal(bool, dict, str)

    def __init__(self, model_dir: str = "models", parent=None) -> None:
        super().__init__(parent)
        self.model_dir = model_dir

    def run(self) -> None:
        from app.ai.bootstrap_models import retrain_all_models
        try:
            metrics = retrain_all_models(
                model_dir=self.model_dir,
                fetch_online=True,
                progress_callback=lambda msg: self.progress.emit(msg)
            )
            self.finished.emit(True, metrics, "Model retraining completed successfully.")
        except Exception as exc:
            logger.error(f"ModelRetrainWorker error: {exc}")
            self.finished.emit(False, {}, str(exc))



class SimulationTickWorker(QObject):
    """
    Periodically calls NetworkManager.tick_simulation() to generate packet events.
    """
    packet_generated = Signal(object)   # PacketEvent

    def __init__(self, network_manager, interval_ms: int = 800, parent=None) -> None:
        super().__init__(parent)
        self._manager = network_manager
        self._interval_ms = interval_ms
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def start(self) -> None:
        """Start the simulation tick timer."""
        self._timer.start(self._interval_ms)
        logger.debug(f"SimulationTickWorker started at {self._interval_ms}ms interval.")

    def stop(self) -> None:
        """Stop the simulation tick timer."""
        self._timer.stop()
        logger.debug("SimulationTickWorker stopped.")

    def set_interval(self, ms: int) -> None:
        """Change the tick interval while running."""
        self._interval_ms = ms
        if self._timer.isActive():
            self._timer.setInterval(ms)

    def _tick(self) -> None:
        """Produce one packet event per tick."""
        try:
            event = self._manager.tick_simulation()
            if event:
                self.packet_generated.emit(event)
        except Exception as exc:
            logger.error(f"SimulationTickWorker tick error: {exc}")


class OllamaRemediationWorker(QObject):
    """
    Queries local Ollama Llama 3.2 model in a background thread.
    Streams back raw response tokens and final parsed reports.
    """
    token_received = Signal(str)  # Streams raw chunk tokens
    finished = Signal(object)      # Emits final RemediationReport
    status_changed = Signal(str)  # "Analyzing...", "Streaming response...", "Completed"

    def __init__(self, context: dict, parent=None) -> None:
        super().__init__(parent)
        self.context = context
        self._is_cancelled = False

    def start(self) -> None:
        """Starts the streaming query in a standard daemon thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def cancel(self) -> None:
        """Flags the worker to stop processing and close connection."""
        self._is_cancelled = True

    def _run(self) -> None:
        self.status_changed.emit("Analyzing...")
        try:
            from app.ai.ollama.client import OllamaClient
            from app.ai.ollama.prompt_builder import PromptBuilder
            from app.ai.ollama.response_parser import ResponseParser

            client = OllamaClient()
            prompt = PromptBuilder.build_remediation_prompt(self.context)
            system = PromptBuilder.SYSTEM_INSTRUCTIONS

            accumulated = ""
            started = False

            # Query stream generator
            generator = client.query_stream(prompt, system)
            for chunk in generator:
                if self._is_cancelled:
                    logger.info("OllamaRemediationWorker stream canceled.")
                    return

                if not started:
                    started = True
                    self.status_changed.emit("Streaming response...")

                accumulated += chunk
                self.token_received.emit(chunk)

            if self._is_cancelled:
                return

            self.status_changed.emit("Completed")
            
            # Parse final structured payload
            report = ResponseParser.parse_response(accumulated)
            self.finished.emit(report)

        except Exception as exc:
            logger.error(f"OllamaRemediationWorker stream error: {exc}")
            from app.ai.ollama.response_parser import RemediationReport
            self.status_changed.emit("Completed") # Revert status gracefully
            self.finished.emit(RemediationReport(threat_summary=f"Worker stream error: {exc}"))


class ComplianceAuditorWorker(QObject):
    """
    Runs deterministic compliance checks in background.
    Emits finished(Dict[str, dict]) for framework checklists.
    """
    finished = Signal(dict)

    def __init__(self, network_manager, parent=None) -> None:
        super().__init__(parent)
        self._manager = network_manager

    def start(self) -> None:
        """Starts compliance checks in a standard daemon thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self) -> None:
        try:
            from app.ai.compliance.evaluator import ComplianceEvaluator
            evaluator = ComplianceEvaluator()
            
            results = {
                "NIST CSF": evaluator.evaluate_framework("NIST CSF", self._manager),
                "ISO 27001": evaluator.evaluate_framework("ISO 27001", self._manager),
                "OWASP ASVS": evaluator.evaluate_framework("OWASP ASVS", self._manager),
            }
            self.finished.emit(results)
        except Exception as exc:
            logger.error(f"ComplianceAuditorWorker error: {exc}")
            self.finished.emit({})


class PDFReportWorker(QObject):
    """
    Generates ReportLab PDF incident reports asynchronously.
    Emits finished(filepath, success) when done.
    """
    finished = Signal(str, bool)

    def __init__(
        self,
        output_path: str,
        incident_data: dict,
        timeline_events: list,
        compliance_results: list,
        mitre_info: dict = None,
        ai_remediation: dict = None,
        devices_list: list = None,
        parent=None
    ) -> None:
        super().__init__(parent)
        self.output_path = output_path
        self.incident_data = incident_data
        self.timeline_events = timeline_events
        self.compliance_results = compliance_results
        self.mitre_info = mitre_info
        self.ai_remediation = ai_remediation
        self.devices_list = devices_list or []

    def start(self) -> None:
        """Starts report generation in a standard daemon thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self) -> None:
        try:
            from app.utils.pdf_generator import PDFIncidentReportGenerator
            PDFIncidentReportGenerator.generate_report(
                output_path=self.output_path,
                incident_data=self.incident_data,
                timeline_events=self.timeline_events,
                compliance_results=self.compliance_results,
                mitre_info=self.mitre_info,
                ai_remediation=self.ai_remediation,
                devices_list=self.devices_list
            )
            self.finished.emit(self.output_path, True)
        except Exception as exc:
            logger.error(f"PDFReportWorker error: {exc}", exc_info=True)
            self.finished.emit(str(exc), False)


class DatabaseWriteWorker(QObject):
    """
    Writes threat history metrics and incident timelines to local SQLite database.
    """
    finished = Signal(bool)

    def __init__(self, query: str, params: tuple = (), parent=None) -> None:
        super().__init__(parent)
        self.query = query
        self.params = params

    def start(self) -> None:
        """Starts DB write operation in a standard daemon thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self) -> None:
        import sqlite3
        from app.config.loader import ConfigLoader
        db_path = ConfigLoader.load().database.db_path
        try:
            conn = sqlite3.connect(db_path, timeout=5.0)
            cursor = conn.cursor()
            cursor.execute(self.query, self.params)
            conn.commit()
            conn.close()
            try:
                self.finished.emit(True)
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"DatabaseWriteWorker error executing query: {exc}")
            try:
                self.finished.emit(False)
            except Exception:
                pass

