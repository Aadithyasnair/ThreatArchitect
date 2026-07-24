from PySide6.QtWidgets import QApplication
from app.ui.widgets.diagnostics_window import DiagnosticsWindow


def test_diagnostics_validation():
    """Verify diagnostics window check methods run and evaluate successfully."""
    app = QApplication.instance() or QApplication([])
    window = DiagnosticsWindow()

    # Validate individual validation items
    assert window._check_python_version()[0] == "PASS"
    assert window._check_packages()[0] == "PASS"
    assert window._check_database()[0] == "PASS"
    assert window._check_config()[0] == "PASS"
    assert window._check_ollama()[0] in ("PASS", "WARNING")
    assert window._check_llama_model()[0] in ("PASS", "WARNING")
    assert window._check_write_permissions()[0] == "PASS"
