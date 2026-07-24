from PySide6.QtWidgets import QApplication
from app.ui.widgets.settings_dialog import SettingsDialog
from app.config.loader import ConfigLoader


def test_settings_dialog_fields():
    """Verify settings dialog displays active values and updates config on save."""
    app = QApplication.instance() or QApplication([])
    dialog = SettingsDialog()

    # Initial values match active config
    config = ConfigLoader.load()
    assert dialog.theme_combo.currentText() == config.theme.active
    assert dialog.packet_speed_spin.value() == config.simulation.packet_speed_ms
    assert dialog.anim_speed_spin.value() == config.network.animation_speed
    assert dialog.log_combo.currentText() == config.logging.level

    # Modify values
    dialog.theme_combo.setCurrentText("light")
    dialog.packet_speed_spin.setValue(1200)
    dialog.anim_speed_spin.setValue(2.5)

    # Mock settings_changed signal
    changed_configs = []
    dialog.settings_changed.connect(changed_configs.append)

    # Save
    dialog._save_settings()

    assert len(changed_configs) == 1
    new_cfg = changed_configs[0]
    assert new_cfg.theme.active == "light"
    assert new_cfg.simulation.packet_speed_ms == 1200
    assert new_cfg.network.animation_speed == 2.5

    # Restore default settings
    dialog.theme_combo.setCurrentText("dark")
    dialog.packet_speed_spin.setValue(800)
    dialog.anim_speed_spin.setValue(1.0)
    dialog._save_settings()
