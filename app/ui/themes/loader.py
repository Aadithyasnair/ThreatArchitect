import logging
from PySide6.QtWidgets import QApplication
from app.config.models import AppConfig
from app.ui.themes.palette import ThemePalette
from app.ui.themes.dark_theme import DarkTheme

logger = logging.getLogger("ThemeLoader")

class ThemeLoader:
    """Manages application-wide theme loading and updates."""
    
    @staticmethod
    def apply(app: QApplication, config: AppConfig) -> None:
        """Apply active theme configuration to QApp."""
        logger.info(f"Applying theme: {config.theme.active}")
        
        palette_config = ThemePalette.from_config(config.theme)
        
        # Apply standard system dialog/palette properties
        q_palette = DarkTheme.get_q_palette(palette_config)
        app.setPalette(q_palette)
        
        # Apply QSS
        stylesheet = DarkTheme.get_stylesheet(palette_config)
        app.setStyleSheet(stylesheet)
        
        logger.info("Theme styles successfully initialized.")
