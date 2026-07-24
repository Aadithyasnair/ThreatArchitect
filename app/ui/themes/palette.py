from dataclasses import dataclass
from app.config.models import ThemeConfig

@dataclass(frozen=True)
class ThemePalette:
    """Type-safe wrapper for visual theme colors."""
    background: str
    surface: str
    primary_accent: str
    green: str
    yellow: str
    red: str
    text: str
    border: str
    hover: str

    @classmethod
    def from_config(cls, config: ThemeConfig) -> 'ThemePalette':
        return cls(
            background=config.background,
            surface=config.surface,
            primary_accent=config.primary_accent,
            green=config.green,
            yellow=config.yellow,
            red=config.red,
            text=config.text,
            border=config.border,
            hover=config.hover
        )
