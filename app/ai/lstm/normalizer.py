"""
app.ai.lstm.normalizer — Feature normalization utilities for flow sequences.
"""

from __future__ import annotations
import numpy as np


class MinMaxNormalizer:
    """Normalizes feature matrices/tensors to [0, 1] range."""

    def __init__(self, feature_range: tuple[float, float] = (0.0, 1.0)) -> None:
        self.min_val = feature_range[0]
        self.max_val = feature_range[1]
        self.data_min: np.ndarray | None = None
        self.data_max: np.ndarray | None = None

    def fit(self, data: np.ndarray) -> MinMaxNormalizer:
        """Computes column min and max across data."""
        arr = np.asarray(data)
        if arr.ndim > 2:
            arr = arr.reshape(-1, arr.shape[-1])
        self.data_min = np.min(arr, axis=0)
        self.data_max = np.max(arr, axis=0)
        return self

    def transform(self, data: np.ndarray) -> np.ndarray:
        """Transforms data using stored min and max."""
        arr = np.asarray(data, dtype=np.float32)
        if self.data_min is None or self.data_max is None:
            return arr
        denom = np.where((self.data_max - self.data_min) == 0, 1.0, self.data_max - self.data_min)
        scaled = (arr - self.data_min) / denom
        return np.clip(scaled * (self.max_val - self.min_val) + self.min_val, 0.0, 1.0)

    def fit_transform(self, data: np.ndarray) -> np.ndarray:
        return self.fit(data).transform(data)

    def to_dict(self) -> dict:
        return {
            "min_val": self.min_val,
            "max_val": self.max_val,
            "data_min": self.data_min.tolist() if self.data_min is not None else None,
            "data_max": self.data_max.tolist() if self.data_max is not None else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> MinMaxNormalizer:
        norm = cls(feature_range=(data.get("min_val", 0.0), data.get("max_val", 1.0)))
        if data.get("data_min") is not None:
            norm.data_min = np.array(data["data_min"], dtype=np.float32)
        if data.get("data_max") is not None:
            norm.data_max = np.array(data["data_max"], dtype=np.float32)
        return norm

