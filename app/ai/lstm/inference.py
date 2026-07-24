"""
app.ai.lstm.inference — LSTMAnomalyDetector inference engine.
"""

from __future__ import annotations
import numpy as np
import logging
from typing import Optional, Sequence, Any
from app.ai.lstm.lstm_model import LSTMAutoencoder

logger = logging.getLogger("LSTMAnomalyDetector")


class LSTMAnomalyDetector:
    """Anomaly detection engine calculating reconstruction error for sequence features."""

    def __init__(self, model: Optional[LSTMAutoencoder] = None) -> None:
        self._model = model or LSTMAutoencoder()

    def set_model(self, model: LSTMAutoencoder) -> None:
        self._model = model

    def detect_anomalies(self, sequence: Sequence[Any]) -> float:
        """
        Computes normalized anomaly score [0.0, 1.0] for input flow sequence.
        Higher score indicates higher reconstruction error (potential anomaly).
        """
        if not sequence:
            return 0.0

        try:
            arr = np.array(sequence, dtype=np.float32)
            if arr.ndim == 1:
                arr = np.expand_dims(arr, axis=0)

            # Normalize sequence features to [0, 1]
            norm_arr = self._model.normalizer.transform(arr)

            # Reconstruct sequence using autoencoder
            reconstructed = self._model.forward(norm_arr)

            # Calculate Mean Squared Error (MSE) on normalized features
            mse = float(np.mean((norm_arr - reconstructed) ** 2))

            # Sigmoid/tanh scaling for normalized 0.0 to 1.0 score
            scaled_score = float(np.tanh(mse * 2.5))
            return max(0.0, min(1.0, scaled_score))
        except Exception as e:
            logger.warning(f"Error during anomaly detection inference: {e}")
            return 0.0

