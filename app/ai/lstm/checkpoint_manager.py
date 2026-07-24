"""
app.ai.lstm.checkpoint_manager — Checkpoint manager for autoencoder persistence.
"""

from __future__ import annotations
import os
import joblib
import pickle
import logging
from typing import Optional
from app.ai.lstm.lstm_model import LSTMAutoencoder

logger = logging.getLogger("CheckpointManager")


class CheckpointManager:
    """Manages saving and loading model checkpoints."""

    @staticmethod
    def save_checkpoint(model: LSTMAutoencoder, filepath: str) -> bool:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            joblib.dump(model.state_dict(), filepath)
            logger.info(f"Model checkpoint saved successfully to: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save checkpoint to {filepath}: {e}")
            return False

    @staticmethod
    def load_checkpoint(filepath: str) -> Optional[LSTMAutoencoder]:
        if not os.path.exists(filepath):
            logger.warning(f"Checkpoint file not found: {filepath}")
            return None

        try:
            try:
                state = joblib.load(filepath)
            except Exception:
                with open(filepath, "rb") as f:
                    state = pickle.load(f)

            model = LSTMAutoencoder(
                input_dim=state.get("input_dim", 16),
                hidden_dim=state.get("hidden_dim", 8),
            )
            model.load_state_dict(state)
            logger.info(f"Loaded checkpoint from: {filepath}")
            return model
        except Exception as e:
            logger.error(f"Error loading checkpoint from {filepath}: {e}")
            return LSTMAutoencoder()

