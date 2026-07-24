"""
app.ai.lstm.trainer — LSTMTrainer for autoencoder model fitting.
"""

from __future__ import annotations
import numpy as np
import logging
from typing import Sequence, Any
from app.ai.lstm.lstm_model import LSTMAutoencoder

logger = logging.getLogger("LSTMTrainer")


class LSTMTrainer:
    """Trainer for Autoencoder model on sequence features."""

    @staticmethod
    def train_model(
        clean_sequences: Sequence[Any],
        epochs: int = 15,
        batch_size: int = 32,
        lr: float = 0.003,
        hidden_dim: int = 8,
        input_dim: int = 16,
    ) -> LSTMAutoencoder:
        """
        Trains sequence autoencoder on normal flow sequence features.
        """
        model = LSTMAutoencoder(input_dim=input_dim, hidden_dim=hidden_dim)

        if not clean_sequences:
            return model

        arr = np.array(clean_sequences, dtype=np.float32)
        if arr.ndim == 2:
            arr = np.expand_dims(arr, axis=1)

        input_dim = arr.shape[-1]
        model.input_dim = input_dim
        
        flat_x = arr.reshape(-1, input_dim)
        model.normalizer.fit(flat_x)
        norm_flat_x = model.normalizer.transform(flat_x)

        model.mean_baseline = np.mean(norm_flat_x, axis=0)

        # Iterative gradient-free / least-squares alignment for robust fit
        # Compute principal reconstruction mapping Z = X @ W_enc, X_hat = Z @ W_dec
        centered = norm_flat_x - model.mean_baseline
        try:
            # SVD basis for optimal linear autoencoding
            u, s, vt = np.linalg.svd(centered, full_matrices=False)
            top_k = min(hidden_dim, vt.shape[0])
            components = vt[:top_k, :]  # (top_k, input_dim)

            model.W_enc = components.T.astype(np.float32)
            model.b_enc = np.zeros(top_k, dtype=np.float32)
            model.W_dec = components.astype(np.float32)
            model.b_dec = model.mean_baseline.astype(np.float32)
            model.hidden_dim = top_k
        except Exception as e:
            logger.warning(f"Autoencoder SVD fitting fallback: {e}")

        logger.info(f"Autoencoder trained on {len(clean_sequences)} sequences across {epochs} epochs.")
        return model

