"""
app.ai.lstm.lstm_model — Pure NumPy Autoencoder for sequence anomaly detection.

Provides high-performance sequence reconstruction and anomaly scoring without
external deep-learning C++ DLL dependencies.
"""

from __future__ import annotations
import numpy as np
from app.ai.lstm.normalizer import MinMaxNormalizer


class LSTMAutoencoder:
    """
    Sequence Autoencoder using NumPy linear algebra projections and non-linear activations.
    Emulates the autoencoder interface for flow feature sequences.
    """

    def __init__(self, input_dim: int = 16, hidden_dim: int = 8, seed: int = 42) -> None:
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.normalizer = MinMaxNormalizer()

        rng = np.random.default_rng(seed)
        # Xavier / Glorot initialization
        scale_enc = np.sqrt(2.0 / (input_dim + hidden_dim))
        scale_dec = np.sqrt(2.0 / (hidden_dim + input_dim))

        self.W_enc = rng.normal(0, scale_enc, (input_dim, hidden_dim)).astype(np.float32)
        self.b_enc = np.zeros(hidden_dim, dtype=np.float32)

        self.W_dec = rng.normal(0, scale_dec, (hidden_dim, input_dim)).astype(np.float32)
        self.b_dec = np.zeros(input_dim, dtype=np.float32)

        self.mean_baseline = np.ones(input_dim, dtype=np.float32)

    def forward(self, x: np.ndarray | list) -> np.ndarray:
        """
        Encodes and reconstructs input sequence or batch of sequences.
        Shape of x: (batch, seq_len, input_dim) or (seq_len, input_dim).
        """
        arr = np.asarray(x, dtype=np.float32)

        # Handle dimension mismatch gracefully
        if arr.shape[-1] != self.input_dim:
            if arr.ndim == 3:
                # Resize or slice input_dim axis
                pad_width = max(0, self.input_dim - arr.shape[-1])
                arr = np.pad(arr, ((0, 0), (0, 0), (0, pad_width)))[:, :, :self.input_dim]
            elif arr.ndim == 2:
                pad_width = max(0, self.input_dim - arr.shape[-1])
                arr = np.pad(arr, ((0, 0), (0, pad_width)))[:, :self.input_dim]

        # Encoder: Linear + Tanh
        latent = np.tanh(np.matmul(arr, self.W_enc) + self.b_enc)

        # Decoder: Linear reconstruction
        reconstructed = np.matmul(latent, self.W_dec) + self.b_dec

        return reconstructed

    def __call__(self, x: np.ndarray | list) -> np.ndarray:
        return self.forward(x)

    def state_dict(self) -> dict:
        return {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "W_enc": self.W_enc,
            "b_enc": self.b_enc,
            "W_dec": self.W_dec,
            "b_dec": self.b_dec,
            "mean_baseline": self.mean_baseline,
            "normalizer": self.normalizer.to_dict(),
        }

    def load_state_dict(self, state: dict) -> None:
        self.input_dim = state.get("input_dim", self.input_dim)
        self.hidden_dim = state.get("hidden_dim", self.hidden_dim)
        self.W_enc = state.get("W_enc", self.W_enc)
        self.b_enc = state.get("b_enc", self.b_enc)
        self.W_dec = state.get("W_dec", self.W_dec)
        self.b_dec = state.get("b_dec", self.b_dec)
        self.mean_baseline = state.get("mean_baseline", self.mean_baseline)
        if "normalizer" in state:
            self.normalizer = MinMaxNormalizer.from_dict(state["normalizer"])

