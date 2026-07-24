"""
tests/test_lstm — Verifies Autoencoder training, inference, and anomaly score.
"""

import pytest
import numpy as np
from app.ai.lstm.lstm_model import LSTMAutoencoder
from app.ai.lstm.dataset import FlowSequenceDataset
from app.ai.lstm.trainer import LSTMTrainer
from app.ai.lstm.inference import LSTMAnomalyDetector


def test_lstm_model_shapes() -> None:
    """Verifies that input sequences yield matching shape reconstructions."""
    model = LSTMAutoencoder(input_dim=16, hidden_dim=8)

    # Input batch shape: (batch_size=4, sequence_length=5, input_dim=16)
    x = np.random.randn(4, 5, 16)
    y = model(x)
    assert y.shape == x.shape


def test_lstm_dataset() -> None:
    """Verifies dataset length and item structure."""
    seqs = [[[1.0] * 16] * 5] * 10  # 10 samples of length 5
    dataset = FlowSequenceDataset(seqs)
    assert len(dataset) == 10
    item = dataset[0]
    assert item.shape == (5, 16)


def test_lstm_training_and_inference() -> None:
    """Verifies complete Autoencoder train/inference pipeline works and responds to errors."""
    # Generate simple clean synthetic data
    clean_sequences = []
    for _ in range(25):
        # Baseline normal vectors
        seq = [[1.0] * 16 for _ in range(5)]
        clean_sequences.append(seq)

    # Train model
    model = LSTMTrainer.train_model(clean_sequences, epochs=5, batch_size=8, hidden_dim=16)

    detector = LSTMAnomalyDetector(model)

    # Evaluate a normal clean sequence
    normal_seq = [[1.0] * 16 for _ in range(5)]
    normal_score = detector.detect_anomalies(normal_seq)

    # Evaluate a sequence with huge outlier values
    anomaly_seq = [[10.0] * 16 for _ in range(5)]
    anomaly_score = detector.detect_anomalies(anomaly_seq)

    # Anomaly score should be higher than normal score due to reconstruction mismatch
    assert anomaly_score >= normal_score
    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= anomaly_score <= 1.0
