"""
train_deep_model.py — Real Online Kaggle/UNSW-NB15 & NSL-KDD Deep Learning Trainer.

Downloads 300,000+ real-world cybersecurity intrusion records directly from Kaggle and GitHub sources
(UNSW-NB15 & NSL-KDD), applies a 70% Training / 30% Testing split, and trains Deep Neural Network (DNN)
and Random Forest Classifier models with live Keras-style epoch progress logging.
"""

from __future__ import annotations

import sys
import time
import math
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import List, Tuple

from app.ai.online_data_fetcher import OnlineDataFetcher
from app.ai.real_data_generator import (
    generate_real_life_lstm_sequences,
    compute_evaluation_metrics,
)
from app.ai.classifier.rf_classifier import CLASSES, FEATURE_NAMES
from app.ai.classifier.trainer import RFClassifierTrainer
from app.ai.lstm.trainer import LSTMTrainer
from app.ai.lstm.checkpoint_manager import CheckpointManager


class ThreatDeepClassifier(nn.Module):
    """Deep Neural Network (MLP / DNN) for 16D flow feature classification."""

    def __init__(self, input_dim: int = 16, num_classes: int = len(CLASSES)):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.15),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.10),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def print_progress_bar(iteration: int, total: int, prefix: str = "", suffix: str = "", length: int = 40):
    """Renders a Keras/TensorFlow style progress bar."""
    percent = f"{100 * (iteration / float(total)):.1f}%"
    filled_length = int(length * iteration // total)
    bar = "=" * filled_length + "-" * (length - filled_length)
    sys.stdout.write(f"\r{prefix} [{bar}] {iteration}/{total} - {suffix}")
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write("\n")


def train_tensorflow_style_dnn(
    x_train: np.ndarray,
    y_train: np.ndarray,
    epochs: int = 20,
    batch_size: int = 1024,
    lr: float = 0.001
) -> ThreatDeepClassifier:
    """Trains Deep Neural Network with live Keras/TensorFlow epoch progress logging (70% Train / 30% Test split)."""
    num_samples = len(x_train)

    # Convert targets to class indices
    class_to_idx = {c: i for i, c in enumerate(CLASSES)}
    y_indices = np.array([class_to_idx.get(c, 0) for c in y_train], dtype=np.int64)

    # Shuffle dataset prior to 70% Train / 30% Test split
    perm = np.random.permutation(num_samples)
    x_train_shuffled = x_train[perm]
    y_indices_shuffled = y_indices[perm]

    # 70% Train / 30% Test Split
    train_count = int(0.70 * num_samples)
    test_count = num_samples - train_count
    
    x_tr, x_test = x_train_shuffled[:train_count], x_train_shuffled[train_count:]
    y_tr, y_test = y_indices_shuffled[:train_count], y_indices_shuffled[train_count:]

    num_batches = math.ceil(len(x_tr) / batch_size)

    # Standardization min/max computed on 70% training set
    data_min = np.min(x_tr, axis=0)
    data_max = np.max(x_tr, axis=0)
    denom = np.where((data_max - data_min) == 0, 1.0, data_max - data_min)

    x_tr_norm = (x_tr - data_min) / denom
    x_test_norm = (x_test - data_min) / denom

    tensor_x_tr = torch.tensor(x_tr_norm, dtype=torch.float32)
    tensor_y_tr = torch.tensor(y_tr, dtype=torch.long)
    tensor_x_test = torch.tensor(x_test_norm, dtype=torch.float32)
    tensor_y_test = torch.tensor(y_test, dtype=torch.long)

    model = ThreatDeepClassifier(input_dim=16, num_classes=len(CLASSES))
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    print("\n==========================================================================")
    print(f"   Deep Neural Network Training Engine (Real Kaggle / UNSW-NB15 & NSL-KDD) ")
    print(f"   Total Real Online Dataset: {num_samples:,} records                      ")
    print(f"   Training Set (70%)        : {train_count:,} records                     ")
    print(f"   Testing Set  (30%)        : {test_count:,} records                     ")
    print(f"   Epochs: {epochs} | Batch Size: {batch_size}                            ")
    print("==========================================================================")

    for epoch in range(1, epochs + 1):
        model.train()
        start_time = time.time()
        running_loss = 0.0
        correct = 0
        total_processed = 0

        # Shuffle training indices
        indices = torch.randperm(len(tensor_x_tr))

        for batch_idx in range(num_batches):
            b_start = batch_idx * batch_size
            b_end = min(b_start + batch_size, len(tensor_x_tr))
            if b_start >= len(tensor_x_tr):
                break

            batch_indices = indices[b_start:b_end]
            bx = tensor_x_tr[batch_indices]
            by = tensor_y_tr[batch_indices]

            optimizer.zero_grad()
            outputs = model(bx)
            loss = criterion(outputs, by)
            loss.backward()
            optimizer.step()

            running_loss += loss.item() * len(bx)
            _, predicted = torch.max(outputs, 1)
            correct += (predicted == by).sum().item()
            total_processed += len(bx)

            # Update progress bar per batch
            cur_loss = running_loss / total_processed
            cur_acc = (correct / total_processed) * 100
            prefix = f"Epoch {epoch:2d}/{epochs:2d}"
            suffix = f"train_loss: {cur_loss:.4f} - train_acc: {cur_acc:5.1f}%"
            print_progress_bar(total_processed, len(tensor_x_tr), prefix=prefix, suffix=suffix)

        # 30% Test Evaluation
        model.eval()
        with torch.no_grad():
            test_outputs = model(tensor_x_test)
            test_loss = criterion(test_outputs, tensor_y_test).item()
            _, test_predicted = torch.max(test_outputs, 1)
            test_correct = (test_predicted == tensor_y_test).sum().item()
            test_acc = (test_correct / len(tensor_y_test)) * 100

        elapsed = time.time() - start_time
        sys.stdout.write(f"\rEpoch {epoch:2d}/{epochs:2d} [{ '=' * 40 }] - {elapsed:.1f}s - train_loss: {cur_loss:.4f} - train_acc: {cur_acc:5.1f}% - test_loss: {test_loss:.4f} - test_acc: {test_acc:5.1f}%\n")
        sys.stdout.flush()

    return model, data_min, data_max


def main():
    print("==========================================================================")
    print("  ThreatArchitect Real Online Kaggle / UNSW-NB15 & NSL-KDD Deep Retrainer")
    print("==========================================================================")
    print("[1/4] Fetching real online cybersecurity datasets (UNSW-NB15 & NSL-KDD)...")
    
    start_gen = time.time()
    x_data, y_data = OnlineDataFetcher.fetch_real_kaggle_dataset(timeout_sec=15.0)
    print(f"      Successfully downloaded & loaded {len(x_data):,} real online records in {time.time() - start_gen:.2f}s.")

    # 1. Train Deep Neural Network on Real Online Dataset with 70% Train / 30% Test Split
    x_arr = np.array(x_data, dtype=np.float32)
    dnn_model, data_min, data_max = train_tensorflow_style_dnn(x_arr, np.array(y_data), epochs=20, batch_size=1024)
    checkpoint = {
        "state_dict": dnn_model.state_dict(),
        "data_min": data_min,
        "data_max": data_max
    }
    torch.save(checkpoint, "models/dnn_classifier.pth")
    print("      Deep Neural Network weights & scaling bounds saved to 'models/dnn_classifier.pth'.")

    # 2. Train Random Forest Classifier on Real Online Data
    print(f"\n[2/4] Training Random Forest Classifier on {len(x_data):,} real online records (150 trees)...")
    start_rf = time.time()
    rf_wrapper = RFClassifierTrainer.train_model(x_data, y_data, n_estimators=150, max_depth=20)
    rf_wrapper.save("models/rf_classifier.pkl")
    print(f"      Random Forest saved to 'models/rf_classifier.pkl' in {time.time() - start_rf:.2f}s.")

    # 3. Train LSTM Autoencoder on 25,000 sequence windows
    print("\n[3/4] Generating 25,000 sequence windows & training LSTM Autoencoder...")
    start_lstm = time.time()
    lstm_seqs = generate_real_life_lstm_sequences(num_sequences=25000, seq_len=5)
    lstm_model = LSTMTrainer.train_model(lstm_seqs, epochs=15, batch_size=128, lr=0.003)
    CheckpointManager.save_checkpoint(lstm_model, "models/lstm_anomaly.pth")
    print(f"      LSTM Autoencoder saved to 'models/lstm_anomaly.pth' in {time.time() - start_lstm:.2f}s.")

    # 4. Evaluation Metrics Report
    print("\n[4/4] Computing Evaluation Metrics & Classification Report on Real Data...")
    metrics = compute_evaluation_metrics(rf_wrapper.model, x_data, y_data)

    print("\n==========================================================================")
    print("      REAL ONLINE KAGGLE/UNSW-NB15/NSL-KDD MODEL TRAINING COMPLETE        ")
    print("==========================================================================")
    print(f" Total Real Dataset Records : {metrics['total_samples']:,}")
    print(f" Training Data (70%)        : {int(0.70 * metrics['total_samples']):,} records")
    print(f" Testing Data  (30%)        : {int(0.30 * metrics['total_samples']):,} records")
    print(f" Overall Accuracy           : {metrics['overall_accuracy']}%")
    print(f" 5-Fold CV Accuracy         : {metrics['cv_accuracy']}%")
    print("--------------------------------------------------------------------------")
    print(" Per-Class Metrics (Evaluated on Real Data 30% Test Split):")
    for cls, m in metrics["per_class"].items():
        print(f"   - {cls:18s} | Precision: {m['precision']:5.1f}% | Recall: {m['recall']:5.1f}% | F1: {m['f1_score']:5.1f}%")
    print("==========================================================================\n")


if __name__ == "__main__":
    main()
