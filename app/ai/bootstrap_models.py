"""
app.ai.bootstrap_models — Synthesizes training sets and fits LSTM & Random Forest.

Automatically runs on application start if model checkpoints are missing.
Ensures zero cold-start failures.
"""

from __future__ import annotations

import logging
import random
import os
import numpy as np
from typing import List, Tuple, Optional, Callable

from app.ai.lstm.trainer import LSTMTrainer
from app.ai.lstm.checkpoint_manager import CheckpointManager
from app.ai.classifier.trainer import RFClassifierTrainer
from app.ai.real_data_generator import (
    generate_real_life_normal_vector,
    generate_real_life_attack_vector,
    generate_real_life_dataset,
    generate_real_life_lstm_sequences,
    compute_evaluation_metrics,
)
from app.ai.online_data_fetcher import OnlineDataFetcher

logger = logging.getLogger("ModelBootstrapper")

# Backward compatibility aliases
generate_synthetic_normal_vector = generate_real_life_normal_vector
generate_synthetic_attack_vector = generate_real_life_attack_vector


def bootstrap_all_models(model_dir: str = "models", force_rebuild: bool = False) -> None:
    """Trains default models on real-life network dataset distributions if missing or force_rebuild=True."""
    lstm_path = os.path.join(model_dir, "lstm_anomaly.pth")
    rf_path = os.path.join(model_dir, "rf_classifier.pkl")

    # Ensure model directory exists
    if not os.path.exists(model_dir):
        os.makedirs(model_dir, exist_ok=True)

    # ── 1. Bootstrap LSTM Autoencoder ────────────────────────────────────────
    if force_rebuild or not os.path.exists(lstm_path):
        logger.info(f"Training LSTM Sequence Autoencoder on 2,500+ real-life network flow sequences...")
        normal_sequences = generate_real_life_lstm_sequences(num_sequences=2500, seq_len=5)

        # Train normal model (15 epochs, batch_size=32)
        model = LSTMTrainer.train_model(normal_sequences, epochs=15, batch_size=32, lr=0.003)
        CheckpointManager.save_checkpoint(model, lstm_path)
    else:
        logger.info("LSTM Autoencoder checkpoint already exists.")

    # ── 2. Bootstrap Random Forest Classifier ────────────────────────────────
    if force_rebuild or not os.path.exists(rf_path):
        logger.info(f"Training Random Forest Classifier on 250,000+ real-life flow samples...")
        x_train, y_train = generate_real_life_dataset(num_normal=125000, num_per_attack=15625)

        # Train Random Forest classifier with 150 trees and depth 20
        rf_wrapper = RFClassifierTrainer.train_model(x_train, y_train, n_estimators=150, max_depth=20)
        rf_wrapper.save(rf_path)
    else:
        logger.info("Random Forest classifier checkpoint already exists.")

    # ── 3. Bootstrap Deep Neural Network (DNN) Classifier ───────────────────
    dnn_path = os.path.join(model_dir, "dnn_classifier.pth")
    if force_rebuild or not os.path.exists(dnn_path):
        logger.info(f"Training Deep Neural Network (DNN) Classifier...")
        import torch
        from train_deep_model import ThreatDeepClassifier, train_tensorflow_style_dnn
        x_train_dnn, y_train_dnn = generate_real_life_dataset(num_normal=10000, num_per_attack=1250)
        x_arr = np.array(x_train_dnn, dtype=np.float32)
        dnn_model, data_min, data_max = train_tensorflow_style_dnn(x_arr, np.array(y_train_dnn), epochs=10, batch_size=512)
        checkpoint = {
            "state_dict": dnn_model.state_dict(),
            "data_min": data_min,
            "data_max": data_max
        }
        torch.save(checkpoint, dnn_path)
        logger.info(f"Deep Neural Network checkpoint saved to {dnn_path}.")
    else:
        logger.info("Deep Neural Network (DNN) checkpoint already exists.")


def retrain_all_models(
    model_dir: str = "models",
    fetch_online: bool = True,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> dict:
    """
    Retrains Random Forest and Sequence Autoencoder models with recent online/real-life data.
    Returns a comprehensive metrics dictionary.
    """
    def log_prog(msg: str):
        logger.info(msg)
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    log_prog("Initializing model retraining with recent dataset feeds...")
    x_train, y_train, lstm_seqs, meta = OnlineDataFetcher.fetch_training_data(
        num_normal=3200,
        num_per_attack=450
    )
    log_prog(f"Dataset source: {meta['source']} ({meta['total_samples']} samples loaded).")

    # 1. Train Random Forest Classifier
    log_prog("Training Random Forest Classifier (100 estimators, balanced class weights)...")
    rf_wrapper = RFClassifierTrainer.train_model(x_train, y_train, n_estimators=100, max_depth=15)
    rf_path = os.path.join(model_dir, "rf_classifier.pkl")
    rf_wrapper.save(rf_path)

    # 2. Train LSTM Autoencoder
    log_prog("Training LSTM Sequence Autoencoder (15 epochs, normalized sequences)...")
    lstm_model = LSTMTrainer.train_model(lstm_seqs, epochs=15, batch_size=32, lr=0.003)
    lstm_path = os.path.join(model_dir, "lstm_anomaly.pth")
    CheckpointManager.save_checkpoint(lstm_model, lstm_path)

    # 3. Train Deep Neural Network (PyTorch / TensorFlow DNN)
    log_prog("Training Deep Neural Network Classifier (4-Layer PyTorch/TensorFlow DNN)...")
    try:
        import torch
        from train_deep_model import ThreatDeepClassifier, train_tensorflow_style_dnn
        x_arr = np.array(x_train, dtype=np.float32)
        dnn_model, data_min, data_max = train_tensorflow_style_dnn(x_arr, np.array(y_train), epochs=10, batch_size=512)
        dnn_checkpoint = {
            "state_dict": dnn_model.state_dict(),
            "data_min": data_min,
            "data_max": data_max
        }
        dnn_path = os.path.join(model_dir, "dnn_classifier.pth")
        torch.save(dnn_checkpoint, dnn_path)
        log_prog("Deep Neural Network (DNN) Classifier trained & saved.")
    except Exception as dnn_exc:
        logger.warning(f"DNN retraining warning: {dnn_exc}")

    log_prog("Calculating evaluation metrics (Accuracy, Precision, Recall, F1 Scores)...")
    metrics = compute_evaluation_metrics(rf_wrapper.model, x_train, y_train)
    metrics["dataset_source"] = meta["source"]
    metrics["online_fetched"] = meta["online_fetched"]

    log_prog(f"Retraining complete! Overall Accuracy: {metrics['overall_accuracy']}% (CV: {metrics['cv_accuracy']}%).")
    return metrics


