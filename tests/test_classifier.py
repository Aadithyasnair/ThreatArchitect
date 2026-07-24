"""
tests/test_classifier — Verifies Random Forest training, predictions, and Swappability.
"""

import pytest
from app.ai.classifier.trainer import RFClassifierTrainer
from app.ai.classifier.rf_classifier import RFClassifier


def test_random_forest_classification() -> None:
    """Verifies that RF classifier is train-fit and outputs predictions/evidence."""
    # Generate simple training set: Class Normal (0.0 features) vs Class Attack (100.0 features)
    x_train = []
    y_train = []

    # Normal samples
    for _ in range(20):
        x_train.append([1.0] * 16)
        y_train.append("Normal")

    # Attack samples
    for _ in range(20):
        x_train.append([100.0] * 16)
        y_train.append("SYN Flood")

    # Train model
    classifier = RFClassifierTrainer.train_model(x_train, y_train, n_estimators=5)
    
    # Test Normal input classification
    pred, conf, dist, top_feats = classifier.predict([1.0] * 16)
    assert pred == "Normal"
    assert conf > 0.5
    assert "Normal" in dist
    assert len(top_feats) <= 3

    # Test Attack input classification
    pred_att, conf_att, dist_att, top_feats_att = classifier.predict([100.0] * 16)
    assert pred_att == "SYN Flood"
    assert conf_att > 0.5
    assert "SYN Flood" in dist_att
