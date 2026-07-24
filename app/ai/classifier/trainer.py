"""
app.ai.classifier.trainer — Training wrapper for Scikit-Learn classifiers.
"""

from __future__ import annotations

import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from typing import List

from app.ai.classifier.rf_classifier import RFClassifier

logger = logging.getLogger("RFClassifierTrainer")


class RFClassifierTrainer:
    """Trains a Random Forest classifier on flow features."""

    @staticmethod
    def train_model(
        x_data: List[List[float]],
        y_data: List[str],
        n_estimators: int = 100,
        max_depth: int = 15,
    ) -> RFClassifier:
        """
        Fits a RandomForest model on numerical feature vectors and class labels.
        """
        logger.info(f"Training Random Forest classifier on {len(x_data)} real-life flow samples...")
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        model.fit(x_data, y_data)

        # Cross-validation accuracy check
        try:
            scores = cross_val_score(model, x_data, y_data, cv=5)
            mean_acc = float(scores.mean() * 100)
            logger.info(f"Random Forest training complete. 5-Fold CV Accuracy: {mean_acc:.2f}%")
        except Exception as exc:
            logger.info("Random Forest training complete.")

        wrapper = RFClassifier()
        wrapper.model = model
        return wrapper

