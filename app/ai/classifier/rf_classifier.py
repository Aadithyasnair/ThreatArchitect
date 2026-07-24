"""
app.ai.classifier.rf_classifier — Scikit-Learn Random Forest connection classifier.

Implements IMachineLearningClassifier.
"""

from __future__ import annotations

import logging
import os
import joblib
from typing import List, Dict, Tuple, Any

from app.ai.classifier.classifier_interface import IMachineLearningClassifier

logger = logging.getLogger("RFClassifier")

FEATURE_NAMES = [
    "PPS", "BPS", "Avg Packet Size", "SYN Count", "ACK Count", "RST Count", "FIN Count",
    "Protocol", "Dest Port", "Source Port", "TTL", "Window Size",
    "Duration", "Inter-Arrival", "Unique Dsts", "Unique Srcs"
]

CLASSES = [
    "Normal", "Port Scan", "SYN Flood", "ICMP Flood", "ARP Spoof", "SSH Brute Force", "Reconnaissance", "Malware Beacon", "DHCP Starvation", "Unknown"
]



class RFClassifier(IMachineLearningClassifier):
    """
    Random Forest implementation of network attack classifier.

    Maps a 16-dimensional flow feature vector to security threat classes.
    """

    def __init__(self) -> None:
        self.model = None

    def predict(self, feature_vector: List[float]) -> Tuple[str, float, Dict[str, float], List[str]]:
        """
        Classify a single feature vector.
        """
        if self.model is None:
            # Fallback when model is not trained/loaded
            dist = {c: 0.0 for c in CLASSES}
            dist["Unknown"] = 1.0
            return "Unknown", 1.0, dist, ["None"]

        try:
            # Predict probability distribution
            probs = self.model.predict_proba([feature_vector])[0]
            classes = self.model.classes_

            prob_dist = {str(cls): float(prob) for cls, prob in zip(classes, probs)}

            # Get top class
            pred_class = str(self.model.predict([feature_vector])[0])
            confidence = prob_dist.get(pred_class, 0.0)

            # Determine top contributing features for this prediction
            # We multiply the normalized feature values by global importances
            importances = self.model.feature_importances_
            contributions = []
            for name, val, imp in zip(FEATURE_NAMES, feature_vector, importances):
                # Simple heuristic contribution: impact = value * global importance
                # We add a tiny eps to prevent division by zero
                impact = abs(val) * imp
                contributions.append((name, impact))

            # Sort features descending by contribution
            contributions.sort(key=lambda x: x[1], reverse=True)
            top_features = [item[0] for item in contributions[:3]]

            return pred_class, confidence, prob_dist, top_features

        except Exception as exc:
            logger.error(f"Random Forest classification failed: {exc}")
            dist = {c: 0.0 for c in CLASSES}
            dist["Unknown"] = 1.0
            return "Unknown", 1.0, dist, ["Error"]

    def save(self, path: str) -> None:
        """Serialize RF model using joblib."""
        try:
            parent = os.path.dirname(path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

            joblib.dump(self.model, path)
            logger.info(f"Random Forest model saved successfully to '{path}'")
        except Exception as exc:
            logger.error(f"Failed to save RF classifier: {exc}")

    def load(self, path: str) -> bool:
        """De-serialize RF model using joblib."""
        if not os.path.exists(path):
            logger.warning(f"RF model file '{path}' not found.")
            return False

        try:
            self.model = joblib.load(path)
            logger.info(f"Random Forest model loaded successfully from '{path}'")
            return True
        except Exception as exc:
            logger.error(f"Failed to load RF classifier: {exc}")
            return False
