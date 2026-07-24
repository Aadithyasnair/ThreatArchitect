"""
app.ai.classifier.classifier_interface — Interface for ML connection classifiers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Any


class IMachineLearningClassifier(ABC):
    """
    Interface defining ML classifier requirements.

    Permits swapping models (Random Forest, Gradient Boosting, XGBoost)
    without modifying threat modeling engine dispatch logic.
    """

    @abstractmethod
    def predict(self, feature_vector: List[float]) -> Tuple[str, float, Dict[str, float], List[str]]:
        """
        Classifies a single 16-dimensional flow feature vector.

        Returns:
            Tuple of:
            - str: Predicted class name
            - float: Confidence score (probability of the predicted class, 0.0 to 1.0)
            - dict: Probability distribution across all classes
            - list: Sorted list of names of top contributing features
        """
        pass

    @abstractmethod
    def save(self, path: str) -> None:
        """Save classifier model weights to file."""
        pass

    @abstractmethod
    def load(self, path: str) -> bool:
        """Load classifier model weights from file."""
        pass
