"""
app.ai.lstm.dataset — FlowSequenceDataset for sequence feature processing.
"""

from __future__ import annotations
import numpy as np
from typing import Sequence, Any


class FlowSequenceDataset:
    """Sequence dataset wrapper providing numpy array items for training and inference."""

    def __init__(self, sequences: Sequence[Any]) -> None:
        self.data = [np.array(s, dtype=np.float32) for s in sequences]

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> np.ndarray:
        return self.data[idx]
