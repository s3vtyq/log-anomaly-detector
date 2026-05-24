"""Anomaly detection for security log data.

Uses Isolation Forest (primary) with autoencoder option for detecting
unusual patterns in time-windowed log features.
"""

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


@dataclass
class DetectionResult:
    """Results from anomaly detection.

    Attributes:
        predictions: numpy array where 1 = normal, -1 = anomaly.
        anomaly_scores: anomaly score (lower = more anomalous).
        anomaly_windows: DataFrame rows flagged as anomalous.
        normal_windows: DataFrame rows flagged as normal.
        detection_rate: fraction of windows flagged as anomalous.
        feature_columns: list of feature names used.
    """
    predictions: np.ndarray
    anomaly_scores: np.ndarray
    anomaly_windows: pd.DataFrame
    normal_windows: pd.DataFrame
    detection_rate: float
    feature_columns: list[str]


@dataclass
class DetectorConfig:
    """Configuration for the anomaly detector."""
    contamination: float = 0.05       # Expected anomaly ratio in data
    n_estimators: int = 200            # Number of trees in Isolation Forest
    max_samples: int | str = "auto"   # Samples per tree
    random_state: int = 42
    feature_columns: list[str] | None = None  # Auto-detect if None
    exclude_columns: list[str] = field(
        default_factory=lambda: ["window", "timestamp", "label"]
    )


def _auto_detect_feature_columns(df: pd.DataFrame, exclude: list[str]) -> list[str]:
    """Detect numeric feature columns, excluding obvious non-features."""
    excluded = set(exclude + ["window", "timestamp", "hour", "day_of_week",
                               "is_business_hours", "is_weekend"])
    cols = []
    for col in df.columns:
        if col in excluded:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            cols.append(col)
    return cols


def detect_anomalies(
    df: pd.DataFrame,
    config: DetectorConfig | None = None,
) -> DetectionResult:
    """Run Isolation Forest anomaly detection on feature DataFrame.

    Args:
        df: Feature DataFrame from features.extract_features().
        config: Detector configuration.

    Returns:
        DetectionResult with predictions, scores, and split windows.
    """
    if config is None:
        config = DetectorConfig()

    if df.empty:
        raise ValueError("Empty DataFrame — nothing to detect")

    feature_cols = config.feature_columns or _auto_detect_feature_columns(
        df, config.exclude_columns
    )

    # Filter to only numeric columns that actually exist
    available_cols = [c for c in feature_cols if c in df.columns]
    if not available_cols:
        raise ValueError(
            "No feature columns found in DataFrame. "
            "Run feature extraction first."
        )

    X = df[available_cols].fillna(0).values

    model = IsolationForest(
        n_estimators=config.n_estimators,
        max_samples=config.max_samples,
        contamination=config.contamination,
        random_state=config.random_state,
        n_jobs=-1,
    )

    predictions = model.fit_predict(X)
    scores = model.score_samples(X)  # Higher = more normal

    result_df = df.copy()
    result_df["prediction"] = predictions
    result_df["anomaly_score"] = scores

    anomalies = result_df[result_df["prediction"] == -1].copy()
    normals = result_df[result_df["prediction"] == 1].copy()

    detection_rate = float(len(anomalies)) / float(len(result_df))

    return DetectionResult(
        predictions=predictions,
        anomaly_scores=scores,
        anomaly_windows=anomalies,
        normal_windows=normals,
        detection_rate=detection_rate,
        feature_columns=available_cols,
    )


def get_anomaly_summary(result: DetectionResult) -> dict[str, Any]:
    """Summarize detection results for reporting."""
    if result.anomaly_windows.empty:
        return {"message": "No anomalies detected."}

    # Sort anomalies by score (most anomalous first)
    sorted_anoms = result.anomaly_windows.sort_values("anomaly_score")

    # Compute which features contributed most (z-score deviation)
    all_data = pd.concat([result.normal_windows, result.anomaly_windows])
    feature_means = all_data[result.feature_columns].mean()
    feature_stds = all_data[result.feature_columns].std().replace(0, 1)

    anomaly_means = result.anomaly_windows[result.feature_columns].mean()
    z_scores = (anomaly_means - feature_means).abs() / feature_stds
    top_features = z_scores.sort_values(ascending=False).head(5)

    return {
        "total_windows": len(result.anomaly_windows) + len(result.normal_windows),
        "anomaly_count": len(result.anomaly_windows),
        "detection_rate": result.detection_rate,
        "most_anomalous_times": sorted_anoms[["window", "anomaly_score"]]
            .head(10),
        "top_driving_features": top_features,
        "normal_stats": {
            "mean_windows": len(result.normal_windows),
            "feature_means": result.normal_windows[result.feature_columns]
                .mean().to_dict(),
        },
    }
