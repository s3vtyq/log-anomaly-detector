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


def explain_anomaly(
    result: DetectionResult,
    window_index: int = 0,
) -> str:
    """Generate a human-readable explanation for an anomalous window.

    Args:
        result: Detection result from detect_anomalies().
        window_index: Which anomalous window to explain (0 = most anomalous).

    Returns:
        Human-readable explanation string.
    """
    if result.anomaly_windows.empty:
        return "No anomalies to explain."

    sorted_anoms = result.anomaly_windows.sort_values("anomaly_score")
    if window_index >= len(sorted_anoms):
        window_index = 0

    row = sorted_anoms.iloc[window_index]

    # Compute per-feature deviations
    all_data = pd.concat([result.normal_windows, result.anomaly_windows])
    means = all_data[result.feature_columns].mean()
    stds = all_data[result.feature_columns].std().replace(0, 1)

    anom_values = row[result.feature_columns]
    z_scores = ((anom_values - means).abs() / stds).sort_values(ascending=False)

    # Build explanation
    window_time = row.get("window", "unknown")
    score = row.get("anomaly_score", 0)
    total_events = row.get("total_count", 0)

    lines = [
        f"Window: {window_time}  (anomaly score: {score:.4f})",
        f"Total events in this window: {int(total_events)}",
        "",
        "Why this window is anomalous:",
    ]

    # Explain top 5 features driving the deviation
    for feat, z in z_scores.head(5).items():
        z = round(z, 2)
        actual = anom_values.get(feat, 0)
        normal_mean = means.get(feat, 0)
        direction = "higher" if actual > normal_mean else "lower"

        if "count_" in feat:
            t = feat.replace("count_", "").upper()
            lines.append(
                f"  \u2022 {t} event count is {direction} than normal "
                f"(actual: {actual:.1f}, normal: {normal_mean:.2f}, z={z})"
            )
        elif "error_rate" in feat:
            t = feat.replace("error_rate_", "").upper()
            lines.append(
                f"  \u2022 {t} error rate is {direction} than normal "
                f"(actual: {actual:.1%}, normal: {normal_mean:.2%}, z={z})"
            )
        elif "unique_ips" in feat:
            t = feat.replace("unique_ips_", "").upper()
            lines.append(
                f"  \u2022 {t} IP diversity is {direction} than normal "
                f"(z-score: {z})"
            )
        elif "suspicious" in feat:
            lines.append(
                f"  \u2022 Suspicious {feat} is {direction} "
                f"(z-score: {z})"
            )
        else:
            lines.append(
                f"  \u2022 {feat} is {direction} than normal (z-score: {z})"
            )

    # Classify the anomaly type
    z_count_ssh = z_scores.get("count_ssh", 0)
    z_critical = z_scores.get("is_critical", 0)
    z_susp_path = z_scores.get("is_suspicious_path", 0)
    z_susp_agent = z_scores.get("is_suspicious_agent", 0)

    lines.append("")
    if z_count_ssh > 1.5:
        lines.append("\U0001f50d Assessment: Possible SSH brute-force attack")
    elif z_critical > 1.5:
        lines.append("\U0001f50d Assessment: Possible system compromise or service failure")
    elif z_susp_path > 1.5 or z_susp_agent > 1.5:
        lines.append("\U0001f50d Assessment: Possible web application scanning")
    else:
        lines.append("\U0001f50d Assessment: Unusual pattern — review the feature deviations above")

    return "\n".join(lines)
