"""Feature extraction from raw security logs.

Parses SSH, web, and syslog lines into numerical feature vectors
that can be fed into anomaly detection models.
"""

import re
import math
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Iterator

import numpy as np
import pandas as pd


# ── Parsers ────────────────────────────────────────────────────

SSH_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<message>.+)"
)

WEB_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+-\s+-\s+'
    r'\[(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})[^\]]*\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)"'
)

SYSLOG_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+(?P<facility>\w+):\s+(?P<message>.+)"
)

SUSPICIOUS_PATHS = {
    "wp-admin", "/../", "passwd", ".env", "phpmyadmin",
    "shell.php", "config.bak", "admin.php", "?id=", "--",
    "/api/", "union", "select", "1=1",
}

SUSPICIOUS_AGENTS = {
    "sqlmap", "nikto", "nmap", "masscan", "wfuzz",
    "censys", "acunetix", "nessus",
}

SUSPICIOUS_USERS = {
    "root", "admin", "test", "admin1", "oracle", "postgres", "guest",
}


def _parse_timestamp(timestamp_str: str, fmt: str) -> datetime | None:
    """Parse a timestamp string with error handling."""
    try:
        now = datetime.now()
        year = now.year
        parsed = datetime.strptime(timestamp_str, fmt)
        return parsed.replace(year=year)
    except (ValueError, OSError):
        return None


def _parse_ssh(line: str, log_type: str) -> dict | None:
    m = SSH_PATTERN.search(line)
    if not m:
        return None
    ts = _parse_timestamp(m.group("timestamp"), "%b %d %H:%M:%S")
    if ts is None:
        return None
    msg = m.group("message").lower()
    return {
        "timestamp": ts,
        "log_type": "ssh",
        "is_failed": 1 if "failed password" in msg else 0,
        "is_invalid_user": 1 if "invalid user" in msg else 0,
        "is_accepted": 1 if "accepted" in msg and "publickey" not in msg else 0,
        "is_accepted_key": 1 if "accepted publickey" in msg else 0,
        "is_break_in": 1 if "possible break-in" in msg or "reverse mapping" in msg else 0,
        "is_suspicious_user": 1 if any(u in msg for u in SUSPICIOUS_USERS) else 0,
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", msg) else 0,
        "error_count": msg.count("error") + msg.count("failed") + msg.count("timeout"),
    }


def _parse_web(line: str, log_type: str) -> dict | None:
    m = WEB_PATTERN.search(line)
    if not m:
        return None
    ts = _parse_timestamp(m.group("timestamp"), "%d/%b/%Y:%H:%M:%S")
    if ts is None:
        return None
    status = int(m.group("status"))
    path = m.group("path").lower()
    agent = m.group("agent").lower()
    size = int(m.group("size"))

    is_suspicious_path = any(sp in path for sp in SUSPICIOUS_PATHS)
    is_suspicious_agent = any(sa in agent for sa in SUSPICIOUS_AGENTS)

    return {
        "timestamp": ts,
        "log_type": "web",
        "status": status,
        "size": size,
        "is_error": 1 if status >= 400 else 0,
        "is_not_found": 1 if status == 404 else 0,
        "is_forbidden": 1 if status == 403 else 0,
        "is_server_error": 1 if status >= 500 else 0,
        "is_suspicious_path": 1 if is_suspicious_path else 0,
        "is_suspicious_agent": 1 if is_suspicious_agent else 0,
        "is_post": 1 if m.group("method") == "POST" else 0,
        "path_depth": path.count("/"),
    }


def _parse_syslog(line: str, log_type: str) -> dict | None:
    m = SYSLOG_PATTERN.search(line)
    if not m:
        return None
    ts = _parse_timestamp(m.group("timestamp"), "%b %d %H:%M:%S")
    if ts is None:
        return None
    msg = m.group("message").lower()
    facility = m.group("facility")

    return {
        "timestamp": ts,
        "log_type": "syslog",
        "facility_kern": 1 if facility == "kern" else 0,
        "facility_auth": 1 if facility == "auth" else 0,
        "facility_daemon": 1 if facility == "daemon" else 0,
        "is_error": 1 if msg.startswith("error") else 0,
        "is_warning": 1 if msg.startswith("warning") else 0,
        "is_critical": 1 if msg.startswith("critical") else 0,
        "is_info": 1 if msg.startswith("info") else 0,
        "has_oom": 1 if "oom" in msg else 0,
        "has_iptables": 1 if "iptables" in msg else 0,
        "has_denied": 1 if "denied" in msg or "failed" in msg else 0,
        "has_timeout": 1 if "timeout" in msg else 0,
        "error_count": msg.count("error") + msg.count("critical") + msg.count("failed"),
    }


PARSERS = {"ssh": _parse_ssh, "web": _parse_web, "syslog": _parse_syslog}


# ── Aggregation-based Features ────────────────────────────────

def detect_log_type(path: str, sample_lines: int = 20) -> str:
    """Auto-detect log type by trying each parser on sample lines.

    Reads the first N lines of a file and checks which parser
    matches the most lines.

    Returns: 'ssh', 'web', 'syslog', or 'unknown'.
    """
    scores = {"ssh": 0, "web": 0, "syslog": 0}
    try:
        with open(path) as f:
            for i, line in enumerate(f):
                if i >= sample_lines:
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for log_type, parser in PARSERS.items():
                    if parser(line, log_type) is not None:
                        scores[log_type] += 1
    except (FileNotFoundError, OSError):
        return "unknown"

    # Return type with highest match count
    max_type = max(scores, key=scores.get)
    if scores[max_type] == 0:
        return "unknown"
    # If web and ssh/syslog are similar, prefer the dominant one
    total = sum(scores.values())
    if total > 0 and scores[max_type] / total >= 0.3:
        return max_type
    return "unknown"


def parse_log_file(path: str, log_type: str = "auto") -> pd.DataFrame:
    """Parse a log file into a DataFrame of raw events.

    Args:
        path: Path to the log file.
        log_type: One of 'ssh', 'web', 'syslog', or 'auto' (detect from format).

    Returns:
        DataFrame with parsed features, one row per log line.
    """
    # Auto-detect format if needed
    detected_type = log_type
    if detected_type == "auto":
        # First check if it's a labeled synthetic file
        with open(path) as f:
            first_line = f.readline().strip()
        if first_line.startswith("ssh "):
            detected_type = "ssh"
        elif first_line.startswith("web "):
            detected_type = "web"
        elif first_line.startswith("syslog "):
            detected_type = "syslog"
        else:
            # Not labeled → try parser-based detection
            detected_type = detect_log_type(path)

    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Handle labeled synthetic files (strip label prefix)
            if log_type == "auto":
                if line.startswith("ssh ") and detected_type == "ssh":
                    line = line[4:]
                elif line.startswith("web ") and detected_type == "web":
                    line = line[4:]
                elif line.startswith("syslog ") and detected_type == "syslog":
                    line = line[7:]

            # Skip header lines
            if line.startswith("#"):
                continue

            parser = PARSERS.get(detected_type)
            if parser is None:
                continue

            record = parser(line, detected_type)
            if record:
                records.append(record)

    df = pd.DataFrame(records)
    if df.empty:
        import warnings
        hints = {
            "ssh": "SSH auth logs contain 'sshd' entries",
            "web": "Web logs follow Apache Combined format (IP - - [date] ...)",
            "syslog": "Syslog has facility: message format",
            "unknown": "Could not detect log format",
        }
        warnings.warn(f"No events parsed from {path}. "
                      f"Detected type: {detected_type}. "
                      f"Hint: {hints.get(detected_type, '')}")
    return df


def extract_features(
    df: pd.DataFrame,
    window_minutes: int = 5,
) -> pd.DataFrame:
    """Aggregate raw parsed logs into time-windowed feature vectors.

    Each window becomes one sample. Features include:
    - Volume (event count per type)
    - Error/failure rates
    - Entropy of IP addresses (high = many distinct IPs)
    - Suspicious path/agent ratios
    - Time-based features

    Args:
        df: DataFrame from parse_log_file().
        window_minutes: Size of time windows in minutes.

    Returns:
        DataFrame with aggregated features, one row per time window.
    """
    if df.empty:
        return pd.DataFrame()

    df = df.sort_values("timestamp")
    df["window"] = df["timestamp"].dt.floor(f"{window_minutes}min")

    groups: list[pd.DataFrame] = []

    for log_type in df["log_type"].unique():
        subset = df[df["log_type"] == log_type].copy()
        if subset.empty:
            continue

        agg = subset.groupby("window").agg(**{
            # Volume
            f"count_{log_type}": ("timestamp", "count"),

            # Error density
            f"error_rate_{log_type}": (
                "is_error" if "is_error" in subset.columns else "error_count",
                "mean",
            ),

            # Unique IPs (count of source IPs per window)
            f"unique_ips_{log_type}": (
                "has_ip" if "has_ip" in subset.columns else "timestamp",
                lambda x: (
                    subset.loc[x.index, "is_error"].sum()  # fallback
                    if "is_error" in subset.columns
                    else len(x)
                ),
            ),
        }).reset_index()

        # Compute IP entropy (anonymized from has_ip count)
        if "has_ip" in subset.columns:
            ip_counts = subset.groupby("window")["has_ip"].sum()
            agg[f"ip_entropy_{log_type}"] = agg["window"].map(
                lambda w: _compute_entropy(subset[subset["window"] == w]["has_ip"].values)
            )

        groups.append(agg)

    if not groups:
        return pd.DataFrame()

    # Merge all log types on window
    result = groups[0]
    for g in groups[1:]:
        result = result.merge(g, on="window", how="outer")

    result = result.fillna(0)

    # Total event count across all types
    count_cols = [c for c in result.columns if c.startswith("count_")]
    if count_cols:
        result["total_count"] = result[count_cols].sum(axis=1)

    # Add time features
    result["hour"] = result["window"].dt.hour
    result["day_of_week"] = result["window"].dt.dayofweek
    result["is_business_hours"] = ((result["hour"] >= 8) & (result["hour"] <= 18)).astype(int)
    result["is_weekend"] = (result["day_of_week"] >= 5).astype(int)

    return result.sort_values("window").reset_index(drop=True)


def _compute_entropy(values: np.ndarray) -> float:
    """Compute Shannon entropy of a set of values."""
    if len(values) == 0:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_features_from_file(
    path: str,
    log_type: str = "auto",
    window_minutes: int = 5,
) -> pd.DataFrame:
    """Convenience: parse + extract features in one call."""
    df = parse_log_file(path, log_type)
    return extract_features(df, window_minutes)
