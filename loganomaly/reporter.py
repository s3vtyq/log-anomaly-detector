"""CLI reporter for anomaly detection results.

Uses the `rich` library for colored, formatted terminal output.
"""

from pathlib import Path
from datetime import datetime

import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.columns import Columns
from rich.text import Text
from rich import box

from .detector import DetectionResult

console = Console()


def print_banner():
    """Print an ASCII banner."""
    banner = Text(
        r"""
  _                     _                             _ 
 | |   ___   __ _  __ _| | __ _ _   _ _ __ ___   ___ | |
 | |  / _ \ / _` |/ _` | |/ _` | | | | '_ ` _ \ / _ \| |
 | | | (_) | (_| | (_| | | (_| | |_| | | | | | | (_) | |
 |_|  \___/ \__, |\__, |_|\__,_|\__, |_| |_| |_|\___/|_|
            |___/ |___/         |___/                    
 Security Log Anomaly Detector
""",
        style="bold cyan",
    )
    console.print(banner)
    console.print("Unsupervised ML for security log analysis", style="italic green")
    console.print()


def print_detection_summary(result: DetectionResult, elapsed: float, title: str = ""):
    """Print a comprehensive detection report.

    Args:
        result: Detection result from detector.detect_anomalies().
        elapsed: Time taken for detection in seconds.
        title: Optional section title.
    """
    if title:
        console.print(f"\n[bold yellow]═══ {title} ═══[/]")

    total = result.anomaly_windows.shape[0] + result.normal_windows.shape[0]

    # ── Summary stats ───────────────────────────────────────
    stats = Table(
        box=box.ROUNDED,
        title="Detection Summary",
        title_style="bold blue",
    )
    stats.add_column("Metric", style="cyan")
    stats.add_column("Value", style="white")

    stats.add_row("Total time windows", str(total))
    stats.add_row("Normal windows", style_text(str(result.normal_windows.shape[0]), "green"))
    stats.add_row("Anomalous windows", str(result.anomaly_windows.shape[0]))
    stats.add_row("Detection rate", f"{result.detection_rate:.2%}")
    stats.add_row("Features used", str(len(result.feature_columns)))
    stats.add_row("Time taken", f"{elapsed:.2f}s")

    console.print(stats)

    # ── Top anomalous windows ──────────────────────────────
    if not result.anomaly_windows.empty:
        anom_sorted = result.anomaly_windows.sort_values("anomaly_score").head(10)
        table = Table(
            box=box.ROUNDED,
            title="🔴 Top Anomalous Time Windows",
            title_style="bold red",
        )
        table.add_column("Time Window", style="yellow")
        table.add_column("Anomaly Score", justify="right")
        table.add_column("Total Events", justify="right", style="cyan")

        # Add type-specific columns if they exist
        for lt in ["ssh", "web", "syslog"]:
            col = f"count_{lt}"
            if col in anom_sorted.columns:
                table.add_column(f"{lt.upper()} Events", justify="right")

        for _, row in anom_sorted.iterrows():
            score_str = f"{row['anomaly_score']:.4f}"
            time_str = str(row["window"]) if "window" in row.index else "N/A"
            total_events = int(row.get("total_count", 0))

            extra_cols = []
            for lt in ["ssh", "web", "syslog"]:
                col = f"count_{lt}"
                if col in anom_sorted.columns:
                    extra_cols.append(str(int(row.get(col, 0))))

            table.add_row(time_str, score_str, str(total_events), *extra_cols)

        console.print(table)

    # ── Top driving features ────────────────────────────────
    if result.anomaly_windows.shape[0] > 0:
        all_data = pd.concat([result.anomaly_windows, result.normal_windows])
        means = all_data[result.feature_columns].mean()
        stds = all_data[result.feature_columns].std().replace(0, 1)

        anom_means = result.anomaly_windows[result.feature_columns].mean()
        z_scores = (anom_means - means).abs() / stds
        top_features = z_scores.sort_values(ascending=False).head(8)

        ftable = Table(
            box=box.ROUNDED,
            title="🎯 Top Features Driving Anomaly Detection",
            title_style="bold magenta",
        )
        ftable.add_column("Feature", style="cyan")
        ftable.add_column("Deviation (z-score)", justify="right")
        ftable.add_column("Anomaly Mean", justify="right")
        ftable.add_column("Overall Mean", justify="right")

        for feat, z in top_features.items():
            a_mean = anom_means.get(feat, 0)
            o_mean = means.get(feat, 0)
            ftable.add_row(
                feat,
                f"{z:.2f}",
                f"{a_mean:.3f}",
                f"{o_mean:.3f}",
            )

        console.print(ftable)

    # ── Known pattern classification (heuristic) ────────────
    if result.anomaly_windows.shape[0] > 0:
        _print_pattern_hints(result)


def _print_pattern_hints(result: DetectionResult):
    """Try to classify what kind of anomaly we detected."""
    hints = []
    cols = result.feature_columns

    # Check for SSH brute-force pattern
    if "count_ssh" in cols:
        ssh_count = result.anomaly_windows["count_ssh"].mean()
        normal_count = result.normal_windows["count_ssh"].mean()
        if ssh_count > normal_count * 3 and ssh_count > 5:
            hints.append("🔥 Possible SSH brute-force attack (high SSH volume)")

    if "error_rate_ssh" in cols:
        err_rate = result.anomaly_windows["error_rate_ssh"].mean()
        normal_err = result.normal_windows["error_rate_ssh"].mean()
        if err_rate > normal_err * 2 and err_rate > 0.3:
            hints.append("🔐 High SSH auth failure rate — potential credential stuffing")

    # Web attacks
    if "is_suspicious_path" in cols:
        sp_rate = result.anomaly_windows["is_suspicious_path"].mean()
        normal_sp = result.normal_windows["is_suspicious_path"].mean()
        if sp_rate > normal_sp * 3:
            hints.append("🌐 Suspicious URL patterns detected — possible web scanning")

    if "is_suspicious_agent" in cols:
        sa_rate = result.anomaly_windows["is_suspicious_agent"].mean()
        normal_sa = result.normal_windows["is_suspicious_agent"].mean()
        if sa_rate > normal_sa * 3:
            hints.append("🤖 Suspicious user agents detected — automated scanning tools")

    if "is_error" in cols and "log_type" in result.anomaly_windows.columns:
        web_errors = result.anomaly_windows[
            result.anomaly_windows.get("log_type", pd.Series()) == "web"
        ]["is_error"].mean()
        if web_errors > 0.5:
            hints.append("⚠️  Elevated HTTP error rate — probing or misconfiguration")

    # System anomalies
    if "is_critical" in cols:
        crit_rate = result.anomaly_windows["is_critical"].mean()
        normal_crit = result.normal_windows["is_critical"].mean()
        if crit_rate > normal_crit * 2:
            hints.append("💀 Critical system events detected — possible compromise")

    if "has_denied" in cols:
        denied = result.anomaly_windows["has_denied"].mean()
        normal_denied = result.normal_windows["has_denied"].mean()
        if denied > normal_denied * 3:
            hints.append("🚫 Access denied / AppArmor denials — possible privilege escalation")

    if not hints:
        hints.append("📊 Anomaly pattern isn't a known attack type — check the feature deviations above")

    console.print()
    for hint in hints:
        console.print(Panel(hint, border_style="bold yellow", width=70))
    console.print()


def print_feature_table(df: pd.DataFrame, max_rows: int = 20):
    """Print a preview of the feature DataFrame."""
    table = Table(
        box=box.SIMPLE,
        title="Feature Window Preview",
        title_style="bold blue",
    )
    for col in df.columns[:10]:
        table.add_column(col[:20])

    for idx, (_, row) in enumerate(df.iterrows()):
        if idx >= max_rows:
            break
        table.add_row(*[str(v)[:12] for v in row.values[:10]])

    if len(df) > max_rows:
        console.print(f"... and {len(df) - max_rows} more rows")
    console.print(table)


def print_log_preview(filepath: str, max_lines: int = 10):
    """Print a preview of a log file."""
    path = Path(filepath)
    if not path.exists():
        console.print(f"[red]File not found: {filepath}[/]")
        return

    console.print(f"\n[bold]Log preview:[/] {filepath}")

    table = Table(box=box.SIMPLE)
    table.add_column("Line", style="dim", justify="right")
    table.add_column("Content", style="white")

    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            display = line.rstrip()[:100]
            table.add_row(str(i + 1), display)

    console.print(table)
    console.print()


def style_text(text: str, color: str) -> str:
    """Return styled text string (rich markup)."""
    return f"[{color}]{text}[/]"
