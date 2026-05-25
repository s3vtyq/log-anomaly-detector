"""CLI entry point for loganomaly.

Usage:
    loganomaly generate               Generate synthetic log data
    loganomaly analyze <logfile>      Analyze a log file
    loganomaly detect <features.csv>  Run detection on pre-extracted features
    loganomaly full-run               Generate → extract → detect (demo mode)
"""

import time
import json
from pathlib import Path

import click
import pandas as pd

from . import __version__
from .generator import generate_dataset
from .features import parse_log_file, extract_features, extract_features_from_file
from .detector import DetectorConfig, detect_anomalies, get_anomaly_summary, explain_anomaly
from .reporter import (
    print_banner,
    print_detection_summary,
    print_feature_table,
    print_log_preview,
    console,
)
from rich.panel import Panel


@click.group()
@click.version_option(version=__version__)
def cli():
    """loganomaly - Security Log Anomaly Detector

    Unsupervised ML tool that finds unusual patterns in SSH, web, and
    system logs using Isolation Forest.
    """
    pass


@cli.command()
@click.option("-o", "--output-dir", default="data/samples",
              help="Output directory for generated logs")
@click.option("-n", "--total-events", default=5000, type=int,
              help="Total events to generate")
@click.option("-a", "--anomaly-ratio", default=0.05, type=float,
              help="Fraction of events to be anomalous")
@click.option("--days", default=7, type=int,
              help="Number of days of log history")
@click.option("--seed", default=42, type=int,
              help="Random seed")
def generate(output_dir, total_events, anomaly_ratio, days, seed):
    """Generate synthetic log data for testing.

    Creates SSH auth logs, web server logs (Apache Combined format),
    and syslog files with injected anomalies.
    """
    print_banner()
    console.print("[bold]Generating synthetic security logs...[/]")
    console.print(f"  Events: {total_events} ({anomaly_ratio:.0%} anomalies)")
    console.print(f"  Timespan: {days} days")
    console.print()

    paths = generate_dataset(
        output_dir=output_dir,
        total_events=total_events,
        anomaly_ratio=anomaly_ratio,
        days=days,
        seed=seed,
    )

    console.print("[green]✓[/] Generated log files:")
    for key, path in paths.items():
        size = path.stat().st_size
        console.print(f"  [cyan]{key}:[/] {path} ({size:,} bytes)")

    # Show 5 lines of each
    for log_type in ["ssh", "web", "syslog"]:
        if log_type in paths:
            print_log_preview(str(paths[log_type]), max_lines=5)

    console.print("\n[bold yellow]Next:[/] [i]loganomaly analyze <file>[/i] or [i]loganomaly full-run[/i]")


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--type", "-t", "log_type", default="auto",
              type=click.Choice(["ssh", "web", "syslog", "auto"]),
              help="Log type (auto-detects from content)")
@click.option("--window", "-w", default=5, type=int,
              help="Time window in minutes")
@click.option("--contamination", "-c", default=0.05, type=float,
              help="Expected anomaly ratio")
@click.option("--show-windows", is_flag=True,
              help="Show extracted feature windows")
@click.option("--export", "-e", type=click.Path(),
              help="Export features to CSV")
@click.option("--explain", is_flag=True,
              help="Show detailed explanation of why each anomaly was flagged")
def analyze(logfile, log_type, window, contamination, show_windows, export, explain):
    """Analyze a log file for anomalies.

    Parses the log, extracts time-windowed features, and runs
    Isolation Forest anomaly detection.
    """
    print_banner()
    start = time.time()

    console.print(f"[bold]Analyzing:[/] {logfile}")
    console.print(f"  Log type: {log_type}")
    console.print(f"  Window: {window} min | Contamination: {contamination:.0%}")
    console.print()

    # Parse and extract features
    with console.status("[cyan]Parsing log file...[/]"):
        df_features = extract_features_from_file(logfile, log_type, window)

    if df_features.empty:
        console.print("[red]✗[/] No features could be extracted. Check the log format.")
        return

    console.print(f"[green]✓[/] Extracted {len(df_features)} time windows")
    console.print(f"  Features: {len(df_features.columns)}")

    if show_windows:
        print_feature_table(df_features)

    if export:
        df_features.to_csv(export, index=False)
        console.print(f"[green]✓[/] Features exported to {export}")

    # Run detection
    with console.status("[yellow]Running Isolation Forest...[/]"):
        config = DetectorConfig(contamination=contamination)
        result = detect_anomalies(df_features, config)

    elapsed = time.time() - start
    print_detection_summary(result, elapsed)

    if explain:
        console.print("\n[bold magenta]═══ Anomaly Explanations ═══[/]")
        for i in range(min(5, len(result.anomaly_windows))):
            explanation = explain_anomaly(result, i)
            console.print(Panel(explanation, border_style="yellow", width=72))
            console.print()


@cli.command()
@click.argument("features_csv", type=click.Path(exists=True))
@click.option("--contamination", "-c", default=0.05, type=float)
@click.option("--trees", "-t", default=200, type=int,
              help="Number of isolation trees")
@click.option("--export", "-e", type=click.Path(),
              help="Export detection results to CSV")
def detect(features_csv, contamination, trees, export):
    """Run detection on pre-extracted features CSV.

    Expects a CSV with time-windowed feature columns
    (as produced by 'loganomaly analyze --export').
    """
    print_banner()
    start = time.time()

    console.print(f"[bold]Running detection on:[/] {features_csv}")
    console.print()

    df = pd.read_csv(features_csv)

    config = DetectorConfig(
        contamination=contamination,
        n_estimators=trees,
    )
    result = detect_anomalies(df, config)

    elapsed = time.time() - start
    print_detection_summary(result, elapsed)

    if export:
        # Build output DataFrame with predictions
        output = df.copy()
        output["prediction"] = result.predictions
        output["anomaly_score"] = result.anomaly_scores
        output.to_csv(export, index=False)
        console.print(f"[green]✓[/] Results exported to {export}")


@cli.command()
@click.option("-n", "--events", default=3000, type=int,
              help="Number of events to generate")
@click.option("-a", "--anomaly-ratio", default=0.05, type=float)
@click.option("--output", "-o", default="./loganomaly-demo-output",
              type=click.Path(), help="Output directory for demo files")
def full_run(events, anomaly_ratio, output):
    """Run the full pipeline: generate → extract → detect.

    A one-shot demo that creates synthetic logs, extracts features,
    and runs anomaly detection with a detailed report.
    """
    print_banner()
    console.print("[bold cyan]═══════════════════════════════════[/]")
    console.print("[bold cyan]   Full Pipeline Demo", justify="center")
    console.print("[bold cyan]═══════════════════════════════════[/]")
    console.print()

    # Phase 1: Generate
    console.print("[bold]Phase 1/3:[/] Generating synthetic logs...")
    paths = generate_dataset(
        output_dir=Path(output) / "logs",
        total_events=events,
        anomaly_ratio=anomaly_ratio,
    )
    console.print(f"  [green]✓[/] {events} events ({anomaly_ratio:.0%} anomalies)")
    console.print()

    # Phase 2: Extract features
    console.print("[bold]Phase 2/3:[/] Extracting features...")
    all_dfs = []
    for log_type in ["ssh", "web", "syslog"]:
        log_path = paths[log_type]
        df = extract_features_from_file(
            str(log_path), log_type, window_minutes=5
        )
        all_dfs.append(df)
        console.print(f"  [green]✓[/] {log_type}: {len(df)} windows")

    combined = pd.concat(all_dfs, ignore_index=True)
    combined = combined.fillna(0)

    # Aggregate to same time windows
    if "window" in combined.columns:
        # Sum counts across log types for the same window
        agg_cols = [c for c in combined.columns if c not in ["window"]]
        combined = combined.groupby("window").sum().reset_index()

    features_path = Path(output) / "features.csv"
    combined.to_csv(features_path, index=False)
    console.print(f"  [green]✓[/] Combined features saved: {features_path}")
    console.print(f"  Total windows: {len(combined)}")
    console.print()

    # Phase 3: Detect
    console.print("[bold]Phase 3/3:[/] Running anomaly detection...")
    t0 = time.time()

    config = DetectorConfig(contamination=anomaly_ratio)
    result = detect_anomalies(combined, config)

    elapsed = time.time() - t0

    print_detection_summary(result, elapsed, title="Full Pipeline Results")

    # Export results
    results_path = Path(output) / "detection_results.csv"
    combined["prediction"] = result.predictions
    combined["anomaly_score"] = result.anomaly_scores
    combined.to_csv(results_path, index=False)
    console.print(f"\n[green]✓[/] Full results exported: {results_path}")

    # Print summary JSON
    summary = get_anomaly_summary(result)
    summary_path = Path(output) / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    console.print(f"[green]✓[/] Summary exported: {summary_path}")

    console.print("\n[bold cyan]Demo complete![/]")


if __name__ == "__main__":
    cli()
