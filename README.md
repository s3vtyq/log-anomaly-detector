# Security Log Anomaly Detector

> Unsupervised ML tool that finds unusual patterns in SSH, web, and system logs using Isolation Forest.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green)]()
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange)]()

---

## Demo

```
loganomaly full-run
```

Running the full pipeline generates 3000 synthetic log events, extracts time-windowed features, and detects anomalies:

```
Phase 1/3: Generating synthetic logs...
  ✓ 3000 events (10% anomalies)

Phase 2/3: Extracting features...
  ✓ ssh: 1000 windows
  ✓ web: 1000 windows
  ✓ syslog: 1000 windows

Phase 3/3: Running anomaly detection...

      Detection Summary
┌────────────────────┬───────┐
│ Metric             │ Value │
├────────────────────┼───────┤
│ Total time windows │ 1100  │
│ Normal windows     │ 994   │
│ Anomalous windows  │ 106   │
│ Detection rate     │ 9.64% │
│ Features used      │ 11    │
│ Time taken         │ 0.21s │
└────────────────────┴───────┘

                         🔴 Top Anomalous Time Windows
┌────────────┬────────────┬────────────┬────────────┬────────────┬─────────────┐
│ Time       │    Anomaly │      Total │            │            │      SYSLOG │
│ Window     │      Score │     Events │ SSH Events │ WEB Events │      Events │
├────────────┼────────────┼────────────┼────────────┼────────────┼─────────────┤
│ 2026-05-20 │    -0.7491 │          1 │          0 │          1 │           0 │
│ 15:30:00   │            │            │            │            │             │
│ 2026-05-22 │    -0.7491 │          1 │          0 │          1 │           0 │
│ 09:00:00   │            │            │            │            │             │
└────────────┴────────────┴────────────┴────────────┴────────────┴─────────────┘

                🎯 Top Features Driving Anomaly Detection
╭───────────────────┬─────────────────────┬──────────────┬──────────────╮
│ Feature           │ Deviation (z-score) │ Anomaly Mean │ Overall Mean │
├───────────────────┼─────────────────────┼──────────────┼──────────────┤
│ error_rate_syslog │                2.09 │        0.491 │        0.047 │
│ unique_ips_syslog │                2.09 │        0.491 │        0.047 │
│ count_ssh         │                0.86 │        0.660 │        0.909 │
╰───────────────────┴─────────────────────┴──────────────┴──────────────╯
```

### Explaining *why* (the `--explain` flag)

```
loganomaly analyze data/samples/ssh.log --type ssh --explain
```

Shows per-window explanations with exact feature deviations:

```
═══ Anomaly Explanations ═══
╭────────────────────────────────────────────────────────────────────╮
│ Window: 2026-05-20 03:20:00  (anomaly score: -0.7048)             │
│ Total events in this window: 3                                     │
│                                                                    │
│ Why this window is anomalous:                                      │
│   • SSH event count is higher than normal (actual: 1.0, ...)      │
│   • SYSLOG error rate is higher than normal (actual: 33%, ...)    │
│                                                                    │
│ 🔍 Assessment: Possible SSH brute-force attack                     │
╰────────────────────────────────────────────────────────────────────╯
```

---

## 🏗️ Architecture

Open `docs/architecture.html` in a browser for the full interactive diagram.

```
┌─────────────────┐     ┌──────────────────────┐     ┌───────────────────┐
│  LOG GENERATOR  │     │  FEATURE ENGINEERING  │     │  ANOMALY DETECTOR │
│                 │     │                       │     │                   │
│  SSH auth logs──┼────►│ Regex parsers        ├────►│ Isolation Forest  │
│  Web logs───────┼────►│ 5-min windows        │     │ (200 trees)       │
│  Syslog─────────┼────►│ 28+ features         │     │ Autoencoder (opt) │
│  Anomalies: 5%  │     │ IP entropy, rates    │     │ Unsupervised      │
└─────────────────┘     └──────────────────────┘     └────────┬──────────┘
                                                              │
                                                              ▼
                                                     ┌────────────────┐
                                                     │  CLI REPORT    │
                                                     │  Rich tables   │
                                                     │  Anomaly score │
                                                     │  Explain mode  │
                                                     └────────────────┘
```

---

## Installation

```bash
git clone https://github.com/s3vtyq/log-anomaly-detector.git
cd log-anomaly-detector
pip install -e .
# or: pip install -r requirements.txt
```

---

## Usage

### Quick demo (30 seconds)

```bash
loganomaly full-run
```

Run end-to-end with default settings. Everything is synthetic — no server needed.

### Generate custom log data

```bash
loganomaly generate -n 10000 -a 0.05 -o data/samples
```

Controls: `-n` events total, `-a` anomaly ratio (default 5%), `--days` log range.

### Analyze a specific log type

```bash
loganomaly analyze data/samples/ssh.log --type ssh
loganomaly analyze data/samples/web.log --type web
loganomaly analyze data/samples/syslog.log --type syslog
```

Each runs regex parsing → feature extraction → Isolation Forest in one command.

### Get explanations

```bash
loganomaly analyze data/samples/ssh.log --type ssh --explain
```

Add `--explain` to see per-window natural-language explanations of why specific time windows were flagged.

### Advanced: export features + re-analyze

```bash
loganomaly analyze data/samples/ssh.log --export features.csv
loganomaly detect features.csv
```

Export to CSV for sharing or re-running with different settings.

### Options

| Command | Description |
|---|---|
| `generate` | Create synthetic SSH, web, and syslog files |
| `analyze FILE` | Parse + extract features + run detection |
| `detect CSV` | Run detection on pre-extracted features |
| `full-run` | End-to-end pipeline demo |

| Flag | Description |
|---|---|
| `-t, --type` | Log type: `ssh`, `web`, `syslog`, or `auto` |
| `-w, --window` | Time window in minutes (default: 5) |
| `-c, --contamination` | Expected anomaly ratio (default: 0.05) |
| `--explain` | Show per-window anomaly explanations |
| `--export FILE` | Export features/results to CSV |
| `-n` | Number of events (generate/full-run) |

---

## How It Works

### 1. Log Parsing

SSH, web (Apache Combined), and syslog formats each have dedicated regex parsers:

- **SSH**: timestamp, success/failure, user, IP, break-in signals
- **Web**: method, path, status code, response size, user agent suspiciousness
- **Syslog**: facility, severity, OOM/denial/timeout indicators

### 2. Feature Extraction

Events are grouped into 5-minute time windows. Each window produces a feature vector:

| Feature | What it captures |
|---|---|
| `count_ssh/web/syslog` | Event volume per type |
| `error_rate_ssh` | SSH auth failure fraction |
| `ip_entropy_ssh` | Source IP diversity (high = scanning) |
| `is_suspicious_path` | Web paths matching attack patterns |
| `is_suspicious_agent` | Known scanner user agents |
| `is_critical` | Severely critical system events |
| `has_denied` | Access denials / AppArmor blocks |
| `hour`, `is_weekend` | Behavioral time context |

### 3. Anomaly Detection

Uses **Isolation Forest** — an unsupervised ensemble method that isolates anomalies by randomly partitioning the feature space. Anomalies require fewer splits to isolate (they're "weird" compared to the bulk). No labeled training data needed.

Optional **autoencoder** mode (PyTorch) detects anomalies via reconstruction error.

### 4. Explanation Engine

The `--explain` flag computes per-feature z-scores for each anomalous window, showing exactly which features deviated and by how much. Automatically classifies anomaly types (brute-force, web scanning, system compromise).

---

## Project Structure

```
log-anomaly-detector/
├── loganomaly/
│   ├── __init__.py     # Package metadata
│   ├── generator.py    # Synthetic log generation (SSH, web, syslog)
│   ├── features.py     # Regex parsers + time-window aggregation
│   ├── detector.py     # Isolation Forest + explain_anomaly()
│   ├── reporter.py     # Rich CLI tables and output formatting
│   └── cli.py          # Click CLI with 4 commands
├── docs/
│   └── architecture.html  # Interactive SVG architecture diagram
├── data/samples/       # Generated logs (gitignored)
├── pyproject.toml      # Build config
├── requirements.txt    # Python dependencies
└── README.md
```

---

## Requirements

- Python 3.10+
- scikit-learn, pandas, numpy, rich, click

---

## Roadmap

- [x] `--explain` flag — per-window anomaly explanations
- [ ] Autoencoder (PyTorch) detector option
- [ ] Real log file support (syslog, `/var/log/auth.log`, Apache access.log)
- [ ] Real-time tail mode
- [ ] Grafana dashboard integration

---

## License

MIT — built by [s3vtyq](https://github.com/s3vtyq). Go ahead, fork it.
