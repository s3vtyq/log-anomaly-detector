# Security Log Anomaly Detector

> Unsupervised machine learning tool that finds unusual patterns in SSH, web, and system logs using Isolation Forest.

---

## What It Does

Generates realistic synthetic security logs, extracts time-windowed features, and detects anomalies without needing labeled training data.

```
SSH logs  ─┐
Web logs   ─┤──►  Feature Extraction  ──►  Isolation Forest  ──►  Anomaly Report
Syslog     ─┘       (window + aggregate)        (unsupervised)
```

### Anomalies it detects

| Attack / Event | Log Type | Signs |
|---|---|---|
| SSH brute-force | `ssh` | Rapid failed logins, many source IPs |
| Web app scanning | `web` | Suspicious paths (`/../`, `sqlmap`, `/wp-admin`) |
| Reconnaissance | `web` | Weird user agents, 404 flood |
| Privilege escalation | `syslog` | AppArmor denials, `/etc/shadow` access |
| OOM / service crash | `syslog` | Memory pressure, critical daemon failures |
| Port scanning | both | iptables drops, timeouts |

---

## Installation

```bash
cd log-anomaly-detector
pip install -e .
```

---

## Usage

### Quick demo

```bash
loganomaly full-run
```

Generates 3000 events, extracts features, runs detection, and prints a report.

### Step by step

**1. Generate synthetic logs**

```bash
loganomaly generate -n 10000 -a 0.05
```

Creates SSH, web, and syslog files with 5% injected anomalies.

**2. Analyze a log file**

```bash
loganomaly analyze data/samples/ssh.log --type ssh -w 5
```

Parses the file, creates 5-minute windows, runs detection.

**3. Export + detect on features**

```bash
loganomaly analyze data/samples/ssh.log -w 5 --export features.csv
loganomaly detect features.csv --contamination 0.05
```

### Options

```
  generate          Generate synthetic logs
  analyze  FILE     Parse + extract + detect
  detect   CSV      Run detection on pre-extracted features
  full-run          Full pipeline demo

Global:
  --version   Show version
  --help      Show help
```

---

## Project Structure

```
log-anomaly-detector/
├── loganomaly/
│   ├── __init__.py     # Package version
│   ├── generator.py    # Synthetic log generation (SSH, web, syslog)
│   ├── features.py     # Feature extraction & time-window aggregation
│   ├── detector.py     # Isolation Forest anomaly detection
│   ├── reporter.py     # Colored CLI output (rich tables)
│   └── cli.py          # Click CLI entry point
├── data/samples/       # Generated logs (gitignored)
├── pyproject.toml      # Build config
├── requirements.txt    # Dependencies
└── README.md
```

---

## How It Works

### 1. Log Parsing

Each log type has its own regex parser that extracts structured fields:

- **SSH**: timestamps, success/failure, user, IP presence, break-in signals
- **Web**: method, path, status code, response size, user agent suspiciousness
- **Syslog**: facility, severity level, OOM/denial/timeout indicators

### 2. Feature Extraction (Windowing)

Events are grouped into time windows (default 5 min). For each window:

| Feature | Description |
|---|---|
| `count_ssh` | Volume of SSH events |
| `error_rate_ssh` | Fraction of failed auth attempts |
| `ip_entropy_ssh` | Diversity of source IPs (high = scanning) |
| `status`, `is_error` | HTTP response stats |
| `is_suspicious_path` | Paths matching known attack patterns |
| `is_suspicious_agent` | Agents from known scanning tools |
| `is_critical`, `has_denied` | Severe system events |
| `hour`, `is_weekend` | Behavioral time context |

### 3. Anomaly Detection (Isolation Forest)

Isolation Forest isolates anomalies by randomly partitioning features. Anomalies require fewer splits to isolate — they're "different" from the bulk of the data. No training labels needed.

---

## Example Output

```
═══ Detection Summary ═══
┌─────────────────────┬──────────┐
│ Metric              │ Value    │
├─────────────────────┼──────────┤
│ Total time windows  │ 309      │
│ Normal windows      │ 294      │
│ Anomalous windows   │ 15       │
│ Detection rate      │ 4.85%    │
│ Features used       │ 28       │
│ Time taken          │ 0.31s    │
└─────────────────────┴──────────┘

🔴 Top Anomalous Time Windows
┌──────────┬───────────────┬────────────┬────────────┬──────────┬──────────┐
│ Window   │ Anomaly Score │ Total      │ SSH Events │ Web      │ Syslog   │
├──────────┼───────────────┼────────────┼────────────┼──────────┼──────────┤
│ 15:20    │ -0.1824       │ 38         │ 28         │ 6        │ 4        │
│ 03:45    │ -0.1651       │ 42         │ 35         │ 2        │ 5        │
└──────────┴───────────────┴────────────┴────────────┴──────────┴──────────┘

🔥 Possible SSH brute-force attack (high SSH volume)
```

---

## Requirements

- Python 3.10+
- scikit-learn, pandas, numpy, rich, click

---

## Roadmap

- [ ] Real log file support (syslog, Apache, auth.log)
- [ ] Autoencoder (PyTorch) detector option
- [ ] Grafana dashboard integration
- [ ] Real-time monitoring mode
- [ ] `--explain` flag showing *why* specific windows are anomalous

---

## License

MIT
