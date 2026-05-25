# log-anomaly-detector

I got tired of seeing security tools that need a PhD to set up, so I built something that just runs.

It generates fake SSH, web, and system logs, then throws Isolation Forest at them to find anomalies. Everything is synthetic — you don't need a server, don't need real logs, don't need labeled data. Just `pip install` and go.

## What it looks like

```
$ loganomaly full-run

Phase 1/3: Generating synthetic logs...
  ✓ 3000 events (10% anomalies)
Phase 2/3: Extracting features...
  ✓ ssh: 1000 windows  |  web: 1000 windows  |  syslog: 1000 windows
Phase 3/3: Running anomaly detection...

      Detection Summary
┌────────────────────┬───────┐
│ Total windows      │ 1100  │
│ Normal             │ 994   │
│ Anomalous          │ 106   │
│ Detection rate     │ 9.64% │
│ Time taken         │ 0.21s │
└────────────────────┴───────┘

Top features driving detection:
  error_rate_syslog  (z=2.09)  ← syslog errors are way up
  count_ssh          (z=0.86)  ← more SSH activity than usual
```

You can also ask *why* a specific window was flagged:

```
$ loganomaly analyze ssh.log --explain

Window: 2026-05-20 03:20:00  (score: -0.70)
Why: SSH event count is higher (actual: 1.0, normal: 0.5)
     SYSLOG error rate is higher (actual: 33%, normal: 5%)
     → Possible SSH brute-force attack
```

## How it works (the quick version)

1. A generator creates logs that look real — SSH auth attempts, Apache web requests, syslog daemon messages. About 5% of them have "anomalies" mixed in (brute-force spikes, scanning tools, OOM crashes).
2. The parser reads each log type with its own regex, extracts structured fields.
3. Events get grouped into 5-minute windows. Each window becomes a row of features — counts, error rates, IP entropy, suspicious path ratios.
4. Isolation Forest runs on those features and flags windows that look weird.

The hard part was getting the regex parsers right. Apache log format has like 5 different timestamp variations depending on the timezone config. If your server runs on UTC, `%z` outputs an empty string and the whole thing breaks. That was fun to debug.

## Commands

```bash
loganomaly generate                     # create synthetic logs
loganomaly analyze <file>               # parse + run detection (auto-detects format)
loganomaly analyze /var/log/auth.log    # works with real logs too
loganomaly full-run                     # do everything in one shot
```

Flags: `--type ssh|web|syslog|auto`, `--explain`, `--window 5`, `--contamination 0.05`

It auto-detects the log format by reading the first 20 lines and trying each parser. So you can just point it at a real auth.log or access.log and it figures out what to do.

## Install

```bash
git clone https://github.com/s3vtyq/log-anomaly-detector.git
cd log-anomaly-detector
pip install -r requirements.txt
```

or

```bash
pip install -e .
```

Needs Python 3.10+, scikit-learn, pandas, numpy, rich, click.

## What's inside

```
loganomaly/
├── generator.py     # creates fake SSH/web/syslog data
├── features.py      # regex parsers → feature vectors
├── detector.py      # Isolation Forest + explain logic
├── reporter.py      # pretty CLI tables
└── cli.py           # 4 commands
```

Each file is under 300 lines. Generator uses weighted random choices to make normal traffic patterns and weighted-anomaly injections. Features computes z-scores under the hood. Detector wraps scikit-learn's IsolationForest. Reporter uses Rich for tables.

## What I'd add next

- Autoencoder option with PyTorch
- A mode that tails a log file in real-time

But honestly it works well enough for a portfolio piece.

MIT. Fork it if you want.
