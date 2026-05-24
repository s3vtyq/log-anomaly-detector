"""Synthetic security log generator.

Generates realistic SSH auth logs, web server logs, and system logs
with configurable anomaly injection for unsupervised anomaly detection.
"""

import random
import datetime
import tempfile
from pathlib import Path
from typing import TextIO

# ── Common IP pools ──────────────────────────────────────────────

LEGIT_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5", "10.0.0.12", "10.0.0.50",
    "172.16.0.8", "172.16.0.15",
]

ATTACKER_IPS = [
    "185.220.101.x", "91.121.89.x", "45.33.32.x",
    "104.248.50.x", "159.89.214.x",
]

USERS = ["root", "admin", "carol", "bob", "alice", "deploy", "jenkins", "svc-monitor"]

# ── 1. SSH / Auth Log Generator ────────────────────────────────

SSH_ATTEMPTS = [
    "Accepted password for {user} from {ip} port {port} ssh2",
    "Failed password for {user} from {ip} port {port} ssh2",
    "Failed password for invalid user {user} from {ip} port {port} ssh2",
    "Accepted publickey for {user} from {ip} port {port} ssh2",
    "Connection closed by authenticating user {user} {ip} port {port} [preauth]",
    "Did not receive identification string from {ip}",
    "reverse mapping checking getaddrinfo for {ip} failed - POSSIBLE BREAK-IN ATTEMPT!",
]

# Weights: most logs are successes, some failures, rare unusual
SSH_WEIGHTS = [0.50, 0.25, 0.12, 0.10, 0.01, 0.01, 0.01]


def _anonymize_ip(ip: str) -> str:
    """Replace last octet with a random value for attacker IPs with .x suffix."""
    if ip.endswith(".x"):
        base = ip[:-2]
        return f"{base}.{random.randint(1, 254)}"
    return ip


def _random_ssh_event(time: datetime.datetime) -> str:
    """Generate a single SSH log line."""
    ip = _anonymize_ip(random.choice(LEGIT_IPS))
    user = random.choice(USERS)
    port = random.randint(1024, 65535)
    msg = random.choices(SSH_ATTEMPTS, weights=SSH_WEIGHTS, k=1)[0]
    line = msg.format(ip=ip, user=user, port=port)
    return f"{time.strftime('%b %d %H:%M:%S')} {_hostname()} sshd[{random.randint(1000, 9999)}]: {line}"


def _brute_force_ssh_event(time: datetime.datetime) -> str:
    """Generate a rapid brute-force attempt."""
    ip = _anonymize_ip(random.choice(ATTACKER_IPS))
    user = random.choice(["root", "admin", "test", "admin1", "user", "oracle", "postgres"])
    port = random.randint(1024, 65535)
    line = SSH_ATTEMPTS[1].format(ip=ip, user=user, port=port)  # Failed password
    return f"{time.strftime('%b %d %H:%M:%S')} {_hostname()} sshd[{random.randint(1000, 9999)}]: {line}"


# ── 2. Web Server Log Generator ────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
]

SUSPICIOUS_AGENTS = [
    "sqlmap/1.7.2",
    "Nmap Scripting Engine",
    "nikto/2.5.0",
    "Mozilla/5.0 (compatible; CensysInspect/1.0)",
    "Wfuzz/3.1.0",
    "masscan/1.3.2",
]

PATHS = ["/", "/login", "/dashboard", "/api/users", "/about", "/contact"]
SUSPICIOUS_PATHS = [
    "/wp-admin", "/admin.php", "/.env", "/phpmyadmin/",
    "/../../etc/passwd", "/?id=1+AND+1=1--", "/api/v1/users?limit=1000",
    "/shell.php", "/config.php.bak",
]

STATUS_CODES = [200, 200, 200, 200, 301, 304, 200, 200, 200, 404, 403, 500]
SUSPICIOUS_STATUS = [404, 403, 500, 200, 200, 404, 403]


def _random_web_event(time: datetime.datetime) -> str:
    """Generate a single normal web log line (Apache Combined format)."""
    ip = _anonymize_ip(random.choice(LEGIT_IPS))
    method = random.choice(["GET", "GET", "GET", "POST", "PUT"])
    path = random.choice(PATHS)
    status = random.choice(STATUS_CODES)
    size = random.randint(200, 50000)
    agent = random.choice(USER_AGENTS)
    return (
        f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'
    )


def _attack_web_event(time: datetime.datetime) -> str:
    """Generate a suspicious web log line."""
    ip = _anonymize_ip(random.choice(ATTACKER_IPS))
    method = random.choice(["GET", "POST", "HEAD", "OPTIONS"])
    path = random.choice(SUSPICIOUS_PATHS)
    status = random.choice(SUSPICIOUS_STATUS)
    size = random.randint(0, 2000)
    agent = random.choice(SUSPICIOUS_AGENTS)
    return (
        f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'
    )


# ── 3. System Log Generator ────────────────────────────────────

SYSLOG_MESSAGES_NORMAL = [
    "INFO: Service apache2 started successfully",
    "INFO: Cron job completed - cleanup_daily",
    "INFO: Disk usage check passed: / 45%, /var 62%, /home 12%",
    "INFO: nginx - config test successful",
    "INFO: SSH session closed for user {user}",
    "INFO: Package list updated successfully",
    "INFO: User {user} logged out",
    "INFO: Certificate renewal check - no action needed",
    "INFO: Network interface eth0: link up, 1000Mb/s full duplex",
    "INFO: Database backup completed: 245MB in 3.2s",
]

SYSLOG_MESSAGES_ANOMALOUS = [
    "ERROR: Disk I/O timeout on /dev/sda1 - 5 retries exhausted",
    "CRITICAL: OOM killer invoked for process nginx (PID 3124)",
    "ERROR: kernel: TCP:三次握手中SYN包未连接时限逾 - port scan detected",
    "CRITICAL: auditd: FAILED attempt to access /etc/shadow by user www-data",
    "ERROR: kernel: UNSAFE /proc/PID/mem write detected from PID 1912",
    "CRITICAL: Failed to start audit daemon - relaying to syslog",
    "ERROR: sshd: Timeout before authentication for {ip}",
    "WARNING: File /etc/passwd modified outside package manager",
    "ERROR: iptables: DROP IN=eth0 OUT= MAC=... SRC={ip} DST=... PROTO=TCP DPT=22",
    "CRITICAL: AppArmor DENIED operation: exec of /tmp/malicious.sh",
]

SYSLOG_FACILITIES = ["auth", "kern", "daemon", "user", "cron", "syslog"]


def _random_syslog_event(time: datetime.datetime) -> str:
    """Generate a single normal syslog line."""
    msg = random.choice(SYSLOG_MESSAGES_NORMAL).format(user=random.choice(USERS))
    facility = random.choice(SYSLOG_FACILITIES)
    return f"{time.strftime('%b %d %H:%M:%S')} {_hostname()} {facility}: {msg}"


def _anomalous_syslog_event(time: datetime.datetime) -> str:
    """Generate an anomalous syslog event."""
    ip = _anonymize_ip(random.choice(ATTACKER_IPS))
    msg = random.choice(SYSLOG_MESSAGES_ANOMALOUS).format(ip=ip)
    facility = random.choice(["kern", "auth", "daemon"])
    return f"{time.strftime('%b %d %H:%M:%S')} {_hostname()} {facility}: {msg}"


# ── Helpers ─────────────────────────────────────────────────────

_hostname_cache: str | None = None


def _hostname() -> str:
    global _hostname_cache
    if _hostname_cache is None:
        _hostname_cache = random.choice(["server01", "web01", "db01", "monitor"])
    return _hostname_cache


# ── Main Generator ──────────────────────────────────────────────

def generate_dataset(
    output_dir: str | Path = "data/samples",
    total_events: int = 5000,
    anomaly_ratio: float = 0.05,
    days: int = 7,
    seed: int = 42,
) -> dict[str, Path]:
    """Generate synthetic security logs with injected anomalies.

    Args:
        output_dir: Directory to write log files.
        total_events: Total number of log events across all types.
        anomaly_ratio: Fraction of events that are anomalous (0.0 - 1.0).
        days: Number of days of log history to simulate.
        seed: Random seed for reproducibility.

    Returns:
        Dict mapping log type -> Path to generated file.

    Each log line has a header line prefixed with ANOMALOUS or NORMAL
    for training ground truth, plus a clean file without labels.
    """
    random.seed(seed)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    base_time = datetime.datetime.now() - datetime.timedelta(days=days)

    log_types = {
        "ssh": (_random_ssh_event, _brute_force_ssh_event),
        "web": (_random_web_event, _attack_web_event),
        "syslog": (_random_syslog_event, _anomalous_syslog_event),
    }

    results: dict[str, Path] = {}

    for log_type, (normal_fn, anomaly_fn) in log_types.items():
        labeled_path = out / f"{log_type}_labeled.log"
        clean_path = out / f"{log_type}.log"

        events_for_type = total_events // len(log_types)
        n_anomalies = int(events_for_type * anomaly_ratio)
        n_normal = events_for_type - n_anomalies

        events_normal = [False] * n_normal + [True] * n_anomalies
        random.shuffle(events_normal)

        with open(labeled_path, "w") as flab, open(clean_path, "w") as fclean:
            flab.write("# LABELED LOG - first column: ANOMALOUS or NORMAL\n")
            for i, is_anomaly in enumerate(events_normal):
                # Spread events across time
                offset = (i / len(events_normal)) * days * 86400
                t = base_time + datetime.timedelta(seconds=offset) + \
                    datetime.timedelta(seconds=random.randint(0, 60))

                line = (anomaly_fn if is_anomaly else normal_fn)(t)
                label = "ANOMALOUS" if is_anomaly else "NORMAL"
                flab.write(f"{label} {line}\n")
                fclean.write(f"{line}\n")

        results[log_type] = clean_path

    results["labeled"] = out / "all_labeled.log"

    # Also write a combined labeled log
    with open(results["labeled"], "w") as fout:
        fout.write("# COMBINED LABELED LOG\n")
        for log_type in ["ssh", "web", "syslog"]:
            lp = out / f"{log_type}_labeled.log"
            with open(lp) as fin:
                for line in fin:
                    if not line.startswith("#"):
                        fout.write(f"{log_type} {line}")

    return results


if __name__ == "__main__":
    paths = generate_dataset()
    for key, path in paths.items():
        print(f"{key}: {path}")
