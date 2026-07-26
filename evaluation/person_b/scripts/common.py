"""
Shared helpers for Person B's evaluation scripts (E4, E5, E6, E8).

Read-only with respect to the CAGE source tree: everything here talks to the
already-running server over HTTP (/api/*) or tails its log file / shells out
to kubectl/docker. No src/ file is imported or modified by anything in this
evaluation/ tree.

Run these scripts from WSL Ubuntu (same environment used throughout this
project's own testing) — they assume `kubectl`, `docker`, and `python3` are
on PATH and pointed at the `cage` kind cluster.
"""
import subprocess
import time
import csv
import os
from datetime import datetime

BASE_URL = "http://localhost:5000"


def tail_new_lines(logfile, start_pos):
    """Read whatever's been appended to logfile since start_pos. Returns
    (lines, new_pos)."""
    with open(logfile, "r", errors="replace") as f:
        f.seek(start_pos)
        lines = f.readlines()
        end_pos = f.tell()
    return lines, end_pos


def parse_log_ts(line):
    """CAGE's own log format: 'YYYY-MM-DD HH:MM:SS,mmm LEVEL message'."""
    ts_str = line[:23]
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        return None


def wait_for_pattern(logfile, start_pos, pattern, timeout_sec,
                      keywords=("WARNING", "CRITICAL", "HIGH", "MEDIUM", "LOW")):
    """Poll logfile for a line containing `pattern` and any of `keywords`.
    Returns (found: bool, matched_line: str|None, ts: datetime|None, end_pos: int)."""
    pos = start_pos
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        lines, pos = tail_new_lines(logfile, pos)
        for line in lines:
            if pattern in line and any(k in line for k in keywords):
                return True, line.strip(), parse_log_ts(line), pos
        time.sleep(0.2)
    return False, None, None, pos


def run(cmd, timeout=None, check=False):
    """subprocess.run wrapper returning (returncode, stdout, stderr)."""
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd} failed (rc={r.returncode}): {r.stderr}")
    return r.returncode, r.stdout, r.stderr


def kubectl_exec(pod, args, namespace="default", timeout=15):
    cmd = ["kubectl", "exec", "-n", namespace, pod, "--"] + args
    return run(cmd, timeout=timeout)


def http_get_json(path):
    import urllib.request
    import json
    with urllib.request.urlopen(BASE_URL + path, timeout=10) as resp:
        return json.loads(resp.read().decode())


def find_server_pid():
    rc, out, _ = run(["pgrep", "-f", "src/server.py"])
    pids = [p for p in out.strip().split("\n") if p]
    return pids


def process_cpu_rss(pid):
    """Returns (cpu_pct: float, rss_mb: float) for a given PID via ps, or
    (None, None) if the process is gone."""
    rc, out, _ = run(["ps", "-o", "%cpu=,rss=", "-p", str(pid)])
    line = out.strip()
    if not line:
        return None, None
    parts = line.split()
    if len(parts) < 2:
        return None, None
    try:
        return float(parts[0]), float(parts[1]) / 1024.0
    except ValueError:
        return None, None


def ensure_csv_header(path, header):
    new_file = not os.path.exists(path)
    if new_file:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    f = open(path, "a", newline="")
    writer = csv.writer(f)
    if new_file:
        writer.writerow(header)
        f.flush()
    return f, writer


def now_iso():
    return datetime.now().isoformat()
