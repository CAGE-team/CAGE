"""
Shared log-tailing "did this alert fire" helper, factored out of the pattern
already used independently in run_ablation.py, capture_latency.py, and
run_benign_controls.py so the new Person-A scripts don't each reimplement
byte-offset tracking and severity-keyword matching slightly differently.

All CAGE server output is plain stdout/stderr text (see src/server.py --
there's no structured log sink), so "did X fire" is determined by tailing
the redirected server log file for a line containing the rule name plus a
severity keyword, exactly as the existing scripts already do.
"""
import time

SEVERITY_KEYWORDS = ("WARNING", "CRITICAL", "HIGH", "MEDIUM", "LOW")


def tail_new_lines(logfile: str, start_pos: int):
    with open(logfile, "r") as f:
        f.seek(start_pos)
        lines = f.readlines()
        end_pos = f.tell()
    return lines, end_pos


def wait_for_pattern(logfile: str, start_pos: int, pattern: str, timeout_sec: float,
                      poll_interval: float = 0.2):
    """Polls `logfile` from `start_pos` for a line containing `pattern`
    alongside a severity keyword. Returns (fired: bool, matched_line: str|None,
    end_pos: int, elapsed_sec: float).

    end_pos always advances to "however far we've read", even on timeout --
    callers should use it as the next call's start_pos so a slow-to-arrive
    line from THIS trial isn't double-counted as a false positive for the
    NEXT trial once it does show up.
    """
    pos = start_pos
    t0 = time.monotonic()
    deadline = t0 + timeout_sec
    while time.monotonic() < deadline:
        lines, pos = tail_new_lines(logfile, pos)
        for line in lines:
            if pattern in line and any(k in line for k in SEVERITY_KEYWORDS):
                return True, line.strip(), pos, time.monotonic() - t0
        time.sleep(poll_interval)
    return False, None, pos, time.monotonic() - t0


def current_log_size(logfile: str) -> int:
    import os
    return os.path.getsize(logfile)
