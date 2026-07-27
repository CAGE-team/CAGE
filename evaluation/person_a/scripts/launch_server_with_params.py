#!/usr/bin/env python3
"""
Drop-in replacement for `python3 src/server.py`, used ONLY for the
parameter-sensitivity sweep (run_parameter_sensitivity.py). Applies
threshold overrides (see lib/param_patch.py) before the server's own
consumers are constructed, then runs the exact same startup sequence
server.py's own __main__ block runs -- nothing about server.py's actual
code is modified or duplicated; this just imports and executes it via
runpy after the patch is in place.

Usage (same env vars as ABLATION_MODE, plus the ones this reads):
    T1610_BURST_THRESHOLD=3 ABLATION_MODE=fused \\
        python3 evaluation/person_a/scripts/launch_server_with_params.py

Recognized overrides (all optional -- unset means "use the built-in
default", identical behavior to running server.py directly):
    T1610_BURST_THRESHOLD       -> causal_graph.CONNECTION_BURST_THRESHOLD
    T1499_FORKBOMB_THRESHOLD    -> causal_graph.FORK_BOMB_EXEC_THRESHOLD
    T1613_RBAC_THRESHOLD        -> audit_log_consumer.RBAC_DISCOVERY_THRESHOLD

For a plain baseline run with no overrides, this behaves identically to
`python3 src/server.py` -- safe to use as the default launcher for every
Person-A experiment, not just the sensitivity sweep, if you want one
consistent entry point.
"""
import os
import runpy
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))       # .../evaluation/person_a/scripts
PERSON_A_DIR = os.path.dirname(SCRIPTS_DIR)                     # .../evaluation/person_a
EVALUATION_DIR = os.path.dirname(PERSON_A_DIR)                  # .../evaluation
PROJECT_ROOT = os.path.dirname(EVALUATION_DIR)                  # .../CAGE

sys.path.insert(0, PROJECT_ROOT)   # for `src.causal_graph`, `src.audit_log_consumer`
sys.path.insert(0, PERSON_A_DIR)   # for `lib.param_patch`

from lib.param_patch import apply_overrides  # noqa: E402

if __name__ == "__main__":
    changed = apply_overrides()
    if changed:
        print("[launch_server_with_params] Applied overrides (old -> new):")
        for name, (old, new) in changed.items():
            print(f"    {name}: {old} -> {new}")
    else:
        print("[launch_server_with_params] No overrides set -- running with "
              "built-in defaults, identical to `python3 src/server.py`.")

    server_path = os.path.join(PROJECT_ROOT, "src", "server.py")
    runpy.run_path(server_path, run_name="__main__")
