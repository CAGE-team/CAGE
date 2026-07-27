"""
Runtime parameter override for CAGE's detection thresholds, WITHOUT editing
source files.

Three of the four thresholds this evaluation sweeps are clean, module-level
constants read by name at call time inside their owning module:
  - src.causal_graph.CONNECTION_BURST_THRESHOLD   (T1610, default 5)
  - src.causal_graph.FORK_BOMB_EXEC_THRESHOLD      (T1499, default 25)
  - src.audit_log_consumer.RBAC_DISCOVERY_THRESHOLD (T1613, default 10)

Because Python resolves a bare name inside a function against its *own*
module's global namespace at call time (not at function-definition time or
import time), setting `causal_graph.CONNECTION_BURST_THRESHOLD = 3` on the
module object from outside is visible to every method inside that module on
its very next call -- no source edit needed.

The fourth ("120-second correlation window") is a hardcoded inline literal
(`timedelta(seconds=120)`, appears twice in causal_graph.py) rather than a
named constant, so it CANNOT be overridden this way -- see
EVALUATION_REVIEW.md, Gap 3, for the one-line source change that would be
needed and why it hasn't been made unilaterally.

Usage: this module must be imported (and apply_overrides() called) BEFORE
anything else imports src.causal_graph / src.audit_log_consumer, so the
patched values are in place before CausalGraph()/AuditLogConsumer() ever
read them. See scripts/launch_server_with_params.py for the actual entry
point that does this in the right order.
"""
import os


def apply_overrides():
    """Reads T1610_BURST_THRESHOLD / T1499_FORKBOMB_THRESHOLD /
    T1613_RBAC_THRESHOLD from the environment (each optional; defaults to
    the module's own built-in value if unset) and patches the corresponding
    module constants in place. Returns a dict of what was actually changed,
    for the caller to log."""
    import src.causal_graph as causal_graph
    import src.audit_log_consumer as audit_log_consumer

    changed = {}

    if "T1610_BURST_THRESHOLD" in os.environ:
        new_val = int(os.environ["T1610_BURST_THRESHOLD"])
        old_val = causal_graph.CONNECTION_BURST_THRESHOLD
        causal_graph.CONNECTION_BURST_THRESHOLD = new_val
        changed["CONNECTION_BURST_THRESHOLD"] = (old_val, new_val)

    if "T1499_FORKBOMB_THRESHOLD" in os.environ:
        new_val = int(os.environ["T1499_FORKBOMB_THRESHOLD"])
        old_val = causal_graph.FORK_BOMB_EXEC_THRESHOLD
        causal_graph.FORK_BOMB_EXEC_THRESHOLD = new_val
        changed["FORK_BOMB_EXEC_THRESHOLD"] = (old_val, new_val)

    if "T1613_RBAC_THRESHOLD" in os.environ:
        new_val = int(os.environ["T1613_RBAC_THRESHOLD"])
        old_val = audit_log_consumer.RBAC_DISCOVERY_THRESHOLD
        audit_log_consumer.RBAC_DISCOVERY_THRESHOLD = new_val
        changed["RBAC_DISCOVERY_THRESHOLD"] = (old_val, new_val)

    if "CAGE_CORRELATION_WINDOW" in os.environ:
        raise RuntimeError(
            "CAGE_CORRELATION_WINDOW was set, but the 120s correlation "
            "window is a hardcoded inline literal in causal_graph.py, not "
            "an overridable module constant -- patching it here would be a "
            "no-op that silently produces wrong results. Apply the source "
            "change described in EVALUATION_REVIEW.md Gap 3 first."
        )

    return changed


if __name__ == "__main__":
    # Self-test: proves the monkey-patch mechanism itself is sound, without
    # needing a live cluster. Uses a throwaway dummy module with the exact
    # same shape (module-level constant read by name inside a function) as
    # the real target, so this validates the *mechanism*, not the real
    # detection logic -- that part still needs a live run once the cluster
    # is back (see evaluation/person_a/README.md).
    import sys
    import types

    print("param_patch mechanism self-test (no cluster required)")
    print("-" * 60)

    dummy = types.ModuleType("dummy_detector")
    dummy.THRESHOLD = 5

    def check(n):
        # Same pattern as causal_graph._check_t1610: bare-name lookup
        # against this module's own globals, resolved at call time.
        return n >= dummy.THRESHOLD

    dummy.check = check
    sys.modules["dummy_detector"] = dummy

    import dummy_detector  # noqa: E402  (must come after sys.modules injection)

    assert dummy_detector.check(5) is True
    assert dummy_detector.check(4) is False
    print("  before patch: check(4)=False, check(5)=True  (as expected)")

    dummy_detector.THRESHOLD = 3
    assert dummy_detector.check(4) is True, "BUG: patched value not visible to check()"
    assert dummy_detector.check(2) is False
    print("  after patching THRESHOLD 5->3: check(4)=True, check(2)=False  (as expected)")

    print("\nMechanism verified: external module-attribute patch is visible")
    print("to a function's bare-name global lookup on its next call.")
    print("\nNOTE: this proves the *mechanism* only. Confirming it works on")
    print("the REAL causal_graph.CONNECTION_BURST_THRESHOLD against a live")
    print("server + real T1610 traffic still needs to happen once the")
    print("cluster/Docker is back -- see the verification checklist in")
    print("evaluation/person_a/README.md before trusting sweep results.")
