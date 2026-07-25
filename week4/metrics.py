import json
from datetime import datetime

# How close (in seconds) an alert must land to an injected attack event to
# count as detecting it. Matches the order of magnitude this project's own
# trial-based measurement scripts already use as a detection-wait window
# (capture_latency.py / run_ablation.py both poll for up to ~15-30s).
MATCH_WINDOW_SECONDS = 30


def _parse_ts(ts):
    """Accept either an epoch float/int (time.time()-style, used by
    capture_latency.py) or an ISO-8601 string (used by CAGE's own alert
    timestamps) — both conventions already coexist in this project."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


class MetricsCollector:
    def __init__(self, scenario_name):
        self.scenario_name = scenario_name
        self.start_time = datetime.now()
        self.alerts = []
        self.attack_events = []
        self.metrics = {}

    def add_alert(self, alert, timestamp):
        self.alerts.append({"alert": alert, "timestamp": timestamp})

    def add_attack_event(self, event_type, description, timestamp):
        self.attack_events.append({
            "type": event_type,
            "description": description,
            "timestamp": timestamp
        })

    def compute_metrics(self):
        """Compute TP, FP, FN, Precision, Recall.

        An alert is a true positive only if it actually corresponds to an
        injected attack event — same technique (matching the alert's rule
        against the event's type, treating a chain rule like
        "T1059->T1552" as covering each of its hops) and within
        MATCH_WINDOW_SECONDS of it. Everything else is a false positive,
        which is what makes a benign-only scenario (add_attack_event()
        never called) meaningful: every alert then has nothing to match,
        so every one correctly counts as a false positive. An attack event
        with no matching alert is a false negative.
        """
        tp = len([a for a in self.alerts if self._matching_attack_event(a) is not None])
        fp = len(self.alerts) - tp
        fn = len([e for e in self.attack_events if not self._detected(e)])

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0

        return {
            "scenario": self.scenario_name,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "total_alerts": len(self.alerts),
            "total_attack_events": len(self.attack_events),
        }

    def _rule_matches_type(self, rule, event_type):
        """"T1059" matches rule "T1059", and also matches each hop of a
        chain rule like "T1059->T1552" or "T1059→T1552"."""
        if not rule or not event_type:
            return False
        hops = rule.replace("→", "->").split("->")
        return event_type in hops

    def _matching_attack_event(self, alert_entry):
        rule = alert_entry.get("alert", {}).get("rule", "")
        alert_ts = _parse_ts(alert_entry.get("timestamp"))
        if alert_ts is None:
            return None
        for event in self.attack_events:
            if not self._rule_matches_type(rule, event.get("type", "")):
                continue
            event_ts = _parse_ts(event.get("timestamp"))
            if event_ts is None:
                continue
            if abs(alert_ts - event_ts) <= MATCH_WINDOW_SECONDS:
                return event
        return None

    def _detected(self, event):
        event_ts = _parse_ts(event.get("timestamp"))
        if event_ts is None:
            return False
        for a in self.alerts:
            rule = a.get("alert", {}).get("rule", "")
            if not self._rule_matches_type(rule, event.get("type", "")):
                continue
            alert_ts = _parse_ts(a.get("timestamp"))
            if alert_ts is None:
                continue
            if abs(alert_ts - event_ts) <= MATCH_WINDOW_SECONDS:
                return True
        return False

    def print_report(self):
        metrics = self.compute_metrics()
        print("\n" + "="*60)
        print(f"SCENARIO: {metrics['scenario']}")
        print("="*60)
        print(f"True Positives:  {metrics['true_positives']}")
        print(f"False Positives: {metrics['false_positives']}")
        print(f"False Negatives: {metrics['false_negatives']}")
        print(f"Precision:       {metrics['precision']}")
        print(f"Recall:          {metrics['recall']}")
        print("="*60 + "\n")
        return metrics
