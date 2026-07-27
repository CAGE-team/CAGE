"""
Statistics helpers for CAGE's evaluation — specifically the Wilson score
confidence interval for binomial proportions (detection rates).

Why Wilson and not the normal ("Wald") approximation: the Wald interval
(p +/- z*sqrt(p(1-p)/n)) breaks down exactly where this evaluation lives —
small N (10-30 trials) and observed rates at or near 0% or 100%. At p=1.0,
Wald collapses to a zero-width interval ("100% +/- 0%"), which is a false
claim of certainty from a handful of trials. Wilson stays well-behaved in
both regimes and is the standard recommendation for exactly this use case
(see Brown, Cai & DasGupta 2001, "Interval Estimation for a Binomial
Proportion").

No external dependencies beyond the standard library.
"""
import math


def wilson_ci(successes: int, n: int, confidence: float = 0.95):
    """Wilson score interval for a binomial proportion.

    Returns (point_estimate, ci_low, ci_high), all in [0, 1]. Returns
    (0.0, 0.0, 0.0) for n == 0 rather than raising, since evaluation CSVs
    occasionally have a technique with zero trials during script testing —
    callers should treat that as "no data", not a real 0% rate.
    """
    if n == 0:
        return 0.0, 0.0, 0.0
    if successes < 0 or successes > n:
        raise ValueError(f"successes={successes} out of range for n={n}")

    z = _z_for_confidence(confidence)
    p_hat = successes / n
    denom = 1 + z * z / n
    centre = p_hat + z * z / (2 * n)
    half_width = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * n)) / n)

    low = (centre - half_width) / denom
    high = (centre + half_width) / denom
    return p_hat, max(0.0, low), min(1.0, high)


def _z_for_confidence(confidence: float) -> float:
    # Only the two levels this evaluation actually uses; avoids a scipy
    # dependency for one lookup.
    table = {0.90: 1.6448536269514722, 0.95: 1.959963984540054, 0.99: 2.5758293035489004}
    if confidence not in table:
        raise ValueError(f"unsupported confidence level {confidence}; add it to the table if needed")
    return table[confidence]


def fmt_rate_with_ci(successes: int, n: int, confidence: float = 0.95) -> str:
    """'9/10 (90.0%, 95% CI [59.6%, 98.2%])' — the standard format used
    throughout this evaluation's tables."""
    p, lo, hi = wilson_ci(successes, n, confidence)
    pct = int(confidence * 100)
    return f"{successes}/{n} ({p*100:.1f}%, {pct}% CI [{lo*100:.1f}%, {hi*100:.1f}%])"


def precision_recall_f1(tp: int, fp: int, fn: int):
    """Standard precision/recall/F1 from confusion counts. Returns 0.0 for
    any metric whose denominator is 0 rather than raising (e.g. a technique
    with zero false positives across every condition -- precision is
    undefined by the raw formula, but reporting 0.0 with an explicit "no FP
    observed" note in the caller is more honest than crashing)."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


if __name__ == "__main__":
    # Self-test: no cluster needed, pure arithmetic. Run directly to verify
    # this module before anything else depends on it.
    print("Wilson CI self-test (no cluster required)")
    print("-" * 60)

    cases = [
        (10, 10, "10/10 -- should NOT claim a zero-width 100% interval"),
        (9, 10, "9/10"),
        (0, 10, "0/10 -- should NOT claim a zero-width 0% interval"),
        (5, 10, "5/10 -- widest interval, maximum uncertainty at p=0.5"),
        (29, 30, "29/30 -- larger N should narrow the interval vs 9/10"),
    ]
    for successes, n, label in cases:
        print(f"  {label:55s} {fmt_rate_with_ci(successes, n)}")

    p, lo, hi = wilson_ci(10, 10)
    assert hi < 1.0, "BUG: 10/10 must not produce a zero-width 100% CI"
    assert lo > 0.0, "BUG: 10/10's lower bound must be > 0"
    p0, lo0, hi0 = wilson_ci(0, 10)
    assert lo0 == 0.0 and hi0 > 0.0, "BUG: 0/10's interval must not be zero-width either"

    prec, rec, f1 = precision_recall_f1(tp=9, fp=1, fn=1)
    print(f"\n  precision_recall_f1(tp=9,fp=1,fn=1) -> P={prec:.3f} R={rec:.3f} F1={f1:.3f}")
    assert abs(prec - 0.9) < 1e-9 and abs(rec - 0.9) < 1e-9

    print("\nAll self-tests passed.")
