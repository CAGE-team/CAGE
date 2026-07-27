## Table 4 — Detection Latency Statistics by Technique/Source

| Technique | Source | N | Min (s) | Median (s) | Mean (s) | 95% CI of mean (s) | Stdev (s) | p95 (s) | Max (s) |
|---|---|---|---|---|---|---|---|---|---|
| T1059 | Tetragon eBPF | 20 | 27.31 | 27.96 | 27.96 | [27.88, 28.04] | 0.17 | 28.11 | 28.11 |
| T1552 | K8s audit log | 20 | 0.16 | 0.18 | 0.19 | [0.18, 0.20] | 0.02 | 0.25 | 0.26 |

95% CI of the mean is a t-distribution interval (df = N−1); not reported when N ≤ 1.
