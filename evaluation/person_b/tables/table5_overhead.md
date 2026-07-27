## Table 5 — Resource Overhead Summary (CAGE Server Process)

| Phase | N samples | Mean CPU (%) | 95% CI CPU (%) | Peak CPU (%) | Mean RSS (MB) | 95% CI RSS (MB) | Peak RSS (MB) |
|---|---|---|---|---|---|---|---|
| baseline_cage_off | 1 | 0.0 | — | 0.0 | 0.0 | — | 0.0 |
| idle_pre | 60 | 3.2 | [3.20, 3.20] | 3.2 | 134.8 | [134.80, 134.80] | 134.8 |
| active | 121 | 3.2 | [3.16, 3.18] | 3.2 | 134.8 | [134.83, 134.85] | 134.9 |
| idle_post | 60 | 3.1 | [3.10, 3.10] | 3.1 | 134.9 | [134.90, 134.90] | 134.9 |

95% CI is a t-distribution interval on the mean (df = N_samples−1). Note %CPU as reported by `ps` is a decaying lifetime average, not an instantaneous reading — see the Limitations section.
