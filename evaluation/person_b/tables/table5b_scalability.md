## Table 5b — NetworkMonitor Sequential-Polling Cycle Time vs. Pod Count

| N scan-target pods | Total monitored pods | N waves | Mean cycle time (s) | 95% CI (s) | Target interval (s) | Over target? |
|---|---|---|---|---|---|---|
| 1 | 3 | 9 | 4.69 | [3.58, 5.80] | 5 | no |
| 2 | 4 | 9 | 4.68 | [3.60, 5.76] | 5 | no |
| 4 | 6 | 9 | 5.35 | [4.57, 6.12] | 5 | yes |
| 8 | 10 | 9 | 5.35 | [4.57, 6.13] | 5 | yes |
| 16 | 18 | 9 | 4.90 | [3.78, 6.03] | 5 | no |

95% CI is a t-distribution interval on the mean (df = N_waves−1).
