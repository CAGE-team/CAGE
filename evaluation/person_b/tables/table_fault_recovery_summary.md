## E8 Summary — Fault-Recovery Success Rate by Scenario (Wilson 95% CI)

| Fault | Reps (N) | Functional recovery rate | Wilson 95% CI | Mean detect (s) | Mean recover (s) | Mean functional-recovery (s) | Spurious alerts (total across reps) |
|---|---|---|---|---|---|---|---|
| audit-log-truncate | 5 | 5/5 (100%) | [0.57, 1.00] | 53.1 | — | 226.0 | 12 |
| control-plane-outage | 5 | 5/5 (100%) | [0.57, 1.00] | 58.2 | — | 250.3 | 0 |
| tetragon-consumer-kill | 5 | 5/5 (100%) | [0.57, 1.00] | 0.4 | 2.0 | 13.3 | 4 |

Wilson score interval, not the naive normal-approximation interval -- appropriate for small N (this evaluation's default is 5 reps/scenario) where the naive interval can exceed [0,1] or understate uncertainty. 'Functional recovery' requires a real post-fault attack to be correctly detected, not merely /api/health reporting healthy.
