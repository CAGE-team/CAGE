## E8 — Fault Injection and Recovery, Per-Rep Detail (supporting Fig. 2)

| Fault | Rep | Health-detected (s) | Health-recovered (s) | Functional recovery confirmed (s) | Spurious alerts during fault |
|---|---|---|---|---|---|
| tetragon-consumer-kill | 1 | 0.5 | 2.0 | 26.6 | 1 |
| tetragon-consumer-kill | 2 | 0.5 | 2.0 | 9.9 | 1 |
| tetragon-consumer-kill | 3 | 0.0 | 2.0 | 10.0 | 0 |
| tetragon-consumer-kill | 4 | 0.5 | 2.0 | 10.0 | 1 |
| tetragon-consumer-kill | 5 | 0.5 | 2.0 | 10.1 | 1 |
| audit-log-truncate | 1 | 65.0 | — | 219.9 | 3 |
| audit-log-truncate | 2 | 68.0 | — | 250.1 | 3 |
| audit-log-truncate | 3 | 40.8 | — | 219.9 | 2 |
| audit-log-truncate | 4 | 44.3 | — | 220.1 | 2 |
| audit-log-truncate | 5 | 47.4 | — | 220.0 | 2 |
| control-plane-outage | 1 | 50.7 | — | 250.0 | 0 |
| control-plane-outage | 2 | 55.0 | — | 251.9 | 0 |
| control-plane-outage | 3 | 57.0 | — | 250.0 | 0 |
| control-plane-outage | 4 | 62.4 | — | 249.9 | 0 |
| control-plane-outage | 5 | 66.0 | — | 249.9 | 0 |
