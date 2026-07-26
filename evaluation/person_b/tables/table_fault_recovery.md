## E8 — Fault Injection and Recovery (supporting Fig. 2)

| Fault | Health-detected (s) | Health-recovered (s) | Functional recovery confirmed (s) | Spurious alerts during fault |
|---|---|---|---|---|
| tetragon-consumer-kill | 0.5 | 2.0 | 34.9 | 1 |
| audit-log-truncate | 60.4 | — | 241.9 | 0 |
| control-plane-outage | 90.0 | — | 303.8 | 1 |
