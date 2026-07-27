# Person B Evaluation — E4/E5/E6/E8

Scripts, raw data, figures, and tables for the "Performance, Overhead,
Robustness" half of `EVALUATION_PLAN.md` (see `EVALUATION_REVIEW.md` at the
repo root for the standards review this work follows). Nothing under
`src/` is modified by anything in this tree — every script talks to the
already-running CAGE server over its HTTP API, tails its log file, or
shells out to `kubectl`/`docker`.

Run everything from WSL Ubuntu (same environment this project's own testing
has used throughout) with `attacker`, `legitimate-app`, and `scan-targets`
already deployed and a `fused`-mode server running.

## Layout

```
person_b/
├── scripts/           E4/E5/E6/E8 data-collection scripts + common.py helpers
├── plotting/           Figure/table generation, reads data/ writes figures/ and tables/
├── data/               Raw CSVs (committed — this is the actual evidence)
├── figures/             Generated PNGs
├── tables/               Generated markdown tables
└── RESULTS.md          Final write-up: what was actually run, real numbers, honest caveats
```

## Running each experiment

All scripts default to a **reduced scale** for practical session time —
every reduction is stated in its script's docstring and in `RESULTS.md`,
with the CLI flag to restore the full `EVALUATION_PLAN.md` spec noted
alongside. Re-run at full scale any time by passing the larger values.

```bash
cd evaluation/person_b/scripts

# E4a — latency distribution (plan spec: N=20; default here: N=10)
python3 run_latency_batch.py distribution --trials 20 --logfile <path to running server's log>

# E4b — connection-age sweep (restarts the server; plan spec ages 5,15,30,60,120)
python3 run_latency_batch.py connage --ages 5,15,30,60,120

# E5 — resource overhead (plan spec: 300/600/300s; default here: 60/120/60s)
python3 measure_overhead.py --idle-sec 300 --active-sec 600

# E6 — NetworkMonitor scalability (restarts the server once per N)
python3 measure_scalability.py --counts 1,2,4,8,16 --waves-per-n 3

# E8 — fault injection (run last; scenario "control-plane" stops/starts a
# cluster node container — disposable local dev cluster only)
python3 inject_faults.py --scenario all --logfile <path to running server's log>
```

## Generating figures and tables

```bash
cd evaluation/person_b/plotting
pip install matplotlib --break-system-packages   # if not already present
python3 plot_latency_cdf.py          # Fig. 6
python3 plot_latency_connage.py      # Fig. 7
python3 plot_overhead.py             # Fig. 9
python3 plot_fault_timeline.py       # Fig. 2
python3 build_tables.py              # Table 4, 5, 5b, E8 supporting table
```

## Reproducing at full plan-spec scale

Nothing here is hardcoded to the reduced scale — every duration/trial-count
is a CLI flag with a documented default. Re-running with the full
`EVALUATION_PLAN.md` numbers (N=20 latency trials, 300/600/300s overhead
phases, etc.) requires no script changes, only larger flag values, and
appends to the same CSVs (each script's CSV writer opens in append mode) —
so a full-scale run can extend the session-time-constrained pilot data
already in `data/` rather than replace it. If you want a clean full-scale
run instead, delete the relevant CSV in `data/` first.
