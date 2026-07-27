# Resume State — read this first if picking up a stopped session

Last updated: 2026-07-26 17:47 UTC

## Goal
Full N=10 re-run of Person A's evaluation (E1, E2, E3-new-code, E9).
E3-old-code-comparison and E7 (sweep) are explicitly descoped for time
(user-approved call).

## Status right now

| Stage | Status | Output |
|---|---|---|
| E1 (detection accuracy, N=10) | **DONE** | `evaluation/person_a/output/results_detection_accuracy*.csv`, Fig 5, Table 1 already regenerated |
| E2 `tetragon_only` (N=10) | **DONE** | 6 Tetragon techniques 10/10, 5 audit techniques 0/10 -- clean, matches pilot |
| E2 `audit_only` (N=10) | **DONE** | 5 audit techniques 10/10, 6 tetragon techniques 0/10 -- exact complement of tetragon_only, clean |
| E2 `fused` (N=10) | **DONE** | 11/11 techniques all 10/10 -- clean, matches expectations |
| E3 new-code (N=10) | **DONE** | all 5 chains 10/10 (50/50 total) -- clean, validates episode-scoped re-arm fix |
| E9 (N=10) | **IN PROGRESS** | starting now |

## If resuming after an interruption

1. Check `/tmp/claude-*/scratchpad/final_e2.csv` — if it exists and has
   rows, DO NOT delete it. Check the last `condition,technique` row to see
   how far `tetragon_only` got.
2. Check whether the kind cluster / CAGE server is still up:
   `kubectl get nodes` and `curl localhost:5000/api/health`. If the
   cluster is down, it needs full recovery (see `EVALUATION_REVIEW.md`
   history / `SESSION_REPORT.md` section 1 for the exact steps — the
   `kind-config.yaml` fix is already permanently applied, so
   `kind create cluster --config kind-config.yaml --name cage` should
   just work cleanly).
3. If the server process died, restart it with the SAME `ABLATION_MODE`
   the interrupted run needed (check `final_e2.csv`'s last `condition`
   column value), verify `[ON]/[OFF]` pattern via
   `curl localhost:5000/api/health`, then re-run
   `run_ablation_full.py <condition> <logfile> final_e2.csv --trials 10 --yes`
   — it will APPEND to the existing CSV (opened in `"a"` mode), so
   completed rows are not lost, but note it does NOT automatically skip
   techniques it already has data for -- if resuming mid-condition,
   either accept a few duplicate rows for the technique that was
   interrupted (harmless, just dedupe before generating figures) or trim
   the CSV to remove that technique's partial rows first and let it redo
   that one technique cleanly.
4. Continue with whichever E2 condition(s) are still "Not started" above,
   then E3, then E9, following the same commands used earlier this
   session (see `evaluation/person_a/README.md` for exact command forms).
5. Once all stages show DONE, regenerate all figures/tables, update
   `SESSION_REPORT.md`'s results section, and this file's status table.

## Key fact for whoever resumes

All experiment scripts now flush results to disk after EVERY trial (not
just at the end) — this was a fix made mid-session after a crash lost 35
minutes of E1 data. So even an abrupt interruption loses at most the one
technique/chain/boundary that was actively running, never a whole
experiment's worth of prior work.
