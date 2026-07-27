# CAGE Evaluation

Evaluation materials for the IEEE paper, split by the two-person division of
labor set out in `../EVALUATION_PLAN.md` and refined in `../EVALUATION_REVIEW.md`
(read that second file first — it's the sufficiency review and the
finalized experiment roadmap, including 2 new experiments (E9 evasion
resistance, E10 window sensitivity — blocked, see below), a threat model,
and a reproducibility checklist added on top of the original plan).

- **`person_a/`** — built and verified (to the extent possible without a
  live cluster). Covers E1 (detection accuracy), E2 (full 11-technique
  ablation), E3 (chain dedup before/after), E7 (parameter sweep), E9
  (evasion boundary), and E10 (window sensitivity — blocked pending a
  one-line source prerequisite, see `EVALUATION_REVIEW.md` Gap 3). Start at
  [`person_a/README.md`](person_a/README.md).
- **`person_b/`** — not built yet; out of scope until requested separately.

## Reading order

1. `../EVALUATION_PLAN.md` — the original experiment design.
2. `../EVALUATION_REVIEW.md` — sufficiency critique, gaps, and the
   finalized figure/table list (11 figures, 8 tables).
3. `person_a/README.md` — how to actually run Person A's share.
