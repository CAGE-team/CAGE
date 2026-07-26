# CAGE — Evaluation Plan Review & Finalized Roadmap

Independent review of `EVALUATION_PLAN.md` against IEEE journal-level
evaluation standards. **`EVALUATION_PLAN.md` is left untouched** — this file
records what's already strong, what's missing or weak, and the concrete
additions needed to close the gaps. Read this alongside the original plan;
together they are the roadmap to run.

Verified before writing this: every code reference the original plan makes
(`CONNECTION_BURST_THRESHOLD` at `src/causal_graph.py:42`, `STALE_AFTER_SECONDS`
at `src/server.py:312`, `WATCH_BACKOFF_MAX` at `src/uid_resolver.py:28`) checked
out exactly against the current source. The plan is not guessing about the
codebase — its procedures are executable as written.

---

## 1. What's already strong (keep as-is)

- **Every experiment has an explicit hypothesis**, not just a procedure —
  this is the single most important thing a reviewer checks for, and the
  plan does it for all 8 experiments without exception.
- **Figure-type discipline.** Ten figures, eight distinct chart types, zero
  generic bar charts, and each type is chosen because it's the *correct*
  representation for that data's shape (CDF for a latency distribution,
  radar for multi-axis categorical coverage, PR-curve for a threshold
  sweep). This is above the bar for most systems-paper submissions, where
  reviewers routinely dock points for bar-charting things that aren't
  categorical comparisons.
- **Honest-by-design.** T1610's threshold-dependent FP rate, T1021's missing
  scope exclusion, and the Tetragon connection-age latency effect are
  written up as findings to report, not bugs to hide. This reads as rigor
  to a reviewer, not weakness — keep this posture in the actual paper text.
- **E3's old-code-vs-new-code dedup comparison** is a genuinely rare kind of
  figure in a systems paper: quantified before/after evidence for a *named,
  specific* engineering fix, reproducible via `git show`. This is one of
  the strongest single pieces of evidence in the whole plan — don't cut it
  under time pressure.
- **E8's fault injection** (control-plane outage, subprocess kill, audit log
  truncation) tests real operational resilience, not just detection
  accuracy. Very few detection-system papers do this; it's a genuine
  differentiator for reviewer confidence in a systems/security venue.
- **The A/B split has almost no cross-dependency** — both tracks only need
  a running `fused`-mode server, so they're genuinely parallelizable.

## 2. Gaps that need to be closed before submission

### 2.1 No statistical uncertainty anywhere (highest priority)

Every detection-rate number in the plan (E1, E2, E3, E7) is a raw fraction
— "9/10", "90%" — with no confidence interval. At N=10–20 per condition, a
reviewer at IEEE journal level will ask for this explicitly; a 9/10
observed rate has a 95% Wilson interval of roughly **[60%, 98%]**, which is
a very different claim than the bare "90%" implies. This is cheap to fix
and should not be skipped:

- Add a **Wilson score interval** (better-behaved than the normal
  approximation at small N and bounded proportions) to every cell in
  Tables 1, 2, 3, and 7 — not just the paper text, the tables themselves.
- For latency (Table 4), report **median + IQR** alongside mean, and note
  standard deviation — the CDF figure (Fig. 6) already shows the full
  distribution shape, so the table should complement it with dispersion,
  not just a point estimate.
- Add one sentence to the Experimental Setup (§5.1) justifying sample
  sizes pragmatically: N was bounded by real wall-clock trial time (up to
  60s worst-case detection-wait per trial), not by a formal power
  analysis — say this plainly rather than let a reviewer assume an
  unstated one exists.

### 2.2 No quantitative external baseline

Table 6 (related-work comparison) is **qualitative** — feature checkboxes
against K8NTEXT/UNICORN/PACED/Falco/vanilla-Tetragon from their papers, not
measurements. E2's ablation (`tetragon_only` vs `audit_only` vs `fused`) is
a strong *internal* baseline for the fusion claim, but it is not the same
thing as running an *external* tool against the same attack suite in the
same environment and reporting its numbers side-by-side with CAGE's.

A full head-to-head against Falco is a real undertaking and may not fit the
remaining time budget. Two honest options, not mutually exclusive:

- **If time allows:** run vanilla Tetragon alone (no CAGE correlation
  layer — just raw per-event alerting, no chain correlation) against the
  same E1 attack set, and report its FP rate on the same benign trials.
  This is nearly free since Tetragon is already running — it isolates
  "what does correlation/fusion buy you over raw per-event alerts from the
  same sensor," a sharper and cheaper claim than a full Falco comparison.
- **If not:** add one explicit sentence to §5.7 (Limitations) stating this
  was not done and why (time/scope), rather than letting Table 6's
  qualitative framing implicitly stand in for a quantitative one. The
  current plan doesn't flag this omission at all — that's the actual gap,
  not necessarily the missing experiment itself.

### 2.3 Threats to validity is incomplete

Current §5.7 covers: single-node cluster, kernel/BTF dependency, Tetragon
latency, T1021 scope, NetworkMonitor scaling. Missing, all of which a
careful reviewer will raise if the paper doesn't pre-empt them:

- **Synthetic, non-adaptive attack scripts.** Every trial across E1–E3 and
  E7 is a fixed, known, non-evasive command sequence run by the
  researchers themselves — not red-team-style obfuscation, renamed
  binaries, or timing designed to straddle the 120s correlation window.
  State this plainly: detection rates characterize CAGE against this
  attack set, not against an adaptive adversary.
- **Virtualization-environment generalizability.** E4/E5's absolute
  latency and overhead numbers are measured on a `kind` cluster inside
  WSL2, not bare-metal Kubernetes. Person B's own experiments are the ones
  most exposed to this — the *relative* findings (audit fast/Tetragon
  slower, overhead bounded post-load) likely generalize, but the absolute
  numbers may not transfer directly to a production node. Say so.
- **No adversarial evasion testing.** Related to the first point but
  distinct enough to state separately: CAGE's namespace-only scope
  exclusion closes the *known* name-based bypass found and fixed this
  session, but no experiment specifically tries other plausible evasion
  strategies (e.g., spreading a chain across >120s deliberately, or a
  slow-and-low technique variant). Flag as future work if not tested.
- **Small-N statistical uncertainty** — covered in §2.1 above, but it's
  also a threat-to-validity item in its own right, not just a table
  formatting fix.

### 2.4 No formal metric-matching definition

The paper will use Precision/Recall/F1 (E1) and TP/FP/FN (throughout), but
the plan never states the exact rule for *what counts as a match* between
an injected attack and a fired alert. `week4/metrics.py`'s
`MetricsCollector` was fixed this session specifically because the old
version matched on a naive `"T105" in rule` substring (which silently
misclassified every non-T1059 technique) — given that history, the paper
needs an explicit "Metric Definitions" paragraph in §5.1 stating the actual
matching rule now in use (technique identity + a stated time-window
tolerance around the injected attack's timestamp), so a reviewer can
evaluate whether the matching methodology itself is sound, not just trust
the resulting numbers.

### 2.5 No macro-averaged headline number

Fig. 5's heatmap gives per-technique Precision/Recall/F1, which is the
right primary evidence — but there's no single aggregate number for the
abstract/intro (e.g., "CAGE achieves an X% macro-averaged F1 across all 11
techniques"). Add one summary row to Table 1 (macro-average across
techniques, unweighted) — cheap, and it's the number that ends up quoted
in the abstract regardless, so it should come from the same rigor as
everything else rather than being computed ad hoc when someone drafts the
abstract later.

### 2.6 E8 doesn't test for false positives caused by the fault injection itself

E8 currently measures *time-to-detect* and *time-to-recover* for each
injected fault. It doesn't check whether the fault injection **itself**
produces spurious detection alerts (e.g., does force-killing the
`TetragonConsumer` subprocess, or a `docker stop`/`start` cycle on the
control-plane, generate any false T1059/T1548/etc. alert as a side effect
of the disruption). This is a cheap, high-value addition: log
`alerts_during_fault` per scenario in `results_fault_recovery.csv` and
report it as a supporting claim ("fault injection produced zero spurious
detections across N=3 scenarios") — strengthens the robustness story for
almost no extra cost, since `/api/alerts` is already being polled for the
recovery check anyway.

### 2.7 "Expected output" framing risk

Several experiments (especially E5, E6) state confident "expected output"
before any data exists. That's fine as a stated *hypothesis* — the
methodology write-up should treat it that way explicitly, and whoever
collects the data (this document's author, for Person B's share) must
report what was **actually observed**, including if it contradicts the
stated expectation, rather than writing the results section to match the
prediction. Noted here so it's explicit, not assumed.

### 2.8 No artifact-availability statement

Increasingly expected at IEEE venues (and required for artifact-evaluation
badges where offered). Add one sentence to the paper stating that all
scripts, raw CSVs, and figure-generation code are available in the
repository's `evaluation/` directory — which this session is about to
create, so this becomes true rather than aspirational.

---

## 3. Net verdict

The original plan's *structure* (which experiment proves which claim, which
figure type fits which data, the results-section narrative arc) is already
publication-quality and shouldn't be restructured. The gaps above are all
**additive** — statistical rigor, a couple of missing limitations, one
metric-definition paragraph, one summary row, one extra logged column in
E8 — not replacements for anything already planned. None of them change
which experiments to run; they change what gets reported alongside the
numbers those experiments produce.

**Finalized roadmap = `EVALUATION_PLAN.md` (unchanged) + this file's
additions.** Concretely, when writing up results:

1. Every rate table (1, 2, 3, 7) gets a Wilson CI column.
2. Table 4 gets median/IQR/stdev, not just mean.
3. Table 1 gets one macro-average summary row.
4. `results_fault_recovery.csv` gets an `alerts_during_fault` column.
5. §5.1 gets a short "Metric Definitions" paragraph and a sample-size
   justification sentence.
6. §5.7 gains four items: synthetic/non-adaptive attacks, virtualization
   generalizability, no adversarial-evasion testing, and (if the vanilla-
   Tetragon-alone comparison in §2.2 isn't run) the missing quantitative
   baseline.
7. One artifact-availability sentence, pointing at `evaluation/`.

---

## 4. Person B scope confirmed

Per `EVALUATION_PLAN.md` §4: **E4, E5, E6, E8** — latency distribution +
connection-age characterization, resource overhead, NetworkMonitor
scalability, fault injection/recovery. Figures 2, 6, 7, 9. Tables 4, 5, 5b,
plus half of Table 6 (the related-work literature research, joint with
Person A). This review's additions apply directly to that scope: Table 4's
CI/IQR, the `alerts_during_fault` column in E8, and the virtualization-
generalizability threat item are all Person-B-owned deliverables layered on
top of the original plan, executed together with it — see
`evaluation/person_b/` for the actual scripts, data, figures, and results
write-up.
