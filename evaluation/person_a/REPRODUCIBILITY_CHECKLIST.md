# Reproducibility Checklist (Gap 6)

Fill in the blanks from your actual evaluation machine before submission.
This is the kind of statement IEEE venues increasingly expect even without
a formal artifact-evaluation track — it costs little to prepare now, while
everything is fresh, and is painful to reconstruct later.

## Software versions

| Component | Version | How to check |
|---|---|---|
| Tetragon | ______ (repo says v1.7.0) | `kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra version` |
| kind | ______ | `kind version` |
| kubectl | ______ | `kubectl version --client` |
| Docker / Docker Desktop | ______ | `docker version` |
| Python | ______ | `python3 --version` |
| Python packages | ______ | `pip freeze \| grep -iE "flask|kubernetes|networkx|matplotlib|numpy"` |
| Kubernetes (kind node image) | ______ | `kubectl get nodes -o wide` (look at KERNEL-VERSION / CONTAINER-RUNTIME columns too) |
| Host kernel | ______ (matters for T1610's BTF requirement) | `uname -r` |

## Hardware / environment

| Field | Value |
|---|---|
| Host OS | ______ (this dev environment: WSL2 on Windows) |
| CPU | ______ |
| RAM | ______ |
| Cluster topology | 1 control-plane + 2 worker nodes (`kind-config.yaml`) |

## Exact reproduction commands, per table

Fill in once each experiment has actually been run for the final numbers —
this section is the payoff of using scripts instead of manual steps: every
row should be one copy-pasteable command.

```
Table 1 (detection accuracy):
  python3 evaluation/person_a/scripts/run_detection_accuracy.py <logfile> <outfile> --trials 20

Table 2 (ablation matrix):
  # once per condition, server restarted between each:
  python3 evaluation/person_a/scripts/run_ablation_full.py tetragon_only <logfile> <outfile>
  python3 evaluation/person_a/scripts/run_ablation_full.py audit_only <logfile> <outfile>
  python3 evaluation/person_a/scripts/run_ablation_full.py fused <logfile> <outfile>

Table 3 (chain dedup):
  python3 evaluation/person_a/scripts/run_chain_dedup_comparison.py <logfile> <outfile> --code-version new
  # + the manual old-code comparison, see README.md

Table 7 (parameter sensitivity + evasion):
  python3 evaluation/person_a/scripts/run_parameter_sensitivity.py --mode evasion <logfile> <outfile>
  # + one sweep run per threshold value, see README.md
```

## Known non-determinism to disclose

- **Tetragon delivery latency is connection-age-dependent** (see README.md's
  Evaluation section) — re-running the same experiment at a different wall-
  clock offset from server startup can produce different latency numbers
  even with identical attack commands. State the server-uptime-at-trial-time
  distribution alongside latency figures, not just the figures alone.
- Trial-to-trial timing (`sleep` calls between attacks) is real wall-clock
  time, not simulated — total experiment duration will vary run to run by
  seconds, not something to worry about, but don't expect byte-identical
  timing CSVs between repeated full runs.
