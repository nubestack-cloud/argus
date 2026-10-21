# `E14` — lifecycle-matrix live fixtures

Retained fault fixtures from the 18-row lifecycle test matrix, a campaign that ran between
2026-09-01 and 2026-09-06 and **completed** — all 18 rows reached a result. Its board item is
deliberately gone: `PROJECT.md` maintenance rule 2 removes a completed item and makes Git history the
completion record, and the per-row narratives that item pointed at lived in documents deleted in the
2026-09-05 consolidation (`lld/README.md` maps each removed document to where its content lives now).

What remains here is a **regression-reproduction set**, which is what `fixtures/` is for: twelve files
that re-induce a known, already-diagnosed fault so a future change can be measured against a result
somebody established once. It is not a test suite — nothing runs these automatically — and it is not
the campaign's evidence. Each file's own header is the evidence it retains, and the header is the part
worth reading before the manifest.

**The matrix was organized by lifecycle PATH, not by catalogue fault** — detection mechanism ×
correlation behaviour × remediation channel × fix shape. Many catalogue entries share one path, so one
row stands for a path rather than for a fault. That is why twelve files reach into a catalogue category
of 48 entries without claiming to cover it.

## What this set proves, and what it deliberately does not

It proves reproducibility of a *symptom*, not of an outcome. Every file induces a real Kubernetes
fault deterministically, and several carry a dated, confirmed end-to-end result — a real incident, a
real analysis, in two cases a real merged pull request. What none of them prove is that the same
outcome happens today:

- **Four rows recorded a result that was NOT what the row was built to test**, and say so in their own
  headers. Row 7's fixture never reaches the human-approval half it was written for, because the model
  correctly declines to restart a permanently-broken command. Row 8 produced **two** incidents where
  the row demanded one. Row 10 produced a correct diagnosis instead of the honest "could not determine"
  it exists to test. Row 17 did not, on its own, demonstrate row 16. Treat all four as recorded
  boundaries, not as pass marks.
- **The hub has moved since these ran.** Most importantly for this set, a `GenericConditionAnomaly:*`
  finding no longer opens an incident at all: `internal/gateway/promotion.go` forces those reasons to
  `Class=Anomaly`/`Confidence=Unverified`/`Impact=None`, and `shouldPromoteFinding` admits only an
  active fault with better-than-unverified evidence and observed degradation. **Row 17's whole recorded
  result was an incident opened by exactly such a finding, so re-running it today reproduces the
  finding and not the incident.** That is the 2026-09-07 earned-promotion decision working as intended,
  not a regression. Rows 1, 2, 7, 8, 9, 10 and 15 reach ARGUS through other reasons and are unaffected.
- **Rows 1–4 do not record their ARGUS-side result in the file.** Their headers record the raw
  Kubernetes symptom being verified live; the incident and analysis IDs were written up in a document
  since deleted, and are in Git history.
- No row here was re-run after 2026-09-06. Every dated claim below is that date or earlier.

## Which rows have a file

| # | File | What it induces (from that file's own header) | Live result the file itself records |
|---|---|---|---|
| 1 | `row01-pending-pod-insufficient-cpu.yaml` | A Pod requesting 32 CPU where every node reports 8 allocatable, so the scheduler can never place it: `Phase=Pending` indefinitely plus a repeating `Warning/FailedScheduling` naming "Insufficient cpu". Carries row 12's healthy control in the same file. | Raw Kubernetes symptom verified live 2026-09-03 (`kind-argus-disposable`). No ARGUS-side result in the file. |
| 2 | `row02-pending-pod-taint-no-toleration.yaml` | The same category by a different mechanism: one node tainted, a Pod pinned to it by `nodeSelector` with no matching toleration, so `FailedScheduling` reads "had untolerated taint" instead. Carries its own tolerating healthy control. | Nothing beyond the 2026-09-03 retarget to `rke2` node names. No ARGUS-side result in the file. |
| 3 | `row03-deployment-no-readiness-probe.yaml` | A posture audit of a *healthy* object — a Deployment with no probe of any kind whose container sleeps 20s before it could serve, so its Pods read `Ready` long before they are. The fault has a symptom only *during* a rollout. Carries row 13's healthy control. | Confirmed live 2026-09-03 that new Pods read `1/1 Ready` within ~2–3s. The file also records that **no rule or Go checker detects this shape** — that absence is the row's finding. |
| 4 | `row04-all-replicas-one-node.yaml` | A property of a *set*: three replicas pinned to one node by `nodeSelector`, every Pod individually `Ready`, the risk existing only across the replica set. Carries row 14's anti-affinity healthy control. | The file records the prior (2026-09-01) live verification of the rule *firing*, and states that whether it becomes a useful incident was this row's separate job. |
| 5 | `row05-fix-spanning-two-files.yaml` | **A note, not a manifest — there is nothing to `kubectl apply`.** Describes the repo-side run: one Deployment with two independent bugs across `deployment.yaml` and `configmap.yaml`, fixed by one pull request. | Run 2026-09-06. One `OpenPR` plan, one PR (`argocd-argus-test#76`), one commit carrying both files, merged and synced, `resolution_kind='remediated'` confirmed in Postgres. |
| 6 | `row06-helm-values-precedence.yaml` | **Also a note, not a manifest.** The Helm multi-`-f` precedence trap: an edit to the *overridden* values file must render as "no effective change". Points at `internal/render/testdata/precedence-chart/` for the unit-test version. | Run 2026-09-06 via a dedicated chart whose `values-prod.yaml` lowers a memory limit into an OOMKill. Analysis named the winning file; PR `argocd-argus-test#77` merged; `resolution_kind='remediated'` confirmed in Postgres. |
| 7 | `row07-crashloop-old-rule-inplace-fix.yaml` | A real `CrashLoopBackOff` (`sleep 5; exit 1`) on a non-GitOps Deployment, to exercise the pre-existing pod-conditions detector and the in-place remediation channel. | Live 2026-09-03 on `rke2`: incident, auto-analysis at confidence 1.00 within ~35s. **But the row's own goal was not reached** — the model correctly proposed no plan, so this fixture never exercises approve-and-execute. A transient crashloop is the fixture this row still needs. |
| 8 | `row08-correlation-merge-two-detectors-one-object.yaml` | One always-failing Deployment driving two findings at two tiers: `CrashLoopBackOff` on the Pod and a sustained `Available=False` on the Deployment, to test whether correlation folds them into one incident. An always-failing `readinessProbe` is folded in so `Available` can actually stay continuously False. | Live 2026-09-03 on `rke2`: **two incidents, not one**, confirmed directly in Postgres. Root cause read from `correlationIdentity.find()` — it matches on exactly one tier. The file argues this is the accepted tradeoff `sweep_detector.go`'s "Overlap 2" comment already documents, on a second pair. |
| 9 | `row09-recreate.yaml` | A non-GitOps Deployment mounting a ConfigMap. **Applying the file alone leaves it healthy** — the fault is induced by deleting the ConfigMap and force-recreating the Pod, producing a repeating `FailedMount: configmap "e14-row9-cm" not found`. | Run 2026-09-06: auto-analysed at confidence 0.95, correctly routed in-place, and then correctly **declined** to fabricate `CreateResource` content it could not ground in evidence. Dismissed with a note. |
| 10 | `row10-honest-negative-transient-oom.yaml` | A bare Pod that OOMKills against a 20Mi limit, then restarts twice more via an `emptyDir` marker so `lastState` is overwritten with a normal exit before analysis runs. | Live 2026-09-03 on `rke2`: a real incident, auto-analysed at confidence 1.00 — **the wrong result for this row.** Tool calls could still read the container's own command, which is durable spec evidence the trick never erases. The file states what a working fixture for this row would need. |
| 15 | `row15-stuck-finalizer.yaml` | A ConfigMap carrying a finalizer nothing will ever remove. **The file alone does not induce the fault** — `kubectl delete ... --wait=false` does, leaving `deletionTimestamp` set forever. | Run 2026-09-06: detected by `checkGenericStuckFinalizer` after the 10-minute sustained threshold, medium severity, auto-analysed at confidence 1.00, and **no plan proposed — correctly**, because no typed remediation action touches `metadata.finalizers`. |
| 17 | `row17-novel-crd-discovery.yaml` | A genuinely novel CRD (`RowProbe`) outside `supportedGVKs`, reachable only through the discovered watch set, carrying a backdated sustained `Ready=False`. Chains discovery → generic condition predicate → the polarity gate → the redacted tool surface → a real investigation. | Live 2026-09-03 on `rke2`: full chain confirmed for the first time; finding `[polarity unverified]`, severity low, manually analysed at confidence 0.40 landing on `Diagnosed` rather than a confident guess, with redaction confirmed in the analysis text. **Read the promotion-gate caveat above before re-running this one.** |

## The six rows with no file, and why

Nothing was lost here — none of the six ever had a file of its own.

- **Row 11** (severity-floor decline: a real low-severity finding correctly *not* auto-analysed)
  needed no fixture at all. The test cluster already carried standing `Detected`/`low` incidents with
  `auto_analysis_attempted_at IS NULL`, which is the evidence the `{high,critical}` floor is excluding
  them correctly.
- **Rows 12, 13 and 14** are the healthy negative controls for rows 1, 3 and 4. They live *inside*
  `row01-...`, `row03-...` and `row04-...` as a second object in the same file, so one
  `kubectl apply`/`kubectl delete` pair exercises the fault and its control together. Each of those
  three files labels its control object in a comment.
- **Row 16** (a wrong cached condition-polarity verdict, surfaced rather than silently dropped) was
  closed using row 17's CRD plus a deliberately wrong verdict seeded straight into `condition_polarity`
  before the fault fired. Reproducing it needs that `INSERT`, which is in Git history, not in any file
  here — `row17-...`'s own FOLLOW-UP note says so.
- **Row 18** (unattended execution closing the loop with no human approval) ran in one dedicated
  throwaway namespace under a one-time, explicitly scoped authorization that **does not carry to a
  later run** — see `PROJECT.md`'s "Decided" entry of 2026-09-06 and `lld/14-adrs.md`. No fixture was
  retained, on purpose: re-inducing it means re-deciding the authorization first.

The remaining rows' own definitions — the full six-column matrix — are in Git history with the board
item that carried them.

## Before inducing anything

**Cluster-specific values are baked into two files.** Rows 2 and 4 pin objects to
`my-rke2-cluster-worker-2` and `my-rke2-cluster-worker-1` via `kubernetes.io/hostname`; both files
carry a NODE NAMES comment explaining what to swap. Against any other cluster they will simply sit
`Pending` for the wrong reason, which is a silent, misleading failure rather than a loud one.

**Row 1 assumes node capacity.** Its 32-CPU request was chosen against 8-allocatable nodes. Raise it if
your nodes are larger.

**Several rows need a wait, not just an apply.** Rows 4, 8 and 15 depend on the agent's 10-minute
`defaultSweepSustainedThreshold`; row 17 additionally depends on the 1-minute
`DefaultWatchSetRefreshInterval` before a freshly-installed CRD is visible at all (it was 15
minutes until PROJECT.md `B177` shortened it). Row 10 needs
`restartCount` to reach 2 before analysis means anything.

**Every namespace is `e14-row*`**, which is the reliable way to confirm you have removed
everything. Rows 1, 2, 3, 4, 7, 8, 10 and 17 additionally label every object
`e14-lifecycle-matrix: "true"`; rows 9 and 15 do not, so a label selector alone will miss them.

## Inducing one row

Each file's header carries its own exact `Usage:` block; that is authoritative for that row. The
general shape:

```
kubectl apply -f row01-pending-pod-insufficient-cpu.yaml
kubectl -n e14-row01 get pod row01-cpu-pending -w
kubectl delete -f row01-pending-pod-insufficient-cpu.yaml
```

Three rows need an extra step, because the manifest alone is deliberately healthy:

```
# row 2 — taint the node first, untaint it last
kubectl taint nodes my-rke2-cluster-worker-2 e14-row02=special:NoSchedule
kubectl apply -f row02-pending-pod-taint-no-toleration.yaml

# row 9 — apply, wait for health, THEN remove what it depends on
kubectl apply -f row09-recreate.yaml
kubectl -n e14-row9-recreate delete configmap e14-row9-cm
kubectl -n e14-row9-recreate delete pod -l app=e14-row9-app

# row 15 — the delete call IS the fault
kubectl apply -f row15-stuck-finalizer.yaml
kubectl -n e14-row15-finalizer delete configmap e14-row15-cm --wait=false
```

Rows 5 and 6 have nothing to apply; read them for the repo-side procedure.

## Teardown

`kubectl delete -f <file>` for every row that has a manifest, plus:

```
kubectl taint nodes my-rke2-cluster-worker-2 e14-row02=special:NoSchedule-   # row 2
kubectl -n e14-row15-finalizer patch configmap e14-row15-cm \
  --type=merge -p '{"metadata":{"finalizers":null}}'                          # row 15, by hand
kubectl delete crd rowprobes.e14test.argus.internal                          # row 17
```

Row 15's finalizer removal is an operator action, not something ARGUS does or should do — that is the
row's own result. Removing it is what lets the object finish deleting so the namespace can go.
