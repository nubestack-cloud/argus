---
name: argus-add-detector
description: Add a new detection to ARGUS the way this codebase does it — a declarative rule in internal/agent/rules/default-rules.yaml when the condition fits the rule shapes, a Go sweep checker when it needs logic, or an event/pod-condition path for a live signal — with the finding's class, impact and references set so promotion and correlation do the right thing, plus RBAC, settings, coverage and a live check. Use when asked to detect, catch, alert on or add a detector or rule for a Kubernetes fault.
argument-hint: [the fault to detect, e.g. "Argo CD Application stuck in Unknown sync"]
---

# Add a detection

Apply [`argus-context`](../argus-context/SKILL.md) first. The agent is read-only, and a detector
that needs a new verb or a Secret is an RBAC change for
[`argus-security-review`](../argus-security-review/SKILL.md), not a detail.

**Build a mechanism, not a case.** A detection is a general condition ("an Application's sync status
is Unknown, sustained"), not one fixture's symptom. The narrow reproduction proves it works; it
never becomes the rule's grammar.

## 1. Pick the mechanism — the lightest that can express it

| Mechanism | Where | When |
|---|---|---|
| **Declarative rule** | `internal/agent/rules/default-rules.yaml`, evaluated by `internal/agent/rules.go` in the sweep | One object's own fields: compare a field to a literal or another field, a time boundary (`expiresWithin`), a selector matching no pods, a missing field, sustained for N minutes. **Default choice.** The schema and its shapes are in `rules.go`'s package comment. |
| **Go sweep checker** | `internal/agent/sweep_detector.go`, appended to `sweepCheckers` | Needs a join across objects, owner suppression, or arithmetic the rule shapes cannot express (`checkOrphanedPVC` is a recent example). |
| **Event path** | `internal/agent/detector.go` | The signal only exists as a Warning event. |
| **Pod conditions** | `internal/agent/pod_conditions_detector.go` | Live pod state: waiting reasons, restarts, readiness. |
| **Posture** | `internal/agent/posture_detector.go` | Configuration risk rather than a fault. |

Do not add a fifth mechanism. If none fits, say why before building one.

## 2. Set the finding so the hub treats it right

Whether a finding opens an incident is the hub's decision (`internal/gateway/promotion.go`), and
which incident it joins is `internal/gateway/finding.go`'s. Both read what the detector sets:

- **`class`**: `fault` (something is broken) or `risk` (something will break or is mis-set). A
  risk does not open an incident on its own.
- **`impact`** and **`confidence`**: what the evidence supports. A finding that is real but
  expected (a probe failing on a pod that is starting during a rollout) is kept with impact `none`
  rather than dropped.
- **The workload**: set `WorkloadGVK` and `WorkloadName` to the owning controller (Pod → ReplicaSet →
  Deployment; Job → CronJob; `internal/agent/workload.go`), so every pod of one workload is one
  incident.
- **`References`**: what the object is waiting on (its PVC, ConfigMap or Secret while Pending, or an
  unready Node), so a cause and its symptoms join one incident (`referenceBridge`).
- **A sustain period** for anything that flaps. A refresh's brief Unknown must never fire.
- **The message**: what is wrong, on which object, and what that means for the operator, in one
  sentence. No secret values: `Finding.Message` is redacted at the tunnel, but do not rely on it.

Also decide how the incident **clears**. Cleared-incident closure (`internal/autoanalyze/cleared.go`)
re-runs the rule, or checks live health for the kinds `liveVerdict` knows. A Go checker whose
condition it cannot re-evaluate closes only by the quiet-period path. If that is wrong for this
fault, extend `liveVerdict`.

## 3. Wire-up the build will not catch

- **RBAC**: the kind must be readable by the investigate identity
  (`deploy/helm/argus-agent/templates/clusterrole.yaml`), and the GVK known to the agent's
  discovery and supported-kinds lists (`internal/agent/discovery.go`, `tools.go`).
- **A new rule ID** goes in `internal/api/settings.go`'s `knownRuleIDs` and the Settings page's rule
  list (`web/src/pages/SettingsPage.tsx`). A test pins the Go list to the YAML.
- **A comment on the rule or checker** cites the issue-catalogue entries it covers
  (`issue-catalog/k8s-issue-catalog.yaml`). That is what the coverage matrix reads.
- **`go run ./scripts/coverage`** regenerates `docs/coverage-matrix.*`.

## 4. Test it

- A unit test with the fault and with the healthy control (`rules_test.go` for a rule;
  `sweep_detector_test.go` with the fake clientset for a checker). Include the case that must
  **not** fire: suspended, still within the sustain period, owned by something that suppresses it.
- If it changes promotion or correlation, add a `*_db_test.go` in `internal/gateway`.
- **Live**, with [`argus-live-test`](../argus-live-test/SKILL.md): a fixture under `fixtures/` that
  causes the fault in a test namespace. Watch the finding arrive and the incident open (or correctly
  not open). Fix the fault and watch the incident close by the expected path. Only that earns a
  `docs/VERIFICATION.md` entry.

## Output

The mechanism chosen and why, the rule or checker, the finding fields (class, impact, workload,
references, sustain), how it clears, the RBAC delta (or "none"), the tests, and what was observed
live, or that it was not tested live.
