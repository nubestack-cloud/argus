# Loop campaign — detection breadth and lifecycle exits, rke2, 2026-10-13

A regression-reproduction set, like `../e14-lifecycle-matrix`: each file re-induces faults whose
ARGUS-side result was observed live on `rke2` on 2026-10-13. Nothing runs these automatically. The
dated results are in `docs/VERIFICATION.md` ("Incident loop campaign, rke2, 2026-10-13"); this file
says what each fixture is for and how to drive it.

Everything lives in namespace `argus-loop-test` (plus `argus-loop-quota`, `argus-loop-limits`,
`argus-loop-term`, and cluster-scoped objects named `argus-loop-*`). Every object carries
`loop.argus.io/scenario`. The lifecycle exits that execute a fix need the remediation agent enabled
for `argus-loop-test` only (`remediate.enabled=true`, `remediate.namespaces={argus-loop-test}`).

## Files

| File | Scenarios | How to drive |
|---|---|---|
| `w1-workloads.yaml` | S01–S05, S07–S11, S22 | `kubectl apply` |
| `w1-network.yaml` | S12–S17 | `kubectl apply` |
| `w1-storage-config.yaml` | S06, S19, S23–S28, S30, S31 | `kubectl apply`, then delete `s19-claim` (PV goes Released) and `s28-finalized` with `--wait=false` |
| `w2-namespace-stuck.yaml` | S29 | apply, then `kubectl delete namespace argus-loop-term --wait=false` |
| `w2-revert-image.yaml` | S01b, S01c | apply healthy, then roll both to a non-existent tag (header) |
| `w3-more-kinds.yaml` | S20, S33, S36–S41 | apply; for S20 delete `s20-scratch` while `s20-holds-pvc` still mounts it |
| `w4-correlation.yaml` | S22b | apply after the ReplicaSet-workload fix (S22's regression check) |

## Scenario → expected result

Fault (F) opens an incident; risk (R) is a finding only — those are the negative controls.

| # | Fault | Detector | Expected |
|---|---|---|---|
| S01 | Image tag that does not exist | pod conditions | F |
| S02 | CrashLoopBackOff, permanent | pod conditions | F |
| S03 | OOMKilled (the fix ARGUS proposes is not enough — see below) | pod conditions | F |
| S04 | `configMapKeyRef` to a missing key | warning events | F |
| S05 | Requests no node can satisfy | events + PendingTimeout | F |
| S06 | PVC naming a StorageClass that does not exist | events + PVCPendingTimeout | F |
| S07 | Readiness probe always failing | Unhealthy events | F |
| S08 | Job past its backoffLimit | events + JobFailed | F |
| S09 | CronJob whose runs fail | per run | F |
| S10 | StatefulSet image never pulls | pod conditions + `statefulset-rollout-stalled` | F |
| S11 | DaemonSet image never pulls | pod conditions (5 pods → one incident) | F |
| S12 | Service selector matches no pod | `ServiceNoEndpoints` | R |
| S13 | Service targetPort names a port no pod has | `ServiceTargetPortUnresolved` | F |
| S14 | Ingress backed by a missing Service | `IngressBackendServiceMissing` | F |
| S15 | Ingress port its Service does not expose | `IngressBackendPortMismatch` | F |
| S16 | Two Ingresses on one host and path | `IngressHostPathCollision` | F |
| S17 | NetworkPolicy selecting no pod | `networkpolicy-selects-no-pods` | R |
| S19 | PV Released and retained | `persistentvolume-released-stuck` | R |
| S20 | PVC deleted while mounted | `persistentvolumeclaim-stuck-terminating` | F |
| S22 | Deployment naming a missing ServiceAccount | FailedCreate + ReplicaFailure | F (one incident) |
| S23 | Missing Secret volume | FailedMount | F |
| S24 | ResourceQuota the Deployment cannot fit | FailedCreate + `resourcequota-at-hard-limit` | F + R |
| S25 | LimitRange the requests violate | FailedCreate | F |
| S26 | PDB allowing no disruption | `pdb-blocks-all-disruptions` | R |
| S27 | HPA whose target does not exist | FailedGetScale + HPAScalingBlocked | F |
| S28 | ConfigMap stuck on a finalizer | GenericStuckFinalizer | F |
| S29 | Namespace stuck Terminating | GenericStuckFinalizer (+ the held object) | F |
| S30 | Validating webhook whose Service has no endpoints | `WebhookBackingServiceUnreachable` | F |
| S31 | Certificate naming a missing Issuer | generic condition | anomaly, no incident |
| S33 | Argo CD Application path that does not exist | `argo-application-sync-unknown` | F |
| S36 | Init container always fails | pod conditions | F |
| S37 | Liveness probe kills a healthy container | pod conditions + Unhealthy | F |
| S38 | Missing ConfigMap volume | FailedMount | F |
| S39 | Private image, no pull secret | pod conditions | F |
| S40 | Node affinity nothing satisfies | FailedScheduling | F |
| S41 | PriorityClass that does not exist | FailedCreate + ReplicaFailure | F (one incident) |

## Lifecycle exits

| Exit | Scenario | Drive | Expected |
|---|---|---|---|
| Cleared before anyone looked | S04 | add the missing key | Resolved, self_healed, "reads healthy now; nothing was investigated or applied" |
| Object deleted | S08, S20, S28, S29, S30 | delete it | Resolved, "no longer exists" |
| Fixed after investigation | S07 | analyse, then fix the probe | Resolved, self_healed |
| Fixed while a plan waits | S01b | analyse, then set the image back by hand | Resolved, "the pending approval was withdrawn" |
| Approved fix that works | S01c | analyse, approve the revert | Validating → Resolved, remediated |
| Approved fix that does not | S03 | analyse, approve (128Mi is still too little for this fixture) | Validating → Reopened |
| Rollback | S03 | `POST /executions/{id}/rollback` | change undone, Reopened |
| Rejected | S01c (first pass) | reject | PlanRejected, fault untouched |
| Dismissed | S02 | dismiss with a note | Dismissed; the still-running fault is tolerated, no new incident |
| Recurrence | S01b | break it again after it closed | a new incident whose `priorIncidents` names the closed one |
| Rule re-run | S10, S20 | fix | the rule that opened it no longer fires |
| Periodic re-check | S13–S16 | fix | the sweep that found it stops finding it |
| Still broken | S01, S05, S06, S09, S24, S25, S27, S36, S37, S39–S41 | leave | must stay open |

## Cleaning up

```
kubectl delete namespace argus-loop-test argus-loop-quota argus-loop-limits
kubectl delete pv argus-loop-s19-pv
kubectl -n argocd delete application argus-loop-s33
helm upgrade argus-agent … --reset-then-reuse-values --set remediate.enabled=false
```
