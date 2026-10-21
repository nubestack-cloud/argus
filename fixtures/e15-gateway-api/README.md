# `E15` — Gateway API live fixtures

Induces catalogue entries `GW-004`, `GW-005` and `GW-006` plus a route-level dangling
reference, on a cluster with Gateway API installed. Created 2026-09-07.

**Why this fixture exists.** Gateway API is the proof case for kind-agnostic detection: all 32 of its
catalogue entries key on a status condition, so if ARGUS needed a Gateway-specific *detector* to see
them, the discovered-watch-set mechanism did not work. It does not need one — the kinds are enumerated
in `supportedGVKs` and the agent ClusterRole so they can be read at all, and from there the existing
generic predicates do the whole job. The fixtures themselves are ordinary Kubernetes objects.

**What this fixture proves, and what it deliberately does not.** Measured live 2026-09-07 (single
agent, after an earlier run was invalidated by three concurrent agent processes): the mechanism holds —
discovery resolved a 216-kind watch set with no Gateway-specific code and no RBAC exclusions — and
detection holds: every condition in the table below is visible, each correctly naming which listener
or parent is broken. **What it does not prove is any end-to-end outcome, because these faults open
zero incidents today.** Every entry in this category reaches ARGUS through a `Class=Anomaly`
predicate, and this hub does not promote an anomaly to an incident while earned promotion stays
disabled — the conservative default, not a defect. So there is no analysis and no pull-request fix
behind any of it. `docs/VERIFICATION.md` carries the full account, including what would still block
promotion if it were switched on.

## Prerequisites

Neither is installed by default; both were added to the `rke2` test cluster on 2026-09-07.

```
# Gateway API standard CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml

# A controller, required: without one, Gateway objects carry NO status conditions at all,
# so none of these faults can be induced. NGINX Gateway Fabric installs from plain manifests.
kubectl apply -f https://raw.githubusercontent.com/nginx/nginx-gateway-fabric/v1.6.1/deploy/crds.yaml
kubectl apply -f https://raw.githubusercontent.com/nginx/nginx-gateway-fabric/v1.6.1/deploy/default/deploy.yaml
```

## Applying

```
kubectl apply -f namespace.yaml
kubectl -n gwapi-verify create secret tls conflict-cert --cert=<crt> --key=<key>   # any self-signed pair
kubectl apply -f gw-faults.yaml
kubectl apply -f httproute-dangling-backend.yaml
```

The agent re-runs discovery every `DefaultWatchSetRefreshInterval` (1 minute,
`internal/agent/discovery.go` — shortened from 15 minutes for PROJECT.md `B177`), so a
freshly-installed CRD is not visible immediately, but within about a minute rather than a quarter
of an hour.

## What each fixture produces

`gw-faults.yaml` is deliberately ONE Gateway carrying three listeners rather than three Gateways.
NGINX Gateway Fabric reconciles only one Gateway per GatewayClass and marks every other one
`Accepted=False(GatewayConflict)` without evaluating its listeners at all — so separate Gateways
produce one real result and one ignored object, not three faults.

| Listener | Condition observed 2026-09-07 | Catalogue |
|---|---|---|
| `plain` / `secure` | `Conflicted=True(ProtocolConflict)`, `Accepted=False`, `Programmed=False` | `GW-005` |
| `badcert` | `ResolvedRefs=False(InvalidCertificateRef)`, `Accepted=False`, `Programmed=False` | `GW-006` |
| (Gateway level) | `Programmed=False` | `GW-004` shape |
| `httproute-dangling-backend.yaml` | `ResolvedRefs=False(BackendNotFound)` | route-level dangling reference |

**`Conflicted=True` is the point of this fixture.** It is an inverted-polarity condition — `True` is
the unhealthy state, where most conditions are healthy when `True` — and it sits in the same object
as three normal-polarity conditions. `internal/conditionpolarity` has to get both directions right on
one object, which nothing else in the fixture set exercises.

## Teardown

```
kubectl delete namespace gwapi-verify
```

Leaves the CRDs and controller in place. To remove those too, delete the manifests listed under
Prerequisites in reverse order.
