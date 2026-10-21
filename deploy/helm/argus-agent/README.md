# argus-agent-chart

The ARGUS agent connects one Kubernetes cluster to an ARGUS hub. It detects problems, answers the
hub's read-only investigation requests, and reports cluster facts. It always dials out to the hub;
nothing connects into the cluster.

## Install

The hub chart already installs this chart for the cluster the hub runs in. For every other cluster,
the hub's **Clusters → Enroll a cluster** prints these commands with the values filled in:

```bash
kubectl create namespace argus-system
kubectl -n argus-system create secret generic argus-enrollment-token --from-literal=token=<token>
helm install argus-agent oci://registry-1.docker.io/nubestack/argus-agent-chart --version 0.2.0 \
  -n argus-system \
  --set namespace.create=false \
  --set hub.apiUrl=https://argus.example.com \
  --set enrollment.tokenSecretRef.name=argus-enrollment-token \
  --set displayName=prod-eu
```

The token stays in a Secret, never in Helm's stored values. (`enrollment.token=<token>` works too, for
a quick test.)

A **fleet token** (**Clusters → Fleet tokens** on the hub) can be shared by every cluster, so the
same values roll out everywhere. Argo CD and Flux examples are in `deploy/examples/` of the ARGUS
repository.

## What it deploys

| Resource | When |
|---|---|
| `argus-agent` Deployment under the read-only `argus-investigate` ServiceAccount | Always |
| `ClusterRole` with list/get/watch only: no Secrets, no `pods/exec`, no write verb | Always |
| Identity `Secret`, readable and writable only by the agent | Always (`identity.mode=secret`) |
| `argus-remediate` Deployment, ServiceAccount, namespace Roles and admission policies | `remediate.enabled` |
| Node cordon/drain grant and its admission policy | `remediate.nodeOps.enabled` |
| `argus-dryrun` identity for server-side dry runs | `dryRun.enabled` |
| `argus-policy-controller` identity and the `ExecutionWindow` CRD | `policyController.enabled` |
| `services/proxy` grant on one Prometheus Service | `metrics.prometheusService.name` |

## Good to know

- **Read-only by default.** Write access (`remediate.*`) is a second Deployment with its own
  identity, limited to the namespaces you list and to the fields ARGUS's typed actions change. It
  needs Kubernetes 1.30+ (ValidatingAdmissionPolicy).
- **Upgrades keep the enrollment.** The agent's identity is a Secret the chart does not overwrite.
  `helm uninstall` decommissions the agent, and `helm upgrade --force` replaces the identity: never
  `--force` an enrolled agent.
- **Values are validated** by the chart's `values.schema.json`.
- **Sizing.** The default memory limit (1Gi) covers about 5,000 pods; `values.yaml` has the formula
  for larger clusters.
- **Private CA for the hub.** `--set-file hub.caBundle=./ca.pem` or `hub.caSecretRef.name`.
- **Moving the tunnel.** `hub.tunnelEndpoint` points an enrolled agent at a different tunnel address
  (for example from a dedicated port to the hub's Ingress) without enrolling again.

Every value is documented in `helm show values oci://registry-1.docker.io/nubestack/argus-agent-chart --version 0.2.0`.

User guide (installation and use): <https://argus.nubestack.com/>. Install and upgrade reference:
[`docs/INSTALL.md`](https://github.com/nubestack-collab/ARGUS/blob/main/docs/INSTALL.md).
