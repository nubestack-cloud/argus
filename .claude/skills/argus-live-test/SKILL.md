---
name: argus-live-test
description: Exercise an ARGUS change against the real lab deployment — build the hub/agent images, roll them out to the rke2 install, confirm the new build is what is running, then drive the changed behaviour through the real API and real cluster objects and watch it happen. Use after a change to detection, correlation, incident lifecycle, investigation, remediation, an API route, or anything the owner will review on the live hub; or when asked to "test it live", "deploy and check", or "prove it works on the cluster".
argument-hint: [the behaviour to prove — defaults to what the working-tree diff changes]
---

# Prove an ARGUS change on the lab deployment

`docs/VERIFICATION.md` only records what was **observed on a live cluster**, and this repo has
shipped fully tested features that did nothing in the running configuration. This skill is how a
change earns that. Run [`argus-qa`](../argus-qa/SKILL.md) first — deploying a build that fails its
own tests wastes a rollout.

## Ground rules

- **Only the two lab clusters.** rke2 (`~/key/rke2.yaml`, context `default`) hosts the hub and an
  agent; the second lab cluster (its own kubeconfig, e.g. `~/key/second-cluster.yaml`) runs the second agent. Never point a
  command at any other kubeconfig or context, and pass `--context` explicitly on every `kubectl` and
  `helm` call so a changed default context cannot redirect one.
- **Faults go in a test namespace you create and delete**, never in a namespace something else
  lives in. Fixture manifests live under `fixtures/` (the `loop-campaign/` set covers most kinds);
  reuse one before writing a new one.
- **Never print a credential.** The bootstrap password, access tokens, the model token and the
  GitHub token go through files and stdin. No unfiltered `helm get values`.
- **Remediation is off on the lab by default.** Turn it on for the test namespace only, for the test,
  and off again afterwards; say both in the report.
- Do not commit. Deploying is expected; committing is the owner's call.

## 1. Build and roll out

```
TAG=ci-$(date +%m%d%H%M)
docker build --build-arg VERSION=$TAG --target hub   -t nubestack/argus-hub:$TAG   -f Dockerfile .
docker build --build-arg VERSION=$TAG --target agent -t nubestack/argus-agent:$TAG -f Dockerfile .   # only if agent code changed
```

Then push, resolve the pushed digest, and `helm upgrade` with both pinned:

```
docker push nubestack/argus-hub:$TAG
DIGEST=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' nubestack/argus-hub:$TAG | grep -m1 '^nubestack/argus-hub@' | sed 's/.*@//')
KUBECONFIG=~/key/rke2.yaml helm upgrade argus-hub deploy/helm/argus-hub -n argus-system --kube-context default \
  --reset-then-reuse-values --set image.tag=$TAG --set image.digest=$DIGEST --wait --timeout 10m
```

The agent is the same shape with `deploy/helm/argus-agent`, run once per cluster (rke2 with context
`default`, and the second lab cluster with its own kubeconfig and context). Afterwards, move the chart
pins to what runs with `./scripts/pin-image-digests.sh --hub-tag $TAG` (plus `--agent-tag $TAG` if
you rolled the agent); it edits `values.yaml` in place and keeps the comments.

The build is by hand rather than `scripts/build-images.sh` because that script tags with
`git describe --dirty`, which is the same string for every uncommitted build, so successive lab
rollouts could not be told apart. Always pass `VERSION`: without it the binary reports `dev`.

## 2. Confirm what is actually running

A rollout that "succeeded" can still be serving the previous build. Check before testing anything:

- Pods: `kubectl --context default -n argus-system get pods` — new pods are Ready, old ones gone, and
  each pod's image digest is the one you pushed.
- Both clusters reconnected: `GET /api/v1/clusters` shows both lab clusters `Active` with a fresh
  heartbeat. rke2's agent takes about a minute to come back after a hub restart. A hub restart also
  resets each agent's connected-since time, which delays anything gated on a quiet period (cleared
  incident closure, for one) by that period.
- For a UI change: fetch the served `index-*.js` and grep it for a string only the new code has —
  plus a string that is in neither, as the negative control.

## 3. Get a session

Read the bootstrap admin password from the `argus-hub-argus-hub-bootstrap` Secret straight into the
login request body (stdin), write the returned access token to a scratchpad file, and send it with
`-H "Authorization: Bearer $(cat token)"`. Tokens expire: a sudden `401 ... token is expired` means
log in again, not a broken route.

`GET /api/v1/me` returns 200 with **no** token, so it proves nothing about auth. Check a real route
and its negative case (no token → 401; a viewer token on a gated route → 403).

## 4. Plan the test from the diff

`git diff --stat`, then write down — before touching the cluster — what you will do, what you
expect to see, and how long it should take. For each changed behaviour:

| Changed area | What a live test looks like |
|---|---|
| Detection / a rule | Apply the fixture that causes the fault; watch `GET /api/v1/findings` and the incident list for the expected detector, reason and severity. Then the control: a healthy object must **not** open one. |
| Correlation | Cause two symptoms of one fault; expect one incident carrying both findings, not two. |
| Lifecycle / closure | Fix the fault partway through (before analysis, during, after a plan, while awaiting approval) and watch it close by the expected path and timeline event. Also leave one broken and confirm it stays open. |
| Investigation | `POST /api/v1/incidents/{id}/analyze` for one incident; read the analysis for the expected root cause, evidence references and route. |
| Remediation | In the test namespace with remediation on: approve the plan, watch preflight, execution, validation and resolution, then confirm the object really changed. |
| An API route | Success, no token (401), missing capability (403), bad input (400), with the RFC 9457 body. |
| UI | Hand over to [`argus-visual-test`](../argus-visual-test/SKILL.md) against the live hub. |

`scripts/smoke-test.sh` is the broad API contract suite. It is written for the local compose stack
and enrolls its own throwaway agent against a disposable kind cluster, so run it there (RUNBOOK.md)
rather than against the lab hub.

## 5. What to leave to the owner

Say plainly instead of attempting: anything outside the two lab clusters; changes to a shared
namespace or to platform components (ingress, CNI, storage, Argo CD itself); a real merge into the
GitOps test repository beyond the test branch; anything needing a human judgement about how the page
reads.

## 6. Clean up

Delete the test namespace and anything else you created, switch remediation back off if you turned
it on, kill any port-forward or local process you started, and check that the incidents your
fixtures opened closed (or say which are still open, and why).

## 7. Report, and record what was proven

1. Image tag and digests, and the evidence they are what is running.
2. Each test: what was done, what was expected, what was observed, with incident IDs and timings.
   A failure is reported as observed, with the API output.
3. What was not tested, and why.
4. Whether an automated test should be added: a `*_db_test.go` for a query or correlation rule, a
   fixture under `fixtures/` for a fault shape, a Vitest spec for UI logic. Prefer a test of
   behaviour over one of wiring; for a low-risk mechanical change, "none needed" with the reason is
   an acceptable answer.

Then add an entry to `docs/VERIFICATION.md` for what was observed live — and only that — and run
`go run ./scripts/coverage` if the entry or a rule changed.
