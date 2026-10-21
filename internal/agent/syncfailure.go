package agent

// This file detects a fault class that was **completely invisible** to ARGUS: a
// manifest the cluster refused.
//
// # The gap, measured — and narrower than it first looked
//
// Every other detector in this package watches cluster state, which shares one
// assumption: the broken thing is IN the cluster. A manifest the API server
// rejects never gets there. Observed twice on 2026-08-24 — a CronJob with an
// invalid schedule, and a pull request changing a Job's immutable
// `spec.template`:
//
//	CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value:
//	  "not a cron expression": expected exactly 5 fields, found 4
//	Job.batch "immut-job" is invalid: spec.template: ... field is immutable
//
// **The first version of this comment claimed ARGUS saw nothing at all. That was
// wrong, and checking it is what found out.** Argo CD emits a Warning Event
// (`OperationCompleted`) on the Application when a sync fails, and detector.go's
// catch-all already forwards it. An incident existed.
//
// What was actually wrong is subtler and still worth fixing:
//
//   - **Severity.** The event arrives at the catch-all's default `medium`, which
//     is BELOW the `high,critical` band auto-analysis triggers on. So the fault
//     was reported at a priority that guaranteed nothing would look at it.
//   - **Durability.** An Event is subject to §179's fifteen-minute staleness
//     gate. Argo emits one per retry attempt and then stops — the observed
//     Application settled at `phase=Failed` after five retries — so the event
//     ages out while the cluster is still not what the repository says. A
//     condition read off the object reports for as long as it is true.
//
// Proven live: this check attached to the existing incident for that Application
// and escalated it `medium -> high`, with a message naming the API server's own
// rejection instead of a generic sync failure. So the honest description is not
// "a fault nobody saw" but "a fault reported at a priority nobody would act on,
// through a signal that expires while the fault does not".
//
// This closes it for Argo CD. The equivalent for Flux (a `Kustomization` or
// `HelmRelease` whose `Ready` condition is False) is a symmetric signal and the
// RBAC for it is already granted, but it is deliberately NOT implemented here:
// Flux is not installed on either cluster available to this project, so it could
// be written and not exercised, and an untested detector for a controller nobody
// can reproduce against is a claim rather than a capability.
//
// # Which field is the signal, and why not the obvious one
//
// Read off the live object rather than assumed, and the obvious guesses are both
// wrong:
//
//   - `status.conditions` was **empty** on a persistently failing Application.
//     Conditions are the idiomatic place to look and there is nothing there.
//   - `status.operationState.phase` was **"Running"**, not "Failed" — because Argo
//     was still retrying, with `retryCount` climbing. A check waiting for
//     "Failed" would wait forever on the exact case that matters most: a sync
//     that can never succeed.
//
// What is actually true of a failing sync is `operationState.phase` reporting a
// terminal failure OR a retry already in progress, and `operationState.message`
// carrying the API server's own rejection — which is the text that names the
// field, the value and the reason, and is the difference between "a sync failed"
// and something an operator can act on.

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const reasonGitOpsSyncFailed = "GitOpsSyncFailed"

var argoApplicationsGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "applications",
}

// dynamicSweepChecker is a sweep check that reads a custom resource, so it needs
// a dynamic client rather than the typed one every other check uses.
//
// A separate list rather than widening sweepChecker's signature: that signature
// is shared by eleven checks and their tests, and none of them wants a second
// client. Keeping the two lists distinct also makes the interesting property
// visible at a glance — these are the checks that depend on a CRD being present.
type dynamicSweepChecker struct {
	name string
	fn   func(ctx context.Context, dyn dynamic.Interface, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error)
}

var dynamicSweepCheckers = []dynamicSweepChecker{
	{"argo sync failed", checkArgoSyncFailed},
	{"schedules not running", checkStaleSchedules},
	{"batch and AI workloads", checkBatchAIWorkloads},
}

// checkArgoSyncFailed reports an Argo CD Application whose last sync could not be
// applied.
//
// One candidate per Application rather than per rejected object. Argo reports the
// failure as one operation with one message, and it is genuinely one fault — the
// operator pushed a commit the cluster will not accept. Splitting it per object
// would mean parsing that message, which is a free-text field.
func checkArgoSyncFailed(ctx context.Context, dyn dynamic.Interface, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := dyn.Resource(argoApplicationsGVR).Namespace(metav1.NamespaceAll).List(ctx, sweepListOptions)
	if err != nil {
		// No Argo CD on this cluster is the common case, not an error. Reported as
		// "nothing to do" so a cluster without it does not log a failure every
		// thirty seconds — noise that trains an operator to ignore this detector's
		// messages.
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return nil, nil
		}
		if apierrors.IsForbidden(err) {
			// Distinguished from absence deliberately: a chart that was never
			// updated is a fixable configuration problem, and it should not look
			// like "you are not running Argo".
			return nil, fmt.Errorf("listing Argo Applications is forbidden — the agent's ClusterRole needs get,list,watch on argoproj.io/applications: %w", err)
		}
		return nil, err
	}

	var out []sweepCandidate
	for i := range list.Items {
		app := &list.Items[i]
		phase, _, _ := unstructured.NestedString(app.Object, "status", "operationState", "phase")
		message, _, _ := unstructured.NestedString(app.Object, "status", "operationState", "message")
		retries, _, _ := unstructured.NestedInt64(app.Object, "status", "operationState", "retryCount")
		syncStatus, _, _ := unstructured.NestedString(app.Object, "status", "sync", "status")

		if !argoSyncIsFailing(phase, retries) {
			continue
		}

		// A sync that failed but has since been superseded by a successful one
		// leaves the old message behind; requiring OutOfSync as well means the
		// declared state is genuinely not applied right now.
		if syncStatus == "Synced" {
			continue
		}

		revision, _, _ := unstructured.NestedString(app.Object, "status", "sync", "revision")
		detail := strings.TrimSpace(message)
		if detail == "" {
			detail = "no message was recorded"
		}
		out = append(out, sweepCandidate{
			GVK: "argoproj.io/v1alpha1/Application", Namespace: app.GetNamespace(), Name: app.GetName(),
			UID: string(app.GetUID()), ResourceVersion: app.GetResourceVersion(),
			Reason: reasonGitOpsSyncFailed,
			Message: fmt.Sprintf("Argo CD cannot apply this Application's manifests (phase %s, %d retr%s, revision %s): %s",
				phase, retries, plural(retries), shortRev(revision), detail),
			// "high": the cluster is not what the repository says it is, and the
			// operator's declared change is not in effect. Not "critical", which
			// this file reserves for cluster-infrastructure blast radius — a
			// failing sync is scoped to one Application.
			Severity: "high",
			// Argo records no "failing since" timestamp anywhere on the object —
			// operationState carries startedAt for the CURRENT attempt, which
			// resets on every retry and would therefore always look new. So the
			// observed-duration gate decides, the same way the Service checks
			// handle having no authoritative timestamp.
			OccurredAt: now,
		})
	}
	return out, nil
}

// argoSyncIsFailing decides whether an operationState describes a sync that
// cannot be applied.
//
// The retry clause is the important half and the non-obvious one. Argo keeps a
// permanently failing sync at phase "Running" while it retries, so a check that
// waited for "Failed" would never fire on a manifest the API server will refuse
// every single time — which is the case this detector exists for. A retryCount
// above zero says an attempt has already failed, whatever the phase claims.
func argoSyncIsFailing(phase string, retryCount int64) bool {
	switch phase {
	case "Failed", "Error":
		return true
	case "Running":
		return retryCount > 0
	default:
		// "Succeeded", "Terminating", or empty (never synced).
		return false
	}
}

func plural(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	if rev == "" {
		return "unknown"
	}
	return rev
}
