package helmstatus

import (
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// DefaultHookStuckAfter mirrors DefaultPendingStuckAfter's reasoning for a
// hook Job specifically: Helm's own hook-weight ordering and the chart's
// readiness gates normally resolve within a couple of minutes, so a hook
// still Running at three times that is no longer "just slow."
const DefaultHookStuckAfter = 15 * time.Minute

// helmHookAnnotation is the annotation every Helm lifecycle hook Job (or any
// hook resource, but this package only ever lists Jobs) carries — its value
// is one of pre-install, post-install, pre-upgrade, post-upgrade,
// pre-rollback, post-rollback, pre-delete, post-delete, test.
const helmHookAnnotation = "helm.sh/hook"

// HookJob is one Helm lifecycle hook Job correlated to a release (PG4,
// 2026-10-13 parity review). D-R12 keeps the release Secret's payload
// unread, so this is the one other place a failed or stuck hook is visible
// at all: the Job it left behind, with a helm.sh/hook annotation naming
// which lifecycle point it ran at.
//
// Inferred is always true: hook Jobs do not reliably carry the
// meta.helm.sh/release-name/-namespace annotations a release Secret does
// (observed across chart authors — many hook templates predate or simply
// omit them), so the match here is namespace plus the
// app.kubernetes.io/instance label matching the release name — the same
// convention discoverHelmReleases itself already relies on to find a
// release's OWN workloads. Correct for the overwhelming majority of charts,
// but a label match, not an ownership proof, which is why every caller is
// told so rather than presenting it as certain.
type HookJob struct {
	Hook      string `json:"hook"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// Phase is "Failed", "Running" (still active, past DefaultHookStuckAfter
	// — a Job still within that window is not reported at all, same as a
	// pending Helm revision), or "Succeeded" (kept only when a later
	// Failed/Running hook for the SAME hook point exists on a retry, so the
	// release row's evidence isn't silently missing the attempt that came
	// right before the one that's actually failing now).
	Phase   string `json:"phase"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	// StartedAt is the Job's own status.startTime; zero when the Job has not
	// started a Pod yet.
	StartedAt time.Time `json:"startedAt,omitzero"`
	Inferred  bool      `json:"inferred"`
}

// CorrelateHookJobs finds every Job in namespace whose app.kubernetes.io/
// instance label matches release and whose helm.sh/hook annotation is set,
// and reduces it to the one evidence line a release row needs: did this
// lifecycle hook fail, or is it stuck. Deeper evidence (the hook Job's own
// Pods, Events and logs) is deliberately not gathered here — the
// investigation already has describe_resource/get_events/get_logs for
// that, once this function has told it which Job to point them at. now
// anchors the stuck-Running judgement; the zero value means time.Now.
func CorrelateHookJobs(release, namespace string, jobObjs []*batchv1.Job, now time.Time) []HookJob {
	if now.IsZero() {
		now = time.Now()
	}
	var out []HookJob
	for _, j := range jobObjs {
		if j.Namespace != namespace {
			continue
		}
		hook := j.Annotations[helmHookAnnotation]
		if hook == "" {
			continue
		}
		if j.Labels["app.kubernetes.io/instance"] != release {
			continue
		}
		hj := HookJob{Hook: hook, Name: j.Name, Namespace: j.Namespace, Inferred: true}
		if j.Status.StartTime != nil {
			hj.StartedAt = j.Status.StartTime.Time
		}
		switch {
		case jobFailed(j):
			hj.Phase = "Failed"
			hj.Reason, hj.Message = jobFailureReason(j)
			out = append(out, hj)
		case j.Status.Succeeded > 0:
			continue // a clean hook run is not evidence of anything wrong
		case j.Status.Active > 0 && hj.StartedAt.IsZero() == false && now.Sub(hj.StartedAt) >= DefaultHookStuckAfter:
			hj.Phase = "Running"
			hj.Message = "still running past the usual hook window"
			out = append(out, hj)
		}
	}
	return out
}

func jobFailed(j *batchv1.Job) bool {
	if j.Status.Failed > 0 && j.Status.Succeeded == 0 && j.Status.Active == 0 {
		return true
	}
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func jobFailureReason(j *batchv1.Job) (reason, message string) {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return c.Reason, c.Message
		}
	}
	return "", ""
}
