package health

import (
	"cmp"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// replicaState is what a replica-based controller reports, reduced to what
// its grade depends on.
type replicaState struct {
	want, ready, available int32
	// checkAvailable: the controller tracks availability (a Deployment does;
	// the others do not report it the same way) and it must reach want too.
	checkAvailable bool
	// lagging: the controller has not yet acted on the current spec.
	lagging bool
}

func lagging(generation, observed int64) bool { return observed > 0 && observed < generation }

// Workload grades a controller, batch or storage object; a kind it does not
// know is unknown, so the caller can fall back. Off or finished on purpose
// is neutral, not degraded or unknown: scaled to zero, a Job still running
// (under way is not healthy), a PVC waiting for its first consumer.
func Workload(obj any, now time.Time) Verdict {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return deploymentVerdict(o)
	case *appsv1.ReplicaSet:
		return replicaState{want: specReplicas(o.Spec.Replicas), ready: o.Status.ReadyReplicas, lagging: lagging(o.Generation, o.Status.ObservedGeneration)}.verdict()
	case *appsv1.StatefulSet:
		return replicaState{want: specReplicas(o.Spec.Replicas), ready: o.Status.ReadyReplicas, lagging: lagging(o.Generation, o.Status.ObservedGeneration)}.verdict()
	case *appsv1.DaemonSet:
		// Wanting none means the selector matches no node: nothing to run.
		return replicaState{want: o.Status.DesiredNumberScheduled, ready: o.Status.NumberReady, lagging: lagging(o.Generation, o.Status.ObservedGeneration)}.verdict()
	case *batchv1.Job:
		return jobVerdict(o)
	case *batchv1.CronJob:
		return cronJobVerdict(o, now)
	case *corev1.PersistentVolumeClaim:
		return pvcVerdict(o)
	}
	return Verdict{Level: LevelUnknown}
}

// deploymentVerdict adds the Deployment's Progressing condition to its
// replica counts. The counts miss a stalled rollout: when the new
// ReplicaSet can never become ready the old pods go on serving, every count
// reads full, and only Progressing=False (ProgressDeadlineExceeded) says the
// rollout is stuck. The object panel grades that condition degraded
// (web/src/insight/summaryModel.ts, workloadHealth), and the map must agree
// with it. It only ever makes the verdict worse — a Deployment with nothing
// ready that has also stalled stays unhealthy — and leaves scaled to zero
// alone, with nothing to roll out.
func deploymentVerdict(d *appsv1.Deployment) Verdict {
	v := replicaState{
		want: specReplicas(d.Spec.Replicas), ready: d.Status.ReadyReplicas, available: d.Status.AvailableReplicas,
		checkAvailable: true, lagging: lagging(d.Generation, d.Status.ObservedGeneration),
	}.verdict()
	if v.Reason == "ScaledToZero" || Rank(v.Level) >= Rank(LevelDegraded) {
		return v
	}
	i := slices.IndexFunc(d.Status.Conditions, func(c appsv1.DeploymentCondition) bool {
		return c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse
	})
	if i >= 0 {
		return Verdict{Level: LevelDegraded, Reason: cmp.Or(d.Status.Conditions[i].Reason, "ProgressDeadlineExceeded")}
	}
	return v
}

// verdict grades replica counts.
//
// While the controller has not caught up with the spec the answer is
// neutral (Converging): otherwise every rollout and scale-up reads impaired
// throughout — scaled from 3 to 10, a Deployment is "partly ready" the moment
// the spec changes, before a single pod exists, which is controller lag and
// not an outage. Neutral, not healthy: it declines to call it broken, it
// does not call it fine. And it softens only the workload's own grade; a
// pod that is really failing still reads unhealthy on its own (Pod).
//
// The lag is read from generations, never from age. "Created a moment ago"
// would also soften a workload broken on arrival — an unschedulable 0/3
// Deployment would read neutral — which is exactly when it matters most;
// a generation the controller has not observed is evidence, not a guess.
func (r replicaState) verdict() Verdict {
	switch {
	case r.want == 0:
		return Verdict{Level: LevelNeutral, Reason: "ScaledToZero"}
	case r.ready >= r.want && (!r.checkAvailable || r.available >= r.want):
		return Verdict{Level: LevelHealthy}
	case r.lagging:
		return Verdict{Level: LevelNeutral, Reason: "Converging"}
	case r.ready > 0:
		return Verdict{Level: LevelDegraded, Reason: "PartiallyReady"}
	}
	return Verdict{Level: LevelUnhealthy, Reason: "NoneReady"}
}

// jobVerdict grades a Job. Its terminal conditions come first: a Job that
// failed or completed is that whether or not it was suspended afterwards.
func jobVerdict(j *batchv1.Job) Verdict {
	for _, c := range j.Status.Conditions {
		switch {
		case c.Status != corev1.ConditionTrue:
		case c.Type == batchv1.JobFailed:
			return Verdict{Level: LevelUnhealthy, Reason: "Failed"}
		case c.Type == batchv1.JobComplete:
			return Verdict{Level: LevelNeutral, Reason: "Completed"}
		}
	}
	s := j.Status
	switch {
	case flagSet(j.Spec.Suspend):
		return Verdict{Level: LevelNeutral, Reason: "Suspended"}
	case int(s.Succeeded) >= jobDesiredCompletions(j):
		return Verdict{Level: LevelNeutral, Reason: "Completed"}
	case s.Failed > 0 && s.Active == 0 && s.Succeeded == 0:
		// Failures and nothing else: a real failure.
		return Verdict{Level: LevelUnhealthy, Reason: "Failed"}
	case s.Active > 0:
		// Under way, not finished: not "healthy" either.
		return Verdict{Level: LevelNeutral, Reason: "Running"}
	}
	return Verdict{Level: LevelUnknown}
}

func flagSet(p *bool) bool { return p != nil && *p }

// jobDesiredCompletions is the successes a Job needs: 1 when completions is
// unset, as Kubernetes defaults it. An explicit 0 stays 0 — the controller
// treats such a Job as done without running anything, so it is complete.
func jobDesiredCompletions(j *batchv1.Job) int {
	if c := j.Spec.Completions; c != nil {
		return int(*c)
	}
	return 1
}

// cronJobVerdict grades a CronJob against its own cadence. One that has
// never run is fine while new, and stuck (a bad schedule, a broken
// controller) once it has existed longer than its cadence allows; one whose
// last run is older than that is stale.
func cronJobVerdict(cj *batchv1.CronJob, now time.Time) Verdict {
	if cj == nil {
		return Verdict{Level: LevelUnknown}
	}
	if flagSet(cj.Spec.Suspend) {
		return Verdict{Level: LevelNeutral, Reason: "Suspended"}
	}
	limit := cronStaleThreshold(cj.Spec.Schedule)
	if last := cj.Status.LastScheduleTime; last != nil {
		if now.Sub(last.Time) > limit {
			return Verdict{Level: LevelDegraded, Reason: "Stale"}
		}
		return Verdict{Level: LevelHealthy}
	}
	if now.Sub(cj.CreationTimestamp.Time) > limit {
		return Verdict{Level: LevelDegraded, Reason: "NeverScheduled"}
	}
	return Verdict{Level: LevelNeutral, Reason: "NeverRun"}
}

// pvcVerdicts grade a claim by its phase. Pending is waiting for a consumer
// or for provisioning, nothing to alarm on.
var pvcVerdicts = map[corev1.PersistentVolumeClaimPhase]Verdict{
	corev1.ClaimBound:   {Level: LevelHealthy},
	corev1.ClaimPending: {Level: LevelNeutral, Reason: "Pending"},
	corev1.ClaimLost:    {Level: LevelUnhealthy, Reason: "Lost"},
}

func pvcVerdict(pvc *corev1.PersistentVolumeClaim) Verdict {
	if v, ok := pvcVerdicts[pvc.Status.Phase]; ok {
		return v
	}
	return Verdict{Level: LevelUnknown}
}

// specReplicas is a replica count, 1 when unset as the API defaults it.
func specReplicas(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}
