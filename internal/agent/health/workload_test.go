package health

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func i32p(v int32) *int32 { return &v }
func yes() *bool          { b := true; return &b }

// deploy is a Deployment wanting want, with ready and available replicas,
// at generation gen observed as seen, and any conditions given as
// Type=Status:Reason strings.
func deploy(want, ready, available int32, gen, seen int64, conds ...appsv1.DeploymentCondition) *appsv1.Deployment {
	d := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: i32p(want)}}
	d.Generation = gen
	d.Status = appsv1.DeploymentStatus{ObservedGeneration: seen, ReadyReplicas: ready, AvailableReplicas: available, Conditions: conds}
	return d
}

func progressing(status corev1.ConditionStatus, reason string) appsv1.DeploymentCondition {
	return appsv1.DeploymentCondition{Type: appsv1.DeploymentProgressing, Status: status, Reason: reason}
}

func job(spec batchv1.JobSpec, st batchv1.JobStatus, conds ...batchv1.JobConditionType) *batchv1.Job {
	for _, c := range conds {
		st.Conditions = append(st.Conditions, batchv1.JobCondition{Type: c, Status: corev1.ConditionTrue})
	}
	return &batchv1.Job{Spec: spec, Status: st}
}

func cron(schedule string, createdAgo time.Duration, lastRunAgo time.Duration, suspended bool) *batchv1.CronJob {
	cj := &batchv1.CronJob{Spec: batchv1.CronJobSpec{Schedule: schedule}}
	cj.CreationTimestamp = ago(createdAgo)
	if lastRunAgo > 0 {
		at := ago(lastRunAgo)
		cj.Status.LastScheduleTime = &at
	}
	if suspended {
		cj.Spec.Suspend = yes()
	}
	return cj
}

func TestWorkload(t *testing.T) {
	cases := []struct {
		why    string
		obj    any
		level  Level
		reason string
	}{
		// Deployments need ready and available.
		{"all there", deploy(4, 4, 4, 2, 2), LevelHealthy, ""},
		{"scaled to zero", deploy(0, 0, 0, 2, 2), LevelNeutral, "ScaledToZero"},
		{"some ready", deploy(4, 1, 1, 2, 2), LevelDegraded, "PartiallyReady"},
		{"ready but not available", deploy(4, 4, 3, 2, 2), LevelDegraded, "PartiallyReady"},
		{"none ready", deploy(4, 0, 0, 2, 2), LevelUnhealthy, "NoneReady"},
		// A surge pod beyond the desired count does not hurt.
		{"surging", deploy(1, 2, 1, 3, 3), LevelHealthy, ""},
		// The old pods keep serving while the new ReplicaSet never comes up.
		{"rollout stalled at full strength", deploy(2, 2, 2, 3, 3, progressing(corev1.ConditionFalse, "ProgressDeadlineExceeded")), LevelDegraded, "ProgressDeadlineExceeded"},
		{"stalled with no reason given", deploy(2, 2, 2, 3, 3, progressing(corev1.ConditionFalse, "")), LevelDegraded, "ProgressDeadlineExceeded"},
		{"stalled and none ready", deploy(2, 0, 0, 3, 3, progressing(corev1.ConditionFalse, "ProgressDeadlineExceeded")), LevelUnhealthy, "NoneReady"},
		{"progressing fine", deploy(2, 2, 2, 3, 3, progressing(corev1.ConditionTrue, "NewReplicaSetAvailable")), LevelHealthy, ""},
		// Scaled up from 3 to 10, the controller one generation behind: lag,
		// not an outage — and neutral, not a claim of health.
		{"controller behind the spec", deploy(10, 3, 3, 8, 7), LevelNeutral, "Converging"},
		// Being new buys nothing: caught up and still nothing ready is broken.
		{"new and caught up, nothing ready", deploy(3, 0, 0, 1, 1), LevelUnhealthy, "NoneReady"},
		{"never observed", deploy(3, 0, 0, 1, 0), LevelUnhealthy, "NoneReady"},

		{"statefulset ready", &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{Replicas: i32p(3)}, Status: appsv1.StatefulSetStatus{ReadyReplicas: 3}}, LevelHealthy, ""},
		{"statefulset short", &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{Replicas: i32p(3)}, Status: appsv1.StatefulSetStatus{ReadyReplicas: 2}}, LevelDegraded, "PartiallyReady"},
		{"replicaset at zero", &appsv1.ReplicaSet{Spec: appsv1.ReplicaSetSpec{Replicas: i32p(0)}}, LevelNeutral, "ScaledToZero"},
		{"replicaset default one, none ready", &appsv1.ReplicaSet{}, LevelUnhealthy, "NoneReady"},
		// A DaemonSet wanting none matches no node.
		{"daemonset everywhere", &appsv1.DaemonSet{Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 6, NumberReady: 6}}, LevelHealthy, ""},
		{"daemonset nowhere", &appsv1.DaemonSet{}, LevelNeutral, "ScaledToZero"},
		{"daemonset half", &appsv1.DaemonSet{Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 6, NumberReady: 3}}, LevelDegraded, "PartiallyReady"},

		// Jobs: terminal conditions first, even over suspension.
		{"job complete", job(batchv1.JobSpec{}, batchv1.JobStatus{}, batchv1.JobComplete), LevelNeutral, "Completed"},
		{"job failed", job(batchv1.JobSpec{}, batchv1.JobStatus{}, batchv1.JobFailed), LevelUnhealthy, "Failed"},
		{"job failed then suspended", job(batchv1.JobSpec{Suspend: yes()}, batchv1.JobStatus{}, batchv1.JobFailed), LevelUnhealthy, "Failed"},
		{"job suspended", job(batchv1.JobSpec{Suspend: yes()}, batchv1.JobStatus{}), LevelNeutral, "Suspended"},
		{"job running", job(batchv1.JobSpec{}, batchv1.JobStatus{Active: 2}), LevelNeutral, "Running"},
		{"job enough successes", job(batchv1.JobSpec{Completions: i32p(3)}, batchv1.JobStatus{Succeeded: 3}), LevelNeutral, "Completed"},
		// Kubernetes treats zero completions as done without running anything.
		{"job wanting none", job(batchv1.JobSpec{Completions: i32p(0)}, batchv1.JobStatus{}), LevelNeutral, "Completed"},
		{"job only failures", job(batchv1.JobSpec{}, batchv1.JobStatus{Failed: 4}), LevelUnhealthy, "Failed"},
		{"job no signal", job(batchv1.JobSpec{Completions: i32p(2)}, batchv1.JobStatus{Succeeded: 1}), LevelUnknown, ""},

		// CronJobs are judged by their own cadence.
		{"cron suspended", cron("0 * * * *", 30*24*time.Hour, 0, true), LevelNeutral, "Suspended"},
		{"cron on time", cron("*/15 * * * *", 30*24*time.Hour, 5*time.Minute, false), LevelHealthy, ""},
		{"cron stale", cron("*/15 * * * *", 30*24*time.Hour, 50*time.Hour, false), LevelDegraded, "Stale"},
		// A weekly job last run five days ago is fine.
		{"weekly, five days", cron("0 4 * * 1", 90*24*time.Hour, 5*24*time.Hour, false), LevelHealthy, ""},
		{"cron new, never run", cron("0 2 * * *", time.Hour, 0, false), LevelNeutral, "NeverRun"},
		{"cron old, never run", cron("0 2 * * *", 4*24*time.Hour, 0, false), LevelDegraded, "NeverScheduled"},

		{"claim bound", &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}, LevelHealthy, ""},
		{"claim waiting", &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}, LevelNeutral, "Pending"},
		{"claim lost", &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimLost}}, LevelUnhealthy, "Lost"},
		{"claim no phase", &corev1.PersistentVolumeClaim{}, LevelUnknown, ""},

		// Not a workload kind.
		{"a pod", &corev1.Pod{}, LevelUnknown, ""},
		{"a nil cronjob", (*batchv1.CronJob)(nil), LevelUnknown, ""},
	}
	for _, c := range cases {
		v := Workload(c.obj, clock)
		if v.Level != c.level || v.Reason != c.reason {
			t.Errorf("%s: %s/%q, want %s/%q", c.why, v.Level, v.Reason, c.level, c.reason)
		}
	}
}
