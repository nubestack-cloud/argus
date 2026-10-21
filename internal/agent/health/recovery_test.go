package health

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodDisplayLevel adds failing to schedule and stuck terminating as a floor:
// at least degraded, never better than Pod said.
func TestPodDisplayLevel(t *testing.T) {
	gone := metav1.NewTime(clock.Add(-15 * time.Minute))
	unschedulable := pod(corev1.PodPending, created(time.Minute), func(p *corev1.Pod) {
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable}}
	})
	gated := pod(corev1.PodPending, created(time.Minute), func(p *corev1.Pod) {
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonSchedulingGated}}
	})
	wedged := pod(corev1.PodRunning, mains(ctr("api", ready(), running(time.Hour))), func(p *corev1.Pod) { p.DeletionTimestamp = &gone })
	wedgedAndLooping := pod(corev1.PodRunning, mains(ctr("api", restarts(4), waiting("CrashLoopBackOff"))), func(p *corev1.Pod) { p.DeletionTimestamp = &gone })
	for _, c := range []struct {
		why  string
		p    *corev1.Pod
		want Level
	}{
		{"unschedulable", unschedulable, LevelDegraded},
		// Held back on purpose is not a scheduling failure.
		{"scheduling gated", gated, LevelHealthy},
		{"stuck terminating", wedged, LevelDegraded},
		{"stuck and looping", wedgedAndLooping, LevelUnhealthy},
		{"fine", pod(corev1.PodRunning, mains(ctr("api", ready(), running(time.Hour)))), LevelHealthy},
	} {
		if got := PodDisplayLevel(c.p, clock); got != c.want {
			t.Errorf("%s: %s, want %s", c.why, got, c.want)
		}
	}
}

func TestIsStuckTerminating(t *testing.T) {
	deleting := func(d time.Duration) *corev1.Pod {
		at := metav1.NewTime(clock.Add(-d))
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &at}}
	}
	if IsStuckTerminating(&corev1.Pod{}, clock) || IsStuckTerminating(deleting(3*time.Minute), clock) || !IsStuckTerminating(deleting(12*time.Minute), clock) {
		t.Error("stuck terminating is more than ten minutes")
	}
}

// A sidecar is an init container with restartPolicy Always.
func sidecarSpec(name string, probe bool) podOpt {
	return func(p *corev1.Pod) {
		always := corev1.ContainerRestartPolicyAlways
		c := corev1.Container{Name: name, RestartPolicy: &always}
		if probe {
			c.ReadinessProbe = &corev1.Probe{}
		}
		p.Spec.InitContainers = append(p.Spec.InitContainers, c)
	}
}

// Crash history must neither hide a loop that is still going nor keep
// flagging one that is over.
func TestCrashRecovery(t *testing.T) {
	crashed := lastRun("Error", 1, 30*time.Second)
	// up30s is a serving container restarted thirty seconds ago.
	up30s := func(extra ...csOpt) corev1.ContainerStatus {
		return ctr("api", append([]csOpt{ready(), restarts(2), running(30 * time.Second), crashed}, extra...)...)
	}
	notReady := func(c *corev1.ContainerStatus) { c.Ready = false }
	noStart := func(c *corev1.ContainerStatus) { c.State.Running.StartedAt = metav1.Time{} }
	named := func(n string) csOpt { return func(c *corev1.ContainerStatus) { c.Name = n } }
	cases := []struct {
		why    string
		pod    *corev1.Pod
		level  Level
		reason string
	}{
		// Back for under the backoff: still a loop, but serving.
		{"restarted moments ago, serving", pod(corev1.PodRunning, mains(up30s())), LevelDegraded, "CrashLoopBackOff"},
		{"many restarts, serving", pod(corev1.PodRunning, mains(up30s(restarts(40)))), LevelDegraded, ""},
		{"waiting again", pod(corev1.PodRunning, mains(up30s(waiting("CrashLoopBackOff"), notReady))), LevelUnhealthy, "CrashLoopBackOff"},
		{"running, not ready", pod(corev1.PodRunning, mains(up30s(notReady))), LevelUnhealthy, ""},
		{"up past the backoff", pod(corev1.PodRunning, mains(up30s(running(6*time.Minute)))), LevelHealthy, ""},
		{"up half an hour", pod(corev1.PodRunning, mains(up30s(running(30*time.Minute)))), LevelHealthy, ""},
		// A start long after the last termination is not the same loop (a
		// node back after an outage)...
		{"crash long before this run", pod(corev1.PodRunning, mains(up30s(lastRun("Error", 1, 3*time.Hour)))), LevelHealthy, ""},
		// ...but a gap of one maximum backoff is.
		{"one backoff between", pod(corev1.PodRunning, mains(up30s(running(time.Minute), lastRun("Error", 1, 6*time.Minute)))), LevelDegraded, ""},
		// No start time: judged by the termination; recent stays flagged.
		{"no start time, recent crash", pod(corev1.PodRunning, mains(up30s(noStart))), LevelDegraded, ""},
		{"no start time, old crash", pod(corev1.PodRunning, mains(up30s(noStart, lastRun("Error", 1, 6*time.Minute)))), LevelHealthy, ""},
		// A readiness gate does not make a ready container down.
		{"readiness gate pending", pod(corev1.PodRunning, mains(up30s()), func(p *corev1.Pod) {
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ReadinessGatesNotReady"}}
		}), LevelDegraded, ""},
		// With a probe or without, a restart this recent stays visible.
		{"probed flapper", pod(corev1.PodRunning, probed("api"), mains(up30s(running(90*time.Second), lastRun("Error", 1, 90*time.Second)))), LevelDegraded, ""},
		// An init container that failed once and then finished is done.
		{"init retried, then completed", pod(corev1.PodRunning, inits(ctr("schema", restarts(1), exited("Completed", 0, ""), crashed)),
			mains(ctr("api", ready(), running(10*time.Minute)))), LevelHealthy, ""},
		// The worst container decides.
		{"one serving, one down", pod(corev1.PodRunning, mains(up30s(), ctr("worker", restarts(1), waiting("CrashLoopBackOff"), crashed))), LevelUnhealthy, ""},
		// A serving loop never hides another container's failure.
		{"beside an image pull failure", pod(corev1.PodRunning, mains(up30s(), ctr("img", waiting("ImagePullBackOff")))), LevelUnhealthy, "ImagePullBackOff"},
		{"beside an OOM kill", pod(corev1.PodRunning, mains(up30s(), ctr("mem", exited("OOMKilled", 137, "")))), LevelUnhealthy, "OOMKilled"},
		{"beside a broken init", pod(corev1.PodRunning, inits(ctr("setup", waiting("CreateContainerConfigError"))), mains(up30s())), LevelUnhealthy, "CreateContainerConfigError"},
		// OOM: over it once ready behind a probe; not when it just came back.
		{"OOM long ago", pod(corev1.PodRunning, probed("api"), mains(ctr("api", ready(), restarts(1), running(20*time.Minute), lastRun("OOMKilled", 137, 30*time.Minute)))), LevelHealthy, ""},
		{"OOM moments ago", pod(corev1.PodRunning, probed("api"), mains(ctr("api", restarts(1), running(30*time.Second), lastRun("OOMKilled", 137, 40*time.Second)))), LevelUnhealthy, "OOMKilled"},
		// An OOM loop keeps its own word.
		{"looping on OOM", pod(corev1.PodRunning, mains(ctr("api", restarts(4), exited("OOMKilled", 137, ""), lastRun("OOMKilled", 137, 0)))), LevelUnhealthy, "OOMKilled"},
		// A native sidecar that is serving counts like a main container; an
		// ordinary init container running with crash history does not serve.
		{"sidecar serving", pod(corev1.PodRunning, sidecarSpec("proxy", false), inits(up30s(named("proxy")))), LevelDegraded, ""},
		{"probed sidecar serving", pod(corev1.PodRunning, sidecarSpec("proxy", true), inits(up30s(named("proxy")))), LevelDegraded, ""},
		{"ordinary init running", pod(corev1.PodRunning, inits(up30s(named("proxy")))), LevelUnhealthy, ""},
	}
	for _, c := range cases {
		v := Pod(c.pod, clock)
		if v.Level != c.level || c.reason != "" && v.Reason != c.reason {
			t.Errorf("%s: %s/%q, want %s/%q", c.why, v.Level, v.Reason, c.level, c.reason)
		}
	}
}

func TestActiveOOMKilledContainers(t *testing.T) {
	p := pod(corev1.PodRunning, probed("settled"),
		mains(
			ctr("killed", exited("OOMKilled", 137, "")),
			ctr("restarting", waiting("CrashLoopBackOff"), lastRun("OOMKilled", 137, 0)),
			ctr("settled", ready(), running(40*time.Minute), lastRun("OOMKilled", 137, 41*time.Minute)),
		),
		// Init containers are left out of this list.
		inits(ctr("init", exited("OOMKilled", 137, ""))),
	)
	var names []string
	for _, cs := range ActiveOOMKilledContainers(p, clock) {
		names = append(names, cs.Name)
	}
	if strings.Join(names, ",") != "killed,restarting" {
		t.Errorf("active = %v", names)
	}
	// ...though they count for the pod.
	initOnly := pod(corev1.PodRunning, inits(ctr("init", restarts(1), running(time.Minute), lastRun("OOMKilled", 137, 0))))
	if !PodHasActiveOOMKilled(initOnly, clock) {
		t.Error("an init container's recent OOM kill was missed")
	}
	doneInit := pod(corev1.PodRunning, inits(ctr("init", exited("Completed", 0, ""), lastRun("OOMKilled", 137, 0))))
	if PodHasActiveOOMKilled(doneInit, clock) {
		t.Error("an init container that finished after its OOM kill still counts")
	}
}

func TestActiveCrashLoopContainerStatuses(t *testing.T) {
	crashed := lastRun("Error", 1, 0)
	p := pod(corev1.PodRunning, probed("flapping"),
		mains(
			ctr("looping", restarts(2), waiting("CrashLoopBackOff"), crashed),
			ctr("flapping", ready(), restarts(2), running(30*time.Second), crashed),
			ctr("settled", restarts(2), running(10*time.Minute), crashed),
			ctr("oom", restarts(2), waiting("CrashLoopBackOff"), lastRun("OOMKilled", 137, 0)),
		),
		inits(
			ctr("init-looping", restarts(1), waiting("CrashLoopBackOff"), crashed),
			ctr("init-done", restarts(1), exited("Completed", 0, ""), crashed),
		),
	)
	var names []string
	for _, cs := range ActiveCrashLoopContainerStatuses(p, clock) {
		names = append(names, cs.Name)
	}
	if strings.Join(names, ",") != "looping,flapping,init-looping" {
		t.Errorf("looping = %v", names)
	}
	if ActiveCrashLoopContainerStatuses(nil, clock) != nil {
		t.Error("nil pod")
	}
}

func TestCrashLoopDiagnosisChoices(t *testing.T) {
	// The container waiting in its loop now is described before one that
	// crashed more recently but is running this moment.
	p := pod(corev1.PodRunning, mains(
		ctr("runner", restarts(2), running(time.Second), lastRun("Error", 139, 20*time.Second)),
		ctr("waiter", restarts(2), waiting("CrashLoopBackOff"), lastRun("Error", 126, 30*time.Second)),
	))
	if cause, _ := PodCrashLoopDiagnosis(p, clock); !strings.Contains(cause, `container "waiter"`) || !strings.Contains(cause, "exit code 126") {
		t.Errorf("cause = %q", cause)
	}
	// Serving again within the settle window: worded as a recovery to watch.
	serving := pod(corev1.PodRunning, mains(ctr("api", ready(), restarts(2), running(time.Minute), lastRun("Error", 1, time.Minute))))
	if cause, action := PodCrashLoopDiagnosis(serving, clock); !strings.Contains(cause, "is serving again") || !strings.HasPrefix(action, "Watch for another restart") {
		t.Errorf("serving = %q / %q", cause, action)
	}
	// Replicas that died a second apart read alike: no durations in the text.
	quick := func(ran time.Duration) *corev1.Pod {
		return pod(corev1.PodRunning, mains(ctr("api", restarts(2), waiting("CrashLoopBackOff"), func(c *corev1.ContainerStatus) {
			c.LastTerminationState = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				Reason: "Error", ExitCode: 139, StartedAt: ago(time.Second + ran), FinishedAt: ago(time.Second)}}
		})))
	}
	a, _ := PodCrashLoopDiagnosis(quick(2*time.Second), clock)
	b, _ := PodCrashLoopDiagnosis(quick(5*time.Second), clock)
	if a == "" || a != b || strings.Contains(a, "2s") {
		t.Errorf("replica wording differs: %q / %q", a, b)
	}
}
