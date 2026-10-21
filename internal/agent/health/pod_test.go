package health

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var clock = time.Date(2026, 9, 14, 9, 30, 0, 0, time.UTC)

func ago(d time.Duration) metav1.Time { return metav1.NewTime(clock.Add(-d)) }

// Container status options.
type csOpt func(*corev1.ContainerStatus)

func ready() csOpt           { return func(c *corev1.ContainerStatus) { c.Ready = true } }
func restarts(n int32) csOpt { return func(c *corev1.ContainerStatus) { c.RestartCount = n } }
func waiting(reason string) csOpt {
	return func(c *corev1.ContainerStatus) {
		c.State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}
	}
}
func running(since time.Duration) csOpt {
	return func(c *corev1.ContainerStatus) {
		c.State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: ago(since)}}
	}
}
func exited(reason string, code int32, message string) csOpt {
	return func(c *corev1.ContainerStatus) {
		c.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code, Message: message}}
	}
}

// lastRun sets the previous termination; finished 0 leaves its time unset.
func lastRun(reason string, code int32, finished time.Duration) csOpt {
	return func(c *corev1.ContainerStatus) {
		t := &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code}
		if finished > 0 {
			t.FinishedAt = ago(finished)
		}
		c.LastTerminationState = corev1.ContainerState{Terminated: t}
	}
}

func ctr(name string, opts ...csOpt) corev1.ContainerStatus {
	c := corev1.ContainerStatus{Name: name}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Pod options.
type podOpt func(*corev1.Pod)

func mains(cs ...corev1.ContainerStatus) podOpt {
	return func(p *corev1.Pod) { p.Status.ContainerStatuses = cs }
}
func inits(cs ...corev1.ContainerStatus) podOpt {
	return func(p *corev1.Pod) { p.Status.InitContainerStatuses = cs }
}
func created(d time.Duration) podOpt { return func(p *corev1.Pod) { p.CreationTimestamp = ago(d) } }
func ownedBy(kind, apiVersion string) podOpt {
	return func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, APIVersion: apiVersion, Name: "owner"}}
	}
}

// probed declares a readiness probe on the named main container.
func probed(name string) podOpt {
	return func(p *corev1.Pod) {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: name, ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready"}}}})
	}
}
func notReadyFor(d time.Duration) podOpt {
	return func(p *corev1.Pod) {
		p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionFalse, LastTransitionTime: ago(d)})
	}
}
func podReason(reason, message string) podOpt {
	return func(p *corev1.Pod) { p.Status.Reason, p.Status.Message = reason, message }
}

func pod(phase corev1.PodPhase, opts ...podOpt) *corev1.Pod {
	p := &corev1.Pod{Status: corev1.PodStatus{Phase: phase}}
	for _, o := range opts {
		o(p)
	}
	return p
}

func TestPodGrades(t *testing.T) {
	cases := []struct {
		why    string
		pod    *corev1.Pod
		level  Level
		reason string // checked when set
	}{
		{"running and ready", pod(corev1.PodRunning, mains(ctr("api", ready(), running(time.Hour)))), LevelHealthy, ""},
		{"finished", pod(corev1.PodSucceeded), LevelNeutral, "Completed"},
		{"failed", pod(corev1.PodFailed), LevelUnhealthy, ""},
		// The node is gone and its reports are stale.
		{"phase Unknown", pod(corev1.PodUnknown), LevelUnknown, ""},
		{"waiting in CrashLoopBackOff", pod(corev1.PodRunning, mains(ctr("api", waiting("CrashLoopBackOff")))), LevelUnhealthy, "CrashLoopBackOff"},
		{"OOM-killed now", pod(corev1.PodRunning, mains(ctr("api", exited("OOMKilled", 137, "")))), LevelUnhealthy, "OOMKilled"},
		// Killed once, and ready behind a probe since: over it.
		{"OOM-killed once, recovered", pod(corev1.PodRunning, probed("api"), mains(ctr("api", ready(), running(time.Hour), lastRun("OOMKilled", 137, time.Hour)))), LevelHealthy, ""},
		{"init container cannot pull", pod(corev1.PodPending, created(20*time.Minute), inits(ctr("fetch", waiting("ImagePullBackOff")))), LevelUnhealthy, "ImagePullBackOff"},
		{"pending past the grace period", pod(corev1.PodPending, created(20*time.Minute)), LevelDegraded, "Pending"},
		{"pending, just created", pod(corev1.PodPending, created(time.Minute)), LevelHealthy, ""},
		{"readiness failing for a while", pod(corev1.PodRunning, created(time.Hour), probed("api"), notReadyFor(20*time.Minute),
			mains(ctr("api", running(time.Hour)))), LevelDegraded, "ReadinessProbeFailed"},
		{"readiness failing just now", pod(corev1.PodRunning, created(2*time.Minute), probed("api"), notReadyFor(time.Minute),
			mains(ctr("api", running(2*time.Minute)))), LevelHealthy, ""},
		// Restart counts never reset; ready and stable is fine.
		{"many old restarts, ready", pod(corev1.PodRunning, mains(ctr("api", ready(), restarts(40), running(6*time.Hour)))), LevelHealthy, ""},
		// Churning on clean exits without settling: thrashing.
		{"thrashing on clean exits", pod(corev1.PodRunning, mains(ctr("api", restarts(812), running(20*time.Minute), lastRun("Completed", 0, 45*time.Second)))), LevelDegraded, "HighRestartCount"},
		// The same counts, but every restart days old: a suspend leftover.
		{"restarts days old", pod(corev1.PodRunning, mains(ctr("api", restarts(812), running(70*time.Hour), lastRun("Completed", 0, 70*time.Hour)))), LevelHealthy, ""},
		// Batch work under way is not an all-clear...
		{"a Job's pod", pod(corev1.PodRunning, ownedBy("Job", "batch/v1"), mains(ctr("export", ready(), running(time.Minute)))), LevelNeutral, ""},
		// ...but a failing Job pod keeps its failure...
		{"a Job's pod crash-looping", pod(corev1.PodRunning, ownedBy("Job", "batch/v1"), mains(ctr("export", restarts(5), waiting("CrashLoopBackOff")))), LevelUnhealthy, "CrashLoopBackOff"},
		// ...and only batch/v1 Jobs count.
		{"a custom Job's pod", pod(corev1.PodRunning, ownedBy("Job", "jobs.example.org/v1"), mains(ctr("export", ready(), running(time.Minute)))), LevelHealthy, ""},
		// The pod reason explains an eviction; the containers stopped cleanly.
		{"evicted", pod(corev1.PodFailed, podReason("Evicted", "The node was low on resource: memory."), mains(ctr("api", exited("Completed", 0, "")))), LevelUnhealthy, "Evicted"},
	}
	for _, c := range cases {
		v := Pod(c.pod, clock)
		if v.Level != c.level || c.reason != "" && v.Reason != c.reason {
			t.Errorf("%s: %s/%q, want %s/%q", c.why, v.Level, v.Reason, c.level, c.reason)
		}
	}
}

// A non-serving loop stays unhealthy and named while the kubelet flips its
// state from one poll to the next.
func TestCrashLoopHoldsThroughTheCycle(t *testing.T) {
	for _, state := range []csOpt{waiting("CrashLoopBackOff"), running(0), exited("Error", 1, ""), waiting("CrashLoopBackOff")} {
		p := pod(corev1.PodRunning, mains(ctr("worker", restarts(9), state, lastRun("Error", 1, 0))))
		if v := Pod(p, clock); v.Level != LevelUnhealthy || v.Reason != "CrashLoopBackOff" {
			t.Errorf("%+v: %s/%q", p.Status.ContainerStatuses[0].State, v.Level, v.Reason)
		}
	}
}

// The reason and the message always come from the same container — or the
// pod itself — and a container that only succeeded is never the problem.
func TestPodProblemReasonAndMessage(t *testing.T) {
	setup := ctr("setup", exited("Completed", 0, "setup wrote 4 files"))
	cases := []struct {
		why             string
		pod             *corev1.Pod
		reason, message string
	}{
		{"a failing init container blocks the pod", pod(corev1.PodPending, inits(ctr("schema", waiting("CrashLoopBackOff")))), "CrashLoopBackOff", ""},
		{"nothing but the phase", pod(corev1.PodPending), "Pending", ""},
		// A specific reason is not replaced by the crash-loop word.
		{"pulling, with crash history", pod(corev1.PodRunning, mains(ctr("api", restarts(2), waiting("ImagePullBackOff"), lastRun("Error", 1, 0)))), "ImagePullBackOff", ""},
		{"a successful init container is passed over", pod(corev1.PodFailed, inits(setup), mains(ctr("app", exited("Error", 1, "join failed")))), "Error", "join failed"},
		{"the failed one of two init containers", pod(corev1.PodPending, inits(ctr("ok", exited("Completed", 0, "")), ctr("migrate", exited("Error", 2, "migration 12 failed")))), "Error", "migration 12 failed"},
		{"all succeeded", pod(corev1.PodSucceeded, mains(ctr("job", exited("Completed", 0, "wrote 120 rows")))), "Completed", "wrote 120 rows"},
		// A pod-level signal outranks a container that merely finished, and
		// the finished container lends it no message.
		{"readiness behind a finished init container", pod(corev1.PodRunning, probed("app"), notReadyFor(20*time.Minute), inits(setup),
			mains(ctr("app", running(20*time.Minute)))), "ReadinessProbeFailed", ""},
		// A running pod is its phase, which the crash, OOM and thrash words
		// can still replace; "Completed" would silence them.
		{"running after a finished init container", pod(corev1.PodRunning, inits(setup), mains(ctr("app", running(time.Minute)))), "Running", ""},
		// The failing container has no message, so there is none.
		{"no borrowing from a sibling", pod(corev1.PodFailed, inits(setup),
			mains(ctr("app", exited("Error", 1, "")), ctr("sidecar", exited("Completed", 0, "sidecar shut down cleanly")))), "Error", ""},
		{"evicted", pod(corev1.PodFailed, podReason("Evicted", "The node was low on resource: ephemeral-storage."), mains(ctr("app", exited("Completed", 0, "")))),
			"Evicted", "The node was low on resource: ephemeral-storage."},
		{"failed with no pod reason", pod(corev1.PodFailed, mains(ctr("app", exited("Completed", 0, "")))), "Failed", ""},
		// A container that really failed is more specific than the pod.
		{"a failed container beats the pod reason", pod(corev1.PodFailed, podReason("Evicted", ""), mains(ctr("app", exited("OOMKilled", 137, "container was OOM killed")))),
			"OOMKilled", "container was OOM killed"},
	}
	for _, c := range cases {
		if r, m := PodProblemReason(c.pod, clock), PodProblemMessage(c.pod); r != c.reason || m != c.message {
			t.Errorf("%s: %q / %q, want %q / %q", c.why, r, m, c.reason, c.message)
		}
	}
}

func TestPodCrashLoopDiagnosis(t *testing.T) {
	shortRun := func(code int32) csOpt {
		return func(c *corev1.ContainerStatus) {
			c.LastTerminationState = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				Reason: "Error", ExitCode: code, StartedAt: ago(4 * time.Second), FinishedAt: ago(2 * time.Second)}}
		}
	}
	cause, action := PodCrashLoopDiagnosis(pod(corev1.PodRunning, mains(ctr("api", restarts(3), running(time.Second), shortRun(127)))), clock)
	for _, want := range []string{`container "api"`, "exit code 127 (command not found)", "within seconds"} {
		if !strings.Contains(cause, want) {
			t.Errorf("cause %q lacks %q", cause, want)
		}
	}
	if !strings.Contains(action, "command/args") {
		t.Errorf("action = %q", action)
	}
	// An init container is named as one; an unlisted code gets the general
	// advice.
	cause, action = PodCrashLoopDiagnosis(pod(corev1.PodPending, inits(ctr("schema", restarts(3), waiting("CrashLoopBackOff"), lastRun("Error", 3, time.Minute)))), clock)
	if !strings.HasPrefix(cause, `init container "schema" is crash-looping on exit code 3.`) || !strings.Contains(action, "previous container logs") {
		t.Errorf("init = %q / %q", cause, action)
	}
	// Nothing to diagnose: no loop, an OOM kill (its own path), a clean exit.
	for _, p := range []*corev1.Pod{
		pod(corev1.PodRunning, mains(ctr("api", ready(), running(time.Hour)))),
		pod(corev1.PodRunning, mains(ctr("api", restarts(3), waiting("CrashLoopBackOff"), lastRun("OOMKilled", 137, time.Minute)))),
	} {
		if c, a := PodCrashLoopDiagnosis(p, clock); c != "" || a != "" {
			t.Errorf("%+v diagnosed %q %q", p.Status, c, a)
		}
	}
}
