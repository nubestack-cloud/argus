package health

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// pendingGrace is how long a pod may sit Pending before that is a problem.
const pendingGrace = 5 * time.Minute

// Pod grades a pod. Failure checks come before every benign one — a benign
// answer must never be reached ahead of a failure — in this order:
//
//	Succeeded                  neutral   (finished; lifecycle, not a problem)
//	Failed                     unhealthy
//	Unknown phase              unknown   (node unreachable; its reports are stale)
//	crash loop, not serving    unhealthy
//	fatal wait, active OOM     unhealthy
//	crash loop, still serving  degraded
//	Pending                    degraded past five minutes, healthy before
//	readiness probe failing    degraded
//	thrashing                  degraded
//	run by a Job               neutral   (batch work under way; no all-clear)
//	otherwise                  healthy
//
// Unschedulable and stuck terminating are left out: they are signals of
// their own (IsPodUnschedulable, IsStuckTerminating) that counters may want
// separately. PodDisplayLevel folds them in for a single status per pod.
func Pod(pod *corev1.Pod, now time.Time) Verdict {
	v := Verdict{Level: classifyPodLevel(pod, now)}
	switch v.Level {
	case LevelDegraded, LevelUnhealthy:
		v.Reason, v.Message = PodProblemReason(pod, now), PodProblemMessage(pod)
	case LevelNeutral:
		if pod.Status.Phase == corev1.PodSucceeded {
			v.Reason = "Completed"
		}
	}
	return v
}

// PodDisplayLevel is the level for surfaces that show one status per pod
// (the relationship map, tool summaries). It adds what Pod leaves out —
// failing to schedule, stuck terminating — as a floor: at least degraded, so
// such a pod never reads healthy, and never less than Pod said (a
// crash-looping pod being deleted stays unhealthy).
func PodDisplayLevel(pod *corev1.Pod, now time.Time) Level {
	level := Pod(pod, now).Level
	if IsPodUnschedulable(pod) || IsStuckTerminating(pod, now) {
		level = WorseOf(level, LevelDegraded)
	}
	return level
}

func classifyPodLevel(pod *corev1.Pod, now time.Time) Level {
	switch pod.Status.Phase {
	case corev1.PodSucceeded:
		return LevelNeutral
	case corev1.PodFailed:
		return LevelUnhealthy
	case corev1.PodUnknown:
		// The node is unreachable and the kubelet has stopped reporting, so
		// the container states are stale. Falling through would paint a pod
		// on a lost node green.
		return LevelUnknown
	}
	// The crash history keeps a loop visible through the kubelet's
	// Waiting/Running flicker; the current state decides how urgent it is. A
	// loop that is still serving is only degraded, and must not hide a fatal
	// state on some other container, so it is weighed after them.
	loop := podStableCrashLoopLevel(pod, now)
	fatal := slices.ContainsFunc(allStatuses(pod), func(cs corev1.ContainerStatus) bool {
		return cs.State.Waiting != nil && isFatalWaitingReason(cs.State.Waiting.Reason)
	})
	switch {
	case loop == LevelUnhealthy, fatal, podHasActiveOOMKilled(pod, now):
		return LevelUnhealthy
	case loop == LevelDegraded:
		return LevelDegraded
	case pod.Status.Phase == corev1.PodPending:
		if now.Sub(pod.CreationTimestamp.Time) > pendingGrace {
			return LevelDegraded
		}
		return LevelHealthy
	case podHasReadinessProbeFailure(pod, now):
		return LevelDegraded
	// Many restarts alone also fire on a pod that crashed at start-up and has
	// been Ready for hours (restart counts never reset), and on a node whose
	// restarts are leftovers from a suspend or reboot; thrashing requires
	// not Ready and still churning.
	case podActiveThrashContainer(pod, now):
		return LevelDegraded
	// Batch work under way is not "healthy". The Job itself already reads
	// neutral while it runs (jobVerdict); without this its pods would each
	// read healthy, and one stuck at 1/2 ready because its sidecar outlived
	// the main container would be an all-clear — the claim most worth not
	// making. It is last, so a Job pod that is failing keeps its failure.
	// From the pod only the owner reference is visible, not the Job's
	// status, so the claim is "batch work" (neutral), not an impairment.
	case isOwnedByJob(pod):
		return LevelNeutral
	}
	return LevelHealthy
}

// isOwnedByJob reports a pod a batch/v1 Job created; the group is checked so
// a custom resource that happens to be called Job does not count.
func isOwnedByJob(pod *corev1.Pod) bool {
	return slices.ContainsFunc(pod.OwnerReferences, func(r metav1.OwnerReference) bool {
		return r.Kind == "Job" && strings.HasPrefix(r.APIVersion, "batch/")
	})
}

// PodProblemReason is a short reason token for a pod with a problem. Init
// containers are read first: while one fails the pod stays Pending and the
// main containers have no statuses yet, so without them the reason would be
// just "Pending", hiding the init container's CrashLoopBackOff or
// ImagePullBackOff. now is the clock the pod was graded with, so the reason
// is reproducible.
func PodProblemReason(pod *corev1.Pod, now time.Time) string {
	reason := podProblemReasonRaw(pod, now)
	switch {
	// A looping container flickers between Waiting("CrashLoopBackOff"),
	// Running and Terminated from one poll to the next; on a Running tick the
	// walk gives back a bare phase. When the history says it is a loop, the
	// canonical word holds steady through the whole cycle — unless the walk
	// found something more specific (ImagePullBackOff, OOMKilled, an init
	// failure), which wins.
	case podHasStableCrashLoop(pod, now) && isPhaseOrCrashReason(reason):
		return reasonCrashLoop
	case podHasActiveOOMKilled(pod, now) && isPhaseOnlyReason(reason):
		return "OOMKilled"
	// Churning on failed readiness probes with clean exits is not a classic
	// crash loop, and the walk would name only a phase; HighRestartCount
	// names it, and replaces nothing more specific.
	case podActiveThrashContainer(pod, now) && isPhaseOnlyReason(reason):
		return reasonHighRestart
	}
	return reason
}

// podProblemReasonRaw walks for a reason: a container's own (init first),
// then the pod-level signals, then the phase.
//
// A container that exited 0 is passed over at first: a finished init
// container did its job, and naming its "Completed" as the problem calls a
// success the fault, hides the container that failed after it, and falls
// into the catch-all category with nothing to act on. A pod whose
// containers all succeeded is still described by them, below.
func podProblemReasonRaw(pod *corev1.Pod, now time.Time) string {
	if cs := problemContainer(pod, true); cs != nil {
		return containerStateReason(cs)
	}
	// Pod-level signals outrank a container that only finished, so a
	// completed init container cannot hide a readiness failure.
	if podHasReadinessProbeFailure(pod, now) {
		return reasonReadinessProbeFail
	}
	switch pod.Status.Phase {
	case corev1.PodFailed:
		// Never described by a container that succeeded: for Evicted,
		// DeadlineExceeded, Shutdown and NodeAffinity the kubelet puts the
		// cause on the pod, while the containers it stopped exited cleanly.
		return cmp.Or(pod.Status.Reason, string(corev1.PodFailed))
	case corev1.PodSucceeded:
		if cs := problemContainer(pod, false); cs != nil {
			return containerStateReason(cs)
		}
	}
	// Still running, the phase is the true answer — and phase-like, so the
	// crash-loop, OOM and thrash replacements above can still apply, which
	// "Completed" would have silenced.
	return string(pod.Status.Phase)
}

// problemContainer is the one container status that explains the pod, so
// the reason and the message always come from the same container: the first
// (init containers first) waiting or terminated with a reason, passing over
// a clean exit when skipSucceeded is set.
func problemContainer(pod *corev1.Pod, skipSucceeded bool) *corev1.ContainerStatus {
	for _, statuses := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses} {
		for i := range statuses {
			st := statuses[i].State
			switch {
			case st.Waiting != nil && st.Waiting.Reason != "":
				return &statuses[i]
			case st.Terminated != nil && st.Terminated.Reason != "" && !(skipSucceeded && st.Terminated.ExitCode == 0):
				return &statuses[i]
			}
		}
	}
	return nil
}

func containerStateReason(cs *corev1.ContainerStatus) string {
	switch {
	case cs.State.Waiting != nil:
		return cs.State.Waiting.Reason
	case cs.State.Terminated != nil:
		return cs.State.Terminated.Reason
	}
	return ""
}

func containerStateMessage(cs *corev1.ContainerStatus) string {
	switch {
	case cs.State.Waiting != nil:
		return cs.State.Waiting.Message
	case cs.State.Terminated != nil:
		return cs.State.Terminated.Message
	}
	return ""
}

// PodProblemMessage is the kubelet's own message behind the reason — an
// ImagePullBackOff's "Failed to pull image …: not found", a
// CreateContainerConfigError's "couldn't find key … in Secret …" — taken from
// exactly the container (or pod) the reason came from, so a chatty container
// that merely finished never explains another's failure. A failing container
// with no message gives none rather than borrowing one.
func PodProblemMessage(pod *corev1.Pod) string {
	if cs := problemContainer(pod, true); cs != nil {
		return containerStateMessage(cs)
	}
	// Gated as podProblemReasonRaw's fallback is: a running pod's reason
	// came from readiness or the phase, so a finished container's message
	// would be some other container's.
	switch pod.Status.Phase {
	case corev1.PodFailed:
		return pod.Status.Message
	case corev1.PodSucceeded:
		if cs := problemContainer(pod, false); cs != nil {
			return containerStateMessage(cs)
		}
	}
	return ""
}

// PodRestartContext is what crash triage starts from: restarts across main
// and init containers, and the kubelet's reason for the most recent
// termination (OOMKilled, Error, Completed…) — chronic or acute, and memory
// analysis or previous logs next.
func PodRestartContext(pod *corev1.Pod) (restartCount int32, lastTerminatedReason string) {
	var newest time.Time
	for _, cs := range allStatuses(pod) {
		restartCount += cs.RestartCount
		if t := cs.LastTerminationState.Terminated; t != nil && !t.FinishedAt.IsZero() && t.FinishedAt.After(newest) {
			newest, lastTerminatedReason = t.FinishedAt.Time, t.Reason
		}
	}
	return restartCount, lastTerminatedReason
}

// exitMeaning is what some exit codes say about a crash, and what to check.
var exitMeaning = map[int32]struct{ says, check string }{
	126: {"command found but not executable", "the executable's permissions, its shebang or interpreter, and the pod command/args"},
	127: {"command not found", "the image entrypoint and the pod command/args, and that the binary exists in the image"},
	137: {"killed (SIGKILL), though Kubernetes did not report OOMKilled", "node pressure, a SIGKILL from inside, and the memory limit"},
	139: {"segmentation fault", "previous container logs and recent image or code changes, and native libraries or unsafe code"},
}

// PodCrashLoopDiagnosis is a plain cause and next step for the pod's crash
// loop, or "" for both when there is nothing to act on: no loop, an OOM kill
// (which has its own path), or a clean exit.
func PodCrashLoopDiagnosis(pod *corev1.Pod, now time.Time) (cause, action string) {
	c, ok := activeCrashLoopCandidate(pod, now)
	if !ok {
		return "", ""
	}
	t := c.status.LastTerminationState.Terminated
	if t == nil || t.ExitCode == 0 || t.Reason == "OOMKilled" {
		return "", ""
	}
	who := fmt.Sprintf("container %q", c.status.Name)
	if c.init {
		who = "init " + who
	}
	exit := fmt.Sprintf("exit code %d", t.ExitCode)
	check := "previous container logs, and the pod command, args, config and dependencies"
	if m, known := exitMeaning[t.ExitCode]; known {
		exit += " (" + m.says + ")"
		check = m.check
	}
	short := shortRunContext(t)
	if IsCrashLoopContainerServing(pod, c.status) {
		return fmt.Sprintf("%s restarted after %s and is serving again, within the 5-minute settle window.%s", who, exit, short),
			"Watch for another restart; if it comes, check " + check + "."
	}
	return fmt.Sprintf("%s is crash-looping on %s.%s", who, exit, short), "Check " + check + "."
}

type crashLoopCandidate struct {
	status     corev1.ContainerStatus
	init       bool
	index      int
	stateRank  int
	finishedAt time.Time
}

// activeCrashLoopCandidate is the looping container the diagnosis describes:
// one waiting now before one terminated before one running, then the most
// recent termination, an init container before a main one, then by name and
// position.
func activeCrashLoopCandidate(pod *corev1.Pod, now time.Time) (crashLoopCandidate, bool) {
	var all []crashLoopCandidate
	for _, list := range []struct {
		init     bool
		statuses []corev1.ContainerStatus
	}{{true, pod.Status.InitContainerStatuses}, {false, pod.Status.ContainerStatuses}} {
		for i, cs := range list.statuses {
			if !isStableCrashLoop(&cs, now) {
				continue
			}
			c := crashLoopCandidate{status: cs, init: list.init, index: i, stateRank: crashLoopStateRank(cs)}
			if t := cs.LastTerminationState.Terminated; t != nil {
				c.finishedAt = t.FinishedAt.Time
			}
			all = append(all, c)
		}
	}
	if len(all) == 0 {
		return crashLoopCandidate{}, false
	}
	return slices.MinFunc(all, func(a, b crashLoopCandidate) int {
		if betterCrashLoopCandidate(a, b) {
			return -1
		}
		if betterCrashLoopCandidate(b, a) {
			return 1
		}
		return 0
	}), true
}

func crashLoopStateRank(cs corev1.ContainerStatus) int {
	switch {
	case cs.State.Waiting != nil:
		return 0
	case cs.State.Terminated != nil:
		return 1
	case cs.State.Running != nil:
		return 2
	}
	return 3
}

// betterCrashLoopCandidate reports whether a should be described before b.
func betterCrashLoopCandidate(a, b crashLoopCandidate) bool {
	initFirst := func(c crashLoopCandidate) int {
		if c.init {
			return 0
		}
		return 1
	}
	return cmp.Or(
		cmp.Compare(a.stateRank, b.stateRank),
		b.finishedAt.Compare(a.finishedAt),
		cmp.Compare(initFirst(a), initFirst(b)),
		strings.Compare(a.status.Name, b.status.Name),
		cmp.Compare(a.index, b.index),
	) < 0
}

// shortRunContext adds that a container died within seconds of starting —
// the same words whatever the exact run, so replicas match.
func shortRunContext(t *corev1.ContainerStateTerminated) string {
	if t == nil || t.StartedAt.IsZero() || t.FinishedAt.IsZero() {
		return ""
	}
	if ran := t.FinishedAt.Sub(t.StartedAt.Time); ran > 0 && ran < shortCrashRunWindow {
		return " It exited within seconds of starting."
	}
	return ""
}
