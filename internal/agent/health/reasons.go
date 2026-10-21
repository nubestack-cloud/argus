package health

import (
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// The reason tokens this package writes. They are Kubernetes' own words, so
// that grouping downstream holds steady while the kubelet's instantaneous
// state flickers.
const (
	reasonCrashLoop          = "CrashLoopBackOff"
	reasonHighRestart        = "HighRestartCount"
	reasonReadinessProbeFail = "ReadinessProbeFailed"
)

// highRestartThreshold is the restart count above which a container that is
// still unhealthy counts as thrashing.
const highRestartThreshold = 3

const (
	shortCrashRunWindow = 10 * time.Second
	// crashSettleWindow is the kubelet's longest CrashLoopBackOff wait: a
	// container running longer than this has outlived its loop.
	crashSettleWindow  = 5 * time.Minute
	staleCrashStateGap = 2 * crashSettleWindow
)

// isStableCrashLoop reports a container in a crash loop now: it has
// restarted, its last termination was a crash (CrashLoopBackOff, Error, a
// non-zero exit), and it has not recovered since. It reads the history
// fields — RestartCount and LastTerminationState — not the State the
// kubelet flips between polls, so a loop's brief Running moment does not
// soften the verdict. But that history lasts as long as the container does,
// so without the recovery checks a pod that restarted once at start-up would
// read as looping for ever; see recovered. A clean exit now (exit 0, the
// init container that failed once and then finished) is recovery too. A
// passing readiness probe decides how bad it is (podStableCrashLoopLevel),
// not whether it is a loop, which keeps a flapper visible through its
// Ready/Waiting cycle. OOMKilled is not a crash loop here; it has its own
// path (ActiveOOMKilledContainers).
func isStableCrashLoop(cs *corev1.ContainerStatus, now time.Time) bool {
	if cs.RestartCount == 0 || recovered(cs, now) {
		return false
	}
	if t := cs.State.Terminated; t != nil && t.ExitCode == 0 {
		return false
	}
	last := cs.LastTerminationState.Terminated
	switch {
	case last == nil, last.Reason == "OOMKilled":
		return false
	case last.Reason == "CrashLoopBackOff", last.Reason == "Error":
		return true
	}
	// A non-zero exit with no particular reason is a crash all the same.
	return last.ExitCode != 0
}

// recovered reports a running container that has left its crash history
// behind: running for longer than the backoff, or — when its start time is
// unknown — running since a termination longer ago than that, or started so
// long after its last termination that the two cannot be one loop (a node
// back after a long outage).
func recovered(cs *corev1.ContainerStatus, now time.Time) bool {
	run := cs.State.Running
	if run == nil {
		return false
	}
	if !run.StartedAt.IsZero() && now.Sub(run.StartedAt.Time) >= crashSettleWindow {
		return true
	}
	last := cs.LastTerminationState.Terminated
	switch {
	case last == nil || last.FinishedAt.IsZero():
		return false
	case run.StartedAt.IsZero():
		return now.Sub(last.FinishedAt.Time) >= crashSettleWindow
	}
	return run.StartedAt.Sub(last.FinishedAt.Time) > staleCrashStateGap
}

// allStatuses is the main containers' statuses, then the init containers'.
func allStatuses(pod *corev1.Pod) []corev1.ContainerStatus {
	return slices.Concat(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses)
}

// ActiveCrashLoopContainerStatuses is the main and init containers still in a
// crash loop once the recovery checks have been applied.
func ActiveCrashLoopContainerStatuses(pod *corev1.Pod, now time.Time) []corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	var out []corev1.ContainerStatus
	for _, cs := range allStatuses(pod) {
		if isStableCrashLoop(&cs, now) {
			out = append(out, cs)
		}
	}
	return out
}

// podHasStableCrashLoop reports any container in a crash loop.
func podHasStableCrashLoop(pod *corev1.Pod, now time.Time) bool {
	return podStableCrashLoopLevel(pod, now) != ""
}

// IsCrashLoopContainerServing reports a container with crash history that is
// serving anyway: running and Ready, and either a main container or a native
// sidecar.
func IsCrashLoopContainerServing(pod *corev1.Pod, cs corev1.ContainerStatus) bool {
	if pod == nil || cs.State.Running == nil || !cs.Ready {
		return false
	}
	isMain := slices.ContainsFunc(pod.Status.ContainerStatuses, func(m corev1.ContainerStatus) bool { return m.Name == cs.Name })
	return isMain || restartableInitContainer(pod, cs.Name)
}

// podStableCrashLoopLevel is how bad a pod's crash looping is: unhealthy if
// any looping container is not serving, degraded if every looping one still
// serves, "" if none loops.
func podStableCrashLoopLevel(pod *corev1.Pod, now time.Time) Level {
	level := Level("")
	for _, cs := range allStatuses(pod) {
		switch {
		case !isStableCrashLoop(&cs, now):
		case IsCrashLoopContainerServing(pod, cs):
			level = LevelDegraded
		default:
			return LevelUnhealthy
		}
	}
	return level
}

func containerSpec(containers []corev1.Container, name string) *corev1.Container {
	if i := slices.IndexFunc(containers, func(c corev1.Container) bool { return c.Name == name }); i >= 0 {
		return &containers[i]
	}
	return nil
}

func containerHasReadinessProbe(containers []corev1.Container, name string) bool {
	c := containerSpec(containers, name)
	return c != nil && c.ReadinessProbe != nil
}

// restartableInitContainer reports a native sidecar: an init container with
// restartPolicy Always.
func restartableInitContainer(pod *corev1.Pod, name string) bool {
	c := containerSpec(pod.Spec.InitContainers, name)
	return c != nil && c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
}

// restartedRecently reports a last termination within the window: a
// container still churning, not one that crashed long ago and has gone
// quiet (the suspend or node-reboot leftover, a high restart count with
// every termination days old).
func restartedRecently(cs *corev1.ContainerStatus, now time.Time, within time.Duration) bool {
	t := cs.LastTerminationState.Terminated
	return t != nil && !t.FinishedAt.IsZero() && now.Sub(t.FinishedAt.Time) <= within
}

// isActivelyThrashing reports a container with many restarts that is
// unhealthy now and still churning. Not Ready clears the pod that restarted
// a lot at start-up and is now stable (its count never resets); waiting now
// or a recent termination clears the woken node whose restarts are days
// old. The window is the crash loop's, so the two checks agree.
func isActivelyThrashing(cs *corev1.ContainerStatus, now time.Time) bool {
	if cs.RestartCount <= highRestartThreshold || cs.Ready {
		return false
	}
	return cs.State.Waiting != nil || restartedRecently(cs, now, crashSettleWindow)
}

// podActiveThrashContainer reports a main container thrashing. Init
// containers are left out: a failing one already has a specific reason from
// the init walk in podProblemReasonRaw.
func podActiveThrashContainer(pod *corev1.Pod, now time.Time) bool {
	return slices.ContainsFunc(pod.Status.ContainerStatuses, func(cs corev1.ContainerStatus) bool { return isActivelyThrashing(&cs, now) })
}

// containerHasTrustedReady reports a Ready that a readiness probe stands
// behind; without a probe Ready only means running.
func containerHasTrustedReady(containers []corev1.Container, cs corev1.ContainerStatus) bool {
	return cs.Ready && containerHasReadinessProbe(containers, cs.Name)
}

// oomKilled reports a termination by the OOM killer.
func oomKilled(t *corev1.ContainerStateTerminated) bool { return t != nil && t.Reason == "OOMKilled" }

// containerRecentlyRecoveredFromOOM reports a container whose last run was
// OOM-killed and that has not yet shown it is past it: no probed Ready, and
// running for under five minutes, waiting, or terminated within five.
func containerRecentlyRecoveredFromOOM(containers []corev1.Container, cs corev1.ContainerStatus, now time.Time) bool {
	if !oomKilled(cs.LastTerminationState.Terminated) || containerHasTrustedReady(containers, cs) {
		return false
	}
	if r := cs.State.Running; r != nil && !r.StartedAt.IsZero() {
		return now.Sub(r.StartedAt.Time) <= crashSettleWindow
	}
	return cs.State.Waiting != nil || restartedRecently(&cs, now, crashSettleWindow)
}

// ActiveOOMKilledContainers is the main containers an OOM kill affects now:
// killed this moment, or killed last and not yet over it. Init containers are
// left out so callers can match the result to a template's main containers.
func ActiveOOMKilledContainers(pod *corev1.Pod, now time.Time) []corev1.ContainerStatus {
	var out []corev1.ContainerStatus
	for _, cs := range pod.Status.ContainerStatuses {
		if oomKilled(cs.State.Terminated) || containerRecentlyRecoveredFromOOM(pod.Spec.Containers, cs, now) {
			out = append(out, cs)
		}
	}
	return out
}

// PodHasActiveOOMKilled reports any container — init containers and native
// sidecars included — affected now by an OOM kill it has not recovered from.
func PodHasActiveOOMKilled(pod *corev1.Pod, now time.Time) bool {
	return podHasActiveOOMKilled(pod, now)
}

func podHasActiveOOMKilled(pod *corev1.Pod, now time.Time) bool {
	if len(ActiveOOMKilledContainers(pod, now)) > 0 {
		return true
	}
	return slices.ContainsFunc(pod.Status.InitContainerStatuses, func(cs corev1.ContainerStatus) bool {
		switch {
		case oomKilled(cs.State.Terminated):
			return true
		case !oomKilled(cs.LastTerminationState.Terminated):
			return false
		case cs.State.Terminated != nil && cs.State.Terminated.ExitCode == 0:
			// Finished cleanly since.
			return false
		case cs.State.Running != nil && !cs.State.Running.StartedAt.IsZero() && now.Sub(cs.State.Running.StartedAt.Time) > crashSettleWindow:
			// Running steadily since.
			return false
		}
		return true
	})
}

// PodHasReadinessProbeFailure reports a running pod that has been not Ready
// for longer than the grace period with a probed container still failing.
func PodHasReadinessProbeFailure(pod *corev1.Pod, now time.Time) bool {
	return podHasReadinessProbeFailure(pod, now)
}

func podHasReadinessProbeFailure(pod *corev1.Pod, now time.Time) bool {
	if pod.Status.Phase != corev1.PodRunning || !podReadyFalseLongEnough(pod, now, crashSettleWindow) {
		return false
	}
	return slices.ContainsFunc(pod.Status.ContainerStatuses, func(cs corev1.ContainerStatus) bool {
		return !cs.Ready && cs.State.Running != nil && containerHasReadinessProbe(pod.Spec.Containers, cs.Name)
	})
}

// podReadyFalseLongEnough reports the first of the Ready and ContainersReady
// conditions that is False having been so for at least minAge, judged by its
// transition time, else the pod's age, else taken as long enough.
func podReadyFalseLongEnough(pod *corev1.Pod, now time.Time, minAge time.Duration) bool {
	i := slices.IndexFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return (c.Type == corev1.PodReady || c.Type == corev1.ContainersReady) && c.Status == corev1.ConditionFalse
	})
	if i < 0 {
		return false
	}
	switch since := pod.Status.Conditions[i].LastTransitionTime; {
	case !since.IsZero():
		return now.Sub(since.Time) >= minAge
	case !pod.CreationTimestamp.IsZero():
		return now.Sub(pod.CreationTimestamp.Time) >= minAge
	}
	return true
}

// fatalWaitingReasons are waiting reasons that will not clear by themselves,
// unlike PodInitializing and ContainerCreating: a bad image name never
// becomes good, and the *ContainerError family means the container could not
// be created or started at all.
var fatalWaitingReasons = set("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "InvalidImageName",
	"ImageInspectError", "CreateContainerConfigError", "CreateContainerError", "RunContainerError")

func isFatalWaitingReason(reason string) bool { return fatalWaitingReasons[reason] }

// phaseOrCrashReasons are the reasons a stable crash loop may replace: a bare
// phase or no-op waiting state (the values that flicker), or a crash reason
// already (so one canonical word is used). Anything more specific —
// ImagePullBackOff, OOMKilled — stays.
var phaseOrCrashReasons = set("Running", "Pending", "Succeeded", "Failed", "Unknown", "",
	"PodInitializing", "ContainerCreating", "CrashLoopBackOff", "Error")

func isPhaseOrCrashReason(reason string) bool { return phaseOrCrashReasons[reason] }

// phaseOnlyReasons are the narrower set HighRestartCount may replace: bare
// phases and no-op waiting states only — never a crash reason or a terminal
// phase, which the crash-loop check owns.
var phaseOnlyReasons = set("Running", "Pending", "Unknown", "", "PodInitializing", "ContainerCreating")

func isPhaseOnlyReason(reason string) bool { return phaseOnlyReasons[reason] }

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// StuckTerminatingThreshold is how long a pod may have a deletionTimestamp
// before its termination counts as stuck — wedged on a finalizer or an
// ungraceful node drain — rather than a graceful shutdown.
const StuckTerminatingThreshold = 10 * time.Minute

// IsStuckTerminating reports a pod terminating for longer than
// StuckTerminatingThreshold. Pod ignores deletionTimestamp; PodDisplayLevel
// folds this in, so a wedged pod does not read healthy.
func IsStuckTerminating(pod *corev1.Pod, now time.Time) bool {
	return pod.DeletionTimestamp != nil && now.Sub(pod.DeletionTimestamp.Time) > StuckTerminatingThreshold
}

// IsPodUnschedulable reports that the scheduler tried and failed to place the
// pod: PodScheduled=False with reason Unschedulable. SchedulingGated is held
// back on purpose and is not a failure.
func IsPodUnschedulable(pod *corev1.Pod) bool {
	i := slices.IndexFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool { return c.Type == corev1.PodScheduled })
	return i >= 0 && pod.Status.Conditions[i].Status == corev1.ConditionFalse && pod.Status.Conditions[i].Reason == corev1.PodReasonUnschedulable
}
