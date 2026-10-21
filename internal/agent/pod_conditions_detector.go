package agent

// This file implements the spoke agent's second real Detection Controller:
// it watches Pod *status* directly, rather than relying solely on
// Warning-type Kubernetes Events (detector.go's first detector). Some real
// problems are more reliably visible from a Pod's own status than from a
// still-fresh matching Warning Event by the time anyone looks — a Pod stuck
// in CrashLoopBackOff/ImagePullBackOff, or OOMKilled, may not have one. Runs
// under the same read-only argus-investigate RBAC as every other detector
// in this package — no new verb, no Secret read, no new resource type
// (Pods are already get/list/watch-able).
//
// Same deliberate scope-down as detector.go: no RemediationPolicy CRD, no
// controller-runtime, no hub-side dedup/storm-protection/precedence engine
// — those stay owned by lld/06-detection-framework.md's fuller design, not
// reimplemented here.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"time"

	"argus/internal/tunnel"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

const (
	// podConditionsDetectorID/Version identify this detector's Findings on
	// the wire (tunnel.Finding.DetectorID/DetectorVersion), distinct from
	// detector.go's warningEventsDetectorID/Version.
	podConditionsDetectorID      = "k8s-pod-conditions"
	podConditionsDetectorVersion = "v1"

	// podPendingTimeoutThreshold is how long a Pod may sit in phase Pending
	// (measured from its CreationTimestamp) before this detector reports it
	// as stuck, reason "PendingTimeout" — catches unschedulable/stuck
	// pending Pods that may never emit a fresh Warning Event either. A
	// named constant per this task's own instruction, not a magic number
	// inline; 5 minutes is a judgment call, not a spec'd value — revisit if
	// it proves too chatty or too slow in practice.
	podPendingTimeoutThreshold = 5 * time.Minute

	// The specific waiting/terminated reasons this detector reacts to.
	// Deliberately NOT an exhaustive enumeration of every possible
	// waiting/terminated reason Kubernetes can report — only the ones this
	// task named as mattering here.
	reasonCrashLoopBackOff = "CrashLoopBackOff"
	reasonImagePullBackOff = "ImagePullBackOff"
	reasonErrImagePull     = "ErrImagePull"
	reasonOOMKilled        = "OOMKilled"
	reasonPendingTimeout   = "PendingTimeout"
)

// watchPodConditions is the second Detection Controller: it watches every
// Pod cluster-wide and forwards a deduped tunnel.Finding for each
// newly-eligible condition to findingCh. Same overall shape as
// watchWarningEvents (detector.go): intended to be started once, from Run,
// as its own goroutine; only starts if a live cluster config resolves at
// all (reuses facts.go's newClientset() — the same helper
// watchWarningEvents already uses, not a third copy of that resolution
// logic); retries its own watch loop on any error via watchRetryBackoff
// (detector.go's constant, reused rather than redefined — this is the same
// kind of "one agent's own watch loop reconnecting to its own cluster's API
// server" backoff detector.go's doc comment already reasons about), fully
// independent of the tunnel's connect state; never blocks or panics when no
// cluster is reachable.
func watchPodConditions(ctx context.Context, findingCh chan<- tunnel.Finding, cooldown time.Duration) {
	clientset, err := newClientset()
	if err != nil {
		logger.Warn("pod-conditions detector: no reachable cluster config — detector will not start", logging.Err(err))
		podConditionsRunState.recordError(err, time.Now())
		return
	}

	logger.Info("pod-conditions detector: starting (watching Pod status cluster-wide)")

	// lastSent is this detector's own resend-dedup cooldown map — same
	// findingResendCooldown window and shouldSend/"caller records the send,
	// not the check" convention detector.go's warning-events detector uses.
	// Kept as its own map (not shared with that detector) since the two
	// detectors' fingerprint inputs are computed over different identity
	// shapes (event-object-derived vs. pod-derived) and a shared map would
	// only ever save a little memory at the cost of coupling two otherwise
	// independent goroutines through mutable shared state.
	lastSent := make(map[string]time.Time)

	for {
		if ctx.Err() != nil {
			return
		}

		err := runPodConditionsWatch(ctx, clientset, findingCh, lastSent, cooldown)
		if err != nil && ctx.Err() == nil {
			logger.Warn("pod-conditions detector: watch ended — retrying", logging.Err(err), slog.Duration("retry_backoff", watchRetryBackoff))
		}
		recordPodConditionsWatchOutcome(ctx, err)

		select {
		case <-ctx.Done():
			return
		case <-time.After(watchRetryBackoff):
		}
	}
}

// recordPodConditionsWatchOutcome is watchPodConditions' own analogue of
// detector.go's recordWarningEventWatchOutcome, for the identical reason:
// watchPodConditions calls newClientset() unconditionally, so it can't be
// driven with a fake clientset in a test — this is the small, directly
// testable piece of it that actually decides whether an outcome was a real
// failure worth recording (PROJECT.md T13) or just ctx-driven shutdown.
func recordPodConditionsWatchOutcome(ctx context.Context, err error) {
	if err != nil && ctx.Err() == nil {
		podConditionsRunState.recordError(err, time.Now())
	}
}

// runPodConditionsWatch opens one watch.Interface against the core Pods API
// cluster-wide and processes deliveries until the watch errors, its result
// channel closes, or ctx is cancelled — matching
// runWarningEventWatch's (detector.go) exact shape and its convention of
// returning ctx.Err() on cancellation so the caller can distinguish
// "shutting down" from "a real error worth logging before retrying".
func runPodConditionsWatch(ctx context.Context, clientset kubernetes.Interface, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) error {
	w, err := clientset.CoreV1().Pods(metav1.NamespaceAll).Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("start pods watch: %w", err)
	}
	defer w.Stop()

	// PROJECT.md T13: same reasoning as runWarningEventWatch's identical
	// pair of calls (detector.go) — a successful Watch() open is recorded
	// immediately, and a heartbeat ticker keeps re-affirming it while the
	// watch stays open with nothing to deliver, so a healthy-but-quiet
	// cluster doesn't look stale next to a genuinely unobserved one.
	podConditionsRunState.recordSuccess(time.Now())
	heartbeat := time.NewTicker(detectorSuccessHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			podConditionsRunState.recordSuccess(time.Now())
		case watchEvent, ok := <-w.ResultChan():
			if !ok {
				return errors.New("watch channel closed")
			}
			if watchEvent.Type == watch.Error {
				if status, ok := watchEvent.Object.(*metav1.Status); ok {
					return fmt.Errorf("watch error event: %s", status.Message)
				}
				return fmt.Errorf("watch error event: %v", watchEvent.Object)
			}

			// DELETED carries no live status worth evaluating — a Pod
			// disappearing isn't itself one of this detector's conditions,
			// and whatever it was doing while alive would already have been
			// reported by an earlier ADDED/MODIFIED delivery. Bookmarks (and
			// anything else that isn't a Pod) fall through the type
			// assertion below and are skipped the same way detector.go
			// skips non-Event objects.
			if watchEvent.Type != watch.Added && watchEvent.Type != watch.Modified {
				continue
			}

			pod, ok := watchEvent.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			handleWatchedPod(ctx, clientset, pod, time.Now(), findingCh, lastSent, cooldown)
		}
	}
}

// handleWatchedPod inspects one watched Pod's status for every condition
// this detector cares about and sends a (deduped) tunnel.Finding for each
// one currently true. now is threaded through explicitly (rather than each
// check calling time.Now() independently) so a single call sees one
// consistent instant, and so tests can drive the Pending-timeout threshold
// deterministically.
//
// Both InitContainerStatuses and ContainerStatuses are inspected — an init
// container stuck in CrashLoopBackOff/ImagePullBackOff blocks the whole Pod
// from ever starting its real containers, which is at least as worth
// surfacing as the same condition in a regular container, and the check
// logic is identical for both.
func handleWatchedPod(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod, now time.Time, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	// Resolved once per Pod (not once per condition below) — the owning
	// workload doesn't vary across this Pod's own container statuses, and
	// this is the one place in this detector allowed to pay for the extra
	// ReplicaSet GET (see resolveWorkloadFromOwnerRefs), rather than
	// repeating it per condition.
	workloadGVK, workloadName, _ := resolveWorkloadFromOwnerRefs(ctx, clientset, pod.Namespace, pod.GetOwnerReferences())
	for _, cs := range pod.Status.InitContainerStatuses {
		checkContainerStatus(pod, cs, now, workloadGVK, workloadName, findingCh, lastSent, cooldown)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		checkContainerStatus(pod, cs, now, workloadGVK, workloadName, findingCh, lastSent, cooldown)
	}
	checkPendingTimeout(pod, now, workloadGVK, workloadName, findingCh, lastSent, cooldown)
}

// checkContainerStatus evaluates one container's current state: a Waiting
// state with one of the three watched reasons, or a Terminated state whose
// reason is OOMKilled. At most one of Waiting/Running/Terminated is ever
// set on a corev1.ContainerState, so these are checked as alternatives, not
// both.
func checkContainerStatus(pod *corev1.Pod, cs corev1.ContainerStatus, now time.Time, workloadGVK, workloadName string, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	if waiting := cs.State.Waiting; waiting != nil {
		switch waiting.Reason {
		case reasonCrashLoopBackOff, reasonImagePullBackOff, reasonErrImagePull:
			message := fmt.Sprintf("container %q is waiting: %s", cs.Name, waiting.Reason)
			if waiting.Message != "" {
				message = fmt.Sprintf("%s (%s)", message, waiting.Message)
			}
			sendPodFinding(pod, waiting.Reason, message, severityForReason(waiting.Reason), containerConditionTimestamp(cs, now), now, workloadGVK, workloadName, findingCh, lastSent, cooldown)
		}
		return
	}

	if terminated := cs.State.Terminated; terminated != nil && terminated.Reason == reasonOOMKilled {
		message := fmt.Sprintf("container %q was OOMKilled (exit code %d)", cs.Name, terminated.ExitCode)
		sendPodFinding(pod, reasonOOMKilled, message, severityForReason(reasonOOMKilled), containerConditionTimestamp(cs, now), now, workloadGVK, workloadName, findingCh, lastSent, cooldown)
	}
}

// containerConditionTimestamp returns the best available timestamp for
// "when did this container's currently-reported condition start", per this
// task's own instruction: a watch delivery doesn't always carry a clean
// "when did this specific condition start" timestamp the way an Event
// object's LastTimestamp does (corev1.ContainerStateWaiting in particular
// has no timestamp field at all). Preference order: the CURRENT
// Terminated state's own FinishedAt (set directly when a container is
// terminated right now, e.g. this call's own OOMKilled case) if present;
// else LastTerminationState's FinishedAt (the most recent previous
// crash/exit this container status remembers — often the most informative
// timestamp available for a Waiting/CrashLoopBackOff container, since that
// state itself carries no timestamp); else now, the same last-resort
// fallback detector.go's buildFinding effectively uses when even
// CreationTimestamp is unavailable.
func containerConditionTimestamp(cs corev1.ContainerStatus, now time.Time) time.Time {
	if cs.State.Terminated != nil && !cs.State.Terminated.FinishedAt.IsZero() {
		return cs.State.Terminated.FinishedAt.Time
	}
	if cs.LastTerminationState.Terminated != nil && !cs.LastTerminationState.Terminated.FinishedAt.IsZero() {
		return cs.LastTerminationState.Terminated.FinishedAt.Time
	}
	return now
}

// checkPendingTimeout reports a Pod that has sat in phase Pending for
// longer than podPendingTimeoutThreshold, measured from its own
// CreationTimestamp (always set on any real API object, unlike an Event's
// LastTimestamp/FirstTimestamp which detector.go has to fall back through).
func checkPendingTimeout(pod *corev1.Pod, now time.Time, workloadGVK, workloadName string, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	if pod.Status.Phase != corev1.PodPending {
		return
	}
	if pod.CreationTimestamp.IsZero() {
		return
	}

	pendingFor := now.Sub(pod.CreationTimestamp.Time)
	if pendingFor < podPendingTimeoutThreshold {
		return
	}

	message := fmt.Sprintf("pod has been Pending for %s (created at %s)", pendingFor.Round(time.Second), pod.CreationTimestamp.Time.Format(time.RFC3339))
	sendPodFinding(pod, reasonPendingTimeout, message, severityForReason(reasonPendingTimeout), now, now, workloadGVK, workloadName, findingCh, lastSent, cooldown)
}

// severityForReason implements this detector's stated severity heuristic —
// a simple, stated rule, NOT lld/06-detection-framework.md's real severity
// classification, which doesn't exist in code anywhere in this codebase yet
// (matching detector.go's own honesty about its hardcoded "medium" for
// every Warning event). OOMKilled and CrashLoopBackOff get "high" because
// they usually mean something is actively broken right now; ImagePullBackOff
// /ErrImagePull/PendingTimeout get "medium" because they're often transient
// or config issues (a registry hiccup, a not-yet-applied image pull secret,
// a cluster that's mid-autoscale) and less urgent.
func severityForReason(reason string) string {
	switch reason {
	case reasonOOMKilled, reasonCrashLoopBackOff:
		return "high"
	default:
		return "medium"
	}
}

// buildPodFinding maps one detected Pod condition onto the wire Finding
// shape (internal/tunnel.Finding), matching lld/06-detection-framework.md
// §2's normalized Signal schema subset that struct implements — the same
// contract detector.go's buildFinding targets, just populated from a Pod
// object instead of an Event object. GVK is always the literal "v1/Pod"
// (pods are always core/v1, unlike detector.go's generic Warning-event
// detector which has to read involvedObject.APIVersion dynamically, since
// the involved object there can be any kind).
func buildPodFinding(pod *corev1.Pod, reason, message, severity string, occurredAt time.Time, fingerprint, workloadGVK, workloadName string) tunnel.Finding {
	return tunnel.Finding{
		DetectorID:      podConditionsDetectorID,
		DetectorVersion: podConditionsDetectorVersion,
		Fingerprint:     fingerprint,
		GVK:             "v1/Pod",
		Namespace:       pod.Namespace,
		ObjectName:      pod.Name,
		ObjectUID:       string(pod.UID),
		ResourceVersion: pod.ResourceVersion,
		Reason:          reason,
		Message:         message,
		// Cumulative counting across resends is a hub-side correlation
		// concern (the parallel task's job, per detector.go's identical
		// reasoning), not this detector's — each Finding this detector
		// emits represents one detected occurrence.
		OccurrenceCount: 1,
		Severity:        severity,
		OccurredAt:      occurredAt,
		Class:           tunnel.FindingClassFault,
		Confidence:      tunnel.FindingConfidenceVerified,
		Impact:          tunnel.FindingImpactDegraded,
		WorkloadGVK:     workloadGVK,
		WorkloadName:    workloadName,
		// PodPriority: this function already has the full Pod object in
		// hand — see tunnel.Finding.PodPriority's own doc comment for the
		// absent-vs-zero contract pod.Spec.Priority itself already carries.
		PodPriority: pod.Spec.Priority,
		// What a Pending pod is waiting on (rollout.go podDependencies).
		References: podDependencies(pod),
	}
}

// sendPodFinding computes this Pod condition's fingerprint, applies the
// resend-dedup cooldown, and sends the resulting Finding non-blockingly —
// identical shape to detector.go's handleWatchedEvent, just split into its
// own function since this detector has multiple call sites (container
// waiting/terminated states, plus the Pending-timeout check) that all need
// the same fingerprint/cooldown/send sequence.
//
// Fingerprint: sha256(namespace + 0x1F + "Pod" + 0x1F + podName + 0x1F +
// reason) — reuses detector.go's computeFingerprint verbatim with the kind
// argument hardcoded to the literal "Pod" (matching this task's specified
// algorithm shape exactly), rather than a second copy of the same hashing
// logic. This detector's identity is pod-based (namespace/name/reason), not
// involvedObject-based, but the delimiter-joined-sha256 shape — and its
// same documented limitation versus lld/06-detection-framework.md §4's
// fuller algorithm (object_uid instead of object_name, cluster_fingerprint/
// detector_id folded in) — is identical to detector.go's own fingerprint,
// for the same reasons detector.go's computeFingerprint doc comment already
// gives.
func sendPodFinding(pod *corev1.Pod, reason, message, severity string, occurredAt, now time.Time, workloadGVK, workloadName string, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	fp := computeFingerprint(pod.Namespace, "Pod", pod.Name, reason)

	if !shouldSend(fp, now, lastSent, cooldown) {
		return
	}

	f := buildPodFinding(pod, reason, message, severity, occurredAt, fp, workloadGVK, workloadName)

	// PROJECT.md B176: delivered-then-stamped, never the reverse — see
	// sendSweepFinding's own note and finding_queue.go.
	if emitFinding(f, findingCh) {
		lastSent[fp] = now
	}
}
