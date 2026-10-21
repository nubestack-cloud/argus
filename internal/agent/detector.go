package agent

// This file implements the first real Detection Controller for the spoke
// agent: a single, cluster-wide detector for Warning-type Kubernetes
// Events, per lld/06-detection-framework.md's scope (this is a deliberate
// subset of it — no RemediationPolicy CRD, no controller-runtime, no
// hub-side dedup/storm-protection/precedence engine; those stay owned by
// that document's fuller design, not reimplemented here). It runs under the
// same read-only argus-investigate RBAC the rest of this agent uses — no
// new verb, no Secret read, no new resource type.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"time"

	"argus/internal/tunnel"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

const (
	// warningEventsDetectorID/Version identify this detector's Findings on
	// the wire (tunnel.Finding.DetectorID/DetectorVersion) — the "only one
	// detector class exists so far" state internal/tunnel/protocol.go's
	// Finding doc comment already describes.
	warningEventsDetectorID      = "k8s-warning-events"
	warningEventsDetectorVersion = "v1"

	// staleEventThreshold is how old a Warning Event's own timestamp may be
	// before this detector stops treating it as a description of something
	// happening NOW.
	//
	// Why this exists (WORKLOG §178): a watch opened with no resourceVersion
	// replays every Event currently in the API server as a synthetic ADDED
	// delivery, and Kubernetes keeps Events for an hour by default. So every
	// agent restart re-reported up to an hour of history as fresh Findings.
	// That was observed doing real damage: a restart re-sent a BackOff finding
	// for a Pod that had already been DELETED, and the hub's ordinary
	// recurrence path reopened a Validating incident on the strength of it. An
	// event about a deleted object cannot be evidence of a current problem.
	// With auto-analysis enabled it would also have spent real money
	// re-investigating an hour of stale events on every restart.
	//
	// 15 minutes, chosen against how a still-live problem actually behaves
	// rather than picked round: an ongoing fault's Event keeps being updated —
	// kubelet's CrashLoopBackOff retry interval is capped at 5 minutes, and
	// FailedMount/FailedScheduling retry faster than that — so a live problem's
	// LastTimestamp is minutes old, never tens of minutes. Well under the 1h
	// event TTL this is protecting against, and comfortably above the slowest
	// legitimate retry.
	//
	// Applied to every delivery, not just the startup replay: the two cases are
	// indistinguishable from inside the watch loop, and the rule is the same
	// either way. It costs live detection nothing, because a genuinely current
	// problem is delivered at the moment its timestamp is bumped. What it can
	// drop is a fault that stopped being re-reported while the agent was down;
	// current state is covered independently by the pod-conditions and sweep
	// detectors, which read the objects themselves rather than the event log.
	staleEventThreshold = 15 * time.Minute

	// defaultFindingResendCooldown bounds how often the *same* fingerprint is
	// resent, when internal/agent.Config.FindingResendCooldown doesn't
	// override it (<= 0). Kubernetes redelivers a MODIFIED watch event every
	// time an Event object's count/lastTimestamp bumps, which would
	// otherwise flood the tunnel with near-duplicate Findings for one
	// ongoing problem. This in-memory, per-fingerprint cooldown is a
	// minimal, honest stand-in for lld/06-detection-framework.md §4's real
	// dedup/storm-protection pipeline (persisted cooldowns, occurrence
	// aggregation, sliding windows) — not a replacement for it, and
	// deliberately not persisted across a process restart.
	//
	// This value (and Config.FindingResendCooldown, its override) is
	// deliberately NOT one of internal/settings' DB-backed, live-editable
	// settings, even though it's exactly the kind of numeric knob that
	// pattern usually covers (see e.g. AnalysisMaxIterations there) — the
	// hub has no way to push a config change to an already-connected agent.
	// internal/tunnel's protocol carries Heartbeat/InventoryDelta/Finding
	// client->server and Ack/Error/ToolRequest server->client; nothing
	// shaped like a config push exists in either direction. So this is
	// instead a real, working, but agent-side, restart-required knob:
	// ARGUS_FINDING_RESEND_COOLDOWN_SECONDS, read once at agent startup by
	// cmd/agent/main.go into this Config field. Shipping it as a hub
	// "live-editable" setting instead — one that silently did nothing until
	// the next agent restart — would be exactly the overclaiming this
	// codebase's honesty norms (see e.g. every "not done, deliberately" note
	// in STATUS.md) exist to avoid. Contrast with
	// internal/gateway/finding.go's detector enable/disable, which DOES have
	// a real, honest, restart-free hub-side mechanism (filtering findings
	// after the fact, not pushing config to the agent).
	defaultFindingResendCooldown = 5 * time.Minute

	// watchRetryBackoff is how long watchWarningEvents waits before
	// retrying after a watch error or channel closure. A plain fixed delay
	// (no jitter/growth) is enough here — this is one agent's own watch
	// loop reconnecting to its own cluster's API server, not the tunnel's
	// thundering-herd-against-a-shared-hub problem that warrants the
	// jittered, growing backoff in client.go.
	watchRetryBackoff = 5 * time.Second
)

// watchWarningEvents is the MVP Detection Controller: it watches every
// Warning-type Kubernetes Event cluster-wide and forwards a deduped
// tunnel.Finding for each to findingCh. Intended to be started once, from
// Run, as its own goroutine — it runs for the lifetime of the agent process
// (retrying its watch on any error) and never blocks or panics when no
// cluster is reachable, matching this package's existing best-effort
// convention (facts.go's GatherFacts). It never knows or cares whether a
// tunnel session currently exists; it only ever writes to findingCh.
//
// A plain watch loop (rather than a client-go SharedInformerFactory) is
// deliberately simpler and sufficient for this MVP's scope; upgrading to an
// informer for relist/resync robustness is a reasonable future improvement,
// not required now.
func watchWarningEvents(ctx context.Context, findingCh chan<- tunnel.Finding, cooldown time.Duration) {
	// Reuses facts.go's newClientset() — the same rest.InClusterConfig(),
	// then-kubeconfig resolution GatherFacts already relies on — rather
	// than duplicating that logic here. newClientset only fails when no
	// config can be resolved or built at all (no in-cluster SA token, no
	// KUBECONFIG, no ~/.kube/config, or a malformed one); it makes no
	// network call, so it can't fail merely because the API server is
	// unreachable or auth is broken — that surfaces later, from Watch()
	// itself, inside the retry loop below.
	clientset, err := newClientset()
	if err != nil {
		logger.Warn("warning-events detector: no reachable cluster config — detector will not start", logging.Err(err))
		warningEventsRunState.recordError(err, time.Now())
		return
	}

	logger.Info("warning-events detector: starting (watching Warning events cluster-wide)")

	// lastSent tracks the last time each fingerprint was actually sent, for
	// the resend-dedup cooldown above. It lives for the lifetime of this
	// goroutine — i.e. across watch retries below, never reset per
	// reconnect — and, deliberately for this MVP, is never pruned: an
	// unbounded map is an accepted, flagged tradeoff for a first real
	// detector's honest-stand-in dedup, not a considered long-term design.
	lastSent := make(map[string]time.Time)

	// resumeVersion is the resourceVersion the next watch attempt resumes from,
	// so a reconnect streams only what CHANGED rather than replaying every Event
	// the API server still holds.
	//
	// This is the root cause of the stale-finding problem staleEventThreshold
	// only narrows (WORKLOG §181): a watch opened with no resourceVersion is
	// answered with the current state of every Event — an hour of them, by
	// default retention — and the agent cannot tell those from live ones. That
	// replayed a BackOff for a deleted Pod eleven minutes after the fact and
	// reopened a healthy incident on the hub.
	//
	// Empty on the first attempt, because there is nothing to resume from yet;
	// the threshold gate covers that initial replay. Reset to empty when the
	// server says the cursor is too old (410 Gone), which is the one case where
	// a full replay is the only option available.
	var resumeVersion string

	for {
		if ctx.Err() != nil {
			return
		}

		next, err := runWarningEventWatch(ctx, clientset, findingCh, lastSent, cooldown, resumeVersion)
		resumeVersion = next
		if err != nil && ctx.Err() == nil {
			logger.Warn("warning-events detector: watch ended — retrying", logging.Err(err), slog.Duration("retry_backoff", watchRetryBackoff))
		}
		recordWarningEventWatchOutcome(ctx, err)

		select {
		case <-ctx.Done():
			return
		case <-time.After(watchRetryBackoff):
		}
	}
}

// recordWarningEventWatchOutcome applies watchWarningEvents' own "a shutdown
// is not a failure" rule (PROJECT.md T13) to whatever runWarningEventWatch
// just returned: err is only ever recorded as this detector's own error when
// it's a genuine failure, never when ctx was the thing that ended the watch.
// Split out from watchWarningEvents' retry loop as its own small, directly
// testable function — that loop itself calls newClientset() unconditionally
// and so cannot be driven with a fake clientset in a test.
func recordWarningEventWatchOutcome(ctx context.Context, err error) {
	if err != nil && ctx.Err() == nil {
		warningEventsRunState.recordError(err, time.Now())
	}
}

// runWarningEventWatch opens one watch.Interface against the core Events
// API cluster-wide and processes deliveries until the watch errors, its
// result channel closes, or ctx is cancelled (in which case it returns
// ctx.Err(), matching client.go's runTunnelSession convention of letting
// the caller distinguish "shutting down" from "a real error worth logging
// before retrying").
func runWarningEventWatch(ctx context.Context, clientset kubernetes.Interface, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration, resumeVersion string) (string, error) {
	opts := metav1.ListOptions{
		ResourceVersion: resumeVersion,
		// Bookmarks advance the cursor during quiet periods, so a watch that
		// sees no Events for a while can still be resumed close to the present
		// instead of falling far enough behind to be expired. Advisory — the
		// server may ignore it — and handleWatchedEvent already skips the
		// bookmark objects themselves.
		AllowWatchBookmarks: true,
	}
	w, err := clientset.CoreV1().Events(metav1.NamespaceAll).Watch(ctx, opts)
	if err != nil {
		// A cursor the server has aged out cannot be retried as-is: every
		// attempt would fail the same way and the detector would spin without
		// ever seeing an event again. Dropping the cursor costs one full replay,
		// which the staleness gate then filters.
		if resumeVersion != "" && isResourceVersionTooOld(err) {
			logger.Warn("warning-events detector: resume point too old for the API server — restarting the watch from the current state",
				slog.String("resume_point", resumeVersion), logging.Err(err))
			return "", fmt.Errorf("resume point expired: %w", err)
		}
		return resumeVersion, fmt.Errorf("start events watch: %w", err)
	}
	defer w.Stop()

	// PROJECT.md T13: a successful Watch() open is concrete proof this
	// detector's RBAC and connectivity are currently working — recorded
	// immediately, not deferred until the first delivery, since a
	// genuinely quiet cluster may not deliver anything for a long time.
	warningEventsRunState.recordSuccess(time.Now())
	heartbeat := time.NewTicker(detectorSuccessHeartbeatInterval)
	defer heartbeat.Stop()

	// Advanced on every delivery, including bookmarks and non-Event objects:
	// the cursor tracks the WATCH's position, not this detector's interest in
	// what arrived, and skipping a Normal event's version would leave the next
	// resume asking for changes it has already been shown.
	current := resumeVersion
	for {
		select {
		case <-ctx.Done():
			return current, ctx.Err()
		case <-heartbeat.C:
			// Re-affirms LastSuccessAt purely from "the watch is still
			// open", independent of delivery volume — see
			// detectorSuccessHeartbeatInterval's own doc comment for why a
			// healthy-but-quiet cluster needs this to avoid looking stale.
			warningEventsRunState.recordSuccess(time.Now())
		case watchEvent, ok := <-w.ResultChan():
			if !ok {
				return current, errors.New("watch channel closed")
			}
			if watchEvent.Type == watch.Error {
				status, isStatus := watchEvent.Object.(*metav1.Status)
				if isStatus {
					if status.Reason == metav1.StatusReasonExpired || status.Reason == metav1.StatusReasonGone {
						logger.Warn("warning-events detector: resume point expired mid-watch — restarting from the current state",
							slog.String("resume_point", current), slog.String("status_message", status.Message))
						return "", fmt.Errorf("watch error event: %s", status.Message)
					}
					return current, fmt.Errorf("watch error event: %s", status.Message)
				}
				return current, fmt.Errorf("watch error event: %v", watchEvent.Object)
			}
			if obj, err := meta.Accessor(watchEvent.Object); err == nil && obj.GetResourceVersion() != "" {
				current = obj.GetResourceVersion()
			}

			kubeEvent, ok := watchEvent.Object.(*corev1.Event)
			if !ok {
				// A Bookmark (or anything else non-Event) carries no
				// Warning/Normal signal to evaluate — nothing to do beyond the
				// cursor advance above.
				continue
			}
			handleWatchedEvent(ctx, clientset, kubeEvent, findingCh, lastSent, cooldown)
		}
	}
}

// isResourceVersionTooOld reports whether err is the API server refusing a
// resume point it has aged out of its watch cache.
//
// Both forms are checked because they are genuinely different responses: a watch
// REQUEST rejected up front surfaces as a 410 Gone (IsGone), while a cursor that
// ages out is reported as Expired. Treating only one of them as "start over"
// leaves the other retrying a cursor that can never work again.
func isResourceVersionTooOld(err error) bool {
	return apierrors.IsResourceExpired(err) || apierrors.IsGone(err)
}

// handleWatchedEvent filters to Warning-type events, applies the
// resend-dedup cooldown, builds a tunnel.Finding, and sends it
// non-blockingly.
func handleWatchedEvent(ctx context.Context, clientset kubernetes.Interface, ev *corev1.Event, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	if ev.Type != corev1.EventTypeWarning {
		return
	}

	now := time.Now()
	// Checked before the fingerprint is computed, so a stale event costs
	// nothing and — importantly — does not touch the resend-cooldown map. A
	// replayed old event must not be able to suppress the real, fresh one that
	// may arrive moments later for the same fingerprint.
	if occurredAt := eventOccurredAt(ev); !occurredAt.IsZero() && now.Sub(occurredAt) > staleEventThreshold {
		return
	}

	fp := computeFingerprint(ev.InvolvedObject.Namespace, ev.InvolvedObject.Kind, ev.InvolvedObject.Name, ev.Reason)

	if !shouldSend(fp, now, lastSent, cooldown) {
		return
	}

	f := buildFinding(ev, fp)
	// Workload resolution happens only after the dedup check above has
	// already decided this Finding is going out — see
	// resolveWorkloadForInvolvedObject's own doc comment for why that keeps
	// the extra API call(s) this costs bounded to the resend-cooldown rate,
	// not the raw event rate.
	workloadGVK, workloadName, podPriority, ok := resolveWorkloadForInvolvedObject(ctx, clientset, ev)
	if ok {
		f.WorkloadGVK = workloadGVK
		f.WorkloadName = workloadName
	}
	// PodPriority is independent of whether a workload was resolved (see
	// resolveWorkloadForInvolvedObject's own doc comment) — a bare Pod with
	// no controller still has its own priority worth carrying.
	f.PodPriority = podPriority

	// What a Pending pod is waiting on (rollout.go podDependencies), so the
	// hub can join this to the incident on a PVC/ConfigMap/Secret it needs.
	if ev.InvolvedObject.Kind == "Pod" {
		if pod, err := clientset.CoreV1().Pods(ev.InvolvedObject.Namespace).Get(ctx, ev.InvolvedObject.Name, metav1.GetOptions{}); err == nil {
			f.References = podDependencies(pod)
			if r, ok := unreadyNode(ctx, clientset, pod); ok {
				f.References = append(f.References, r)
			}
		}
	}
	// An autoscaler that cannot get metrics names the metrics API it needs,
	// when that API is down, so every such autoscaler joins one incident.
	if ev.InvolvedObject.Kind == "HorizontalPodAutoscaler" {
		if r, ok := hpaMetricsAPIService(ctx, clientset, ev.Reason); ok {
			f.References = append(f.References, r)
		}
	}
	// A new pod failing its probe while its workload rolls out is the rollout
	// working: recorded, not promoted (rollout.go, PROJECT.md IN2).
	if duringRollout(ctx, clientset, ev, f.WorkloadGVK, f.WorkloadName, now) {
		f.Impact = tunnel.FindingImpactNone
		f.Message += " (during a rollout still in progress)"
	}

	// PROJECT.md B176: delivered-then-stamped, never the reverse — see
	// sendSweepFinding's own note and finding_queue.go.
	if emitFinding(f, findingCh) {
		lastSent[fp] = now
	}
}

// policyEngineReporters are the components that emit policy-result Warning
// events: Kyverno's background scan and admission controller, and
// Gatekeeper's audit and webhook.
var policyEngineReporters = map[string]bool{
	"kyverno-scan":       true,
	"kyverno-admission":  true,
	"gatekeeper-audit":   true,
	"gatekeeper-webhook": true,
}

// eventReporter is the component that emitted ev, from the events.k8s.io
// field when set and the older source.component otherwise.
func eventReporter(ev *corev1.Event) string {
	if ev.ReportingController != "" {
		return ev.ReportingController
	}
	return ev.Source.Component
}

// shouldSend reports whether fingerprint fp should be (re-)sent at instant
// now, given the last-sent-at times recorded in lastSent and a cooldown
// window. It deliberately does NOT record now into lastSent itself — the
// caller only does that once it has decided to actually proceed, so a dry
// check never mutates state.
func shouldSend(fp string, now time.Time, lastSent map[string]time.Time, cooldown time.Duration) bool {
	last, ok := lastSent[fp]
	if !ok {
		return true
	}
	return now.Sub(last) >= cooldown
}

// computeFingerprint returns a stable, deterministic identifier for "this
// same underlying problem recurring": sha256 hex of namespace +
// involvedObject.Kind + involvedObject.Name + reason, joined with the ASCII
// Unit Separator (0x1F) between fields rather than naive concatenation —
// the same field-boundary-collision fix already applied to this codebase's
// audit hash chain (internal/audit/audit.go's computeHash), so e.g.
// namespace="ab"+kind="c" can never hash identically to namespace="a"+kind
// ="bc" once the rest of the input lines up.
//
// Deliberately excludes the event's message text — message strings vary
// slightly run-to-run for the same underlying problem (embedded counts,
// timestamps), and the point of a fingerprint is grouping "the same issue
// recurring," not "the exact same string twice."
//
// This is a deliberately scoped-down subset of
// lld/06-detection-framework.md §4's fingerprint algorithm, which also
// folds in cluster_fingerprint and detector_id and uses object_uid rather
// than object_name (specifically so Pod-name churn across restarts doesn't
// break the grouping once ownership-chain correlation exists) — acceptable
// for this MVP's single-detector scope: the hub already knows which
// cluster a Finding came from via the mTLS connection identity, and this is
// the only detector emitting Findings at all so far.
func computeFingerprint(namespace, kind, name, reason string) string {
	const unitSeparator = "\x1f"
	h := sha256.New()
	for i, part := range []string{namespace, kind, name, reason} {
		if i > 0 {
			h.Write([]byte(unitSeparator))
		}
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// buildFinding maps a Warning-type corev1.Event onto the wire Finding shape
// (internal/tunnel.Finding), matching lld/06-detection-framework.md §2's
// normalized Signal schema subset that struct implements.

// eventOccurredAt is when this Event last said something happened.
//
// LastTimestamp is what a healthy Event normally sets, but some event sources
// don't always set it — falls back to FirstTimestamp, then to CreationTimestamp
// (always present on any real API object), so the result is never the zero time.
// Can still return the zero time if an Event carries none of the three, which
// is why handleWatchedEvent's staleness gate checks for that explicitly rather
// than trusting this to be non-zero. The first version of that gate did trust
// it, and dropped every event in the existing tests. Failing OPEN on an unknown
// timestamp is the deliberate choice: the gate exists to suppress events that
// can be PROVEN old, and discarding a detector's input on an inference that
// cannot be made is the wrong direction for a system whose job is noticing
// things.
func eventOccurredAt(ev *corev1.Event) time.Time {
	if !ev.LastTimestamp.Time.IsZero() {
		return ev.LastTimestamp.Time
	}
	if !ev.FirstTimestamp.Time.IsZero() {
		return ev.FirstTimestamp.Time
	}
	return ev.CreationTimestamp.Time
}

func buildFinding(ev *corev1.Event, fingerprint string) tunnel.Finding {
	gvk := ev.InvolvedObject.Kind
	if ev.InvolvedObject.APIVersion != "" {
		gvk = ev.InvolvedObject.APIVersion + "/" + ev.InvolvedObject.Kind
	}

	occurredAt := eventOccurredAt(ev)

	f := tunnel.Finding{
		DetectorID:      warningEventsDetectorID,
		DetectorVersion: warningEventsDetectorVersion,
		Fingerprint:     fingerprint,
		GVK:             gvk,
		Namespace:       ev.InvolvedObject.Namespace,
		ObjectName:      ev.InvolvedObject.Name,
		ObjectUID:       string(ev.InvolvedObject.UID),
		ResourceVersion: ev.InvolvedObject.ResourceVersion,
		Reason:          ev.Reason,
		Message:         ev.Message,
		// One Finding is one detector delivery. Kubernetes Event count/series.count
		// are cumulative snapshots; storing each snapshot and later summing them
		// turns counts 10, 11, 12 into 33 occurrences. The investigation event
		// tool still exposes Kubernetes' current cumulative count when needed.
		OccurrenceCount: 1,
		Severity:        severityForEventReason(ev.Reason),
		OccurredAt:      occurredAt,
		Class:           tunnel.FindingClassFault,
		Confidence:      tunnel.FindingConfidenceInferred,
		Impact:          tunnel.FindingImpactDegraded,
	}
	// A policy engine reporting that an object does not meet a policy, from
	// its background scan or from admission in audit mode, where the object
	// is let through. Nothing failed: it is a risk, recorded and not promoted,
	// and the same result reaches the object panel as a PolicyReport. When a
	// policy does block a change, the controller making it reports its own
	// failure (a ReplicaSet's FailedCreate naming the webhook), which stays a
	// fault.
	if policyEngineReporters[eventReporter(ev)] {
		f.Class, f.Impact = tunnel.FindingClassRisk, tunnel.FindingImpactNone
	}
	return f
}

// warningEventSeverity classifies a Warning event's real-world urgency by
// its Reason string — replacing the flat, honestly-flagged-as-fake "medium"
// every Warning event used to get regardless of what actually happened.
// Deliberately a fixed, reviewed table (matching this codebase's core
// safety principle of never letting a model or a guess stand in for a
// reviewed classification) rather than an open-ended heuristic — an
// unrecognized Reason falls through to severityForEventReason's "medium"
// default below, preserving today's exact behavior for anything not
// explicitly named here rather than silently guessing at something new.
// Not lld/06-detection-framework.md's full severity model (confidence
// scoring, policy-driven overrides) — a real, reviewed improvement over a
// single hardcoded value, not a claim of completeness.
var warningEventSeverity = map[string]string{
	// Node/cluster-level — the blast radius is everything scheduled there,
	// not one workload.
	"SystemOOM":    "critical",
	"NodeNotReady": "critical",
	"Rebooted":     "high",

	// A workload that's actively down or being actively killed right now.
	"Evicted":                "high",
	"FailedScheduling":       "high",
	"FailedMount":            "high",
	"FailedAttachVolume":     "high",
	"FailedCreatePodSandBox": "high",
	"NetworkNotReady":        "high",
	"BackOff":                "high", // usually a CrashLoopBackOff-adjacent restart storm

	// Often transient, config-related, or self-healing — worth knowing
	// about, less urgent than the above.
	"Unhealthy":    "medium",
	"FailedCreate": "medium",
	"FailedSync":   "medium",
}

// severityForEventReason returns warningEventSeverity's classification for
// reason, or "medium" — the same default every Warning event got before
// this table existed — for anything not explicitly named above.
func severityForEventReason(reason string) string {
	if s, ok := warningEventSeverity[reason]; ok {
		return s
	}
	return "medium"
}
