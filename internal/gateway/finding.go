package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	"argus/internal/audit"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/fleetgroup"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/objectgroup"
	"argus/internal/orchestrator"
	"argus/internal/replicagroup"
	"argus/internal/settings"
	"argus/internal/timeline"
	"argus/internal/tunnel"
)

// objectCorrelationKey is the identity of the THING a Finding is about:
// gvk|namespace|object_name. Must match migration 000036's backfill expression
// exactly, since that migration and this function both write the same column.
//
// Returns "" when the Finding names no object. That is not an error and not a
// key — it is the signal to fall back to fingerprint-only correlation, because
// grouping every object-less finding on a cluster under one degenerate key
// would merge genuinely unrelated problems into a single incident, which is a
// worse failure than the duplication this whole mechanism exists to reduce.
func objectCorrelationKey(f *tunnel.Finding) string {
	if strings.TrimSpace(f.ObjectName) == "" {
		return ""
	}
	return f.GVK + "|" + f.Namespace + "|" + f.ObjectName
}

// workloadCorrelationKey is the identity of the WORKLOAD that owns a Pod a
// Finding is about — gvk|namespace|name of the Deployment/StatefulSet/
// DaemonSet/ReplicaSet/Job the agent resolved via its own OwnerReferences
// walk (internal/agent/workload.go), mirroring objectCorrelationKey's exact
// split: the agent supplies raw identity (f.WorkloadGVK/f.WorkloadName), the
// hub joins it into one display/grouping key. See BACKLOG.md's A3 entry and
// migration 000042 for why this exists — replica-level correlation, the
// residual duplication object-level correlation (migration 000036) does not
// and should not fix (each pod stays its own incident; this only groups
// siblings for display, via internal/replicagroup).
//
// Returns "" when the agent didn't resolve a workload (a bare Pod with no
// controller, or a Finding that isn't about a Pod at all) — not an error,
// the correct state for the large majority of Findings this doesn't apply to.
func workloadCorrelationKey(f *tunnel.Finding) string {
	if strings.TrimSpace(f.WorkloadName) == "" {
		return ""
	}
	return f.WorkloadGVK + "|" + f.Namespace + "|" + f.WorkloadName
}

// relatedWorkloadCorrelationKey is workloadCorrelationKey's BACKLOG.md A3b
// counterpart: the identity of a workload this Finding's OWN object is not
// part of, but is causally linked to via a reference the agent resolved
// itself — a Service's selector matched against the Pods it targets, or a
// PersistentVolumeClaim matched against the Pod(s) that mount it (see
// internal/agent/objectref.go). Same agent-supplies-raw-identity/
// hub-joins-the-key split as workloadCorrelationKey and objectCorrelationKey
// before it.
//
// Deliberately NEVER fed into correlationIdentity below — that would make it
// a fourth MERGE tier, silently folding a PVC's or a Service's own incident
// into the workload's, which A3b's design brief explicitly rules out (see
// migration 000070's header and internal/objectgroup's package doc for the
// full argument). This key only ever reaches incidents.related_workload_key,
// a plain, un-merged column internal/objectgroup.Recompute reads for DISPLAY
// grouping, and it is intentionally computed and stored ONLY here, never
// compared against for the "which incident does this Finding attach to"
// decision.
//
// Returns "" when the agent didn't resolve a related workload — not an
// error, the correct state for the large majority of Findings (everything
// except a PVC/Service sweep candidate whose reference resolved to a Pod
// with a real owner).
func relatedWorkloadCorrelationKey(f *tunnel.Finding) string {
	if strings.TrimSpace(f.RelatedWorkloadName) == "" {
		return ""
	}
	return f.RelatedWorkloadGVK + "|" + f.Namespace + "|" + f.RelatedWorkloadName
}

// workloadRolloutHealthReasons is the closed, reviewed set of Reason
// spellings an OBJECT-tier Finding — one about a Deployment/StatefulSet/
// DaemonSet/ReplicaSet/Job ITSELF, never about a Pod (see
// workloadCorrelationKey's own doc comment for why such a Finding never
// resolves WorkloadName: it IS the workload, not something owned by one) —
// can carry when it is reporting that THE WORKLOAD'S OWN replica/rollout
// signal is unhealthy, as distinct from literally anything else an
// object-tier Finding can be about: a declarative rule (default-rules.yaml),
// a dangling reference, a stuck finalizer, an observed-generation lag, a
// peer-condition-shape outlier (generic_predicates.go), or a future check
// nobody has written yet.
//
// This is BUGS.md 132's answer to "what counts as the same reason" for the
// object<->workload correlation bridge in handleFinding below. Two things
// make it a bounded, principled family rather than a guess:
//
//  1. The three GenericConditionAnomaly entries are restricted to EXACTLY
//     the three condition types k8s.io/api/apps/v1's DeploymentConditionType
//     defines (Available, Progressing, ReplicaFailure) — not copied here as
//     an import (that would pull the whole agent package, client-go
//     included, into the hub's gateway package for one enum), but a closed
//     set from Kubernetes' own API, not an open-ended one this codebase
//     invented. GenericConditionAnomaly itself
//     (internal/agent/generic_predicates.go) is kind-agnostic and fires for
//     ANY condition type on ANY watched kind — a Node's MemoryPressure, a
//     CRD's Ready, anything. Only these three name a workload's OWN rollout
//     status, because the Deployment controller defines them for exactly
//     that purpose. GenericConditionAnomaly:DiskPressure on a Node is
//     deliberately excluded: a real anomaly, just not one a crash-looping
//     pod could plausibly explain.
//  2. The other three — {Deployment,StatefulSet,DaemonSet}ReplicasUnavailable
//     — are internal/agent/sweep_detector.go's own hand-written checkers for
//     the identical fact (fewer ready replicas than desired), for the two
//     kinds whose controllers don't reliably populate a timestamped
//     Available-style condition to drive GenericConditionAnomaly instead
//     (see checkStatefulSetReplicas/checkDaemonSetReplicas's own doc
//     comments on why). Same signal, different plumbing — same family.
//
// Deliberately says nothing about the PAIRING with any specific pod-side
// reason (BackOff, OOMKilled, ImagePullBackOff, ...) — see the "workload"
// case of the bridge below for why that side is intentionally
// unrestricted. This table only grows if Kubernetes adds a fourth
// top-level workload condition type, or this codebase adds a fourth
// hand-written per-kind ReplicasUnavailable checker — never per new fault
// or per new kind of unrelated object-tier check, which is what would make
// this the enumeration-that-grows-per-issue CLAUDE.md/HANDOFF.md's standing
// principle warns against.
var workloadRolloutHealthReasons = map[string]bool{
	"DeploymentReplicasUnavailable":          true, // sweep_detector.go: checkDeploymentReplicas
	"StatefulSetReplicasUnavailable":         true, // sweep_detector.go: checkStatefulSetReplicas
	"DaemonSetReplicasUnavailable":           true, // sweep_detector.go: checkDaemonSetReplicas
	"GenericConditionAnomaly:Available":      true,
	"GenericConditionAnomaly:Progressing":    true,
	"GenericConditionAnomaly:ReplicaFailure": true,
	// The same two facts from the other producers of them: the rule engine's
	// *-rollout-stalled rules (internal/agent/rules/default-rules.yaml, the
	// controller's own Progressing/updated-replica status) and the sweep's
	// ReplicaFailure checkers (a ReplicaSet that cannot create pods). Without
	// them a StatefulSet whose pods could not pull opened a second incident
	// beside its pods' one (loop campaign 2026-10-13, S10).
	"DeploymentRolloutStalled":  true,
	"StatefulSetRolloutStalled": true,
	"DaemonSetRolloutStalled":   true,
	"DeploymentReplicaFailure":  true,
	"ReplicaSetReplicaFailure":  true,
}

// workloadRolloutHealthReasonList is workloadRolloutHealthReasons' keys as a
// slice, computed once — the shape pgx needs to bind a Postgres `= ANY($n)`
// array parameter, which a Go map cannot be passed as directly.
var workloadRolloutHealthReasonList = func() []string {
	out := make([]string, 0, len(workloadRolloutHealthReasons))
	for reason := range workloadRolloutHealthReasons {
		out = append(out, reason)
	}
	return out
}()

// reasonIndicatesWorkloadRolloutHealth reports whether reason is in
// workloadRolloutHealthReasons — pulled out as its own named predicate so
// the object-tier half of the correlation bridge in handleFinding reads as
// a check against the same table the workload-tier half queries with
// `= ANY(...)`, rather than one inline map lookup and one unrelated-looking
// SQL literal.
func reasonIndicatesWorkloadRolloutHealth(reason string) bool {
	return workloadRolloutHealthReasons[reason]
}

// correlationIdentity is the set of keys one Finding can be correlated by, and
// the tier order between them.
//
// Extracted from handleFinding for one specific reason: the advisory lock and
// the lookup MUST agree on which tier is in play. If the lock is taken on the
// object while the lookup queries the workload, two concurrent first-time
// findings for two pods of one workload take different locks, both see no rows,
// and both insert — the exact race the lock exists to prevent, reintroduced
// silently and only under concurrency. Keeping both decisions in one type with
// one switch, and testing them together, is what stops that drifting apart.
type correlationIdentity struct {
	clusterID   string
	workloadKey string
	objectKey   string
	fingerprint string
}

// tier names which key this Finding correlates by, most specific first.
//
// Workload beats object because a workload-level incident already covers this
// pod (see handleFinding's own comment on why pod-level incidents multiply
// without bound). Object beats fingerprint because a fingerprint includes the
// symptom, so one broken object produces several — the measured reason behind
// migration 000036.
func (c correlationIdentity) tier() string {
	switch {
	case c.workloadKey != "":
		return "workload"
	case c.objectKey != "":
		return "object"
	default:
		return "fingerprint"
	}
}

// lockKey serializes "look up -> update, or not found -> insert" across every
// concurrent caller sharing this correlation identity. Tier-prefixed so a
// workload key can never collide with an object key that happens to be the same
// string.
func (c correlationIdentity) lockKey() string {
	switch c.tier() {
	case "workload":
		return c.clusterID + ":wl:" + c.workloadKey
	case "object":
		return c.clusterID + ":obj:" + c.objectKey
	default:
		return c.clusterID + ":" + c.fingerprint
	}
}

// find locates the open incident this Finding belongs to, or returns
// pgx.ErrNoRows when there is none and one should be opened.
//
// Separate queries rather than one with an OR, because each tier must not
// accidentally match on another's key: an incident opened before migration
// 000036's backfill could otherwise be matched by the wrong key and collect
// findings for a different object.
//
// A tier that finds nothing does NOT fall through to the next one. For the
// workload tier that is the whole point: a pod whose workload has no open
// incident yet must open one, and trying object_key next could only match an
// incident for this exact pod — which, if it existed, would itself have a
// workload_key and have been found by the first query.
func (c correlationIdentity) find(ctx context.Context, tx pgx.Tx, id *string, lastSeen *time.Time, state, severity *string) error {
	switch c.tier() {
	case "workload":
		return tx.QueryRow(ctx,
			`SELECT id, last_seen, state, severity FROM incidents
			   WHERE cluster_id = $1 AND workload_key = $2 AND state NOT IN ('Resolved', 'Dismissed')
			   ORDER BY last_seen DESC
			   LIMIT 1`,
			c.clusterID, c.workloadKey).Scan(id, lastSeen, state, severity)
	case "object":
		return tx.QueryRow(ctx,
			`SELECT id, last_seen, state, severity FROM incidents
			   WHERE cluster_id = $1 AND object_key = $2 AND state NOT IN ('Resolved', 'Dismissed')
			   ORDER BY last_seen DESC
			   LIMIT 1`,
			c.clusterID, c.objectKey).Scan(id, lastSeen, state, severity)
	default:
		return tx.QueryRow(ctx,
			`SELECT id, last_seen, state, severity FROM incidents
			   WHERE cluster_id = $1 AND fingerprint = $2 AND object_key IS NULL AND state NOT IN ('Resolved', 'Dismissed')
			   ORDER BY last_seen DESC
			   LIMIT 1`,
			c.clusterID, c.fingerprint).Scan(id, lastSeen, state, severity)
	}
}

// reopenAfterRecurrence moves a Validating incident to Reopened because its
// symptom came back. Split out of handleFinding so the "is this Finding even
// about the post-fix world?" decision above it reads as one choice between two
// outcomes rather than as a bare `break` out of an enclosing switch.
//
// Writes a timeline_events row on the successful transition, in the SAME tx
// as the SetState call above — BACKLOG.md E6's noted gap: this is the
// event-driven half of Validating -> Reopened, and until now it was the only
// one of the two Reopened paths that left no timeline trace.
// orchestrator.ValidationSweeper's own delayed, no-news-is-good-news half
// (internal/orchestrator/validation.go) already records
// timeline.EventValidationOutcome when IT promotes a Validating incident to
// Reopened; this reuses the same event type rather than minting a second one,
// since both are the identical domain fact — a Validating incident found not
// to have actually held — differing only in which mechanism noticed.
func reopenAfterRecurrence(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, objectKey string, f *tunnel.Finding) error {
	err := orchestrator.SetState(ctx, tx, incidentID, orchestrator.StateReopened)
	switch {
	case err == nil:
		// Any symptom on the object reopens it, not only the exact
		// fingerprint that was fixed — which is more correct than the
		// old behaviour: a fault that returns wearing a different
		// reason used to open a brand-new incident and orphan the
		// recurrence from the fix that was supposed to have worked.
		logger.WarnContext(ctx, "incident reopened: its symptom recurred while it was Validating",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID),
			slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type: timeline.EventValidationOutcome,
			Summary: fmt.Sprintf("%s recurred while Validating: %s (object=%s, detector=%s)",
				f.Reason, f.Message, objectKey, f.DetectorID),
			Detail: map[string]any{
				"outcome":     orchestrator.StateReopened,
				"route":       "eventDriven",
				"fingerprint": f.Fingerprint,
				"detectorId":  f.DetectorID,
				"objectKey":   objectKey,
				"reason":      f.Reason,
				"message":     f.Message,
			},
		}); err != nil {
			return fmt.Errorf("record ValidationOutcome timeline event for incident %s: %w", incidentID, err)
		}
		return nil
	case errors.Is(err, orchestrator.ErrIllegalTransition):
		// The state read by the caller was taken before this transaction
		// locked the incident row, so it can be one moment stale:
		// orchestrator.ValidationSweeper may have promoted this
		// incident Validating -> Resolved (terminal) in between, and
		// SetState — which re-reads under a row lock — will now
		// correctly refuse. Logged and carried on rather than
		// returned: the finding itself must still be recorded (the
		// insert in handleFinding), and failing that whole handler would drop
		// an arriving Finding on the floor over a lost race about a
		// state label. A recurrence after Resolved opens a brand-new
		// incident on the next Finding anyway, since the correlation
		// query treats Resolved as closed.
		logger.WarnContext(ctx, "incident was Validating a moment ago but could not be reopened; recording the finding regardless",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID),
			slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason), logging.Err(err))
		return nil
	default:
		return fmt.Errorf("reopen incident %s: %w", incidentID, err)
	}
}

// reopenExpiredIncident is PROJECT.md T2's recurrence path: a Finding
// re-attached (correlationIdentity.find deliberately does not exclude
// StateExpired from its own NOT IN ('Resolved', 'Dismissed') predicates —
// see StateExpired's own doc comment) to an incident that had aged out.
// Moves it to StateDetected, not StateReopened: nothing was ever fixed here,
// so "the fix did not hold" would be a false claim about history this
// incident never had. Mirrors reopenAfterRecurrence's own shape (SetState,
// fail-open on a lost race, log either way) for the identical reasons.
func reopenExpiredIncident(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, objectKey string, f *tunnel.Finding) error {
	err := orchestrator.SetState(ctx, tx, incidentID, orchestrator.StateDetected)
	switch {
	case err == nil:
		logger.WarnContext(ctx, "incident recurred after expiry and was moved back to Detected",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID),
			slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type: timeline.EventIncidentRecurredAfterExpiry,
			Summary: fmt.Sprintf("Recurred after expiry: %s (object=%s, detector=%s)",
				f.Message, objectKey, f.DetectorID),
			Detail: map[string]any{
				"outcome":     orchestrator.StateDetected,
				"fingerprint": f.Fingerprint,
				"detectorId":  f.DetectorID,
				"objectKey":   objectKey,
				"reason":      f.Reason,
				"message":     f.Message,
			},
		}); err != nil {
			return fmt.Errorf("record IncidentRecurredAfterExpiry timeline event for incident %s: %w", incidentID, err)
		}
		return nil
	case errors.Is(err, orchestrator.ErrIllegalTransition):
		// Same lost-race shape reopenAfterRecurrence's own comment
		// describes: the state this caller read can be one moment stale.
		// Logged and carried on — the Finding itself must still be
		// recorded regardless of who currently owns this incident's state.
		logger.WarnContext(ctx, "incident was Expired a moment ago but could not be moved back to Detected; recording the finding regardless",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID),
			slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason), logging.Err(err))
		return nil
	default:
		return fmt.Errorf("reopen expired incident %s: %w", incidentID, err)
	}
}

// rollSettleWindow is how long after a successful fix a Finding may still be
// describing the pods the fix REPLACED, rather than a recurrence.
//
// A pod-template change rolls the workload, and the old pod does not vanish at
// the instant the patch is accepted: it is sent SIGTERM and gets
// terminationGracePeriodSeconds (30 by default) to exit, and it keeps producing
// events the whole time. The measured case (WORKLOG §181) was one second: a fix
// executed at 19:52:16 and the old pod's final BackOff event was stamped
// 19:52:17. A strict "occurred after the execution" test does not catch that —
// the first version of this guard used one, and would not have prevented the
// false reopen it was written for.
//
// 60 seconds: twice the default termination grace period, so it covers a pod
// taking its full allowance plus scheduling slack, and short enough to stay far
// inside the validation grace period that backs it up (see the safety argument
// on staleEvidenceForReopen).
//
// Applied ONLY to objects this incident was already reporting before the fix —
// see objectSeenBeforeFix. A replacement pod that fails immediately is real
// evidence, and an unqualified time window swallows it.
const rollSettleWindow = 60 * time.Second

// promptDeliveryWindow is how long after a Finding OCCURRED it can still be
// treated as evidence of the CURRENT state of a cluster.
//
// Late delivery is the other half of the same bug, and it is what actually
// triggered it. Findings normally arrive within seconds of occurring — measured
// on live deliveries: 0s, 0s, 18s. The one that reopened a healthy incident had
// occurred at 19:52:17 and arrived at 20:03:35, **eleven minutes** later,
// because the agent's event watch reconnected and Kubernetes replayed every
// Event it still held. Something delivered eleven minutes late describes history,
// not now.
//
// 120 seconds gives an order of magnitude over the worst healthy delivery, so a
// tunnel reconnect draining a short queue is not mistaken for a replay.
const promptDeliveryWindow = 2 * time.Minute

// staleEvidenceForReopen reports whether this Finding is too weak to justify
// declaring a validated fix broken, and returns the fix-landed time it was
// judged against — the newest succeeded in-place execution, or, absent one,
// the incident's own validating_at (BUGS.md 138: an OpenPR fix has no
// execution row to check at all; PROJECT.md B139: pr_merged_at, this
// function's original choice for that fallback, is the GitHub merge instant
// rather than when the fix actually landed on the cluster — see below).
//
// # Why a reopen needs a higher bar than a normal update
//
// Reopening says "the change ARGUS made did not work." Getting that wrong on
// stale evidence is worse than the usual false positive, because it discards a
// fix that was in fact working and sends a human to re-investigate a healthy
// workload. Findings are still RECORDED either way — this only gates the state
// transition.
//
// # Why suppressing a reopen cannot lose a real recurrence
//
// This is the part that makes the two windows safe rather than merely
// plausible. A problem that is genuinely still happening RE-SENDS: each detector
// re-reports its fingerprint once per resend cooldown for as long as the fault
// persists. And orchestrator.effectiveGracePeriod guarantees the validation
// window is at least 3x that cooldown — max(15m, 3x cooldown) — so a suppressed
// but real recurrence gets at least three further chances to reopen the incident
// before the sweeper could possibly resolve it, each one arriving well outside
// both windows here. A stale replay, by contrast, never re-sends: the event it
// came from is finished, so the suppression holds exactly where it should.
//
// # Fail open
//
// Any error, no successful execution AND no validating_at, or a Finding with no
// timestamp returns false — reopen as before. Wrongly keeping a broken
// workload in Validating is the dangerous direction, because the sweeper's
// no-news-is-good-news path would then carry it to Resolved.
func staleEvidenceForReopen(ctx context.Context, tx pgx.Tx, incidentID string, f *tunnel.Finding, now time.Time) (bool, string, time.Time, error) {
	occurredAt := f.OccurredAt
	var executedAt time.Time
	err := tx.QueryRow(ctx,
		// The newest SUCCEEDED execution, not the newest of any outcome: a
		// failed execution changed nothing, so no Finding can be stale relative
		// to it — and treating one as a fix would suppress the very evidence
		// that the remediation failed.
		`SELECT executed_at FROM remediation_executions
		  WHERE incident_id = $1 AND outcome = 'succeeded'
		  ORDER BY executed_at DESC
		  LIMIT 1`, incidentID).Scan(&executedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// BUGS.md 138: an OpenPR fix never writes a remediation_executions
		// row at all — that table is the in-place path's own record — so
		// falling through to "not stale" here made this entire guard a
		// silent no-op for every GitOps/PR-merged fix. Confirmed live: a
		// merged PR's incident reopened on a Kubernetes Event replayed by an
		// agent watch restart, naming a pod Argo had already replaced,
		// twelve and a half minutes after the merge — exactly the WORKLOG
		// §181 shape this function exists to catch, just on the other fix
		// path.
		//
		// incidents.validating_at (PROJECT.md B139, migration 000096) is
		// that path's "when did the fix land" reference point — NOT
		// pr_merged_at, this function's original choice: pr_merged_at is
		// the GitHub merge instant, but the workload legitimately keeps
		// emitting findings until GitOps actually syncs, some real time
		// later, so a Finding dated between merge and sync would have been
		// wrongly judged stale against a landing time that hadn't actually
		// happened on the cluster yet. validating_at is stamped by SetState
		// only once this incident is confirmed to have actually entered
		// Validating (i.e. after MergeSweeper has already confirmed the
		// sync), so it is the true landing instant, the same thing
		// remediation_executions.executed_at already is for the in-place
		// route. The rest of this function's logic (roll-settle window,
		// objectSeenBeforeFix, prompt-delivery window) applies identically
		// once given a landing time, regardless of which path produced it.
		var validatingAt *time.Time
		if err := tx.QueryRow(ctx, `SELECT validating_at FROM incidents WHERE id = $1`, incidentID).Scan(&validatingAt); err != nil {
			return false, "", time.Time{}, fmt.Errorf("read validating_at for incident %s: %w", incidentID, err)
		}
		if validatingAt == nil {
			return false, "", time.Time{}, nil
		}
		executedAt = *validatingAt
	} else if err != nil {
		return false, "", time.Time{}, fmt.Errorf("read last execution for incident %s: %w", incidentID, err)
	}
	if occurredAt.IsZero() {
		return false, "", executedAt, nil
	}
	// The roll settle window applies ONLY to objects that existed before the
	// fix. A Finding about an object first seen AFTER the fix cannot possibly be
	// one of "the pods the fix replaced", however few seconds have passed, so
	// applying a time window to it suppresses exactly the evidence that matters.
	//
	// This is not a hypothetical refinement. Measured on rke2: a fix landed at
	// 20:12:54, the replacement pod OOMKilled at 20:13:03 — NINE SECONDS later,
	// because the container fails as soon as it allocates — and a plain
	// 60-second window swallowed all three of its symptoms. The fix had not
	// worked at all. The window was protecting the wrong pod.
	//
	// Costs one extra query, and only here: this whole function runs solely for
	// a Validating incident that has a successful execution, which is rare
	// compared to the finding rate.
	if !occurredAt.After(executedAt.Add(rollSettleWindow)) {
		known, err := objectSeenBeforeFix(ctx, tx, incidentID, f, executedAt)
		if err != nil {
			return false, "", executedAt, err
		}
		if known {
			return true, fmt.Sprintf("it occurred %s, within %s of the fix at %s, and names an object this incident was already reporting before the fix — the objects a fix replaces keep emitting while they terminate",
				occurredAt.UTC().Format(time.RFC3339), rollSettleWindow, executedAt.UTC().Format(time.RFC3339)), executedAt, nil
		}
	}
	if delay := now.Sub(occurredAt); delay > promptDeliveryWindow {
		return true, fmt.Sprintf("it occurred %s but was delivered %s later, so it describes history rather than the cluster's current state",
			occurredAt.UTC().Format(time.RFC3339), delay.Round(time.Second)), executedAt, nil
	}
	return false, "", executedAt, nil
}

// objectSeenBeforeFix reports whether this incident was already reporting
// findings about f's object before the fix landed — i.e. whether the object is
// one the fix could have replaced, rather than a fresh one that appeared after
// it.
//
// Compared on the object's identity rather than on the fingerprint, because a
// fingerprint includes the symptom: the same pod reporting OOMKilled before the
// fix and CrashLoopBackOff after it is still the same pre-existing pod.
func objectSeenBeforeFix(ctx context.Context, tx pgx.Tx, incidentID string, f *tunnel.Finding, executedAt time.Time) (bool, error) {
	if strings.TrimSpace(f.ObjectName) == "" {
		// Nothing to compare. Treated as "known", so a Finding that names no
		// object keeps the plain time-window behaviour rather than being
		// promoted to fresh evidence on the strength of a missing field.
		return true, nil
	}
	var seen bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM findings
		    WHERE incident_id = $1
		      AND gvk = $2 AND namespace = $3 AND object_name = $4
		      AND occurred_at <= $5)`,
		incidentID, f.GVK, f.Namespace, f.ObjectName, executedAt).Scan(&seen)
	if err != nil {
		return false, fmt.Errorf("check whether %s/%s predates incident %s's fix: %w", f.Namespace, f.ObjectName, incidentID, err)
	}
	return seen, nil
}

// severityRank orders the severity ladder for escalation. Mirrors the ordering
// internal/api/approvals.go's approval-queue query already encodes in SQL
// (critical, high, medium, low); kept as a small Go function rather than
// reaching for that SQL because the comparison here happens per-finding on a
// hot path and needs no round trip.
//
// An unrecognized severity ranks LOWEST, so an unexpected value can never
// silently escalate an incident it does not understand.
func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// handleFinding implements this increment's deliberately simplified
// correlation rule — a documented first slice of the full incident state
// machine lld/08-remediation-contracts.md §2 owns, not that machine itself
// (see this repo's addendum to that document). A Finding either bumps an
// already-open incident sharing this cluster_id + fingerprint, or opens a
// new one in state 'Detected'. "Open" means state NOT IN ('Resolved',
// 'Dismissed') — every other state in incidents' CHECK constraint
// (Investigating, RecommendationReady, AwaitingApproval, ...) counts as
// still-open for matching purposes here, since nothing in this codebase yet
// has the machinery that would ever move an incident into most of those
// states anyway.
//
// Several controls apply before that. Detector and rule filters are configured through
// internal/settings/PUT /api/v1/admin/settings' "detection" section (see
// migration 000026_detection_settings and internal/settings.Config for the
// full rationale) — this is the first real, non-hardcoded slice of
// lld/06-detection-framework.md's detection framework, closing the gap
// STATUS.md's Phase 1 row has repeatedly flagged. Neither is the
// RemediationPolicy CRD/cluster-side controller that document's fuller
// design calls for — these are pragmatic, hub-side-only mechanisms:
//
//  1. Per-detector enable/disable (DisabledDetectorIDs): a HUB-SIDE FILTER,
//     applied before anything else in this function — a Finding from a
//     disabled detector is dropped in full (no findings row, no incident
//     touched), and never even reaches the transaction below. This is
//     NOT agent-side suppression: the agent itself keeps running the
//     "disabled" detector and keeps sending its findings exactly as
//     before — internal/tunnel's protocol has no hub-to-agent config-push
//     mechanism today (Heartbeat/InventoryDelta/Finding flow client->server;
//     Ack/Error/ToolRequest flow server->client; nothing shaped like a
//     config push exists either direction), so "disabling a detector" can
//     only mean "the hub ignores what it already received," not "the agent
//     stops doing the work." Live the moment an admin saves the setting —
//     no agent restart, no hub restart.
//
//     1a. Per-RULE enable/disable (DisabledRuleIDs, BUGS.md 111): the identical
//     hub-side filter as 1 above, checked immediately after it, but against
//     f.RuleID rather than f.DetectorID. Exists because every rule-format
//     finding from internal/agent/rules/default-rules.yaml (33 rules and
//     growing) shares the SAME DetectorID ("k8s-sweep") with the other 32
//     rules and every hand-written Go check in that detector — disabling
//     the detector to silence one noisy rule silences all of them. This
//     control targets the rule's own identity instead, leaving every other
//     rule and every hand-written check in the same detector untouched.
//     Same "hub ignores what it already received, agent keeps evaluating
//     the rule" caveat as 1 above.
//
//     1b. Evidence promotion: every non-disabled Finding is normalized to a
//     class, confidence, and impact. Only a fault with non-unverified evidence
//     and degraded/unavailable impact reaches correlation. Risks and anomalies
//     are inserted with incident_id NULL and committed immediately. This is a
//     promotion boundary, not suppression: the observation remains queryable.
//
//  2. Storm protection (StormProtectionMaxNewIncidents/WindowSeconds): if
//     this cluster has already produced that many brand-new (never-seen-
//     fingerprint) incidents within the trailing window, a Finding that
//     would otherwise open yet another new incident is instead recorded as
//     a findings row with incident_id left NULL — "arrived, but not
//     correlated to any incident" — rather than exploding into unlimited
//     fresh incidents. An already-open incident sharing this Finding's
//     fingerprint still updates completely normally regardless of storm
//     protection; only *new*-incident creation is throttled. Every
//     suppression is logged and recorded as an audit event so it's visible,
//     never silent. Also live immediately — this check re-resolves
//     settings.Config fresh on every call, exactly like every other
//     live-editable setting in this codebase.
//
//  3. Tolerations (migration 000041, FindingTolerated, checked in the same
//     branch as storm protection and before it — no need to also count
//     towards the storm-protection ceiling for a Finding that's about to be
//     suppressed anyway): an operator-created rule scoped to one object
//     (optionally narrowed to specific reasons) that stops a real,
//     already-triaged, accepted condition from opening a new incident every
//     time its detector re-fires — e.g. a Service that legitimately has no
//     endpoints because its DaemonSet targets node labels this cluster
//     doesn't have. Unlike storm protection this is per-object and has no
//     ceiling; unlike resolving/dismissing an incident (incident_triage.go)
//     this actually prevents recurrence rather than just closing the current
//     occurrence. See internal/gateway/toleration.go and BACKLOG.md's A5
//     entry for the full design and the live case that motivated it.
//
// A findings row is inserted on every call that gets this far, regardless of
// which incident-correlation branch is taken — a Finding that isn't
// filtered out entirely by rule 1 is always recorded, whether or not it
// started/updated an incident.
//
// Matches the same own-transaction/resolve-scope/commit-on-success shape as
// handleHeartbeat/handleInventoryDelta above.
func (g *Gateway) handleFinding(ctx context.Context, clusterID string, f *tunnel.Finding) error {
	// Resolved once, fresh, before opening the transaction below — this is
	// a read-only decision with nothing else in this request to stay
	// atomic with, so (like handleGetSettings) it reads via the pool
	// directly rather than needing an open tx first.
	cfg, err := settings.Resolve(ctx, g.db.Pool)
	if err != nil {
		return fmt.Errorf("resolve detection settings: %w", err)
	}

	if IsDetectorDisabled(f.DetectorID, cfg.DisabledDetectorIDs) {
		logger.InfoContext(ctx, "dropping a finding from a disabled detector. Hub-side filter only: the agent still ran this detector and sent this finding. See PUT /api/v1/admin/settings' \"detection\" section",
			logging.ClusterID(clusterID), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
		metrics.FindingsProcessedTotal.Inc("dropped_detector_disabled")
		return nil
	}

	// BUGS.md 111: checked alongside the detector-level filter above, but
	// against f.RuleID specifically — the narrower control that lets an
	// operator silence ONE noisy rule-format finding
	// (internal/agent/rules/default-rules.yaml) without silencing the other
	// 32 rules and every hand-written Go check sharing the same DetectorID
	// ("k8s-sweep"). Same drop-in-full, hub-side-only-filter behavior as the
	// detector-level check — see IsRuleDisabled's own doc comment for why an
	// empty (non-rule) RuleID can never match here.
	if IsRuleDisabled(f.RuleID, cfg.DisabledRuleIDs) {
		logger.InfoContext(ctx, "dropping a finding from a disabled rule. Hub-side filter only: the agent still evaluated this rule and sent this finding. See PUT /api/v1/admin/settings' \"detection\" section",
			logging.ClusterID(clusterID), slog.String("rule_id", f.RuleID), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
		metrics.FindingsProcessedTotal.Inc("dropped_rule_disabled")
		return nil
	}

	// CI-P9 (d): the organisation's posture settings, on top of each agent's
	// own. A posture finding's RuleID is its check ID.
	if f.DetectorID == "k8s-posture" && cfg.PostureExcludes(f.Namespace, f.RuleID) {
		metrics.FindingsProcessedTotal.Inc("dropped_rule_disabled")
		return nil
	}

	// PROJECT.md B173: normalized to a Class/Confidence/Impact tuple BEFORE
	// the condition-polarity gate below runs, not after (as it used to run,
	// called only once the correlation transaction had already opened). A
	// legacy agent's GenericConditionAnomaly:* Finding arrives with all
	// three evidence fields empty but ConditionType/ConditionObservedValue
	// populated; normalizeFindingEvidence's own "all three empty" branch
	// recognizes that shape and assigns anomaly/unverified/none — the
	// deliberately weak default for a mechanism whose uncertainty this
	// promotion boundary exists to preserve (see that function's doc
	// comment). Only once that default is in place does the gate below run
	// and, when it independently confirms the condition is a genuine
	// anomaly rather than resolving it as healthy, raise Confidence alone to
	// Verified. normalizeFindingEvidence never reads Class/Confidence/Impact
	// (only assigns them), and the gate never reads any of the three
	// (documented on applyConditionPolarityGate: it "deliberately leaves
	// Class alone," per promotion.go's own WouldPromoteStoredFinding
	// comment) — so this reordering changes nothing about what either
	// function decides, only which one's write is the LAST one standing.
	// With the old order, the gate's Confidence=Verified overwrite landed on
	// a Finding whose Class/Impact were still empty, so
	// normalizeFindingEvidence's invalid-tuple branch (Class=="" is not a
	// valid class) fired and reset all three — silently discarding the
	// gate's own confirmation. With this order the gate's write is final:
	// the tuple lands on (anomaly, verified, none) — still never
	// (fault, verified, degraded), so migration 000107's trigger (which only
	// rewrites that exact byte-identical default triple) has nothing to
	// correct here, and shouldPromoteFinding still requires Impact
	// degraded/unavailable, so this alone still cannot open an incident;
	// see TestWouldPromoteStoredFinding's own "polarity-confirmed generic
	// anomaly" case, which already pins (anomaly, verified, none) as
	// non-promotable. A genuinely invalid/partial tuple unrelated to the
	// gate (any reason the gate doesn't touch, or a non-empty Class already
	// invalid) still goes through the SAME invalid-tuple branch, unchanged —
	// this reordering does not touch that branch's logic at all, only when
	// it runs relative to the gate.
	normalizeFindingEvidence(f)

	// BACKLOG.md E11 piece 3 / E12: a Finding whose Reason carries
	// "GenericConditionAnomaly:<type>" (internal/agent/generic_predicates.go)
	// named an object differing from its agent-observed local majority, but
	// the agent itself does not and cannot know whether that majority
	// reading is the healthy one or the anomalous one — see
	// tunnel.Finding's own doc comment and polarity_gate.go's. Resolve that
	// here, in its own short transaction, BEFORE the correlation
	// transaction below ever opens: a Finding resolved as CONFIDENTLY
	// healthy must never reach correlation/incident-opening at all, the
	// same "drop it, full stop" posture the two disabled-detector/rule
	// checks above already have — but per E12, that is the ONLY thing this
	// gate drops. Everything it could not confidently resolve proceeds,
	// mutated in place (severity floored, Message marked) by the gate
	// itself; there is deliberately no error return here to drop on.
	if proceed := g.applyConditionPolarityGate(ctx, f); !proceed {
		metrics.FindingsProcessedTotal.Inc("dropped_polarity_healthy")
		return nil
	}

	tx, err := g.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	// Same narrowing rationale as handleInventoryDelta above: findings and
	// incidents are two more of migration 000009's generic cluster_id-scoped
	// tables, and this connection already knows exactly which cluster it's
	// about (resolved by lookupClusterBySerial before any message is
	// dispatched), so scope narrowly to it rather than passing nil. Migration
	// 000013 additionally gives both tables a tenant_id-keyed fallback policy
	// (the same fix already applied to clusters/audit_events) — that's what
	// makes GET /api/v1/incidents work for a caller with no single known
	// cluster; this handler doesn't need it since it always has exactly one.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	// normalizeFindingEvidence(f) already ran above, before the polarity
	// gate — B173 moved it there; see that call site's comment.
	// PROJECT.md B153: a no-op today (defaultEarnedPromotionConfig.Enabled
	// is false, checked first and cheaply by earnedFaultPromotionEligible
	// itself) — see earned_promotion.go's own package doc comment for why
	// that stays false until the owner decides otherwise, and why this is
	// still wired in now rather than left as a disconnected module: the
	// point of building the mechanism is that flipping Enabled is the ONLY
	// change flipping the decision would ever require.
	if eligible, why, err := earnedFaultPromotionEligible(ctx, tx, clusterID, f, time.Now(), defaultEarnedPromotionConfig); err != nil {
		logger.ErrorContext(ctx, "earned-promotion check failed; leaving the finding's class as-is",
			logging.ClusterID(clusterID), slog.String("namespace", f.Namespace),
			slog.String("object_name", f.ObjectName), slog.String("reason", f.Reason), logging.Err(err))
	} else if eligible {
		logger.InfoContext(ctx, "earned promotion: upgrading this finding from Anomaly to Fault",
			logging.ClusterID(clusterID), slog.String("namespace", f.Namespace),
			slog.String("object_name", f.ObjectName), slog.String("reason", f.Reason),
			slog.String("why", why))
		f.Class = tunnel.FindingClassFault
	}
	if !shouldPromoteFinding(f) {
		// retained_unpromoted, never suppressed: this branch is exactly the
		// case findingDispositionOf's default arm names, evidence the
		// boundary itself declined to promote — nothing suppressed it after
		// the fact, so there is no reason to record here.
		if err := insertFindingRow(ctx, tx, tenantID, clusterID, f, nil, ""); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit non-promoted finding: %w", err)
		}
		logger.InfoContext(ctx, "retained a finding as evidence without opening an incident",
			logging.ClusterID(clusterID), slog.String("class", f.Class),
			slog.String("confidence", f.Confidence), slog.String("impact", f.Impact), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
		metrics.FindingsProcessedTotal.Inc("retained_unpromoted")
		// PROJECT.md F31: this row is exactly the case IncidentUpdated never
		// covers (it never touched an incident) and the Signals screen exists
		// to show — see FindingRecorded's own doc comment.
		if g.events != nil {
			g.events.Publish(events.FindingRecorded(clusterID))
		}
		return nil
	}

	// Serializes the "look up -> update, or not found -> insert" sequence
	// below across every concurrent caller sharing this (cluster_id,
	// fingerprint) pair — the same pg_advisory_xact_lock pattern
	// internal/audit/audit.go already uses for its hash-chain serialization,
	// transaction-scoped and released automatically at commit/rollback.
	// This closes the race a plain `FOR UPDATE` on the SELECT can't: FOR
	// UPDATE only locks a row that already exists, so two concurrent
	// first-time Findings for a brand-new fingerprint would both see "no
	// rows" and both attempt an INSERT. A DB-level unique constraint was the
	// first approach tried here, but incidents is a partitioned table
	// (PARTITION BY RANGE (first_seen)), and Postgres requires any unique
	// index on a partitioned table to include the partition key — a
	// (cluster_id, fingerprint, first_seen) index wouldn't actually catch
	// two racing inserts with different first_seen values, which is the
	// normal case. The advisory lock sidesteps that limitation entirely by
	// working at the application level instead of the schema level.
	// Correlation is by OBJECT, not by symptom — see migration 000036 for the
	// measured reason (one broken pod produced three incidents, because a
	// fingerprint includes the reason and one object legitimately produces
	// several). objectKey is "" only for a Finding that names no object, in
	// which case this falls back to the original fingerprint behaviour rather
	// than merging unrelated things under a degenerate key.
	objectKey := objectCorrelationKey(f)
	correlateByObject := objectKey != ""
	workloadKey := workloadCorrelationKey(f)
	// BACKLOG.md A3b — computed alongside workloadKey but, unlike it, never
	// fed into corr below: see relatedWorkloadCorrelationKey's own doc
	// comment for why this must stay out of the merge-tier decision and only
	// ever reach incidents.related_workload_key.
	relatedWorkloadKey := relatedWorkloadCorrelationKey(f)

	// Correlate by WORKLOAD when the agent resolved one — one tier above
	// object-level correlation, and the reason it exists is measured rather
	// than theoretical (WORKLOAD §180).
	//
	// Object-level correlation (migration 000036) folds every symptom of one
	// POD onto one incident. That leaves two kinds of duplicate it cannot
	// touch, and only the first was ever the one people talk about:
	//
	//   - HORIZONTAL: 20 replicas of one Deployment failing at once = 20
	//     incidents. Bad, and the case migration 000042 addressed by grouping
	//     them for display.
	//   - TEMPORAL, and far worse: every pod-template change ROLLS the pods,
	//     and each new generation has a new pod name, so a new object_key, so
	//     a new incident. This is unbounded — it grows with time, not with
	//     replica count, and a 1-replica Deployment produces it.
	//
	// One OOMKilling 1-replica Deployment produced SIX incidents this way
	// (WORKLOG §178): three raised memory limits, three rolls, five pod
	// generations. It is also what let one of those incidents be reported as
	// fixed while the workload was still failing — the incident was watching
	// a pod that the fix itself had deleted.
	//
	// Grouped for display was the earlier answer, and workloadCorrelationKey's
	// own doc comment still records the reasoning for it ("each pod stays its
	// own incident; this only groups siblings for display"). That reasoning is
	// now knowingly reversed: display grouping does nothing about the costs
	// that actually hurt — N independent investigations at real model cost for
	// one fault, N notifications, and N incidents eating the storm-protection
	// ceiling that exists to protect against unrelated problems.
	//
	// Deliberately keyed on workload ALONE, not (workload, reason). Matching
	// the reason as well sounds more conservative and is actually incoherent:
	// a merged incident's opening_reason is whichever symptom arrived first, so
	// a second reason on a second pod would match nothing and open a new
	// incident anyway — while the same two reasons on ONE pod would still fold
	// together via object correlation. Keying on the workload alone is simply
	// migration 000036's principle applied one level up, and it makes the
	// object-level rule a special case of it rather than a competing one.
	//
	// Scope is narrow by construction: only POD findings carry a workload key
	// (the agent resolves it from the pod's own OwnerReferences), so a
	// Deployment-, Node-, PVC-, Service- or Ingress-level finding is completely
	// unaffected and keeps object-level correlation exactly as before.
	//
	// The tier choice itself, and the advisory lock that has to agree with it,
	// live in correlationIdentity.
	corr := correlationIdentity{
		clusterID:   clusterID,
		workloadKey: workloadKey,
		objectKey:   objectKey,
		fingerprint: f.Fingerprint,
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, corr.lockKey()); err != nil {
		return fmt.Errorf("acquire correlation lock: %w", err)
	}

	var incidentID, incidentState, incidentSeverity string
	var lastSeen time.Time
	err = corr.find(ctx, tx, &incidentID, &lastSeen, &incidentState, &incidentSeverity)

	// BACKLOG.md AZ1 / item #13: correlationIdentity.find's own doc comment
	// argues a workload-tier miss never needs to fall through to object_key,
	// because an incident for this exact pod "would itself have a
	// workload_key and have been found by the first query." That assumption
	// is false whenever the FIRST Finding for this pod failed to resolve a
	// workload (internal/agent/workload.go's resolveWorkloadForInvolvedObject
	// returns ok=false on a not-yet-gettable or already-gone Pod, or a
	// transient API error) and a LATER Finding for the very same pod
	// succeeds — measured live, CAPABILITIES.md §6br's DEPL-017 fixture: five
	// of six Warning findings for one Recreate rollout came back with no
	// resolved workload. Without this fallback, the resolved finding's
	// workload-tier lookup finds nothing (the earlier incident's workload_key
	// is NULL) and opens a SECOND incident for the exact same object — the
	// opposite of what correlation exists to prevent.
	//
	// Scoped to THIS finding's own object_key, never a sibling's: it can only
	// ever discover an incident this exact pod already opened, so a
	// DIFFERENT pod of the same workload still correlates (or not) purely
	// through the ordinary workload-tier match above, exactly as before this
	// fallback existed.
	if errors.Is(err, pgx.ErrNoRows) && corr.tier() == "workload" && correlateByObject {
		fallbackErr := tx.QueryRow(ctx,
			`SELECT id, last_seen, state, severity FROM incidents
			   WHERE cluster_id = $1 AND object_key = $2 AND state NOT IN ('Resolved', 'Dismissed')
			   ORDER BY last_seen DESC
			   LIMIT 1`,
			clusterID, objectKey).Scan(&incidentID, &lastSeen, &incidentState, &incidentSeverity)
		switch {
		case fallbackErr == nil:
			err = nil
		case errors.Is(fallbackErr, pgx.ErrNoRows):
			// Genuinely no incident for this object either — proceed to the
			// ordinary "open a new one" path below.
		default:
			return fmt.Errorf("object-tier fallback lookup for cluster %s object %s: %w", clusterID, objectKey, fallbackErr)
		}
	}

	// BUGS.md 132: the object<->workload correlation bridge.
	//
	// correlationIdentity.find (and AZ1's fallback just above) each query
	// exactly one tier's own column, by design — but that leaves a Pod's
	// own Finding (workload-tier, keyed on the OWNING workload) and that
	// SAME workload's own Finding about ITSELF (object-tier, keyed on the
	// workload's own object identity — it never resolves a WorkloadName,
	// because it IS the workload) unable to ever find each other's
	// incident, in either arrival order: a workload-tier open leaves
	// object_key set to the FINDING's own object (the pod, not the
	// workload), and an object-tier open leaves workload_key NULL. See
	// BUGS.md 132's own writeup for the live rke2 fixture this closes (a
	// single-replica Deployment whose container always exits 1 opened two
	// incidents 16 minutes apart, neither ever finding the other).
	//
	// Bridging on identity ALONE here would be dangerous — see this
	// switch's own two case comments below for exactly why, and BUGS.md
	// 132's writeup for the invisible-merge scenario it would create — so
	// each direction additionally requires a `reason` check before
	// treating the other tier's key as if it were its own. Both checks
	// resolve to the SAME single invariant, applied from whichever side is
	// heterogeneous enough to need it: an object-tier reason only ever
	// bridges when it is itself workloadRolloutHealthReasons's closed,
	// reviewed family (a workload's own Available/Progressing/
	// ReplicaFailure/ReplicasUnavailable signal) — checked against THIS
	// finding's reason in the "object" case, and against the CANDIDATE
	// incident's opening_reason in the "workload" case, because that is
	// whichever side of the pair is actually the object-tier one.
	// Workload-tier (pod) reasons are never restricted, on either side,
	// because ordinary within-tier correlation already merges ANY pod
	// symptom onto one workload-scoped incident regardless of reason (see
	// workloadCorrelationKey's own doc comment, "keyed on workload alone,
	// not (workload, reason)") — a pod's symptoms are, by construction,
	// evidence about that workload's health no matter which one fired
	// first, so restricting the pod side here would be inconsistent with
	// the tier's own existing rule, not an extra safety margin.
	//
	// Deliberately does not take a second advisory lock for the candidate
	// it bridges into — AZ1's own fallback just above makes the identical
	// choice (its object_key lookup runs under the workload-tier lock
	// alone). A genuinely simultaneous arrival of both tiers' opening
	// findings for the same workload, at the same instant, could in
	// principle still race past this check and open two incidents; the
	// measured real-world case (BUGS.md 132) arrived 16 minutes apart, and
	// taking a second lock here risks a lock-ordering deadlock against a
	// concurrent Finding doing the same bridge in the opposite direction
	// (workload lock then object lock vs. object lock then workload lock).
	// Accepting the same narrow race AZ1 already accepts is more honest
	// than pretending to close it with a lock order that would need its own
	// separate proof.
	if errors.Is(err, pgx.ErrNoRows) {
		switch corr.tier() {
		case "workload":
			// This Finding is a Pod's, and ordinary workload-tier
			// correlation just found no open incident for the owning
			// workload. Before opening a brand-new one, check whether the
			// WORKLOAD ITSELF already has an open incident — stored at the
			// object tier, under object_key = workloadKey, exactly what an
			// object-tier Finding about this same Deployment/StatefulSet/
			// DaemonSet would have opened it with.
			//
			// Restricted to a CANDIDATE whose opening_reason is a
			// rollout-health signal: an object-tier incident can be about
			// anything (a drift rule, a dangling reference, a stuck
			// finalizer, ...), and none of those are plausibly explained by
			// a pod crashing — bridging into one of THOSE on identity alone
			// is precisely the invisible-merge risk (a real, unrelated
			// second fault silently absorbed into an incident that looks
			// tracked) BUGS.md 132's writeup warns against.
			bridgeErr := tx.QueryRow(ctx,
				`SELECT id, last_seen, state, severity FROM incidents
				   WHERE cluster_id = $1 AND object_key = $2 AND state NOT IN ('Resolved', 'Dismissed')
				     AND opening_reason = ANY($3)
				   ORDER BY last_seen DESC
				   LIMIT 1`,
				clusterID, workloadKey, workloadRolloutHealthReasonList).Scan(&incidentID, &lastSeen, &incidentState, &incidentSeverity)
			switch {
			case bridgeErr == nil:
				err = nil
				logger.InfoContext(ctx, "bridged tiers: a pod finding joined its workload's own rollout-health incident",
					logging.IncidentID(incidentID), logging.ClusterID(clusterID),
					slog.String("object_key", objectKey), slog.String("workload_key", workloadKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
			case errors.Is(bridgeErr, pgx.ErrNoRows):
				// No object-tier incident for this workload, or one exists
				// but its opening reason isn't a rollout-health signal —
				// proceed to the ordinary "open a new one" path below.
			default:
				return fmt.Errorf("workload->object correlation bridge for cluster %s workload %s: %w", clusterID, workloadKey, bridgeErr)
			}
		case "object":
			// This Finding is about the workload ITSELF, and ordinary
			// object-tier correlation just found no open incident for it.
			// Before opening a brand-new one, check whether one of THIS
			// WORKLOAD'S OWN PODS already has an open incident — a
			// workload-tier incident stores the pod's identity in
			// object_key and the owning workload's identity in
			// workload_key, so "this object's own key, treated as a
			// workload key" is exactly the column such an incident
			// carries.
			//
			// Restricted THIS time on THIS FINDING's own reason — the
			// mirror image of the "workload" case above, because here the
			// heterogeneous side is the one arriving now rather than the
			// one already stored. An object-tier Finding that is NOT a
			// rollout-health signal (a GitOps-drift rule, a dangling
			// reference, ...) must never bridge into a pod's incident just
			// because they name the same Deployment — that is the exact
			// "unrelated second fault silently absorbed" case BUGS.md 132's
			// writeup calls out, and the concrete reason a same-string-only
			// rule was rejected in favour of this family instead: it is
			// this restriction, not identity, that keeps the bridge narrow.
			if reasonIndicatesWorkloadRolloutHealth(f.Reason) {
				bridgeErr := tx.QueryRow(ctx,
					`SELECT id, last_seen, state, severity FROM incidents
					   WHERE cluster_id = $1 AND workload_key = $2 AND state NOT IN ('Resolved', 'Dismissed')
					   ORDER BY last_seen DESC
					   LIMIT 1`,
					clusterID, objectKey).Scan(&incidentID, &lastSeen, &incidentState, &incidentSeverity)
				switch {
				case bridgeErr == nil:
					err = nil
					logger.InfoContext(ctx, "bridged tiers: a workload's own finding joined a pod finding's incident on the same workload",
						logging.IncidentID(incidentID), logging.ClusterID(clusterID),
						slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
				case errors.Is(bridgeErr, pgx.ErrNoRows):
					// No pod of this workload has an open incident either —
					// proceed to the ordinary "open a new one" path below.
				default:
					return fmt.Errorf("object->workload correlation bridge for cluster %s object %s: %w", clusterID, objectKey, bridgeErr)
				}
			}
		}
	}

	// Reference bridge (PROJECT.md IN3): one cause seen from both ends of a
	// declared dependency. A Pending pod's finding names what it waits on
	// (tunnel.Finding.References: its PVCs, ConfigMaps, Secrets); when one of
	// those already has an open incident, this finding joins it. And the
	// reverse: a finding about an object that an open incident's pod
	// findings name joins that incident. Before this, a PVC that could not
	// bind and the Deployment waiting on it opened two incidents (loop
	// campaign 2026-10-13, S06). Only when nothing above matched, and only
	// on declared references, never on names or reasons.
	if errors.Is(err, pgx.ErrNoRows) {
		bridged, bridgeErr := referenceBridge(ctx, tx, clusterID, f, &incidentID, &lastSeen, &incidentState, &incidentSeverity)
		if bridgeErr != nil {
			return fmt.Errorf("reference correlation bridge for cluster %s: %w", clusterID, bridgeErr)
		}
		if bridged {
			err = nil
			logger.InfoContext(ctx, "bridged by reference: a finding joined the incident on the object it depends on, or that depends on it",
				logging.IncidentID(incidentID), logging.ClusterID(clusterID),
				slog.String("fingerprint", f.Fingerprint), slog.String("reason", f.Reason))
		}
	}

	// findingIncidentID is the incident_id the findings row below is
	// inserted with — a pointer, not the bare incidentID string, so it can
	// be left NULL when storm protection suppresses new-incident creation
	// (findings.incident_id has always been nullable, migration
	// 000004_findings — this is the first code path that actually inserts
	// a NULL there).
	var findingIncidentID *string
	// findingSuppressionReason names WHICH of the two things that can
	// suppress a promotable finding actually did, for the findings row this
	// function inserts (migration 000124, PROJECT.md F31). Empty for every
	// disposition except "suppressed" — internal/api/findings.go's
	// findingDispositionOf derives "suppressed" from (incidentID == nil &&
	// promotable), and this is the one thing that derivation cannot recover
	// on its own, because the toleration/storm-protection branches below
	// never separately record which one fired anywhere durable. Before this
	// column existed the answer lived only in an audit_events row (still
	// written below, unconditionally, alongside this) — see
	// suppressionReasonToleration/suppressionReasonStormProtection's own
	// comment for the closed vocabulary.
	var findingSuppressionReason string
	// findingOutcome classifies this Finding's final disposition for
	// metrics.FindingsProcessedTotal (PROJECT.md T11), set exactly once
	// along whichever branch below this Finding actually takes and
	// recorded, once, right before the successful return at the bottom of
	// this function — every early error return above is instead covered
	// generically by internal/gateway's processFindingAsync ("error"),
	// since a function that returns an error here never reaches this
	// variable's read at all.
	findingOutcome := "updated_existing_incident"

	switch {
	case err == nil:
		// PROJECT.md B150: computed here, BEFORE last_seen is ever touched,
		// and reused (never recomputed) by the reopen-vs-stay-Validating
		// decision further down — see this variable's own doc comment for
		// why advancing last_seen and deciding whether to reopen must be
		// the same decision, not two.
		//
		// The symptom recurred while ARGUS thought a fix had taken —
		// internal/orchestrator's own doc comment names this exact
		// transition as the event-driven half of the Validating ->
		// Resolved/Reopened re-check (the delayed, no-news-is-good-news
		// half is orchestrator.ValidationSweeper). Checked against the
		// state read by the SELECT above, not re-read after any UPDATE —
		// last_seen/occurrence_count changing doesn't itself change what
		// state this incident was in before this Finding arrived.
		//
		// ...but only if this Finding describes the world AFTER the fix.
		//
		// A Validating incident is one ARGUS has applied a change to and is
		// waiting on. A Finding that OCCURRED before that change landed is
		// evidence about the problem the fix was meant to solve — not
		// evidence that the fix failed — and reopening on it declares a
		// working fix broken.
		//
		// This is not hypothetical latency. Measured (WORKLOG §181): a fix
		// executed at 19:52:16, the old pod's last BackOff event was stamped
		// 19:52:17 — one second later, because a rolling update takes a few
		// seconds to remove the old pod — and that event was delivered at
		// 20:03:35, eleven minutes on, when a watch reconnect replayed it.
		// The fix had worked; the new pod was Running and healthy the whole
		// time. The incident reopened anyway.
		//
		// Two independent ways a Finding arrives late, which is why this
		// belongs here rather than in the agent alone:
		//
		//   - The agent's watch reconnects and Kubernetes replays every
		//     Event it still holds (an hour, by default). Narrowed at the
		//     source by resuming from a resourceVersion, but a fresh start
		//     has nothing to resume from.
		//   - The tunnel drops and the agent's queue drains on reconnect.
		//
		// Two windows rather than one comparison, because the first
		// version of this guard used a bare "did it occur after the
		// execution?" test and would NOT have caught the case it was
		// written for — the offending event was stamped one second after
		// the fix, since a rolling update takes seconds to remove the old
		// pod. staleEvidenceForReopen carries both, and the argument for
		// why suppressing a reopen cannot lose a real recurrence.
		//
		// Fails OPEN — an unreadable or absent execution time reopens (and,
		// per B150's own fix, still advances last_seen) as before. Silently
		// keeping a broken workload in Validating because a lookup failed
		// is far worse than one spurious reopen: the incident would sail on
		// to Resolved on the sweeper's no-news-is-good-news path.
		var validatingStaleFinding bool
		if incidentState == orchestrator.StateValidating {
			stale, why, _, staleErr := staleEvidenceForReopen(ctx, tx, incidentID, f, time.Now())
			if staleErr != nil {
				logger.WarnContext(ctx, "could not judge whether this finding is current evidence for the incident; treating it as a recurrence, which is the safe direction",
					logging.IncidentID(incidentID), logging.ClusterID(clusterID),
					slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason), logging.Err(staleErr))
			} else if stale {
				validatingStaleFinding = true
				logger.InfoContext(ctx, "incident stays Validating: this finding is not evidence that the fix failed. The finding is still recorded, but it does not advance last_seen past validating_at",
					logging.IncidentID(incidentID), logging.ClusterID(clusterID),
					slog.String("object_key", objectKey), slog.String("why", why), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
			}
		}

		// PROJECT.md B150: a finding staleEvidenceForReopen just judged is
		// NOT current evidence of a real recurrence must not advance
		// last_seen past validating_at either — a Validating incident's
		// candidate query (internal/orchestrator/validation.go) requires
		// last_seen <= validating_at with zero tolerance, on the explicit,
		// previously-false assumption that state='Validating' alone already
		// guarantees no recurrence happened (a real recurrence would have
		// already reopened it). Before this fix, a correctly-suppressed
		// stale finding still bumped last_seen a few seconds past
		// validating_at, silently and PERMANENTLY excluding the incident
		// from every future sweep tick — reproduced live 2026-09-07
		// (breadth-campaign-round-4 `APP-005` fixture): a trailing finding
		// from the terminating old pod arrived 12 seconds after
		// validating_at, correctly judged stale (no reopen), and the
		// incident then sat in Validating for 22+ minutes past its grace
		// floor with zero further sweep activity, while sibling incidents
		// from the same round cleared normally.
		newLastSeen := lastSeen
		if !validatingStaleFinding {
			newLastSeen = nextLastSeen(lastSeen, f.OccurredAt)
		}
		// Severity escalates to the worst symptom seen on this object, and
		// never de-escalates. Object-level correlation makes this necessary
		// rather than cosmetic: a pod whose first symptom was a medium
		// PendingTimeout and whose second is a critical OOMKill is now ONE
		// incident, and leaving it at the first symptom's severity would hide
		// the escalation that matters. Downgrading is deliberately not done —
		// a later, milder symptom is not evidence that the worse one stopped.
		newSeverity := incidentSeverity
		if severityRank(f.Severity) > severityRank(incidentSeverity) {
			newSeverity = f.Severity
		}
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET last_seen = $2, occurrence_count = occurrence_count + 1, severity = $3 WHERE id = $1`,
			incidentID, newLastSeen, newSeverity); err != nil {
			return fmt.Errorf("update incident %s: %w", incidentID, err)
		}
		// orchestrator.ReadmitForAutoAnalysis: a recurrence on a
		// Diagnosed/NeedsHumanInvestigation incident is the one case
		// SetState's StateReopened branch never covers (these two states
		// never transition through Reopened — sweepSelfHealing's own
		// "Recurrence" doc comment explains why), so nothing else re-arms
		// auto_analysis_attempted_at's one-shot gate for them. Without this,
		// an incident whose first analysis already completed — manual or
		// automatic — has no automatic path back to a fresh conclusion after
		// it recurs, ever, regardless of how long it then sits quiet.
		if err := orchestrator.ReadmitForAutoAnalysis(ctx, tx, incidentID, incidentState); err != nil {
			return err
		}
		if newSeverity != incidentSeverity {
			logger.WarnContext(ctx, "incident severity escalated by a new symptom",
				logging.IncidentID(incidentID), logging.ClusterID(clusterID),
				slog.String("from_severity", incidentSeverity), slog.String("to_severity", newSeverity),
				slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
		}
		findingIncidentID = &incidentID

		// BUGS.md 94: adopt the rule identity of a LATER correlated
		// finding when this incident has none of its own.
		//
		// This is the one place the correlation tier has two producers
		// rather than one. E9's declarative rules and the hand-written Go
		// checkers both emit Findings about the SAME object, so which of
		// them arrives first is a race with no meaning — metrics-server's
		// ordinary "no sample yet" warning events beat a 90s-sustained
		// HPA rule to the same HorizontalPodAutoscaler by two minutes,
		// live on rke2. Correlation itself handled that correctly (same
		// object_key, same tier, one incident — see correlationIdentity),
		// but opening_rule_id was written once at INSERT and so recorded
		// the loser of that race: empty. V3's post-fix re-check
		// (api.RuleStillFires) is gated on it being non-empty, so a rule
		// that genuinely fired could silently never be re-evaluated.
		//
		// Deliberately fills an EMPTY slot only, never overwrites: an
		// incident that already names a rule keeps naming it, which is
		// migration 000071's "a later finding must not retroactively
		// change which rule a re-check re-runs" invariant intact for
		// every case it was actually reasoning about. What changes is the
		// meaning of NULL — it used to mean "the finding that opened this
		// incident carried no rule", and now means "no finding correlated
		// into this incident has EVER carried a rule", which is the only
		// reading V3's gate can act on honestly.
		//
		// Not a correlation-tier change: a rule-format finding lands in
		// exactly the tier it landed in before (object, for every
		// rule-addressable kind — see correlationIdentity.tier), and no
		// finding attaches to an incident it would not have attached to
		// before. Only this one column moves.
		//
		// `opening_rule_id IS NULL` alone would be enough today
		// (handleFinding writes NULL, never ''), but the empty-string
		// case is checked too because that is what RuleStillFires itself
		// treats as "no rule", and a column whose two writers disagree
		// about the absent value is how this class of bug starts.
		if f.RuleID != "" {
			tag, err := tx.Exec(ctx,
				`UPDATE incidents SET opening_rule_id = $2
				  WHERE id = $1 AND (opening_rule_id IS NULL OR opening_rule_id = '')`,
				incidentID, f.RuleID)
			if err != nil {
				return fmt.Errorf("adopt opening_rule_id for incident %s: %w", incidentID, err)
			}
			if tag.RowsAffected() > 0 {
				logger.InfoContext(ctx, "incident adopted a rule identity from a later correlated finding: it was opened by a finding that carried no rule, so the post-fix re-check had nothing to re-run",
					logging.IncidentID(incidentID), logging.ClusterID(clusterID),
					slog.String("rule_id", f.RuleID), slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
			}
		}

		// BACKLOG.md AZ1 / item #13: same "fill an empty slot, never
		// overwrite" discipline as opening_rule_id above, for the same
		// underlying reason — workload_key is normally set once, at INSERT,
		// and is documented to never change afterward. That was fine when the
		// only way it could be null was "this finding's own object has no
		// owning workload" — but a Get failure on the agent side
		// (internal/agent/workload.go's resolveWorkloadForInvolvedObject) also
		// produces null, and unlike "no workload", that is a fixable timing
		// race, not a fact about the object: a Pod's OwnerReferences never
		// change once set, so a LATER finding for the SAME object resolving a
		// workload the FIRST one couldn't is not new information invalidating
		// the old value — it is the same fact, observed successfully this
		// time. The object-tier fallback above (correlationIdentity.find's own
		// invariant no longer held once resolution could fail) is what lets
		// this incident still be found at all once a later finding resolves a
		// workload the opening one couldn't; this is what makes that
		// resolution stick.
		if workloadKey != "" {
			tag, err := tx.Exec(ctx,
				`UPDATE incidents SET workload_key = $2
				  WHERE id = $1 AND (workload_key IS NULL OR workload_key = '')`,
				incidentID, workloadKey)
			if err != nil {
				return fmt.Errorf("backfill workload_key for incident %s: %w", incidentID, err)
			}
			if tag.RowsAffected() > 0 {
				logger.InfoContext(ctx, "incident adopted a workload_key from a later correlated finding: the finding that opened it could not resolve a workload",
					logging.IncidentID(incidentID), logging.ClusterID(clusterID),
					slog.String("workload_key", workloadKey), slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
			}
		}

		// The symptom recurred while ARGUS thought a fix had taken —
		// internal/orchestrator's own doc comment names this exact
		// transition as the event-driven half of the Validating ->
		// Resolved/Reopened re-check (the delayed, no-news-is-good-news
		// half is orchestrator.ValidationSweeper). Checked against the
		// state read by the SELECT above, not re-read after the UPDATE —
		// last_seen/occurrence_count changing doesn't itself change what
		// state this incident was in before this Finding arrived.
		//
		// Reuses validatingStaleFinding, computed once above (PROJECT.md
		// B150) — never a second, independent call to
		// staleEvidenceForReopen here, which is exactly how this decision
		// and the last_seen advancement above could previously disagree
		// (the DB state staleEvidenceForReopen reads does not change
		// between the two call sites in the old code, so a second call
		// would have returned the same verdict every time it was
		// observed to diverge in practice — but "always agrees in
		// practice" is not the same guarantee as "cannot structurally
		// disagree," and one shared computation is the guarantee).
		if incidentState == orchestrator.StateValidating {
			switch {
			case validatingStaleFinding:
				// Already logged above, at the point last_seen's
				// advancement was suppressed for the identical reason.
			default:
				if err := reopenAfterRecurrence(ctx, tx, tenantID, clusterID, incidentID, objectKey, f); err != nil {
					return err
				}
				findingOutcome = "reopened_after_recurrence"
			}
		}
		// PROJECT.md T2: "a recurrence can reopen an expired incident" —
		// the other half of the same re-attachment mechanism, for the
		// other state that stays correlation-reachable while closed. See
		// reopenExpiredIncident's own doc comment for why the destination
		// is Detected, not Reopened.
		if incidentState == orchestrator.StateExpired {
			if err := reopenExpiredIncident(ctx, tx, tenantID, clusterID, incidentID, objectKey, f); err != nil {
				return err
			}
			findingOutcome = "reopened_after_expiry"
		}
	case errors.Is(err, pgx.ErrNoRows):
		suppressed := false
		var tolerationID string
		if correlateByObject {
			tolerationID, err = FindingTolerated(ctx, tx, clusterID, objectKey, f.Reason)
			if err != nil {
				return fmt.Errorf("check toleration for cluster %s object %s: %w", clusterID, objectKey, err)
			}
		}
		if tolerationID != "" {
			suppressed = true
			findingOutcome = "suppressed_toleration"
			findingSuppressionReason = suppressionReasonToleration
			logger.InfoContext(ctx, "a toleration suppresses new-incident creation for this object; the finding is still recorded, just not linked to a new incident",
				logging.ClusterID(clusterID), slog.String("toleration_id", tolerationID),
				slog.String("object_key", objectKey), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
			if err := audit.RecordEvent(ctx, tx, audit.Event{
				TenantID:        tenantID,
				ActorAuthMethod: "mtls_tunnel",
				ClusterID:       &clusterID,
				Outcome:         audit.OutcomeSuccess,
				Details: map[string]any{
					"event":        "finding_suppressed_by_toleration",
					"tolerationId": tolerationID,
					"detectorId":   f.DetectorID,
					"fingerprint":  f.Fingerprint,
					"objectKey":    objectKey,
					"reason":       f.Reason,
				},
			}); err != nil {
				return fmt.Errorf("record toleration-suppression audit event: %w", err)
			}
		}
		if !suppressed && StormProtectionConfigured(cfg.StormProtectionMaxNewIncidents, cfg.StormProtectionWindowSeconds) {
			windowStart := StormProtectionWindowStart(time.Now(), *cfg.StormProtectionWindowSeconds)
			countInWindow, err := countIncidentsCreatedSince(ctx, tx, clusterID, windowStart)
			if err != nil {
				return fmt.Errorf("count recent new incidents for cluster %s: %w", clusterID, err)
			}
			if StormProtectionShouldSuppress(countInWindow, *cfg.StormProtectionMaxNewIncidents) {
				suppressed = true
				findingOutcome = "suppressed_storm_protection"
				findingSuppressionReason = suppressionReasonStormProtection
				logger.WarnContext(ctx, "storm protection engaged: suppressing new-incident creation. The finding is still recorded, just not linked to a new incident",
					logging.ClusterID(clusterID), slog.Int("incidents_in_window", countInWindow),
					slog.Int("window_seconds", *cfg.StormProtectionWindowSeconds),
					slog.Int("ceiling", *cfg.StormProtectionMaxNewIncidents), slog.String("fingerprint", f.Fingerprint), slog.String("detector_id", f.DetectorID), slog.String("reason", f.Reason))
				if err := audit.RecordEvent(ctx, tx, audit.Event{
					TenantID: tenantID,
					// This event has no logged-in-user actor and no bearer
					// token either — the "actor" is this cluster's own
					// already-authenticated mTLS tunnel connection, a fourth
					// case audit.Event's ActorAuthMethod doc comment doesn't
					// yet enumerate alongside "password"/"jwt"/
					// "enrollment_token"/"poll_token" (see that doc comment
					// for the other four).
					ActorAuthMethod: "mtls_tunnel",
					ClusterID:       &clusterID,
					Outcome:         audit.OutcomeSuccess,
					Details: map[string]any{
						"event":                    "storm_protection_suppressed_new_incident",
						"detectorId":               f.DetectorID,
						"fingerprint":              f.Fingerprint,
						"reason":                   f.Reason,
						"newIncidentCountInWindow": countInWindow,
						"maxNewIncidents":          *cfg.StormProtectionMaxNewIncidents,
						"windowSeconds":            *cfg.StormProtectionWindowSeconds,
					},
				}); err != nil {
					return fmt.Errorf("record storm-protection audit event: %w", err)
				}
			}
		}

		if !suppressed {
			findingOutcome = "opened_new_incident"
			incidentID = domain.NewID(domain.PrefixIncident)
			// fingerprint is still stored, but now means "the symptom that
			// opened this incident" rather than an identifier for it — every
			// fingerprint that later attaches is recoverable from the findings
			// rows. object_key is NULL exactly when this Finding named no
			// object, which keeps the fingerprint-only fallback path above
			// able to find its own incidents and not object-correlated ones.
			var objectKeyArg any
			if correlateByObject {
				objectKeyArg = objectKey
			}
			// workload_key/opening_reason are set once, here, at creation —
			// see migration 000042 and workloadCorrelationKey's own doc
			// comment for why they never change afterward even if a later,
			// different-reason finding updates this same incident.
			//
			// Set INDEPENDENTLY of each other, which they were not until
			// migration 000043. opening_reason used to be written only when
			// workload_key was non-empty, because both were assigned from one
			// `if` and replica-level grouping needs workload_key anyway. But
			// opening_reason is a property of the finding that opened the
			// incident, not of whether that finding happened to resolve an
			// owning workload — and the coupling left it NULL on 143 of 152
			// incidents, since only the pod-conditions and sweep detectors
			// supply a workload name and the event-based detector never does.
			// That made a column 000042 describes as "independently useful for
			// display" unusable for display.
			//
			// This cannot change what replica correlation groups:
			// internal/replicagroup matches `workload_key = $2`, which never
			// matches NULL, and Recompute below is called behind its own
			// separate workloadKey guard rather than this one.
			var workloadKeyArg, openingReasonArg any
			if workloadKey != "" {
				workloadKeyArg = workloadKey
			}
			// pod_priority (migration 000111, PROJECT.md T1's workload-
			// criticality factor) is set once, here, at creation — same
			// "never changes afterward" convention as workload_key/
			// opening_reason above, since it names a fact about the Finding
			// that OPENED this incident, not about whichever Finding happens
			// to update it later. f.PodPriority is nil for exactly the cases
			// internal/importance.Factors.WorkloadCriticality's own doc
			// comment names (non-Pod object, older agent, unresolved
			// spec.priority) — nil here means the arg stays untyped nil,
			// which pgx sends as SQL NULL, never a fabricated 0.
			var podPriorityArg any
			if f.PodPriority != nil {
				podPriorityArg = *f.PodPriority
			}
			if f.Reason != "" {
				openingReasonArg = f.Reason
			}
			// opening_rule_id (migration 000071, BACKLOG.md V3) is the raw
			// f.RuleID of the finding that OPENED this incident. Unlike
			// opening_reason next to it, it is NOT written only here: the
			// correlation branch above adopts a LATER correlated finding's
			// RuleID when this column is still empty (BUGS.md 94 — see that
			// UPDATE's own comment for why the race it fixes is meaningless
			// and why filling an empty slot preserves 000071's invariant).
			// Empty for every Finding from the 17 hand-written Go
			// checkers, the two watch-based detectors, or an agent predating
			// tunnel.Finding.RuleID — which is the common case, and NULL
			// says so rather than an empty string. See that field's own doc
			// comment for why RuleID exists instead of reverse-engineering
			// an identifier from Reason.
			var openingRuleIDArg any
			if f.RuleID != "" {
				openingRuleIDArg = f.RuleID
			}
			// related_workload_key (migration 000070, BACKLOG.md A3b) is set
			// once, here, at creation — same "never changes afterward"
			// semantics as workload_key/opening_reason above, and for the
			// same reason: a later, different Finding updating this same
			// incident should not retroactively change what cross-object
			// group it was ever eligible to join. See
			// relatedWorkloadCorrelationKey's own doc comment for why this
			// is a plain display column, never a correlation-identity tier.
			var relatedWorkloadKeyArg any
			if relatedWorkloadKey != "" {
				relatedWorkloadKeyArg = relatedWorkloadKey
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, object_key, workload_key, opening_reason, opening_rule_id, related_workload_key, severity, state, first_seen, last_seen, occurrence_count, pod_priority)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Detected', $11, $11, 1, $12)`,
				incidentID, tenantID, clusterID, f.Fingerprint, objectKeyArg, workloadKeyArg, openingReasonArg, openingRuleIDArg, relatedWorkloadKeyArg, f.Severity, f.OccurredAt, podPriorityArg); err != nil {
				return fmt.Errorf("insert incident: %w", err)
			}
			findingIncidentID = &incidentID

			// BACKLOG.md B1: the detection transition — question 1 of the four
			// the incident screen answers. Written in this same transaction, so
			// a timeline row can never outlive (or be missing from) the
			// incident it describes.
			if err := timeline.Record(ctx, tx, timeline.Event{
				TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
				Type:    timeline.EventIncidentOpened,
				Summary: fmt.Sprintf("%s: %s", f.Reason, f.Message),
				Detail: map[string]any{
					"detectorId": f.DetectorID,
					"gvk":        f.GVK,
					"namespace":  f.Namespace,
					"objectName": f.ObjectName,
					"reason":     f.Reason,
					"message":    f.Message,
					"severity":   f.Severity,
				},
			}); err != nil {
				return fmt.Errorf("record IncidentOpened timeline event: %w", err)
			}
		}
	default:
		return fmt.Errorf("look up existing incident for cluster %s (object=%q fingerprint=%s): %w", clusterID, objectKey, f.Fingerprint, err)
	}

	if err := insertFindingRow(ctx, tx, tenantID, clusterID, f, findingIncidentID, findingSuppressionReason); err != nil {
		return err
	}

	// Recompute this fingerprint's fleet-wide grouping (internal/fleetgroup)
	// whenever this finding actually created or updated an open incident —
	// exactly the "an incident's open/closed status for this fingerprint
	// might have just changed" trigger Recompute's own doc comment calls
	// for. A storm-protection-suppressed finding (findingIncidentID nil)
	// didn't change any incident's open/closed status, so there's nothing
	// to recompute.
	if findingIncidentID != nil {
		// BUGS.md 98: fleetgroup.Recompute's whole job is to look ACROSS
		// clusters (its own SELECT DISTINCT i.cluster_id ... query has no
		// cluster_id predicate at all — that's the point), but this
		// transaction's request scope above was deliberately narrowed to
		// this one clusterID. Under incidents_cluster_scope's RESTRICTIVE
		// policy (migration 000035), a non-empty app.accessible_cluster_ids
		// ANDs on top of the tenant predicate, so Recompute's query
		// structurally could never see another cluster's open incident —
		// distinctClusterCount could never exceed 1, fleet_group_id could
		// never be set, and everything built on it (BatchExecution's
		// wave-1/wave-2 staging, BACKLOG.md R3) was unreachable via the real
		// ingestion path. Confirmed live on two real clusters (BUGS.md 98).
		//
		// Fix: widen to every cluster THIS TENANT can see (nil — the exact
		// convention internal/authz/session.go, internal/api/unattended.go,
		// internal/api/ws.go and others already use for a tenant-wide read;
		// migration 000035's own header names this the required, non-loophole
		// meaning of an empty accessible_cluster_ids: "an AllClusters grant
		// must pass an EMPTY list"), for exactly this one call, then narrow
		// straight back to clusterID before anything else in this
		// transaction runs. tenantID itself is never touched — it is the
		// same value the narrow SetRequestScope call above already set, so
		// this can only ever widen visibility to OTHER CLUSTERS OF THE SAME
		// TENANT, never across tenants.
		//
		// Same transaction, not a second one opened after commit, because
		// Recompute must see this transaction's OWN not-yet-committed write
		// (the incident INSERT/UPDATE earlier in this function) to group it
		// correctly — a second transaction, being a separate Postgres
		// snapshot, cannot see another transaction's uncommitted rows under
		// READ COMMITTED, so it would recompute against a view of the world
		// that doesn't yet include the very incident this call exists to
		// place into a group. Cheap to do in-place: set_config's third
		// argument (true, in internal/data.SetRequestScope) is SET LOCAL
		// semantics, scoped to this transaction and freely reassignable
		// within it — nothing needs "restoring" for the session's sake, only
		// for staying as narrow as correctly possible for the rest of this
		// transaction (defense in depth: replicagroup/objectgroup below
		// already filter by cluster_id explicitly in SQL and don't need the
		// wider scope, so there is no reason to leave RLS loosened past the
		// one call that does).
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			return fmt.Errorf("widen request scope for fleet-group recompute: %w", err)
		}
		fleetErr := fleetgroup.Recompute(ctx, tx, f.Fingerprint)
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			return fmt.Errorf("restore request scope after fleet-group recompute: %w", err)
		}
		if fleetErr != nil {
			return fmt.Errorf("recompute fleet group: %w", fleetErr)
		}
		// Replica-level correlation (internal/replicagroup, migration 000042,
		// BACKLOG.md's A3) — re-scoped version of the same idea, one cluster
		// instead of the whole fleet, keyed on (workload, reason) instead of
		// fingerprint. Called on every finding that touched an open incident,
		// not only on creation: a NEW sibling incident's own Recompute call
		// re-groups every OTHER incident sharing this (workload_key, reason)
		// too, via its own UPDATE — this incident's group can change even
		// when nothing about IT changed, purely because a sibling just
		// appeared or disappeared.
		if workloadKey != "" {
			if err := replicagroup.Recompute(ctx, tx, clusterID, workloadKey, f.Reason); err != nil {
				return fmt.Errorf("recompute replica group: %w", err)
			}
		}
		// Cross-object correlation (internal/objectgroup, migration 000070,
		// BACKLOG.md's A3b) — same "called on every finding that touched an
		// open incident" posture as replicagroup above, and for the same
		// reason: whichever anchor this Finding carries (its OWN workload,
		// if it's Pod-shaped, or the RELATED workload it resolved a
		// reference to, if it's a PVC/Service) might have just gained or
		// lost a sibling incident on the other side of that anchor.
		// Recompute is a no-op when passed "", so calling it with whichever
		// of the two keys is non-empty (never both — see
		// relatedWorkloadCorrelationKey's own doc comment for why one
		// Finding's object is either "is-a" workload member or "references"
		// one, never both) needs no extra guard here.
		anchorWorkloadKey := workloadKey
		if anchorWorkloadKey == "" {
			anchorWorkloadKey = relatedWorkloadKey
		}
		if err := objectgroup.Recompute(ctx, tx, clusterID, anchorWorkloadKey); err != nil {
			return fmt.Errorf("recompute object group: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit finding: %w", err)
	}
	// PROJECT.md T11 — recorded only after the commit above actually
	// succeeds, matching this function's every other post-commit side
	// effect (the event publish just below): a finding whose disposition
	// never durably landed must not be counted as though it had.
	metrics.FindingsProcessedTotal.Inc(findingOutcome)
	// Published only after a successful commit. IncidentUpdated only when
	// this finding actually created or updated an incident — a
	// storm-protection- or toleration-suppressed finding (findingIncidentID
	// nil) touched no incident for an incident-scoped screen to refetch. See
	// internal/events' doc comment for what "publish" means here (a
	// best-effort, non-authoritative refetch hint, never blocking).
	if findingIncidentID != nil && g.events != nil {
		g.events.Publish(events.IncidentUpdated(*findingIncidentID, clusterID))
	}
	// FindingRecorded publishes unconditionally, alongside it — PROJECT.md
	// F31: a suppressed finding is exactly the row IncidentUpdated cannot
	// cover (see FindingRecorded's own doc comment), and this is the one
	// remaining path insertFindingRow above reaches with findingIncidentID
	// nil (the retained_unpromoted early return above publishes its own).
	if g.events != nil {
		g.events.Publish(events.FindingRecorded(clusterID))
	}
	return nil
}

// suppressionReasonToleration/suppressionReasonStormProtection are the
// findings.suppression_reason column's entire closed vocabulary (migration
// 000124, PROJECT.md F31, CHECK-constrained at the database too) — the two
// things that can leave a promotable finding (incident_id NULL, promotion
// verdict promotable) with no incident: an operator-created toleration
// (FindingTolerated below), or storm protection's new-incident ceiling. Kept
// as the ONE definition both handleFinding branches below set
// findingSuppressionReason from, matching internal/api/findings.go's
// suppressed-disposition SQL/Go pair's own "one definition, two readers"
// discipline.
const (
	suppressionReasonToleration      = "toleration"
	suppressionReasonStormProtection = "storm_protection"
)

// insertFindingRow inserts one findings row. suppressionReason is "" for
// every disposition except "suppressed" (see findingSuppressionReason's own
// doc comment at handleFinding) and is written as SQL NULL rather than an
// empty string — findings.suppression_reason's CHECK constraint only
// permits NULL or one of the two constants above.
func insertFindingRow(ctx context.Context, tx pgx.Tx, tenantID, clusterID string, f *tunnel.Finding, incidentID *string, suppressionReason string) error {
	findingID := domain.NewID(domain.PrefixFinding)
	// PROJECT.md B153 addendum: references_out is NULL, not an empty array,
	// when this Finding's object names nothing — see migration 000100's own
	// comment for why NULL is the honest default rather than `[]`.
	var referencesOut any
	if len(f.References) > 0 {
		encoded, err := json.Marshal(f.References)
		if err != nil {
			return fmt.Errorf("encode references: %w", err)
		}
		referencesOut = encoded
	}
	var suppressionReasonArg any
	if suppressionReason != "" {
		suppressionReasonArg = suppressionReason
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings (
		   id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk,
		   namespace, object_name, object_uid, resource_version, reason, message,
		   occurrence_count, severity, occurred_at, incident_id, rule_id,
		   signal_class, confidence, impact, references_out, suppression_reason
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
		findingID, tenantID, clusterID, f.DetectorID, f.DetectorVersion, f.Fingerprint, f.GVK,
		f.Namespace, f.ObjectName, f.ObjectUID, f.ResourceVersion, f.Reason, f.Message,
		f.OccurrenceCount, f.Severity, f.OccurredAt, incidentID, f.RuleID,
		f.Class, f.Confidence, f.Impact, referencesOut, suppressionReasonArg); err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return nil
}

// IsDetectorDisabled reports whether detectorID appears in disabledIDs —
// handleFinding's hub-side detector-enable/disable filter, pulled out as
// its own pure function so it's unit-testable with no database at all (see
// finding_test.go). Exported (not just pulled out) specifically so
// internal/api's detection dry-run endpoint (detection_dryrun.go) can call
// this EXACT function against historical data, rather than a second
// hand-copied reimplementation that could silently drift from what
// handleFinding actually does live — see that file's own doc comment.
func IsDetectorDisabled(detectorID string, disabledIDs []string) bool {
	for _, id := range disabledIDs {
		if id == detectorID {
			return true
		}
	}
	return false
}

// IsRuleDisabled reports whether ruleID appears in disabledIDs —
// handleFinding's hub-side RULE-level enable/disable filter, BUGS.md 111's
// fix. Structurally identical to IsDetectorDisabled above and pulled out as
// its own pure function for the same reason: unit-testable with no database
// at all (see finding_test.go), and exported so internal/api's detection
// dry-run endpoint could call this exact function too, rather than a second
// hand-copied reimplementation that could silently drift from what
// handleFinding actually does live.
//
// ruleID == "" always returns false, regardless of disabledIDs' contents —
// internal/tunnel.Finding.RuleID is empty for every hand-written Go detector
// finding (only rule-format findings, from
// internal/agent/rules/default-rules.yaml, ever set it), and an empty string
// must never be treated as "disabled" even if disabledIDs somehow contained
// one (it never should — internal/api/settings.go's validation rejects an
// empty entry — but this function does not trust that invariant blindly from
// a second, independent code path, matching StormProtectionConfigured's own
// "re-check rather than trust" precedent below).
func IsRuleDisabled(ruleID string, disabledIDs []string) bool {
	if ruleID == "" {
		return false
	}
	for _, id := range disabledIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

// StormProtectionConfigured reports whether cfg carries a real
// storm-protection ceiling. Both fields must be positive — the API
// boundary (internal/api/settings.go's validateDetectionSettingsRequest)
// already rejects "one set, the other missing" before either ever reaches
// org_settings, but this function re-checks both anyway rather than trusting
// that invariant blindly from a second, independent code path. Exported for
// the same reason as IsDetectorDisabled above: internal/api's detection
// dry-run endpoint calls this exact function, never a second copy.
func StormProtectionConfigured(maxNewIncidents, windowSeconds *int) bool {
	return maxNewIncidents != nil && *maxNewIncidents > 0 && windowSeconds != nil && *windowSeconds > 0
}

// StormProtectionWindowStart returns the earliest incidents.first_seen an
// existing incident can have and still count toward the current rolling
// window, given now and the configured window length — pulled out as its
// own pure function so the time arithmetic is unit-testable without a
// database (see finding_test.go). Exported for the same reason as
// IsDetectorDisabled above.
func StormProtectionWindowStart(now time.Time, windowSeconds int) time.Time {
	return now.Add(-time.Duration(windowSeconds) * time.Second)
}

// countIncidentsCreatedSince counts the incidents this hub created for one
// cluster at or after windowStart — the number storm protection compares
// against its configured per-cluster ceiling.
//
// "Created" is measured on the HUB's clock, via the incident id's own ULID
// timestamp (see StormProtectionWindowStartIncidentID for why that, and not
// a timestamp column, is what makes this correct). COLLATE "C" pins the
// comparison to byte order, which is the order the ULID encoding is designed
// around — without it the predicate would depend on whatever locale the
// database happened to be initialized with.
//
// The `id ~ ...` guard (BUGS.md 93) excludes rows whose id is not actually a
// domain.NewID-shaped ULID. argus-context's convention #1 ("IDs are prefixed
// ULIDs via internal/domain.NewID(prefix) ... never construct an ID ad hoc")
// means this should never happen — but manually-seeded SQL test fixtures from
// earlier verification campaigns (`inc_v1validate00000001`,
// `inc_repolink0000000other001`, `inc_f13limits0000000000001`, and others)
// violate it anyway, and this predicate has no way to tell "created recently"
// from "some other string that happens to sort high" without checking the
// shape first. Under byte order, a hand-written suffix starting with a letter
// like 'v', 'r', 'g' or 'f' sorts ABOVE any near-term real ULID timestamp
// prefix (which starts '01' for decades to come), so every such row satisfies
// `id COLLATE "C" >= windowStart's bound` for EVERY window, forever — not
// because it was created recently, but because it was never a timestamp to
// begin with. On a cluster that has accumulated enough of these (rke2's own
// "personal test" cluster: ~19, live-observed 2026-08-26 while verifying
// BACKLOG.md E6's storm-protection scenario), this pins countIncidentsCreatedSince
// permanently above almost any realistic ceiling — storm protection engages
// on every finding, whether or not this cluster has actually produced a real
// burst. The charset below is exactly domain.NewID's output alphabet —
// Crockford base32, lowercased (0-9, a-h, j, k, m, n, p-t, v-z; i/l/o/u are
// never produced) — so every id domain.NewID has ever minted still matches,
// and only non-conforming rows are excluded.
func countIncidentsCreatedSince(ctx context.Context, tx pgx.Tx, clusterID string, windowStart time.Time) (int, error) {
	var count int
	err := tx.QueryRow(ctx,
		`SELECT count(*) FROM incidents
		  WHERE cluster_id = $1
		    AND id COLLATE "C" >= $2
		    AND id ~ '^inc_[0-9a-hjkmnp-tv-z]{26}$'`,
		clusterID, StormProtectionWindowStartIncidentID(windowStart)).Scan(&count)
	return count, err
}

// StormProtectionWindowStartIncidentID returns the lowest incidents.id any
// incident the hub created at or after windowStart can possibly have — the
// lower bound handleFinding's storm-protection count compares against,
// instead of a timestamp column.
//
// WHY AN ID BOUND RATHER THAN A TIMESTAMP (the bug this closes): the count
// used to be `WHERE cluster_id = $1 AND first_seen >= $2`, and
// incidents.first_seen is inserted verbatim from the AGENT-supplied
// f.OccurredAt (see handleFinding's INSERT — deliberately, since first_seen
// genuinely means "when the problem started," which only the agent
// observing it knows). Comparing an agent-stamped column against a
// hub-computed window start silently mixes two unsynchronized clocks, and
// storm protection loses either way round:
//
//   - An agent whose clock trails the hub by more than the window stamps
//     every incident it ever creates OUTSIDE the window, so the count stays
//     0 forever and the configured per-cluster ceiling never engages — no
//     error, no log line, just a control that quietly does nothing.
//   - An agent draining a backlog after a reconnect stamps a burst of
//     genuinely-new incidents with the OLD occurrence times they were
//     detected at — which is exactly the burst storm protection exists to
//     throttle, and exactly the burst that predicate excludes.
//
// incidents has no hub-clock column to compare against instead (no
// created_at/ingested_at — see internal/migrations/000005, 000017, 000020),
// and adding one is a migration this package doesn't own. It doesn't need
// one: every incidents.id is minted hub-side by domain.NewID, and a ULID's
// leading 48 bits ARE a hub-clock millisecond timestamp
// (lld/05-data-model.md §2's "ULIDs sort lexicographically by creation time,
// so ORDER BY id is a free proxy for ORDER BY created_at on every table" —
// the same property internal/argusctl/audit.go already leans on to break
// hash-chain ordering ties). So a ULID with windowStart's timestamp and
// all-zero entropy is a lower bound no earlier incident can sort at or
// above, and `id >= thatBound` is precisely "created by this hub within the
// window," on one clock, with no join and no new column.
//
// COLLATE "C" at the comparison site, not here: Crockford base32 lowercased
// keeps ASCII's digits-before-letters ordering, so byte comparison is the
// correct one, and pinning the collation means the predicate can't be
// changed by whatever locale a given deployment's database was initialized
// with.
func StormProtectionWindowStartIncidentID(windowStart time.Time) string {
	var lower ulid.ULID
	if err := lower.SetTime(ulid.Timestamp(windowStart)); err != nil {
		// windowStart falls outside ULID's representable 48-bit millisecond
		// range — only reachable from an absurd window (pre-1970, or ~10889
		// AD onward). Fall back to the lowest id there is, which counts
		// every incident this cluster has ever had: that errs towards
		// suppressing rather than towards the silent no-op this whole
		// function exists to fix.
		return domain.PrefixIncident + "_" + strings.Repeat("0", ulid.EncodedSize)
	}
	// Entropy left at its zero value on purpose: it makes this the smallest
	// id of that millisecond, so an incident created in the same millisecond
	// as windowStart counts as inside the window.
	return domain.PrefixIncident + "_" + strings.ToLower(lower.String())
}

// StormProtectionShouldSuppress reports whether a brand-new incident should
// be suppressed, given how many new incidents this cluster has already
// produced within the current rolling window (countInWindow) and the
// configured ceiling. Exported for the same reason as IsDetectorDisabled
// above.
func StormProtectionShouldSuppress(countInWindow, maxNewIncidents int) bool {
	return countInWindow >= maxNewIncidents
}

// nextLastSeen decides an incident's new last_seen value given the value
// already stored and a newly-arrived (possibly out-of-order) finding's
// OccurredAt. Tunnel delivery has no ordering guarantee across reconnects/
// retries, so a finding that actually happened earlier than what's already
// recorded must never regress last_seen backwards — this is the one piece of
// handleFinding's logic that's pure enough to unit-test without a database.
func nextLastSeen(currentLastSeen, findingOccurredAt time.Time) time.Time {
	if findingOccurredAt.After(currentLastSeen) {
		return findingOccurredAt
	}
	return currentLastSeen
}

// isClosedIncidentState reports whether state counts as "closed" for this
// package's correlation matching (handleFinding's SQL hardcodes the same
// two values directly in its NOT IN clause — kept here too, in Go, purely so
// the boundary has one unit-testable definition rather than living only as
// an untested SQL string literal). Delegates to fleetgroup.IsClosedState —
// the two packages need the identical definition (fleetgroup.Recompute's own
// "currently open" query must agree with handleFinding's), so this is the
// one place it's defined, not a second, independently-maintained copy.
func isClosedIncidentState(state string) bool {
	return fleetgroup.IsClosedState(state)
}

// referenceBridge looks for an open incident linked to f by a declared
// reference, in either direction, and scans it into the given targets.
func referenceBridge(ctx context.Context, tx pgx.Tx, clusterID string, f *tunnel.Finding, incidentID *string, lastSeen *time.Time, state, severity *string) (bool, error) {
	const open = `state NOT IN ('Resolved', 'Dismissed')`
	scan := func(row pgx.Row) (bool, error) {
		switch err := row.Scan(incidentID, lastSeen, state, severity); {
		case err == nil:
			return true, nil
		case errors.Is(err, pgx.ErrNoRows):
			return false, nil
		default:
			return false, err
		}
	}
	// Forward: an open incident about something this finding depends on.
	refs := f.References
	if len(refs) > 10 {
		refs = refs[:10]
	}
	for _, r := range refs {
		ok, err := scan(tx.QueryRow(ctx,
			`SELECT id, last_seen, state, severity FROM incidents
			  WHERE cluster_id = $1 AND `+open+`
			    AND split_part(object_key, '|', 2) = $2 AND split_part(object_key, '|', 3) = $3
			    AND (split_part(object_key, '|', 1) = $4 OR split_part(object_key, '|', 1) LIKE '%/' || $4)
			  ORDER BY last_seen DESC LIMIT 1`,
			clusterID, r.Namespace, r.Name, r.Kind))
		if err != nil || ok {
			return ok, err
		}
		// Producers: an open incident whose recent findings say they produce
		// what this finding waits on — a pod waiting on Secret x joins the
		// incident on the Certificate whose secretName is x. And the other
		// way: a producer's finding joins the incident of anything waiting on
		// what it produces.
		producer := r
		producer.Role = tunnel.ReferenceRoleProduces
		if r.Role == tunnel.ReferenceRoleProduces {
			producer.Role = ""
		}
		needle, err := json.Marshal([]tunnel.ObjectReference{producer})
		if err != nil {
			return false, err
		}
		ok, err = scan(tx.QueryRow(ctx,
			`SELECT i.id, i.last_seen, i.state, i.severity
			   FROM findings fd JOIN incidents i ON i.id = fd.incident_id
			  WHERE fd.cluster_id = $1 AND fd.ingested_at > now() - interval '1 day'
			    AND fd.signal_class = 'fault' AND fd.references_out @> $2::jsonb
			    AND i.`+open+`
			  ORDER BY i.last_seen DESC LIMIT 1`,
			clusterID, string(needle)))
		if err != nil || ok {
			return ok, err
		}
		// Siblings: an open incident whose recent findings name the same
		// unready Node or unavailable APIService (the agent names either only
		// when it is down, so it is the shared fault: every pod on the node,
		// every autoscaler that needs the metrics API). Not for ConfigMaps,
		// Secrets or PVCs: unrelated workloads often share one, and sharing it
		// is no evidence of a shared cause.
		if r.Kind != "Node" && r.Kind != "APIService" {
			continue
		}
		sibling, err := json.Marshal([]tunnel.ObjectReference{r})
		if err != nil {
			return false, err
		}
		ok, err = scan(tx.QueryRow(ctx,
			`SELECT i.id, i.last_seen, i.state, i.severity
			   FROM findings fd JOIN incidents i ON i.id = fd.incident_id
			  WHERE fd.cluster_id = $1 AND fd.ingested_at > now() - interval '1 day'
			    AND fd.signal_class = 'fault' AND fd.references_out @> $2::jsonb
			    AND i.`+open+`
			  ORDER BY i.last_seen DESC LIMIT 1`,
			clusterID, string(sibling)))
		if err != nil || ok {
			return ok, err
		}
	}
	// Reverse: an open incident whose recent findings depend on this object.
	needle, err := json.Marshal([]tunnel.ObjectReference{{Kind: gvkKind(f.GVK), Namespace: f.Namespace, Name: f.ObjectName}})
	if err != nil {
		return false, err
	}
	return scan(tx.QueryRow(ctx,
		`SELECT i.id, i.last_seen, i.state, i.severity
		   FROM findings fd JOIN incidents i ON i.id = fd.incident_id
		  WHERE fd.cluster_id = $1 AND fd.ingested_at > now() - interval '1 day'
		    AND fd.signal_class = 'fault' AND fd.references_out @> $2::jsonb
		    AND i.`+open+`
		  ORDER BY i.last_seen DESC LIMIT 1`,
		clusterID, string(needle)))
}
