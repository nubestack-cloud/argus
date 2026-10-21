// This file is BACKLOG.md N1's widening of the trigger set notifier.go's own
// package doc comment described as "exactly one question: a new incident
// happened — tell a webhook about it." That question is now one of several:
// a plan awaiting approval, a failed or indeterminate execution, a recurring
// incident, and a pull request that has sat unmerged past its staleness
// threshold (internal/orchestrator/mergewatch.go) all need a human told,
// too — DESIGN.md §13's whole premise ("an unapproved critical fix nobody
// saw is a product failure," §13.3) applies just as much to those as to a
// brand-new incident.
//
// Deliberately a SEPARATE mechanism from notifier.go's incidents.notified_at
// column, not a replacement for it: "new incident" is one clear, one-shot
// event with its own column already built and tested, and folding it into
// this table would touch a working path for no benefit. What's shared is
// the delivery half — the same webhook URL (internal/settings.Resolve),
// the same WebhookNotifier.post, the same poller loop (Run/sweep in
// notifier.go) — per this task's brief: widen WHEN a notification fires,
// don't build a second transport.
//
// # The "one message per incident, updated in place" decision
//
// DESIGN.md §13.3 calls for a single message per incident, edited as the
// incident progresses, not one new message per event. This package cannot
// literally edit a previously-sent message — a generic webhook POST (the
// only transport notifier.go builds; see its own doc comment for why this
// is deliberately not Slack-bot-token-shaped) has no message handle to edit
// later. What IS achievable, and is the property that actually matters for
// avoiding the noise DESIGN.md §13.3 warns about, is: never send more than
// one notification for the SAME still-true condition. incident_notifications
// (migration 000083) holds exactly one row per incident, and NotifyTransition
// below is an upsert that only marks the row "pending send" again when the
// caller-supplied key actually CHANGES from what's already stored — see its
// own doc comment for the exact guard.
//
// The key is caller-defined on purpose, because "the same open question" has
// two different shapes depending on the trigger:
//
//   - internal/orchestrator.SetState passes a key that is unique to THIS
//     transition (a timestamp-suffixed state name) — every call it makes here
//     is already a genuinely new, discrete event (no incident state has a
//     self-edge), including a SECOND entry into a state this incident has
//     been in before, which must still notify. A bare state name would
//     wrongly collapse that second entry into the first.
//   - mergewatch.go's stale-pull-request escalation (and approvalwatch.go's
//     stale-approval escalation) pass a key built from a fixed, literal
//     PREFIX ("AwaitingMerge:StalePR", "AwaitingApproval:Stale") plus a
//     widening tier suffix from internal/orchestrator/escalation.go (48h,
//     5d, 12d, then weekly — BACKLOG.md T3, 2026-09-04). Within one tier
//     the effective key IS fixed: repeated ticks that keep finding the SAME
//     pull request/plan still in the SAME tier must collapse into the one
//     notification already sent, not one per tick. Crossing into the NEXT
//     tier changes the key, which is what lets a condition that has been
//     open for a long time escalate again instead of going silent forever
//     after its first nudge — see escalation.go's own doc comment.
//
// A sweep that keeps observing the same open question (a pull request that
// is STILL stale next tick) is therefore a no-op, and a genuinely new
// condition (AwaitingApproval -> Failed, or a fresh AwaitingApproval after a
// prior Failed cycle) always gets exactly one fresh send. §13.2's full
// routing engine and §13.3's digest batching remain unbuilt (BACKLOG.md N1
// says so explicitly) — this is the smallest mechanism that keeps THIS
// widening from becoming the spam §13.3 exists to prevent.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotifyTransition upserts incident_notifications for one incident's current
// open question. Call it inside the SAME transaction as whatever event
// key/summary describes (internal/orchestrator.SetState,
// internal/orchestrator/mergewatch.go's stale-pull-request branch) so the
// notification record is exactly as durable as the event that caused it —
// if that transaction rolls back, no notification is queued for an event
// that never actually happened either.
//
// key names WHAT changed — an incidents.state value for an orchestrator
// transition, or a caller-defined synthetic key (mergewatch.go's
// "AwaitingMerge:StalePR") for a condition that isn't a state transition at
// all. summary is the human-readable line the eventual webhook payload will
// carry.
//
// Calling this again with the SAME key the incident already has stored is a
// deliberate, silent no-op: the ON CONFLICT ... WHERE guard below only fires
// the update (and therefore only sets pending back to true) when the new key
// differs from what's already there. That WHERE clause is the entire
// mechanism behind this package's "one message per incident, updated in
// place, not one per event" rule — see this file's own doc comment.
func NotifyTransition(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, key, summary string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO incident_notifications (incident_id, tenant_id, cluster_id, notify_key, summary, pending, updated_at)
		VALUES ($1, $2, $3, $4, $5, true, now())
		ON CONFLICT (incident_id) DO UPDATE
		   SET notify_key = EXCLUDED.notify_key,
		       summary    = EXCLUDED.summary,
		       pending    = true,
		       updated_at = now(),
		       -- PROJECT.md B166. A delivery for the PREVIOUS key may be in
		       -- flight right now (notifier.go delivers with no transaction
		       -- open), and its claim must not gate this new condition:
		       -- leaving notify_attempt_at set would make the row look
		       -- already-claimed and hold the fresh notification back for the
		       -- whole notifyAttemptLease window. Clearing it here is safe in
		       -- the other direction too, because both of
		       -- recordTransitionOutcome's statements are guarded on
		       -- notify_key, so the in-flight delivery cannot come back and
		       -- clear a claim or a pending flag that now belongs to this
		       -- key.
		       notify_attempt_at = NULL
		 WHERE incident_notifications.notify_key IS DISTINCT FROM EXCLUDED.notify_key`,
		incidentID, tenantID, clusterID, key, summary)
	if err != nil {
		return fmt.Errorf("notify: record transition for incident %s (key=%s): %w", incidentID, key, err)
	}
	return nil
}

// transitionRow is exactly what one sweep needs to send and clear one
// pending transition notification — mirrors incidentRow's role for the
// "new incident" sweep in notifier.go.
type transitionRow struct {
	IncidentID string
	// ClusterID and Severity are what the routing table matches on
	// (PROJECT.md F32), alongside the transition token TransitionOf derives
	// from NotifyKey. ClusterID is stored on this table already (migration
	// 000083 denormalizes it); Severity is not, and is read from the incident
	// inside the claim transaction — see severitiesFor. Neither appears in the
	// payload.
	ClusterID string
	Severity  string
	NotifyKey string
	Summary   string
	// UpdatedAt is incident_notifications.updated_at, this queue's
	// oldest-first ordering key. Carried on the row for exactly one reason:
	// claimTransitions claims with an ORDER BY but Postgres does not promise
	// RETURNING hands the rows back in that order, so the claimed batch is
	// re-sorted on this in Go before delivery — see claimIncidents' own note
	// on the same hazard. Nothing in the payload uses it.
	UpdatedAt time.Time
}

// payload builds the Slack-incoming-webhook-shaped JSON body for one
// transition notification — same shape incidentRow.payload() builds, so a
// generic receiver (or a real Slack incoming webhook) needs no branching
// logic to tell the two kinds of message apart.
func (row transitionRow) payload() ([]byte, error) {
	text := fmt.Sprintf("Incident update\nincident: %s\n%s", row.IncidentID, row.Summary)
	return json.Marshal(map[string]string{"text": text})
}
