// Package notify is a slice of DESIGN.md §13 (alerting and notifications) —
// not the full design that section eventually specs. No digests, no per-user
// preferences, no interactive Slack callbacks/approval buttons (§13.4, and
// PROJECT.md F32 keeps them out of scope deliberately: a chat callback is a
// claim, not an authorisation). One transport, HTTP POST, and no email,
// PagerDuty or Opsgenie.
//
// §13.2's routing rules ARE now built, and are routing.go's subject: which
// destination a notification goes to, by cluster group, severity and
// transition (PROJECT.md F32). That file owns the rules, their matching and
// their storage; this one owns the queues and the delivery. The seam between
// them is one resolved RoutingTable per sweep tick, handed to both queues —
// see sweep.
//
// The two questions this file's queues answer are "a new incident happened"
// (incidents.notified_at) and "an incident's open question changed"
// (incident_notifications, transitions.go).
//
// Implemented as an independent background poller, the same architectural
// shape as internal/gateway/health.go's HealthMonitor, rather than a call
// wired directly into internal/gateway/finding.go's handleFinding hot path.
// Hooking it into handleFinding would require Gateway to hold a notifier
// dependency and would touch a file other, unrelated work also needs to
// touch — coupling this package deliberately avoids. Instead,
// incidents.notified_at (migration 000017) is how this poller finds new
// work with no other coordination: NULL means "not yet notified," and
// nothing else in the codebase writes to that column.
//
// The webhook URL itself is now DB-backed and live-editable (internal/settings,
// PUT /api/v1/admin/settings) rather than env-var-only: sweep resolves
// internal/settings.Config fresh on every tick, so a URL set or changed
// through that API takes effect on the very next tick, no hub restart
// required. ARGUS_NOTIFY_WEBHOOK_URL still works exactly as before — it's
// now the seed default a null DB column falls back to, per
// internal/settings.Resolve's precedence rule, not the only source. The
// poller itself now always runs (cmd/hub/main.go no longer conditions
// starting it on an env var being set at startup, since a webhook may be
// configured later, live) — an install with nowhere to deliver simply means
// each sweep tick is a no-op until a destination exists.
//
// That URL is still exactly as live-editable now that it is the DEFAULT RULE's
// destination rather than the only one (PROJECT.md F32), and the rules are
// resolved on the same tick, in the same transaction, for the same reason —
// see resolveSettings. "Nowhere to deliver" is now RoutingTable.Deliverable
// rather than a single boolean on settings.Config, and means the same thing:
// no enabled rule, including the default, has a URL.
//
// # No database transaction is ever open across the webhook POST
//
// PROJECT.md B166. Until 2026-09-17 one sweep was one transaction: it
// selected the un-notified rows, POSTed each one, and marked each row
// notified, all inside it, committing at the end. That made the duration of
// a Postgres transaction equal to the duration of an outbound HTTP call to a
// third-party endpoint nobody here controls — a slow receiver held a
// transaction (and its row locks, and a pooled connection, and the vacuum
// horizon) for as long as it felt like taking, and a receiver that
// blackholes connections pinned one for the client's full 10s timeout per
// row, up to twenty rows at a time.
//
// The sweep is now three phases per queue, and the middle one holds nothing:
//
//	claim   (one short transaction) — take up to notifyBatchSize rows by
//	        stamping notify_attempt_at (migration 000106) and COMMIT. This is
//	        the intent record: durable, and deliberately NOT the delivered
//	        marker.
//	deliver (no transaction at all)  — POST each claimed row.
//	record  (one short transaction per row, opened only after that row's POST
//	        has already returned) — write the outcome.
//
// What that buys, and what it costs, stated plainly because the failure modes
// are the substance of this design rather than a footnote:
//
//   - A hub that dies between the claim commit and the POST leaves a row
//     reading "attempted, not delivered" (notify_attempt_at set, notified_at
//     still NULL). It is NOT lost: once the claim ages past
//     notifyAttemptLease the row is eligible again and the next tick sends
//     it. This is why the intent is a separate column rather than an early
//     write to notified_at — the simpler version would lose exactly the
//     notifications sent while the hub was unhealthy.
//   - A hub that dies between the POST and the outcome write re-sends that
//     one notification after the lease expires. Delivery is therefore
//     AT-LEAST-ONCE, chosen deliberately: this package exists because
//     "nobody saw it" is a product failure (DESIGN.md §13.3), so a duplicate
//     message is the cheaper error. It is bounded — one resend per crashed
//     attempt, not one per tick, because the claim is what makes the row
//     ineligible in the meantime.
//   - A receiver that answers 200 AFTER the client's 10s timeout is
//     indistinguishable from one that never answered, and gets a resend on
//     the next tick. That was equally true before this change.
//   - An ordinary failed POST (connection refused, 500, timeout) is NOT left
//     leased: the outcome write releases the claim (notify_attempt_at back to
//     NULL), so it retries on the very next 30s tick exactly as it did
//     before. The lease governs only the crash case.
//   - Concurrency: the claim is a single atomic UPDATE ... RETURNING over a
//     FOR UPDATE SKIP LOCKED subquery, so two hub processes (or a tick that
//     overlaps a long sweep) cannot claim the same row, and neither can send
//     it twice. The old shape had no such guard — both would have POSTed
//     before either committed.
//
// One thing the old shape did that was worse than a held transaction, and is
// worth recording because it looked like correctness: a single failed UPDATE
// anywhere in the sweep returned an error and rolled the whole transaction
// back, discarding the "notified" marks of every row that had ALREADY been
// POSTed successfully in that batch — up to twenty duplicate messages on the
// next tick. Outcomes are now committed per row, so one row's failure can no
// longer un-record another row's delivery.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/outbound"
	"argus/internal/settings"
)

// DefaultNotifyCheckInterval mirrors gateway.DefaultHealthCheckInterval's
// naming and role: how often Run sweeps for un-notified incidents. 30s is
// "soon, not instant" — this is a notification poller, not a paging system,
// so there's no need for aggressive polling.
const DefaultNotifyCheckInterval = 30 * time.Second

// notifyBatchSize caps how many un-notified incidents one sweep sends —
// small batches, since this is a poller, not a firehose. See sweep's doc
// comment for what happens if a sweep consistently hits this cap.
const notifyBatchSize = 20

// notifyAttemptLease is how long a claimed-but-unconfirmed delivery
// (notify_attempt_at set, nothing recorded since) is left alone before the
// row is treated as claimable again.
//
// It exists for ONE case: a hub that died between committing a claim and
// recording that row's outcome. An ordinary delivery failure never waits for
// it, because the outcome write releases the claim explicitly — see the
// package doc comment. So this is a crash-recovery window, and the trade is
// the opposite of what a retry interval's usually is: too SHORT is the
// dangerous direction, since it would let a second sender pick up a row whose
// first delivery is still legitimately in flight and duplicate it for no
// reason.
//
// 15 minutes is comfortably past the worst case for one claim's own
// claim-to-last-delivery span, which is bounded by the batch cap times the
// client timeout: 20 rows x 10s = 200s, about 3.3 minutes. (Each queue claims
// separately, immediately before delivering its own batch, so the two do not
// add up.) A crashed hub's notification is therefore at most ~15 minutes
// late, against a 30s poll interval for everything else — acceptable for a
// queue whose own doc comment says "soon, not instant", and the honest price
// of not double-sending.
const notifyAttemptLease = 15 * time.Minute

// notifyOrphanGrace is how long an incident_notifications row whose incident
// no longer exists is left alone before reapOrphanedTransitions deletes it.
//
// Pure defence in depth, and deliberately not load-bearing. All three callers
// of NotifyTransition (orchestrator's SetState, approvalwatch.go,
// mergewatch.go) queue the row in the SAME transaction that reads or updates
// the incident, so an orphan can only ever be produced by deleting an incident
// that already had one — never by a notification landing a moment before its
// incident commits, which is the race a grace window would exist to survive.
// The window is here so that a future caller which does not hold that property
// degrades into "reaped an hour late" rather than "notification silently
// deleted before it could be sent".
const notifyOrphanGrace = time.Hour

// notifyOrphanReapBatch caps how many orphaned rows one sweep deletes, for the
// same reason notifyBatchSize caps a delivery batch and for the reason B166
// cares about: this package's transactions are meant to be short. A one-time
// backlog (migration 000120's own case — 1,223 rows on this repo's development
// database) drains over a few ticks instead of holding one long transaction,
// and steady state is far below the cap.
const notifyOrphanReapBatch = 500

// WebhookNotifier posts one JSON message per notification to whichever
// destination the tick's RoutingTable selects for it. Every destination is a
// plain HTTP POST target — Slack incoming webhooks and generic webhook
// receivers both just want a POST'd JSON body, so one plain {"text": "..."}
// payload (Slack's incoming-webhook format, harmless/ignorable for a generic
// receiver that doesn't care about the field name) covers both without any
// Slack-specific code.
//
// One http.Client for every destination, deliberately: internal/outbound's
// policy is a property of what ARGUS is allowed to dial, not of which channel
// an operator picked, so a per-destination client would be a way to end up
// with per-destination egress rules nobody chose.
type WebhookNotifier struct {
	db     *data.DB
	client *http.Client
}

// NewWebhookNotifier builds a WebhookNotifier backed by db. Always non-nil,
// unlike the old NewWebhookNotifierFromEnv's nil-able "ok" contract — see
// the package doc comment for why: whether a real webhook URL is configured
// can now change at runtime (via the settings API), so there's no longer a
// meaningful "not configured at construction time" state, and the poller
// always runs; sweep resolves the URL fresh every tick and simply does
// nothing when it's unconfigured.
func NewWebhookNotifier(db *data.DB) *WebhookNotifier {
	return &WebhookNotifier{
		db: db,
		// The webhook URL is admin-configured (internal/settings) and is
		// exactly T15's misuse case: a compromised admin session or a
		// tampered config value pointing this POST at cloud metadata or an
		// internal-only address. Cloud metadata stays unconditionally
		// refused regardless of the line below (internal/outbound's one
		// absolute) — that is the protection that actually matters for a
		// credential-theft vector here.
		//
		// AllowPrivate: ARGUS is a self-hosted internal tool that may have
		// no public endpoint at all. An operator-typed webhook pointing at
		// an internal alerting endpoint, a LAN Mattermost, or a corporate
		// proxy is the COMMON case for this deployment shape, not the
		// attack — unlike a repository host or an AI provider's base_url,
		// which are expected to be reachable services with their own
		// identity, a notification receiver is routinely something the
		// operator stood up purely for their own internal use.
		client: outbound.NewClient(outbound.Policy{
			AllowPrivate: true,
			Reason:       "ARGUS is self-hosted and commonly has no public endpoint; an internal alerting/chat receiver or corporate proxy is the expected webhook target, not an exception",
		}, 10*time.Second),
	}
}

// incidentRow is exactly what one sweep needs to both build a webhook
// payload and mark the row notified — matches sweep's SELECT column list.
type incidentRow struct {
	ID          string
	ClusterID   string
	Fingerprint string
	Severity    string
	FirstSeen   time.Time
}

// payload builds the Slack-incoming-webhook-shaped JSON body describing one
// incident. Pure function, no I/O — the part of this package that's
// unit-testable without a database or an HTTP server (see notifier_test.go).
//
// Deliberately doesn't join against clusters for a display name, keeping
// sweep's query simple — a plain cluster_id is acceptable for this first
// slice; add the join if a display name earns its keep later.
func (row incidentRow) payload() ([]byte, error) {
	text := fmt.Sprintf(
		"New incident on cluster %s\nincident: %s\nfingerprint: %s\nseverity: %s\nfirst seen: %s",
		row.ClusterID, row.ID, row.Fingerprint, row.Severity, row.FirstSeen.UTC().Format(time.RFC3339))
	return json.Marshal(map[string]string{"text": text})
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, the same pattern
// gateway.HealthMonitor.Run and gateway.Gateway.ListenAndServeTLS already
// use in cmd/hub/main.go's runAPI.
// logger is this package's structured logger (PROJECT.md T22).
var logger = logging.For("notify")

func (n *WebhookNotifier) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := n.sweep(sweepCtx)
			metrics.ObserveSweeperRun("notify", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "notification sweep failed", logging.Err(err))
			}
		}
	}
}

// sweep runs one pass over both queues: resolve the webhook configuration,
// then, per queue, claim a batch of work in one short transaction, deliver it
// with no transaction open at all, and record each outcome in its own short
// transaction afterwards.
//
// That three-phase division is the whole of PROJECT.md B166 and is
// load-bearing rather than stylistic — the package doc comment states the
// contract and every failure mode it chooses. The one rule a change here must
// not break: nothing between a claim's COMMIT and an outcome's BEGIN may touch
// the database, because that span is where the HTTP call lives.
//
// nil accessible-cluster-ids is deliberate in every transaction below (unlike
// gateway.handleFinding's narrowing to one known cluster): this poller isn't
// scoped to a single cluster the way a tunnel connection is — it needs to see
// un-notified incidents across the whole tenant, the same access shape GET
// /api/v1/incidents already relies on, which migration 000013's
// tenant_id-keyed policy on incidents makes legal.
//
// Both queues are handed the SAME resolved URL, so a webhook outage or an
// unconfigured URL affects them identically rather than needing separate
// handling — the shared-delivery-half property transitions.go's own doc
// comment is built on. They no longer share a single transaction (nothing
// could, now that delivery happens outside one), and nothing depended on
// their commits being atomic with each other: they are independent rows in
// independent tables, each with its own claim and its own outcome.
func (n *WebhookNotifier) sweep(ctx context.Context) error {
	tenantID, routing, err := n.resolveSettings(ctx)
	if err != nil {
		return err
	}

	// PROJECT.md B175, and deliberately ABOVE the "is a webhook configured"
	// check below rather than beside the queue it cleans up. An orphaned row
	// is undeliverable whether or not a URL is set, and a stack that has never
	// configured one is precisely where the debris accumulates unseen — which
	// is what this repo's own development database did: 1,223 orphaned rows,
	// 39 of them still pending, waiting for the day somebody set a webhook URL
	// and got a burst of notifications about incidents that no longer exist.
	//
	// Not fatal to the tick: housekeeping must never be the reason a real
	// notification does not go out. Logged and stepped over, the same way
	// internal/partition's sweep treats one table's failure.
	if reaped, err := n.reapOrphanedTransitions(ctx, tenantID); err != nil {
		logger.ErrorContext(ctx, "reaping orphaned incident notifications failed; delivery continues", logging.Err(err))
	} else if reaped > 0 {
		logger.InfoContext(ctx, "deleted queued notifications whose incident no longer exists",
			slog.Int64("reaped", reaped))
	}

	// Not configured is not an error: it just means this tick has nothing to
	// do, exactly like the old "poller doesn't run at all" behavior, except
	// checked per-tick instead of once at startup.
	//
	// PROJECT.md F32 widened what "configured" means from one URL to "any
	// enabled rule has a destination with a URL" (RoutingTable.Deliverable),
	// and the default rule carries internal/settings' own URL, so an install
	// that has never written a rule answers this question exactly as it did
	// before. What matters is that it is still checked BEFORE anything is
	// claimed: an install with nowhere to deliver must not stamp claims it
	// cannot honour.
	if !routing.Deliverable() {
		return nil
	}

	if err := n.sweepIncidents(ctx, tenantID, routing); err != nil {
		return err
	}
	// BACKLOG.md N1: the widened trigger set's own pending queue
	// (incident_notifications, migration 000083).
	return n.sweepTransitions(ctx, tenantID, routing)
}

// resolveSettings reads the tenant id and the routing configuration for one
// tick, in a read-only transaction that is closed before anything is claimed
// or delivered.
//
// Resolved fresh every tick (see the package doc comment) — a webhook URL set
// or changed via PUT /api/v1/admin/settings takes effect on the very next
// tick. PROJECT.md F32 extends that same property to the rules: they are read
// here, in this same transaction, so a rule written through
// PUT /api/v1/admin/notification-routing is in force on the next tick too, and
// for the same reason (nothing is cached across ticks). The two are resolved
// together rather than in separate transactions because the default rule IS
// settings' own URL — reading them apart would let a tick route against a
// default that had already changed.
//
// The tenant id is then reused by this tick's other transactions without
// re-resolving it: data.SingleOrganisationID is a server-side constant for
// this confirmed single-organisation deployment, not request-derived state, so
// re-reading it per transaction would buy nothing but round trips. Each of
// those transactions still sets its OWN request scope from it, which is the
// part that actually has to happen per transaction (SET LOCAL does not outlive
// one).
func (n *WebhookNotifier) resolveSettings(ctx context.Context) (string, RoutingTable, error) {
	var tenantID string
	var routing RoutingTable
	// Read-only, so the commit InFleetScope does at the end is a no-op that
	// costs one round trip — worth it for not being the one transaction in
	// this file that opens itself (PROJECT.md G11).
	if err := data.InFleetScope(ctx, n.db.Pool, func(ctx context.Context, tx pgx.Tx, tenant string) error {
		tenantID = tenant
		cfg, err := settings.Resolve(ctx, tx)
		if err != nil {
			return fmt.Errorf("resolve notification settings: %w", err)
		}
		routing, err = LoadRouting(ctx, tx, cfg.NotifyWebhookURL)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return "", RoutingTable{}, err
	}
	return tenantID, routing, nil
}

// inTx runs f inside a new transaction scoped to tenantID, and commits it.
//
// Every database touch in the delivery path goes through this one helper, and
// that is deliberate: it makes each of them a single statement with no room
// for I/O to creep back inside a transaction, which is the defect B166 fixed.
//
// It is now a thin wrapper over data.InScope, which is this same idea moved
// somewhere every background caller can reach it (PROJECT.md G11). Kept rather
// than inlined at its eleven call sites because the signature f takes here —
// no ctx, tenant already bound — is what makes those call sites one-liners,
// and because B166's "no I/O inside a transaction" rule is a property of this
// package's delivery path specifically, not of InScope.
func (n *WebhookNotifier) inTx(ctx context.Context, tenantID string, f func(tx pgx.Tx) error) error {
	return data.InScope(ctx, n.db.Pool, tenantID, nil, func(ctx context.Context, tx pgx.Tx) error {
		return f(tx)
	})
}

// outcomeContext is the context an outcome write runs under: detached from
// the sweep's own cancellation, with its own short deadline.
//
// Detached on purpose. The sweep's ctx is the hub's worker context, which is
// cancelled on SIGTERM — and a POST that has already succeeded must still get
// recorded, or a graceful shutdown timed a few hundred milliseconds unluckily
// turns into a duplicate notification after the restart. The row's delivery
// is already done by the time this is called; all that remains is one UPDATE,
// and it is worth finishing.
//
// The deadline is what keeps that from becoming its own version of the bug
// this file just fixed: a detached context with no timeout would let a
// wedged database hold the shutdown open indefinitely.
func outcomeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

// sweepIncidents runs the "a new incident happened" queue
// (incidents.notified_at, migration 000017) through the claim/deliver/record
// phases.
//
// Every row is routed individually through the tick's RoutingTable
// (PROJECT.md F32) rather than sharing one resolved URL, because the whole
// point of the rules is that two rows in the same batch can legitimately
// belong to different teams. The table is already resolved and holds no
// transaction, so routing costs no database work inside the delivery loop —
// which is what keeps B166's "nothing between a claim's COMMIT and an
// outcome's BEGIN touches the database" rule intact.
func (n *WebhookNotifier) sweepIncidents(ctx context.Context, tenantID string, routing RoutingTable) error {
	incidents, err := n.claimIncidents(ctx, tenantID)
	if err != nil {
		return err
	}

	// Not fatal on its own (the sweep still proceeds) — a signal worth
	// seeing in logs that un-notified incidents may be arriving faster than
	// this poller is sending them, since consistently hitting the cap means
	// some rows are waiting more than one tick.
	if len(incidents) == notifyBatchSize {
		logger.WarnContext(ctx, "sweep hit the batch cap; un-notified incidents may be accumulating",
			slog.Int("batch_size", notifyBatchSize))
	}

	for _, row := range incidents {
		body, err := row.payload()
		if err != nil {
			// A marshal error is a bug in this package, not a delivery
			// failure — log it, and release the claim rather than leaving the
			// row leased for the crash window, but never mark it notified:
			// nothing was sent.
			logger.ErrorContext(ctx, "building the notification payload failed",
				logging.IncidentID(row.ID), logging.Err(err))
			n.recordIncidentOutcome(ctx, tenantID, row.ID, false)
			continue
		}

		rule := n.route(ctx, routing, Notification{
			ClusterID:  row.ClusterID,
			Severity:   row.Severity,
			Transition: TransitionNewIncident,
		}, row.ID)

		// The one line in this package that must not have a transaction open
		// around it.
		delivered := true
		if err := n.post(ctx, rule.Destination.URL, body); err != nil {
			logger.WarnContext(ctx, "POST to the notification webhook failed; retrying next sweep",
				logging.IncidentID(row.ID), slog.String("rule", rule.Name),
				slog.String("destination", rule.Destination.Name), logging.Err(err))
			delivered = false
		}
		n.recordIncidentOutcome(ctx, tenantID, row.ID, delivered)
	}
	return nil
}

// route selects the rule that governs one notification and reports the two
// cases a reader has to be able to tell apart in a log.
//
// Both are "this notification is not going anywhere useful", and neither is
// silent, because this package's failure mode is nobody seeing something:
//
//   - No rule matched at all. Structurally impossible — LoadRouting always
//     appends an unconditional default — so it means the routing table came
//     from somewhere else, and it is reported as the bug it would be. The
//     zero Rule that comes back has an empty URL, so the POST fails and the
//     row is retried rather than marked sent.
//   - A rule matched but its destination has no URL. Reachable exactly once:
//     the default rule on an install that configured a rule but never set
//     ARGUS_NOTIFY_WEBHOOK_URL or the settings column, so Deliverable() is
//     true on the strength of the other rule while anything falling through
//     to the default has nowhere to go. Logged naming the rule, so the fix
//     ("your catch-all has no destination") is visible rather than appearing
//     as a generic POST failure to the empty string.
func (n *WebhookNotifier) route(ctx context.Context, routing RoutingTable, notification Notification, incidentID string) Rule {
	rule, ok := routing.Match(notification)
	if !ok {
		logger.ErrorContext(ctx, "no notification rule matched and no default rule was present",
			logging.IncidentID(incidentID), slog.String("transition", notification.Transition))
		return rule
	}
	if rule.Destination.URL == "" {
		logger.WarnContext(ctx, "the matching notification rule has no destination URL; retrying next sweep",
			logging.IncidentID(incidentID), slog.String("rule", rule.Name),
			slog.String("transition", notification.Transition))
	}
	return rule
}

// claimIncidents takes up to notifyBatchSize un-notified incidents and
// returns exactly the rows it took, committed.
//
// One UPDATE ... RETURNING over a FOR UPDATE SKIP LOCKED subquery, not a
// SELECT followed by an UPDATE: the two-statement version leaves a window in
// which a second sweep selects the same rows, and being unable to do that is
// the entire point of a claim. SKIP LOCKED makes a concurrent claimer take
// the NEXT rows rather than block behind this one — a poller must never wait
// on another poller.
//
// The lease predicate is evaluated in SQL (now() - make_interval) rather than
// against a Go-computed cutoff so that claim and release are timed by one
// clock, Postgres's, the same one that wrote notify_attempt_at.
func (n *WebhookNotifier) claimIncidents(ctx context.Context, tenantID string) ([]incidentRow, error) {
	var claimed []incidentRow
	err := n.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`UPDATE incidents SET notify_attempt_at = now()
			   WHERE (id, first_seen) IN (
			         SELECT id, first_seen FROM incidents
			          WHERE notified_at IS NULL
			            AND (notify_attempt_at IS NULL
			                 OR notify_attempt_at < now() - make_interval(secs => $2))
			          ORDER BY first_seen ASC
			          LIMIT $1
			          FOR UPDATE SKIP LOCKED)
			 RETURNING id, cluster_id, fingerprint, severity, first_seen`,
			notifyBatchSize, notifyAttemptLease.Seconds())
		if err != nil {
			return fmt.Errorf("claim un-notified incidents: %w", err)
		}
		for rows.Next() {
			var r incidentRow
			if err := rows.Scan(&r.ID, &r.ClusterID, &r.Fingerprint, &r.Severity, &r.FirstSeen); err != nil {
				rows.Close()
				return fmt.Errorf("scan claimed incident: %w", err)
			}
			claimed = append(claimed, r)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate claimed incidents: %w", err)
		}
		return nil
	})
	if err != nil {
		// Nothing was committed, so nothing was claimed — drop whatever was
		// scanned rather than delivering rows whose claim rolled back.
		return nil, err
	}

	// The subquery's ORDER BY chooses WHICH rows are claimed; it does not
	// order what RETURNING hands back, which Postgres leaves unspecified.
	// Sorting here is what keeps delivery oldest-first, the order the old
	// SELECT-then-POST loop had for free and the only order a queue should
	// drain in — without it the notification a person waits on is whichever
	// one the executor happened to touch first. Caught by a test that
	// assumed the queue order and got the other one (delivery_db_test.go).
	sort.SliceStable(claimed, func(i, j int) bool {
		return claimed[i].FirstSeen.Before(claimed[j].FirstSeen)
	})
	return claimed, nil
}

// recordIncidentOutcome writes one incident's delivery result, in its own
// transaction, opened only after that row's POST has already returned.
//
// Best-effort, and the two failure directions are deliberately not
// symmetrical. Failing to record a SUCCESS means that one notification is
// re-sent once its claim ages past notifyAttemptLease — a duplicate. Failing
// to record a FAILURE means it is retried after the lease instead of on the
// next tick — a delay. Neither is worth aborting the rest of the batch for,
// so both are logged and the sweep continues; the old code's "return an
// error" here rolled back the whole batch's marks and re-sent every already-
// delivered row.
func (n *WebhookNotifier) recordIncidentOutcome(ctx context.Context, tenantID, incidentID string, delivered bool) {
	// PROJECT.md T11's notification-delivery-failures metric — recorded
	// here, at the point `delivered` is already known, rather than at
	// sweepIncidents' own call site, so it covers the marshal-error branch
	// (payload build failed, never even attempted a POST) the same way as
	// an ordinary failed POST: both are "this notification was not
	// delivered," which is the question this counter answers.
	metrics.NotifyDeliveryTotal.Inc(deliveryOutcome(delivered))
	// Releasing the claim (notify_attempt_at = NULL) on BOTH paths keeps that
	// column meaning exactly one thing: "a delivery is in flight, or a hub
	// died while one was". notified_at remains the only record of delivery.
	stmt := `UPDATE incidents SET notify_attempt_at = NULL WHERE id = $1`
	if delivered {
		stmt = `UPDATE incidents SET notified_at = now(), notify_attempt_at = NULL WHERE id = $1`
	}

	outcomeCtx, cancel := outcomeContext(ctx)
	defer cancel()
	if err := n.inTx(outcomeCtx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(outcomeCtx, stmt, incidentID)
		return err
	}); err != nil {
		if delivered {
			logger.ErrorContext(ctx, "the webhook accepted the message but recording it failed; it will be re-sent once the claim expires",
				logging.IncidentID(incidentID), slog.Duration("claim_lease", notifyAttemptLease), logging.Err(err))
			return
		}
		logger.WarnContext(ctx, "releasing the delivery claim failed; it retries once the claim expires rather than next tick",
			logging.IncidentID(incidentID), slog.Duration("claim_lease", notifyAttemptLease), logging.Err(err))
	}
}

// deliveryOutcome maps a webhook delivery's success/failure to
// metrics.NotifyDeliveryTotal's closed two-value outcome label.
func deliveryOutcome(delivered bool) string {
	if delivered {
		return "success"
	}
	return "failure"
}

// reapOrphanedTransitions deletes incident_notifications rows whose incident
// no longer exists, and reports how many it deleted.
//
// PROJECT.md B175. This is the half of that fix that makes the debris stop
// ACCUMULATING; claimTransitions' own EXISTS guard is the half that makes it
// stop being DELIVERED. Both are needed, because they answer different
// questions: the guard keeps a dead incident out of a batch on the very next
// tick, and this keeps the table from growing a permanent tail of rows the
// guard has to skip past forever.
//
// # Why this is not a foreign key
//
// The obvious fix — incident_notifications.incident_id REFERENCES
// incidents(id) ON DELETE CASCADE — cannot be declared and would not work if
// it could. Measured against a real Postgres 16 while writing this:
//
//   - incidents is PARTITION BY RANGE (first_seen) with PRIMARY KEY
//     (id, first_seen) (migration 000005), and a unique constraint on a
//     partitioned table must contain the partition key. `REFERENCES
//     incidents(id)` therefore fails outright with "there is no unique
//     constraint matching given keys for referenced table". Migration 000083's
//     own comment already said so; it is confirmed, not assumed.
//   - A composite FK on (incident_id, first_seen) IS declarable, and it breaks
//     internal/partition. That job implements retention by DROP TABLE on a
//     whole dated partition, which is exactly where production incidents go to
//     die — and a partition that a foreign key references cannot be dropped:
//     "cannot drop table incidents_y2026m09 because other objects depend on
//     it". The cascade never fires, because the delete never happens. A
//     referential-integrity fix would convert silent debris into a daily
//     partition-maintenance job that fails, which is worse.
//
// So orphans are a fact of this schema, not a bug in it, and the notification
// queue has to tolerate them rather than forbid them.
//
// # Why deleting here cannot delete something real
//
// Both tables are read under the same scope this sweep sets for everything
// else (tenant set, accessible_cluster_ids nil). That matters: if RLS hid
// incidents, every row would LOOK orphaned. It cannot happen in the direction
// that would destroy data, because incident_notifications' policies are never
// WIDER than incidents' — with no tenant set, incident_notifications is
// invisible too and this DELETE touches nothing; with cluster ids set,
// incidents narrows to the same cluster ids. The visibility of the two tables
// moves together, so "cannot see the incident" always implies "cannot see the
// notification either".
func (n *WebhookNotifier) reapOrphanedTransitions(ctx context.Context, tenantID string) (int64, error) {
	var reaped int64
	err := n.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		// The LIMIT lives in a subquery because DELETE has no LIMIT clause of
		// its own. Bounded by notifyOrphanReapBatch so one tick's transaction
		// stays short even against a large backlog, per B166's discipline.
		tag, err := tx.Exec(ctx,
			`DELETE FROM incident_notifications
			  WHERE incident_id IN (
			        SELECT n.incident_id FROM incident_notifications n
			         WHERE n.updated_at < now() - make_interval(secs => $2)
			           AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = n.incident_id)
			         LIMIT $1)`,
			notifyOrphanReapBatch, notifyOrphanGrace.Seconds())
		if err != nil {
			return fmt.Errorf("reap orphaned incident notifications: %w", err)
		}
		reaped = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return reaped, nil
}

// sweepTransitions runs the pending-transition queue (incident_notifications,
// migration 000083 — see transitions.go's own doc comment for what "pending"
// means) through the same claim/deliver/record phases sweepIncidents uses, and
// with the same "a failed POST is retried, never marked sent" discipline.
//
// Split out from sweep only for readability; it is one queue of two, sharing
// this tick's resolved routing table and HTTP client.
func (n *WebhookNotifier) sweepTransitions(ctx context.Context, tenantID string, routing RoutingTable) error {
	pending, err := n.claimTransitions(ctx, tenantID)
	if err != nil {
		return err
	}

	for _, row := range pending {
		body, err := row.payload()
		if err != nil {
			logger.ErrorContext(ctx, "building the transition notification payload failed",
				logging.IncidentID(row.IncidentID), logging.Err(err))
			n.recordTransitionOutcome(ctx, tenantID, row, false)
			continue
		}

		// PROJECT.md F32. The transition token comes from the stored
		// notify_key rather than from a column of its own: the key already
		// begins with the state name in both of the shapes callers produce,
		// and TransitionOf is the one place that fact is written down. That
		// keeps `Reopened` — which internal/orchestrator's notifiableStates
		// already queues, and which F32 requires a rule to be able to name —
		// matchable with no change to the writer side at all.
		rule := n.route(ctx, routing, Notification{
			ClusterID:  row.ClusterID,
			Severity:   row.Severity,
			Transition: TransitionOf(row.NotifyKey),
		}, row.IncidentID)

		delivered := true
		if err := n.post(ctx, rule.Destination.URL, body); err != nil {
			logger.WarnContext(ctx, "POST of a transition notification to the webhook failed; retrying next sweep",
				logging.IncidentID(row.IncidentID), slog.String("notify_key", row.NotifyKey),
				slog.String("rule", rule.Name), slog.String("destination", rule.Destination.Name),
				logging.Err(err))
			delivered = false
		}
		n.recordTransitionOutcome(ctx, tenantID, row, delivered)
	}
	return nil
}

// claimTransitions is claimIncidents' counterpart for the transition queue —
// same atomic UPDATE ... RETURNING / SKIP LOCKED claim, same lease predicate.
//
// It deliberately does NOT touch updated_at: that column is this queue's
// ORDER BY key, so stamping it on claim would reorder the queue every tick and
// starve whatever sat at the front of it.
//
// The EXISTS predicate is PROJECT.md B175: a notification for an incident that
// no longer exists is never claimed, so it is never POSTed. That is a
// correctness rule, not an optimisation — the message this package would send
// names an incident id, and a reader who follows it finds nothing. It is
// checked at claim time rather than at delivery time on purpose: a row filtered
// out here is never stamped notify_attempt_at, so a dead incident cannot
// consume one of the batch's twenty slots ahead of a live one, which is the
// same starvation hazard PROJECT.md's own "a LIMIT with an ORDER BY that
// favours dead rows starves the live ones" lesson records for the
// auto-analysis candidate query. reapOrphanedTransitions then removes the
// rows this guard would otherwise skip past on every tick forever.
func (n *WebhookNotifier) claimTransitions(ctx context.Context, tenantID string) ([]transitionRow, error) {
	var claimed []transitionRow
	err := n.inTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`UPDATE incident_notifications SET notify_attempt_at = now()
			   WHERE incident_id IN (
			         SELECT n.incident_id FROM incident_notifications n
			          WHERE n.pending = true
			            AND (n.notify_attempt_at IS NULL
			                 OR n.notify_attempt_at < now() - make_interval(secs => $2))
			            AND EXISTS (SELECT 1 FROM incidents i WHERE i.id = n.incident_id)
			          ORDER BY n.updated_at ASC
			          LIMIT $1
			          FOR UPDATE SKIP LOCKED)
			 RETURNING incident_id, cluster_id, notify_key, summary, updated_at`,
			notifyBatchSize, notifyAttemptLease.Seconds())
		if err != nil {
			return fmt.Errorf("claim pending incident notifications: %w", err)
		}
		for rows.Next() {
			var r transitionRow
			if err := rows.Scan(&r.IncidentID, &r.ClusterID, &r.NotifyKey, &r.Summary, &r.UpdatedAt); err != nil {
				rows.Close()
				return fmt.Errorf("scan claimed incident notification: %w", err)
			}
			claimed = append(claimed, r)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate claimed incident notifications: %w", err)
		}
		return severitiesFor(ctx, tx, claimed)
	})
	if err != nil {
		return nil, err
	}

	// Oldest-first delivery order, restored in Go — see claimIncidents for why
	// the claim query's own ORDER BY does not give it.
	sort.SliceStable(claimed, func(i, j int) bool {
		return claimed[i].UpdatedAt.Before(claimed[j].UpdatedAt)
	})
	return claimed, nil
}

// severitiesFor fills in each claimed row's incident severity, which the
// routing table matches on (PROJECT.md F32) and incident_notifications does
// not store.
//
// A SECOND statement inside the claim transaction rather than a join in the
// claim itself, because RETURNING can only reference the table being updated.
// It has to happen here, before the claim commits, for B166's reason: once the
// claim is committed the sweep is in the span where the HTTP call lives, and
// nothing in that span may touch the database.
//
// Severity is left empty for a row whose incident disappeared between the
// claim and this statement — a race claimTransitions' own EXISTS guard makes
// vanishingly unlikely and does not forbid. An empty severity ranks below
// every rule's minimum, so such a row falls through to the default rule and is
// still delivered, which is the right direction: the alternative is dropping a
// notification because of a lookup that is only there to refine where it goes.
func severitiesFor(ctx context.Context, tx pgx.Tx, claimed []transitionRow) error {
	if len(claimed) == 0 {
		return nil
	}
	ids := make([]string, 0, len(claimed))
	for _, r := range claimed {
		ids = append(ids, r.IncidentID)
	}
	rows, err := tx.Query(ctx, `SELECT id, severity FROM incidents WHERE id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("read severities for claimed incident notifications: %w", err)
	}
	defer rows.Close()
	severities := make(map[string]string, len(claimed))
	for rows.Next() {
		var id, severity string
		if err := rows.Scan(&id, &severity); err != nil {
			return fmt.Errorf("scan severity for a claimed incident notification: %w", err)
		}
		severities[id] = severity
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate severities for claimed incident notifications: %w", err)
	}
	for i := range claimed {
		claimed[i].Severity = severities[claimed[i].IncidentID]
	}
	return nil
}

// recordTransitionOutcome writes one transition notification's delivery
// result, in its own transaction, after its POST has returned.
//
// Guarded on notify_key as well as incident_id, on BOTH the delivered and the
// released path: if the key changed after this row was claimed (a new
// transition landed mid-delivery, in a different transaction, and is itself
// now pending — NotifyTransition resets notify_attempt_at when that happens),
// neither statement must touch it. Clearing `pending` would drop a
// notification for a condition that was never sent, and clearing the claim
// would release a lease this delivery does not own. A non-match leaves the row
// exactly as NotifyTransition left it: pending, unclaimed, and picked up next
// tick.
func (n *WebhookNotifier) recordTransitionOutcome(ctx context.Context, tenantID string, row transitionRow, delivered bool) {
	metrics.NotifyDeliveryTotal.Inc(deliveryOutcome(delivered))
	stmt := `UPDATE incident_notifications SET notify_attempt_at = NULL
	           WHERE incident_id = $1 AND notify_key = $2`
	if delivered {
		stmt = `UPDATE incident_notifications SET pending = false, notified_at = now(), notify_attempt_at = NULL
		           WHERE incident_id = $1 AND notify_key = $2`
	}

	outcomeCtx, cancel := outcomeContext(ctx)
	defer cancel()
	if err := n.inTx(outcomeCtx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(outcomeCtx, stmt, row.IncidentID, row.NotifyKey)
		return err
	}); err != nil {
		if delivered {
			logger.ErrorContext(ctx, "the webhook accepted the transition but recording it failed; it will be re-sent once the claim expires",
				logging.IncidentID(row.IncidentID), slog.String("notify_key", row.NotifyKey),
				slog.Duration("claim_lease", notifyAttemptLease), logging.Err(err))
			return
		}
		logger.WarnContext(ctx, "releasing a transition delivery claim failed; it retries once the claim expires rather than next tick",
			logging.IncidentID(row.IncidentID), slog.String("notify_key", row.NotifyKey),
			slog.Duration("claim_lease", notifyAttemptLease), logging.Err(err))
	}
}

// post sends one webhook POST to url and reports an error unless the
// response status is 2xx. Never returns a nil error on a non-2xx response —
// sweep depends on that to decide whether to mark a row notified. url is an
// explicit parameter (rather than a field on WebhookNotifier) because it's
// now resolved fresh per sweep tick, not fixed at construction time — see
// the package doc comment.
func (n *WebhookNotifier) post(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
