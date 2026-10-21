package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// BatchExecution: staged unattended rollout across a fleet group.
// BACKLOG.md R3 — the piece blastradius.go's own doc comment named as
// deliberately unbuilt: "the cap refuses; it does not stage."
//
// # What the poller already did, before this file existed
//
// internal/api/unattended.go's sweepUnattended refuses a candidate past the
// blast-radius cap with a `continue` and a log line — nothing marks the
// incident, nothing excludes it from the NEXT tick's candidate query. So a
// refused candidate is silently re-evaluated every 30 seconds until either
// the rolling window opens room (and it executes, unattended, with no more
// deliberation than "there happened to be budget this time") or its
// recommendation ages out past maxUnattendedPlanAge (10 minutes) and falls
// to the human queue. That is a crude, ACCIDENTAL form of staggering — it
// has no idea the candidates it is staggering are the same correlated fault,
// it applies no order, and it never watches whether an earlier execution's
// fix actually held before letting a later one through. This file is the
// deliberate version: it groups the correlated case on purpose, always
// executes a small canary first, and gates the rest on that canary's real
// ValidationSweeper outcome rather than on when the volume cap happens to
// have room.
//
// # Why this is additional, not a replacement
//
// blastradius.go's per-cluster/fleet-wide caps and breaker.go's outcome
// breaker both stay exactly as they are and still apply to every candidate,
// batched or not — a wave-1 candidate still has to clear the ordinary
// budget/breaker gates to execute, same as before this file existed. This
// mechanism only adds a THIRD gate for the specific case fleet correlation
// already detects: hold the non-canary members back regardless of how much
// budget remains, until the canary's outcome is known.
//
// # The batch/wave model
//
// A "batch" is identified by (tenant, fleet_group_id, action_type): the set
// of incidents internal/fleetgroup has already correlated as the same fault
// across clusters, that are also all eligible for the identical unattended
// remediation action_type around the same time. The first time such a group
// reaches two or more members, ResolveBatchGating creates one, assigning a
// small "wave 1" (waveOneSize) and putting everyone else in "wave 2". Wave 1
// flows through the ordinary pipeline unchanged; wave 2 is held — excluded
// from this tick's executable candidates — until wave 1's fate is known:
//
//   - every wave-1 incident reaches Resolved -> the batch is `released` and
//     wave 2 joins the ordinary pipeline too.
//   - any wave-1 incident's outcome is anything else (Reopened, most
//     visibly, but treated the same as any other non-Resolved terminal
//     state — see classifyIncidentState) -> the batch is `blocked` and
//     wave 2 stays held indefinitely. A human can still approve any held
//     incident by hand; this only gates the UNATTENDED path.
//   - wave 1 never reaches either outcome within maxBatchHoldDuration -> the
//     batch is `abandoned`, purely for visibility (by the time this fires,
//     wave 2's own recommendations have almost always independently aged
//     out of maxUnattendedPlanAge too).
//
// One batch per key, ever (enforced by migration 000073's unique index): a
// straggler that shows up after the batch already exists joins it as a new
// wave-2 member rather than starting a second batch, and inherits whatever
// status the batch has already reached.

// BatchStatus values. Mirrors migration 000073's CHECK constraint exactly.
const (
	BatchStatusWave1Pending = "wave1_pending"
	BatchStatusReleased     = "released"
	BatchStatusBlocked      = "blocked"
	BatchStatusAbandoned    = "abandoned"
)

// maxBatchHoldDuration bounds how long a batch may sit waiting on wave 1
// before this package gives up watching it (see BatchStatusAbandoned).
//
// Sized against validationGracePeriod (15 minutes, itself a floor — B2 can
// stretch it further per-cluster) plus real headroom for wave 1 to actually
// execute: a wave-1 candidate can lose to the blast-radius cap for several
// ticks before winning a slot. Two hours is generous enough that a
// genuinely-progressing batch is never abandoned out from under itself,
// while still being a bounded number rather than "forever" for an operator
// looking at a batch that has been sitting for a day.
const maxBatchHoldDuration = 2 * time.Hour

// waveOneSize decides wave 1's size for a batch of `total` correlated,
// simultaneously-eligible candidates. Deliberately small and NOT a fixed
// fraction of total — the point of wave 1 is to be cheap to be wrong about,
// and a percentage would let wave 1 itself grow into a double-digit blast
// radius on a large fleet.
//
//   - total <= 3: wave 1 is exactly one cluster. Holding back more than one
//     of a 2-3-cluster batch would barely reduce the eventual wrong-fix
//     count anyway, so there is nothing to gain from a bigger canary.
//   - total >= 4: wave 1 is two clusters. A second, independent validation
//     is meaningfully more confidence than one — a single cluster's result
//     could be a fluke of that cluster's own state — while two is still a
//     small fraction of any batch this codebase's default caps allow
//     (DefaultUnattendedLimits.MaxFleetWide is 10 per hour).
func waveOneSize(total int) int {
	if total <= 3 {
		return 1
	}
	return 2
}

// waveOutcome is classifyIncidentState's judgement of one wave-1 incident.
type waveOutcome int

const (
	waveOutcomePending waveOutcome = iota
	waveOutcomeSuccess
	waveOutcomeFailure
)

// classifyIncidentState buckets one wave-1 incident's current state for the
// purpose of deciding whether wave 1 held.
//
// Only StateResolved counts as success. Every state that is not one of the
// three "still in flight" ones is read as a failure — not just Reopened
// specifically. This is deliberately the safety-first direction BACKLOG.md
// R3 asks for ("a wrong diagnosis is caught after wave 1's few clusters"):
// Dismissed, Failed, or a bounce back to Investigating from Validating/
// Executing are all states this incident should not have reached if wave
// 1's fix cleanly worked, and treating any of them as "probably fine, release
// wave 2" would be exactly the kind of optimistic reading a safety gate must
// not make. The cost of this choice is symmetrical with V1's own
// (validation.go): occasionally holding wave 2 back for an incident a human
// closed for unrelated reasons, rather than ever releasing it on an ambiguous
// signal.
func classifyIncidentState(state string) waveOutcome {
	switch state {
	case StateResolved:
		return waveOutcomeSuccess
	case StateAwaitingApproval, StateExecuting, StateValidating:
		return waveOutcomePending
	default:
		return waveOutcomeFailure
	}
}

// decideBatchOutcome is ResolveBatchGating's pure judgement, given wave 1's
// current incident states and how long the batch has been open, pulled out
// so it is unit-testable without a database (see batch_test.go) — the same
// discipline blastradius.go's decide and fleetgroup.decideGroupID already
// established for this codebase.
//
// A failure is checked before completeness on purpose: one wave-1 incident
// already having failed is decisive and should block immediately, without
// waiting for the rest of wave 1 (which might still be Executing) to also
// conclude. That is the whole point of a small wave 1 — catching the bad
// signal as early as possible, not waiting for every canary to finish before
// noticing the first one already said no.
func decideBatchOutcome(wave1States []string, age time.Duration) (newStatus string, changed bool) {
	sawFailure := false
	allSuccess := len(wave1States) > 0
	for _, s := range wave1States {
		switch classifyIncidentState(s) {
		case waveOutcomeFailure:
			sawFailure = true
		case waveOutcomePending:
			allSuccess = false
		}
	}
	switch {
	case sawFailure:
		return BatchStatusBlocked, true
	case allSuccess:
		return BatchStatusReleased, true
	case age > maxBatchHoldDuration:
		return BatchStatusAbandoned, true
	default:
		return BatchStatusWave1Pending, false
	}
}

// BatchCandidate is one unattended candidate incident as this file needs to
// know about it — a narrowed view of internal/api's own unattendedCandidate,
// kept separate so this package does not depend on internal/api's type.
type BatchCandidate struct {
	IncidentID   string
	ClusterID    string
	ActionType   string
	FleetGroupID *string // nil/empty: not part of any fleet group, never batched.
}

// BatchMembership is what ResolveBatchGating found or created for one
// candidate incident.
type BatchMembership struct {
	BatchID     string
	WaveNumber  int
	BatchStatus string
}

// Eligible reports whether this membership permits the ordinary unattended
// pipeline to execute the candidate THIS tick. Wave 1 always is — it is what
// produces the signal the rest of the batch waits on. Wave 2 (and any later
// straggler, which always joins as wave 2) is eligible only once the batch
// has been released.
func (m BatchMembership) Eligible() bool {
	if m.WaveNumber <= 1 {
		return true
	}
	return m.BatchStatus == BatchStatusReleased
}

// HoldReason explains, for an operator-facing log line, why an ineligible
// member is not executing this tick. Callers should only use this when
// Eligible() is false.
func (m BatchMembership) HoldReason() string {
	switch m.BatchStatus {
	case BatchStatusBlocked:
		return fmt.Sprintf("part of unattended batch %s: wave 1's fix did NOT hold, so the rest of this fleet-wide batch stays held for a human rather than repeating the same fix", m.BatchID)
	case BatchStatusAbandoned:
		return fmt.Sprintf("part of unattended batch %s: wave 1 never reached a validated outcome in time, so the rest stays held for a human", m.BatchID)
	default:
		return fmt.Sprintf("part of unattended batch %s: waiting for wave 1 to validate before wave 2 is released", m.BatchID)
	}
}

// batch is the internal row shape ResolveBatchGating reads/writes against
// unattended_batches. Not exported: BatchMembership is the only shape a
// caller outside this file needs.
type batch struct {
	ID        string
	Status    string
	Wave1Size int
	TotalSize int
	CreatedAt time.Time
}

// ResolveBatchGating is called once per unattended sweep tick, inside the
// same transaction collectUnattended already holds, before any candidate
// executes. It does three things, in order:
//
//  1. Resolves every batch still waiting on wave 1 against its wave-1
//     members' CURRENT incident states (resolveBatchOutcomes) — so a batch
//     that just found out its canary held or reopened reflects that in the
//     very same tick's gating decision below, not one tick later.
//  2. Groups this tick's candidates that share a non-null fleet_group_id and
//     action_type and have no existing membership, creating a new batch the
//     first time such a group reaches two or more members, or attaching
//     newcomers to an already-existing batch for that key as wave-2
//     stragglers.
//  3. Returns, for every candidate that belongs to some batch, that
//     membership — the caller (internal/api/unattended.go) uses
//     BatchMembership.Eligible to decide which candidates may proceed to the
//     ordinary budget/breaker gates this tick and which stay held.
//
// A candidate absent from the returned map belongs to no batch (no
// fleet_group_id, or its group has never reached two simultaneously eligible
// members) and is entirely ungated by this mechanism — exactly today's
// behaviour.
func ResolveBatchGating(ctx context.Context, tx pgx.Tx, tenantID string, candidates []BatchCandidate, now time.Time) (map[string]BatchMembership, error) {
	if err := resolveBatchOutcomes(ctx, tx, tenantID, now); err != nil {
		return nil, fmt.Errorf("resolve pending batch outcomes: %w", err)
	}

	membership, err := existingMembership(ctx, tx, candidates)
	if err != nil {
		return nil, err
	}

	type groupKey struct{ fleetGroupID, actionType string }
	groups := map[groupKey][]BatchCandidate{}
	for _, c := range candidates {
		if c.FleetGroupID == nil || *c.FleetGroupID == "" {
			continue
		}
		if _, already := membership[c.IncidentID]; already {
			continue
		}
		groups[groupKey{*c.FleetGroupID, c.ActionType}] = append(groups[groupKey{*c.FleetGroupID, c.ActionType}], c)
	}

	for k, group := range groups {
		existing, found, err := findBatch(ctx, tx, tenantID, k.fleetGroupID, k.actionType)
		if err != nil {
			return nil, err
		}
		if !found {
			if len(group) < 2 {
				// Not (yet) a correlated batch: only one simultaneously
				// eligible candidate shares this fleet group and fix right
				// now. Left ungated. If a second one appears on a later
				// tick, this same branch runs again and creates the batch
				// then — nothing here remembers "almost a batch" between
				// ticks, which is fine, since re-detecting costs one query.
				continue
			}
			created, err := createBatch(ctx, tx, tenantID, k.fleetGroupID, k.actionType, group, now)
			if err != nil {
				return nil, err
			}
			for incidentID, m := range created {
				membership[incidentID] = m
			}
			continue
		}
		added, err := addStragglers(ctx, tx, tenantID, existing, group)
		if err != nil {
			return nil, err
		}
		for incidentID, m := range added {
			membership[incidentID] = m
		}
	}

	return membership, nil
}

// existingMembership looks up which of these candidates already belong to a
// batch, keyed by incident id.
//
// Filtered to the candidate's CURRENT action_type: an incident can belong to
// a batch created for an action_type it was recommended in the past
// (a re-analysis can propose a different fix for the same fleet group, which
// is a different coordination scope — see this file's header), and a stale
// membership row under a different action_type must not gate today's
// candidate. Such an incident is treated as having no existing membership
// for its current action_type, which lets it correctly join or start a NEW
// batch keyed on that action_type below.
func existingMembership(ctx context.Context, tx pgx.Tx, candidates []BatchCandidate) (map[string]BatchMembership, error) {
	actionTypeByIncident := map[string]string{}
	ids := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c.FleetGroupID != nil && *c.FleetGroupID != "" {
			ids = append(ids, c.IncidentID)
			actionTypeByIncident[c.IncidentID] = c.ActionType
		}
	}
	out := map[string]BatchMembership{}
	if len(ids) == 0 {
		return out, nil
	}

	rows, err := tx.Query(ctx,
		`SELECT m.incident_id, m.batch_id, m.wave_number, b.status, b.action_type
		   FROM unattended_batch_members m
		   JOIN unattended_batches b ON b.id = m.batch_id
		  WHERE m.incident_id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("look up existing batch membership: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var incidentID, batchActionType string
		var m BatchMembership
		if err := rows.Scan(&incidentID, &m.BatchID, &m.WaveNumber, &m.BatchStatus, &batchActionType); err != nil {
			return nil, fmt.Errorf("scan existing batch membership: %w", err)
		}
		if batchActionType != actionTypeByIncident[incidentID] {
			continue
		}
		out[incidentID] = m
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate existing batch membership: %w", err)
	}
	return out, nil
}

// findBatch looks up the (at most one, per migration 000073's unique index)
// batch for this key.
func findBatch(ctx context.Context, tx pgx.Tx, tenantID, fleetGroupID, actionType string) (batch, bool, error) {
	var b batch
	err := tx.QueryRow(ctx,
		`SELECT id, status, wave1_size, total_size, created_at
		   FROM unattended_batches
		  WHERE tenant_id = $1 AND fleet_group_id = $2 AND action_type = $3`,
		tenantID, fleetGroupID, actionType).Scan(&b.ID, &b.Status, &b.Wave1Size, &b.TotalSize, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return batch{}, false, nil
	}
	if err != nil {
		return batch{}, false, fmt.Errorf("look up batch for fleet group %s / %s: %w", fleetGroupID, actionType, err)
	}
	return b, true, nil
}

// createBatch inserts a brand-new batch and assigns every member of `group`
// to wave 1 or wave 2.
func createBatch(ctx context.Context, tx pgx.Tx, tenantID, fleetGroupID, actionType string, group []BatchCandidate, now time.Time) (map[string]BatchMembership, error) {
	// Deterministic wave assignment: sort by incident id (a ULID, so this
	// also happens to be creation order) rather than trust map/slice
	// iteration order, which Go explicitly does not guarantee is stable
	// across calls — wave assignment must be reproducible, not incidental.
	sorted := append([]BatchCandidate{}, group...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].IncidentID < sorted[j].IncidentID })

	wave1 := waveOneSize(len(sorted))
	batchID := domain.NewID(domain.PrefixUnattendedBatch)
	if _, err := tx.Exec(ctx,
		`INSERT INTO unattended_batches (id, tenant_id, fleet_group_id, action_type, status, wave1_size, total_size, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
		batchID, tenantID, fleetGroupID, actionType, BatchStatusWave1Pending, wave1, len(sorted), now); err != nil {
		return nil, fmt.Errorf("create batch for fleet group %s / %s: %w", fleetGroupID, actionType, err)
	}

	out := make(map[string]BatchMembership, len(sorted))
	for i, c := range sorted {
		waveNumber := 2
		if i < wave1 {
			waveNumber = 1
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO unattended_batch_members (id, batch_id, tenant_id, cluster_id, incident_id, wave_number)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			domain.NewID(domain.PrefixUnattendedBatchMember), batchID, tenantID, c.ClusterID, c.IncidentID, waveNumber); err != nil {
			return nil, fmt.Errorf("add batch member %s: %w", c.IncidentID, err)
		}
		out[c.IncidentID] = BatchMembership{BatchID: batchID, WaveNumber: waveNumber, BatchStatus: BatchStatusWave1Pending}
	}
	return out, nil
}

// addStragglers attaches candidates with no existing membership to an
// already-existing batch, always as wave 2 (see this file's header for why a
// straggler never backfills wave 1). Idempotent per (batch, incident) via
// the migration's unique index, so a candidate this function has already
// seen on an earlier tick is a no-op conflict, not a duplicate row.
func addStragglers(ctx context.Context, tx pgx.Tx, tenantID string, b batch, group []BatchCandidate) (map[string]BatchMembership, error) {
	out := make(map[string]BatchMembership, len(group))
	added := 0
	for _, c := range group {
		tag, err := tx.Exec(ctx,
			`INSERT INTO unattended_batch_members (id, batch_id, tenant_id, cluster_id, incident_id, wave_number)
			 VALUES ($1, $2, $3, $4, $5, 2)
			 ON CONFLICT (batch_id, incident_id) DO NOTHING`,
			domain.NewID(domain.PrefixUnattendedBatchMember), b.ID, tenantID, c.ClusterID, c.IncidentID)
		if err != nil {
			return nil, fmt.Errorf("add straggler %s to batch %s: %w", c.IncidentID, b.ID, err)
		}
		if tag.RowsAffected() > 0 {
			added++
		}
		out[c.IncidentID] = BatchMembership{BatchID: b.ID, WaveNumber: 2, BatchStatus: b.Status}
	}
	if added > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE unattended_batches SET total_size = total_size + $2, updated_at = now() WHERE id = $1`,
			b.ID, added); err != nil {
			return nil, fmt.Errorf("update batch %s total size: %w", b.ID, err)
		}
	}
	return out, nil
}

// resolveBatchOutcomes checks every batch still waiting on wave 1 against
// its wave-1 members' current incident states, and promotes it to
// released/blocked/abandoned per decideBatchOutcome when warranted.
func resolveBatchOutcomes(ctx context.Context, tx pgx.Tx, tenantID string, now time.Time) error {
	rows, err := tx.Query(ctx,
		`SELECT id, created_at FROM unattended_batches WHERE tenant_id = $1 AND status = $2`,
		tenantID, BatchStatusWave1Pending)
	if err != nil {
		return fmt.Errorf("find pending batches: %w", err)
	}
	type pendingBatch struct {
		id        string
		createdAt time.Time
	}
	var pending []pendingBatch
	for rows.Next() {
		var p pendingBatch
		if err := rows.Scan(&p.id, &p.createdAt); err != nil {
			rows.Close()
			return fmt.Errorf("scan pending batch: %w", err)
		}
		pending = append(pending, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate pending batches: %w", err)
	}
	rows.Close()

	for _, p := range pending {
		states, err := wave1States(ctx, tx, p.id)
		if err != nil {
			return err
		}
		newStatus, changed := decideBatchOutcome(states, now.Sub(p.createdAt))
		if !changed {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE unattended_batches SET status = $2, resolved_at = $3, updated_at = $3
			  WHERE id = $1 AND status = $4`,
			p.id, newStatus, now, BatchStatusWave1Pending); err != nil {
			return fmt.Errorf("update batch %s to %s: %w", p.id, newStatus, err)
		}
	}
	return nil
}

// wave1States reads the current incidents.state of every wave-1 member of a
// batch.
func wave1States(ctx context.Context, tx pgx.Tx, batchID string) ([]string, error) {
	rows, err := tx.Query(ctx,
		`SELECT i.state
		   FROM unattended_batch_members m
		   JOIN incidents i ON i.id = m.incident_id
		  WHERE m.batch_id = $1 AND m.wave_number = 1`, batchID)
	if err != nil {
		return nil, fmt.Errorf("read wave-1 incident states for batch %s: %w", batchID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan wave-1 incident state for batch %s: %w", batchID, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate wave-1 incident states for batch %s: %w", batchID, err)
	}
	return out, nil
}

// IncidentBatchInfo is the read-only, API-facing view of one incident's
// batch membership (if any) — internal/api/incidents.go's handleGetIncident
// embeds this in the incident detail response so a held incident's state is
// visible without a new endpoint.
type IncidentBatchInfo struct {
	BatchID      string `json:"batchId"`
	FleetGroupID string `json:"fleetGroupId"`
	ActionType   string `json:"actionType"`
	WaveNumber   int    `json:"waveNumber"`
	BatchStatus  string `json:"batchStatus"`
	Wave1Size    int    `json:"wave1Size"`
	TotalSize    int    `json:"totalSize"`
	Held         bool   `json:"held"`
}

// GetIncidentBatchInfo looks up one incident's most recent batch membership,
// for display on the incident detail screen. Returns nil, nil when the
// incident has never been part of a batch — the ordinary case for the large
// majority of incidents, which never share a fleet group and an unattended
// action_type with anything else.
//
// "Most recent" rather than "the only one": migration 000073 allows one
// incident to belong to more than one batch over its lifetime (a different
// action_type is a different coordination scope, per this file's header),
// and the newest is the one relevant to the incident's CURRENT state.
func GetIncidentBatchInfo(ctx context.Context, tx pgx.Tx, incidentID string) (*IncidentBatchInfo, error) {
	var info IncidentBatchInfo
	err := tx.QueryRow(ctx,
		`SELECT b.id, b.fleet_group_id, b.action_type, m.wave_number, b.status, b.wave1_size, b.total_size
		   FROM unattended_batch_members m
		   JOIN unattended_batches b ON b.id = m.batch_id
		  WHERE m.incident_id = $1
		  ORDER BY m.created_at DESC
		  LIMIT 1`,
		incidentID).Scan(&info.BatchID, &info.FleetGroupID, &info.ActionType, &info.WaveNumber, &info.BatchStatus, &info.Wave1Size, &info.TotalSize)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look up batch info for incident %s: %w", incidentID, err)
	}
	info.Held = !BatchMembership{WaveNumber: info.WaveNumber, BatchStatus: info.BatchStatus}.Eligible()
	return &info, nil
}
