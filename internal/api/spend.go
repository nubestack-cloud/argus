package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/settings"
)

// This file is the "real number to check a ceiling against" half of closing
// two gaps this codebase has flagged for a while, together: STATUS.md
// §28/§49's honest analyses.cost_usd == 0 (no per-model pricing table
// existed), and DESIGN.md §16.4's "hard spend ceilings"
// requirement sitting alongside internal/authz.CapSpendRead/CapSpendManage
// — declared in the capability catalogue since the very first authz pass,
// never implemented by anything until now. internal/settings.Config's
// ComputeCostUSD/CostPricingConfigured/SpendCeilingActive (settings.go) are
// this file's companions — the pricing-and-ceiling CONFIG lives there; this
// file is the real-time SPEND side: summing what's actually been spent
// today, and deciding whether that sum has crossed a configured ceiling.
//
// TodaySpendUSD/SpendCeilingBreached are used by three call sites, each with
// a different, deliberately different, and separately documented policy:
//   - internal/api/analyze.go's handleAnalyzeIncident (the MANUAL path):
//     checks the ceiling and logs clearly if it's breached, but does NOT
//     block — see that handler's own doc comment for the reasoning.
//   - internal/autoanalyze's sweep (the AUTOMATIC, unsupervised path): skips
//     starting any further investigation for the rest of the sweep (and
//     every sweep thereafter, until spend resets or the ceiling is raised)
//     when breached — see that package's own doc comment.
//   - handleGetSpendToday below (GET /api/v1/spend/today): a read-only
//     report of today's real spend and ceiling status, gated on
//     CapSpendRead alone — narrower than CapOrgSettingsWrite (which gates
//     the "cost" section of GET/PUT /api/v1/admin/settings that actually
//     configures pricing/the ceiling), so a resolver (who holds
//     CapSpendRead but not org:settings:write, per authz/permissions.go's
//     builtinRoleCapabilities) can see today's spend without needing full
//     admin-settings access.

// startOfUTCDay is midnight at the start of t's UTC calendar day — the
// "today" boundary both this file's spend total and insights.go's daily
// trend are cut on.
//
// It exists as a pure Go function, rather than as `date_trunc('day', now())`
// in SQL, because that expression truncates in the Postgres SESSION time
// zone, and nothing in this deployment pins one: the hub's DSN
// (ARGUS_DATABASE_URL in deploy/compose/docker-compose.yaml) carries no
// TimeZone parameter, and neither the Dockerfile nor any startup code sets
// one, so the boundary silently became whatever the database server's
// timezone GUC happened to be. For a daily spend CEILING that is not a
// cosmetic problem: on a server west of UTC the window would still include
// yesterday's spend hours into today (a ceiling that stays breached past
// the reset it was supposed to get), and east of UTC it would drop spend
// that has already happened (a ceiling that resets early and lets the day's
// real total through twice). Computing the boundary here, in UTC, makes it
// depend on nothing but the clock, and makes it agree by construction with
// the UTC date handleGetSpendToday reports alongside the number.
func startOfUTCDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

// TodaySpendUSD sums analyses.cost_usd for every analysis created today
// (the current UTC calendar day — see startOfUTCDay for why that boundary
// is computed in Go rather than with date_trunc, and insights.go's
// queryDailyTrend for the same treatment of its day buckets) — the real,
// already-accumulated spend a daily spend ceiling checks against. tx must
// already be scoped (RLS) the same way every other query against `analyses`
// in this codebase requires — callers pass an already-scoped rc.Tx/poller
// transaction, never a bare pool connection.
func TodaySpendUSD(ctx context.Context, tx pgx.Tx) (float64, error) {
	sum, _, err := TodaySpend(ctx, tx)
	return sum, err
}

// TodaySpend is TodaySpendUSD plus the honesty half required by
// lld/07-analysis-contracts.md §10.5: how many of today's analyses have no
// observable cost at all.
//
// A subscription-authenticated CLI backend (migration 000033's
// analyses.cost_basis) stores cost_usd = 0 meaning *unavailable*, not free.
// Summing those into a total silently understates real usage, and — worse —
// makes a daily spend ceiling look satisfied by activity it cannot actually
// see. So the sum deliberately covers only rows whose cost was genuinely
// measured, and the second return reports how many rows were excluded, so a
// caller can say "plus N investigations with no cost data" instead of
// implying the total is complete.
//
// Rows written before migration 000033 were backfilled to 'metered' by that
// migration, so a NULL basis is not expected — it is nonetheless counted as
// unmeasured rather than assumed metered, since guessing in the direction that
// inflates confidence in a safety control is the wrong default.
func TodaySpend(ctx context.Context, tx pgx.Tx) (measuredUSD float64, unmeasuredCount int, err error) {
	// The day boundary is passed in as an explicit UTC timestamptz rather
	// than computed in SQL — see startOfUTCDay.
	err = tx.QueryRow(ctx,
		`SELECT
		   COALESCE(SUM(cost_usd) FILTER (WHERE cost_basis = 'metered'), 0)::float8,
		   COUNT(*) FILTER (WHERE cost_basis IS DISTINCT FROM 'metered')
		 FROM analyses
		 WHERE created_at >= $1`, startOfUTCDay(time.Now()),
	).Scan(&measuredUSD, &unmeasuredCount)
	if err != nil {
		return 0, 0, fmt.Errorf("sum today's analyses.cost_usd: %w", err)
	}
	return measuredUSD, unmeasuredCount, nil
}

// SpendCeilingBreached is pure, DB-free logic — given an already-resolved
// Config and an already-queried today's-spend figure (TodaySpendUSD above),
// it reports whether that spend has reached or exceeded the configured
// daily ceiling. Split out from TodaySpendUSD specifically so it's
// unit-testable with no database at all (see spend_test.go), the same
// "pure decision logic pulled out of the DB-touching query" discipline
// autoanalyze.selectEligible/insights.fillDailyTrend already established.
//
// Always false when settings.Config.SpendCeilingActive() is false — no
// ceiling configured, or pricing not configured (in which case cost_usd is
// always 0 and a ceiling check would be comparing against a number that
// can never mean anything) — see SpendCeilingActive's own doc comment for
// why "no pricing" must mean "this check is a no-op," never a confusing
// block on an always-$0 total. Callers should use SpendCeilingActive
// themselves to decide whether querying TodaySpendUSD is even worth doing
// in the first place — see this file's three call sites.
func SpendCeilingBreached(cfg settings.Config, todaySpendUSD float64) bool {
	if !cfg.SpendCeilingActive() {
		return false
	}
	return todaySpendUSD >= *cfg.DailySpendCeilingUsd
}

// spendTodayResponse is GET /api/v1/spend/today's response shape.
//
// SpendCountable/CeilingEnforceable are the two facts that keep a caller from
// reading TodaySpendUsd as a complete measurement when it cannot be one
// (internal/settings.Config.ActiveProviderSpendCountable/
// SpendCeilingEnforceable — read those doc comments for why the second is
// descriptive only and does NOT gate enforcement).
//
// They are booleans, not a prose reason string: the two consumers are a
// fleet-overview tile whose caption is a few words and an insights tile of the
// same size, and a sentence long enough to be accurate in the settings screen
// does not fit either. The FACTS are the server's to own; how much room the
// wording gets is the screen's. CeilingBreached can be true while
// CeilingEnforceable is false — a deployment that switched from api to cli
// mid-day still has countable rows from earlier — so a caller showing both
// must let "breached" win, since that one actually stopped automatic
// investigation.
type spendTodayResponse struct {
	GeneratedAt          string   `json:"generatedAt"`
	Date                 string   `json:"date"`
	TodaySpendUsd        float64  `json:"todaySpendUsd"`
	PricingConfigured    bool     `json:"pricingConfigured"`
	SpendCountable       bool     `json:"spendCountable"`
	DailySpendCeilingUsd *float64 `json:"dailySpendCeilingUsd"`
	CeilingBreached      bool     `json:"ceilingBreached"`
	CeilingEnforceable   bool     `json:"ceilingEnforceable"`
}

// handleGetSpendToday is GET /api/v1/spend/today. Requires spend:read —
// see this file's own doc comment for why this is a narrower, more widely
// held gate than org:settings:write, which is what actually configures
// pricing/the ceiling (GET/PUT /api/v1/admin/settings' "cost" section,
// settings.go).
func (s *Server) handleGetSpendToday(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	cfg, err := settings.Resolve(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the settings for today's spend failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read spend settings", "")
		return
	}
	todaySpend, err := TodaySpendUSD(ctx, rc.Tx)
	if err != nil {
		logger.ErrorContext(ctx, "computing today's spend failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute today's spend", "")
		return
	}
	writeJSON(w, http.StatusOK, spendTodayResponse{
		GeneratedAt:          nowRFC3339(),
		Date:                 time.Now().UTC().Format("2006-01-02"),
		TodaySpendUsd:        todaySpend,
		PricingConfigured:    cfg.CostPricingConfigured(),
		SpendCountable:       cfg.ActiveProviderSpendCountable(),
		DailySpendCeilingUsd: cfg.DailySpendCeilingUsd,
		CeilingBreached:      SpendCeilingBreached(cfg, todaySpend),
		CeilingEnforceable:   cfg.SpendCeilingEnforceable(),
	})
}

// --- Atomic spend reservation (PROJECT.md T10, lld/01-threat-model.md T12 /
// SR-13) ---
//
// Everything above this point answers "how much has already been spent
// today" — a read. It is checked-then-acted-on by three call sites (see this
// file's own package doc comment), and for two of them that gap is
// deliberate: handleAnalyzeIncident's manual path is a human clicking once,
// supervised, and its own doc comment already explains why it does not
// block. The third, internal/autoanalyze's sweep, is the unsupervised path
// DESIGN.md's spend-ceiling requirement is actually about, and it is also
// the one that runs MULTIPLE investigations concurrently
// (autoanalyze.runWaves, up to autoanalyze.maxConcurrentInvestigations at
// once, each in its own transaction) — so "check the ceiling, then start
// the work, then record the cost afterwards" is a real, reproducible race
// there: two concurrent investigations can each read the same
// already-spent total, each see headroom, and each proceed, together
// spending more than the ceiling ever allowed either of them alone.
//
// ReserveSpend/SettleSpendReservation/ReleaseSpendReservation close that gap
// by making "check the ceiling" and "claim the projected cost" one atomic
// step, backed by the spend_reservations table (migration 000109).

// estimatedTokensPerIterationUpperBound is a deliberately generous
// per-model-round-trip token budget, used ONLY to size a spend RESERVATION
// before a specific investigation's real usage is known (ReserveSpend
// below) — it is not a measurement. `lld/14-adrs.md` D16 already treats
// real per-investigation cost figures as pending on live data; this errs
// high on purpose, because overestimating a reservation only ever holds
// more headroom than an investigation turns out to need (freed back to the
// ceiling on settlement — see SettleSpendReservation), where underestimating
// it is exactly what would let concurrent investigations collectively cross
// the ceiling, which is the invariant this exists to hold.
const estimatedTokensPerIterationUpperBound = 60_000

// projectedInvestigationCostUSD is a conservative UPPER BOUND on what one
// automatic investigation might cost, computed from the same bounds
// internal/llm's tool-calling loop actually enforces
// (settings.Config.AnalysisMaxIterations, defaulting to llm.DefaultMaxIterations)
// and the same per-token pricing ComputeCostUSD uses — but priced entirely
// at whichever of the three configured per-million rates is highest, since
// at reservation time the real split between input/cached/output tokens
// isn't known yet. Returns 0 when pricing isn't configured, matching
// ComputeCostUSD's own "no pricing means cost is always 0" convention —
// ReserveSpend's own SpendCeilingActive check already means this is only
// ever called when pricing IS configured, but this function stays honest
// about its precondition rather than trusting that blindly.
func projectedInvestigationCostUSD(cfg settings.Config) float64 {
	if !cfg.CostPricingConfigured() {
		return 0
	}
	maxIterations := llm.DefaultMaxIterations
	if cfg.AnalysisMaxIterations != nil {
		maxIterations = *cfg.AnalysisMaxIterations
	}
	maxPricePerMillion := *cfg.PricePerMillionInputTokens
	if p := *cfg.PricePerMillionOutputTokens; p > maxPricePerMillion {
		maxPricePerMillion = p
	}
	if p := *cfg.PricePerMillionCachedTokens; p > maxPricePerMillion {
		maxPricePerMillion = p
	}
	estimatedTokens := float64(maxIterations) * estimatedTokensPerIterationUpperBound
	return estimatedTokens / 1_000_000.0 * maxPricePerMillion
}

// SpendReservation is what ReserveSpend hands back to its caller, and what
// SettleSpendReservation/ReleaseSpendReservation reconcile later in the same
// investigation's own transaction (or a later one, if settlement happens on
// a failure path after a rollback — see investigateOne's own call sites).
type SpendReservation struct {
	ID string
	// Active is false exactly when no row was written at all — no ceiling
	// configured, no pricing configured, or the active provider's spend
	// isn't countable (see ReserveSpend). Settle/Release are both
	// intentional no-ops on an inactive reservation, so a caller never has
	// to branch on this itself before calling either.
	Active bool
}

// spendReservationLockKey derives the bigint key ReserveSpend's advisory
// lock takes: hashtextextended over "tenantID:day", so two different
// tenants (or the same tenant on two different days) never contend on the
// same lock, and two reservation attempts for the SAME tenant+day always
// do. Kept as one call site rather than inlined so its own doc comment has
// somewhere to live.
const spendReservationLockKeySQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

// ReserveSpend is SR-13's fix: it makes "is there room under today's
// ceiling" and "claim this investigation's projected cost" one atomic
// operation, by running entirely inside tx — the SAME transaction the
// caller uses to claim the incident for investigation (see
// internal/autoanalyze's investigateOne, which calls this immediately after
// orchestrator.MarkInvestigating, in the same transaction, so a refused
// reservation rolls the claim back too rather than leaving the incident
// stranded Investigating with nothing about to happen).
//
// # How the race actually closes
//
// Two concurrent callers, in two separate transactions, both reach this
// function for the same tenant at close to the same moment. Both take
// `SELECT pg_advisory_xact_lock(...)` on the same key — Postgres blocks the
// second caller until the first caller's transaction COMMITS OR ROLLS BACK,
// not just until the first caller's own statement finishes. So the second
// caller cannot even READ today's committed-plus-reserved total until the
// first caller has either written its own reservation row (and released the
// lock by committing) or decided not to (and released it by rolling back).
// There is no window in which both callers observe the same "spend so far"
// figure and both decide there is room — which is exactly the window the
// old check-then-act version left open. The lock is per-tenant-per-day, not
// global, so unrelated tenants (or the same tenant on different days) never
// contend on it.
//
// # What "no reservation needed" means, and why it's still ok=true
//
// Three cases return (SpendReservation{}, true, nil) — reserving nothing,
// but telling the caller to proceed anyway:
//
//   - No ceiling configured (SpendCeilingActive() false via
//     DailySpendCeilingUsd == nil): there is nothing to protect.
//   - No pricing configured (SpendCeilingActive() false via
//     CostPricingConfigured() false): every analyses row will cost_usd = 0
//     regardless of what runs, so a ceiling check would compare against a
//     number that can never move — see SpendCeilingActive's own doc
//     comment for why that must be a no-op, not a block.
//   - The active provider's spend isn't countable (ActiveProviderSpendCountable()
//     false — a CLI/subscription-billed backend). This is the case this
//     task's own coordination note calls out explicitly: reserving headroom
//     against a run that can never be charged would let a subscription
//     deployment's own ceiling refuse work that costs it nothing, which is
//     a worse bug than the race this function exists to close. Matches
//     ActiveProviderSpendCountable's own "spend from this provider kind can
//     never move the ceiling" reasoning, applied at reservation time
//     instead of only at the read side.
//
// # What a real reservation checks
//
// today's already-measured, chargeable spend (TodaySpendUSD — real
// analyses.cost_usd rows) PLUS every currently-open ('reserved', not yet
// settled or released) reservation for this tenant today, PLUS this call's
// own projected cost (projectedInvestigationCostUSD) — compared against
// cfg.DailySpendCeilingUsd. If that total would exceed the ceiling, no row
// is written and ok is false: the caller must not proceed with the
// investigation this tick (it remains eligible on a later one). Otherwise a
// 'reserved' row is written and must be reconciled exactly once, later, via
// SettleSpendReservation or ReleaseSpendReservation.
func ReserveSpend(ctx context.Context, tx pgx.Tx, cfg settings.Config, tenantID, incidentID, clusterID string) (SpendReservation, bool, error) {
	if !cfg.SpendCeilingActive() || !cfg.ActiveProviderSpendCountable() {
		return SpendReservation{}, true, nil
	}

	day := startOfUTCDay(time.Now())
	lockKey := tenantID + ":" + day.Format("2006-01-02")
	if _, err := tx.Exec(ctx, spendReservationLockKeySQL, lockKey); err != nil {
		return SpendReservation{}, false, fmt.Errorf("acquire spend reservation lock: %w", err)
	}

	measuredUSD, err := TodaySpendUSD(ctx, tx)
	if err != nil {
		return SpendReservation{}, false, err
	}
	var openReservedUSD float64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(reserved_usd), 0)::float8 FROM spend_reservations
		  WHERE tenant_id = $1 AND day = $2 AND status = 'reserved'`,
		tenantID, day,
	).Scan(&openReservedUSD); err != nil {
		return SpendReservation{}, false, fmt.Errorf("sum open spend reservations: %w", err)
	}

	projected := projectedInvestigationCostUSD(cfg)
	if measuredUSD+openReservedUSD+projected > *cfg.DailySpendCeilingUsd {
		return SpendReservation{}, false, nil
	}

	id := domain.NewID(domain.PrefixSpendReservation)
	if _, err := tx.Exec(ctx,
		`INSERT INTO spend_reservations (id, tenant_id, cluster_id, incident_id, day, reserved_usd, status)
		 VALUES ($1, $2, $3, $4, $5, $6, 'reserved')`,
		id, tenantID, clusterID, incidentID, day, projected,
	); err != nil {
		return SpendReservation{}, false, fmt.Errorf("insert spend reservation: %w", err)
	}
	return SpendReservation{ID: id, Active: true}, true, nil
}

// SettleSpendReservation reconciles a reservation to a real, known outcome —
// called once the investigation's actual cost is known (after
// PersistAnalysis has written the real analyses row). No-op on an inactive
// reservation (see SpendReservation.Active).
//
// chargeable must be false whenever the cost basis PersistAnalysis actually
// used is NOT 'metered' — the same TodaySpendUSD/TodaySpend convention that
// only sums 'metered' rows into the figure a ceiling is ever checked
// against (see TodaySpend's own doc comment on cost_basis). When chargeable
// is false, actualUSD is ignored and the reservation is freed as if nothing
// had been spent — this is the specific case this task's coordination note
// asked to be handled explicitly: a subscription-basis run has no
// chargeable cost, so it must not go on eating the ceiling's headroom for
// the rest of the day just because it once reserved room to run.
//
// When chargeable is true, actualUSD is recorded as-is, whether it came in
// UNDER the reservation (the common case — projectedInvestigationCostUSD is
// deliberately an upper bound) or OVER it (a genuinely larger-than-estimated
// investigation). Either way the reservation's own row stops counting
// itself toward future ReserveSpend calls the instant it is marked
// 'settled' — the real number is already inside analyses.cost_usd, which
// TodaySpendUSD sums directly, so an overrun is not silently discarded, it
// simply flows into every later reservation's own measuredUSD term via that
// same query, exactly like any other real, metered analysis would.
func SettleSpendReservation(ctx context.Context, tx pgx.Tx, r SpendReservation, actualUSD float64, chargeable bool) error {
	if !r.Active {
		return nil
	}
	if !chargeable {
		actualUSD = 0
	}
	if _, err := tx.Exec(ctx,
		`UPDATE spend_reservations SET status = 'settled', actual_usd = $2, settled_at = now() WHERE id = $1`,
		r.ID, actualUSD); err != nil {
		return fmt.Errorf("settle spend reservation %s: %w", r.ID, err)
	}
	return nil
}

// ReleaseSpendReservation frees a reservation that produced no chargeable
// result at all — the investigation failed before anything could be
// persisted, or persisting its result itself failed. No-op on an inactive
// reservation. Unlike a settled reservation with actualUSD 0, "released"
// keeps the two outcomes distinguishable in the row itself: settled-at-zero
// means "we know the real cost, and it was nothing to charge"; released
// means "no real outcome was ever produced to reconcile against."
func ReleaseSpendReservation(ctx context.Context, tx pgx.Tx, r SpendReservation) error {
	if !r.Active {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE spend_reservations SET status = 'released', actual_usd = 0, settled_at = now() WHERE id = $1`,
		r.ID); err != nil {
		return fmt.Errorf("release spend reservation %s: %w", r.ID, err)
	}
	return nil
}
