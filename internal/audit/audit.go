// Package audit implements the shared, hash-chained audit-write mechanism
// (lld/05-data-model.md §7, closing SR-15/SR-21) — the single place every
// security-relevant action in this codebase writes an audit_events row
// through, so the chain can never be "mostly consistent because most call
// sites did it the same way." See STATUS.md's "Audit log" entry for why this
// was deliberately deferred until it could be built once and wired in
// everywhere at once, rather than bolted onto the first handler that needed
// it.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// Outcome is a closed set — exactly these three values, never a fourth
// invented at a call site. "denied" covers both an authorization failure
// (missing capability) and a rejected credential/token presentation;
// "error" is reserved for a genuine internal failure while attempting the
// action, distinct from a deliberate policy denial.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"
)

// GenesisPrevHash is the documented prev_hash value for the very first
// audit_events row ever written, when no real previous row exists to chain
// from. A 64-character all-zero hex string — the same length as a real
// SHA-256 hex digest — so genesis is a distinguishable, self-documenting
// sentinel of the right shape, not an empty string or an out-of-band flag
// that verification code would have to special-case by its absence.
// lld/05-data-model.md §7.
var GenesisPrevHash = strings.Repeat("0", 64)

// Event is one audit-worthy occurrence, as recorded by RecordEvent. Field
// meanings mirror the audit_events columns (migration 000008) directly:
//
//   - ActorID is nil when no authenticated actor exists yet at all (e.g. a
//     failed login before credentials were verified, or an unauthenticated
//     agent presenting an enrollment/poll token — the actor in that case is
//     a bearer token, not a user).
//   - ActorAuthMethod records HOW the actor (if any) authenticated for this
//     request: "password" | "jwt" | "enrollment_token" | "poll_token" | ""
//     (empty when not applicable, e.g. an outright login failure).
//   - Capability is nil when the action isn't capability-gated at all
//     (login itself is the standing example).
//   - Scope is the free-form jsonb `scope` column (e.g. {"clusterId": "cl_..."});
//     nil is a legitimate "no scope" value, not an error.
//   - Details is free-form context and is NEVER part of the hash input (see
//     ComputeHash) — it can be redacted under its own, shorter retention
//     window without invalidating the chain (lld/05-data-model.md §7, §9).
type Event struct {
	TenantID        string
	ActorID         *string
	ActorAuthMethod string
	SourceIP        string
	Capability      *string
	Scope           map[string]any
	ClusterID       *string
	Outcome         string
	Details         map[string]any
}

func validOutcome(o string) bool {
	switch o {
	case OutcomeSuccess, OutcomeDenied, OutcomeError:
		return true
	default:
		return false
	}
}

// ComputeHash implements lld/05-data-model.md §7's hash formula:
//
//	hash = SHA-256(prev_hash || tenant_id || actor_id || capability || scope || cluster_id || outcome || occurred_at)
//
// The LLD states that formula but never specifies a field delimiter for the
// "||" concatenation — a real, previously-silent gap (see this package's
// lld/05-data-model.md addendum, dated 2026-08-19): naive concatenation with
// no separator is collision-prone (actor_id="ab" + capability="c" hashes
// identically to actor_id="a" + capability="bc" once every other field lines
// up the same way). This implementation joins fields with 0x1F, ASCII Unit
// Separator ("\x1f") — a control character with no plausible legitimate
// appearance in any of these fields — placed BETWEEN every pair of fields
// (i.e. 7 separators for 8 joined pieces, none leading or trailing). The
// exact byte sequence fed to SHA-256, in order, is:
//
//	prevHash + US + tenantID + US + actorID + US + capability + US +
//	scopeJSON + US + clusterID + US + outcome + US + occurredAtRFC3339Nano
//
// where:
//   - US = the single byte 0x1F.
//   - actorID / capability / clusterID use "" for a nil pointer (never the
//     literal text "<nil>" or "null").
//   - scopeJSON is encoding/json.Marshal(ev.Scope) — see the inline comment
//     below for why that alone is a deterministic, canonical encoding here.
//   - occurredAtRFC3339Nano is occurredAt, forced to UTC, formatted with
//     time.RFC3339Nano — a fixed, deterministic textual format, per this
//     package's contract with its callers (RecordEvent computes exactly one
//     time.Now().UTC() value per call and reuses it for both this hash input
//     and the stored occurred_at column; see RecordEvent).
//
// `details` is deliberately NOT a parameter here — see the package doc and
// migration 000008's comment for why it's excluded from the hash input by
// design; this function has no way to accidentally include it.
//
// Returns an error (deviating from a bare-string signature) only because
// json.Marshal(ev.Scope) can fail for a pathological map[string]any value
// (e.g. one containing a channel or a cyclic structure); every real call
// site in this codebase only ever puts JSON-safe primitives in Scope, but
// silently swallowing a hash-computation failure would be exactly the kind
// of silent corruption a tamper-evident hash chain exists to prevent, so
// this surfaces the error instead of panicking or hashing a truncated input.
//
// Exported (2026-08-19, SR-15) so cmd/argusctl's standalone `audit verify`
// tool — lld/05-data-model.md §7's "independent hash-chain verification
// tool," deliberately NOT a hub API feature so a compromised hub can't
// disable it — can recompute this exact formula from rows it reads directly
// via SQL, instead of a second, driftable reimplementation. See
// NewCoreEvent below for the matching constructor a row-scan-based caller
// needs, since a plain SQL row doesn't naturally produce an Event.
func ComputeHash(prevHash string, ev Event, occurredAt time.Time) (string, error) {
	// map[string]any -> encoding/json.Marshal deterministically sorts object
	// keys (encoding/json's documented behavior for map values), so this is
	// already a canonical encoding for hashing purposes without any extra
	// canonicalization step (e.g. no need to re-marshal through a sorted-keys
	// helper) — this is true regardless of the map's insertion order.
	scopeJSON, err := json.Marshal(ev.Scope)
	if err != nil {
		return "", fmt.Errorf("marshal scope for hash input: %w", err)
	}

	const us = "\x1f" // ASCII Unit Separator
	h := sha256.New()
	for i, part := range []string{
		prevHash,
		ev.TenantID,
		derefOrEmpty(ev.ActorID),
		derefOrEmpty(ev.Capability),
		string(scopeJSON),
		derefOrEmpty(ev.ClusterID),
		ev.Outcome,
		occurredAt.UTC().Format(time.RFC3339Nano),
	} {
		if i > 0 {
			h.Write([]byte(us))
		}
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// NewCoreEvent builds an Event carrying only the fields ComputeHash's formula
// actually reads — for a caller (e.g. a verification tool) that scanned a
// row directly out of the audit_events table via SQL, rather than one about
// to be recorded via RecordEvent. ActorAuthMethod/SourceIP/Details are left
// at their zero values deliberately: none of the three is part of the hash
// input (see ComputeHash's doc comment and the two dedicated tests in
// audit_test.go locking that in), so omitting them here can never produce a
// wrong hash — there is nothing else this constructor needs from the row to
// reproduce ComputeHash's result exactly.
func NewCoreEvent(tenantID string, actorID *string, capability *string, scope map[string]any, clusterID *string, outcome string) Event {
	return Event{
		TenantID:   tenantID,
		ActorID:    actorID,
		Capability: capability,
		Scope:      scope,
		ClusterID:  clusterID,
		Outcome:    outcome,
	}
}

// chainTip returns the hash the next inserted row must carry as its
// prev_hash — the hash of the row at the end of the chain — together with
// that row's occurred_at, which RecordEvent needs to keep the chain's
// timestamps strictly increasing (see nextOccurredAt). On an empty
// audit_events it returns GenesisPrevHash and the zero time.
//
// ORDER BY occurred_at DESC, id DESC is the exact reverse of the order
// internal/argusctl/audit.go's LoadAuditEvents walks the chain in
// (occurred_at ASC, id ASC), so "the tip" here and "the last row" there are
// the same row by construction. The id tiebreaker is not cosmetic, and its
// absence was a real bug: occurred_at is stored at Postgres's microsecond
// resolution (RecordEvent truncates to match — see its own comment), so two
// rows CAN share a timestamp. With no tiebreaker Postgres was free to return
// either of two tied rows here, so an insert could chain from a row the
// verifier does not consider the tip — forking the chain and making
// `argusctl audit verify` report a completely untampered log as tampered.
//
// Its own function, not inline in RecordEvent, so a test can exercise the
// tie directly (audit_db_test.go) rather than having to arrange for
// RecordEvent's own time.Now() to collide with a crafted row's.
func chainTip(ctx context.Context, tx pgx.Tx) (string, time.Time, error) {
	var prevHash string
	var occurredAt time.Time
	err := tx.QueryRow(ctx,
		`SELECT hash, occurred_at FROM audit_events ORDER BY occurred_at DESC, id DESC LIMIT 1`,
	).Scan(&prevHash, &occurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return GenesisPrevHash, time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return prevHash, occurredAt.UTC(), nil
}

// nextOccurredAt returns the occurred_at the row about to be appended must
// carry: now, truncated to the microsecond resolution Postgres actually
// stores (see RecordEvent for why truncating before hashing is mandatory),
// but never at or before the current tip's own occurred_at.
//
// WHY THE CLAMP, AND WHY MIRRORING THE VERIFIER'S ORDERING ISN'T ENOUGH ON
// ITS OWN: the chain's true order is INSERTION order, but neither this
// package nor the verifier has an insertion sequence to read — both infer
// the order from (occurred_at, id). Matching orderings guarantees the two
// sides agree on which row is last; it does NOT guarantee that either one
// agrees with the order the rows were actually written in, and the chain is
// only verifiable when it does. Two ways it can diverge, both named in this
// bug's own report:
//
//   - Two rows in the same microsecond. The tie then falls to id, and
//     internal/domain.NewID builds its ULIDs with crypto/rand entropy, not
//     monotonic entropy — so within a single millisecond id order is
//     effectively a coin flip against insertion order (measured: it
//     disagrees about half the time). The second row's prev_hash points at
//     the first, but the verifier may well walk them the other way round
//     and declare a mismatch.
//   - A backwards wall-clock step (an NTP correction, a VM suspend/resume).
//     A row lands with an occurred_at that precedes its predecessor's, so
//     the verifier walks them in the opposite order to the one their
//     prev_hash links describe. No tiebreaker of any kind helps here.
//
// Forcing occurred_at strictly forward removes both, because it makes
// occurred_at alone a total order that matches insertion order — after which
// the id tiebreaker above never actually has a tie to break, and is pure
// belt-and-braces (it still matters for rows already in the table from
// before this change). RecordEvent runs under a global advisory lock while
// it does this, so the read-tip-then-clamp sequence is serialized across
// every writer in the system, including other hub processes.
//
// The cost is that a burst of audit writes inside one microsecond records
// timestamps up to a few microseconds later than they truly happened. That
// is the right trade: microsecond-level precision in an audit timestamp has
// no consumer, and an unverifiable chain defeats the entire point of the
// table.
func nextOccurredAt(now, tipOccurredAt time.Time) time.Time {
	occurredAt := now.UTC().Truncate(time.Microsecond)
	if !occurredAt.After(tipOccurredAt) {
		return tipOccurredAt.Add(time.Microsecond)
	}
	return occurredAt
}

// RecordEvent appends exactly one row to the hash-chained audit_events table.
//
// tx MUST already be scoped for the correct tenant (i.e. the caller already
// ran data.SetRequestScope on it, or resolved+set scope itself the way
// authz.RotateRefreshToken/RedeemEnrollmentToken do for the no-prior-session
// case) — RecordEvent deliberately does not resolve or set RLS scope itself,
// matching the calling convention every existing handler in this codebase
// already follows before touching any other table.
//
// Concurrency: audit_events' hash chain is one single, global, strictly
// ordered sequence (occurred_at DESC over the whole table, not partitioned
// per tenant or cluster), so two concurrent writers must never both read the
// same "current tip" hash and insert with the same prev_hash — that would
// fork the chain. This is prevented by acquiring a transaction-scoped
// Postgres advisory lock (pg_advisory_xact_lock, released automatically at
// this transaction's commit or rollback — never leaked, never needing a
// manual unlock call) keyed on a fixed name, BEFORE reading the chain tip.
// Every concurrent RecordEvent call in the whole system therefore serializes
// against every other one. That is a deliberately global bottleneck rather
// than a per-tenant/per-cluster one, but audit writes are not a hot path at
// this scale, so the simplicity is worth the (currently negligible) added
// contention.
func RecordEvent(ctx context.Context, tx pgx.Tx, ev Event) error {
	if !validOutcome(ev.Outcome) {
		return fmt.Errorf("audit.RecordEvent: invalid outcome %q: must be one of %q, %q, %q", ev.Outcome, OutcomeSuccess, OutcomeDenied, OutcomeError)
	}

	// Global, named, transaction-scoped advisory lock — see the doc comment
	// above. hashtext(...) returns a 32-bit int; pg_advisory_xact_lock's
	// single-argument overload takes bigint, and Postgres implicitly widens
	// int4 -> int8 for this call, so no explicit cast is needed.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('argus_audit_chain'))`); err != nil {
		return fmt.Errorf("audit.RecordEvent: acquire chain lock: %w", err)
	}

	prevHash, tipOccurredAt, err := chainTip(ctx, tx)
	if err != nil {
		return fmt.Errorf("audit.RecordEvent: read chain tip: %w", err)
	}

	// Exactly one timestamp, reused for both the hash input and the stored
	// occurred_at column — the hash must exactly match what's stored, so the
	// DB's own `now()` default must never fire for this insert.
	//
	// Truncated to microsecond precision because Postgres's timestamptz type
	// only stores microsecond resolution: if this Go value carried
	// nanosecond precision into ComputeHash below but Postgres then silently
	// rounded it on storage, a later independent-verification pass that
	// reads occurred_at back and recomputes the hash from the STORED
	// (rounded) value would never match the hash computed here from the
	// PRE-rounding value — every single row would look tampered. Truncating
	// first makes the value round-trip through storage unchanged, so
	// recomputation from the stored row always reproduces this exact hash.
	//
	// And never at or before the tip's own occurred_at — see nextOccurredAt
	// for why the chain is only verifiable when its timestamps strictly
	// increase, and why mirroring the verifier's row ordering (chainTip) does
	// not achieve that by itself.
	occurredAt := nextOccurredAt(time.Now(), tipOccurredAt)

	hash, err := ComputeHash(prevHash, ev, occurredAt)
	if err != nil {
		return fmt.Errorf("audit.RecordEvent: compute hash: %w", err)
	}

	scopeJSON, err := json.Marshal(ev.Scope)
	if err != nil {
		return fmt.Errorf("audit.RecordEvent: marshal scope: %w", err)
	}
	detailsJSON, err := json.Marshal(ev.Details)
	if err != nil {
		return fmt.Errorf("audit.RecordEvent: marshal details: %w", err)
	}

	var sourceIP *string
	if ev.SourceIP != "" {
		sourceIP = &ev.SourceIP
	}
	var actorAuthMethod *string
	if ev.ActorAuthMethod != "" {
		actorAuthMethod = &ev.ActorAuthMethod
	}

	id := domain.NewID(domain.PrefixAuditEvent)
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events
			(id, tenant_id, actor_id, actor_auth_method, source_ip, capability,
			 scope, cluster_id, outcome, occurred_at, details, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		id, ev.TenantID, ev.ActorID, actorAuthMethod, sourceIP, ev.Capability,
		scopeJSON, ev.ClusterID, ev.Outcome, occurredAt, detailsJSON, prevHash, hash)
	if err != nil {
		return fmt.Errorf("audit.RecordEvent: insert: %w", err)
	}
	return nil
}
