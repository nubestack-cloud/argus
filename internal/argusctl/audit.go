// Independent audit hash-chain verification (lld/05-data-model.md §7,
// closing SR-15 in lld/01-threat-model.md): "a standalone tool ... that reads
// the audit_events partitions in occurred_at order and recomputes each row's
// hash from the previous row's stored hash plus its own core fields,
// flagging the first row where recomputation diverges." Deliberately not a
// hub API route (see cmd/argusctl's package comment and README.md) — a
// compromised hub controls every route the API process serves, so tamper-
// evidence that could be disabled from inside the hub isn't independent of
// it. This tool only needs a Postgres connection string; it never talks to
// the hub API at all.
//
// Split into two halves on purpose:
//   - LoadAuditEvents (this file, DB-touching, not unit-tested here) reads
//     the rows.
//   - VerifyChain (this file, pure/DB-free) does the actual check and is
//     covered by internal/argusctl/audit_test.go without a database — this is
//     the half that actually matters (STATUS.md's build gate says as much),
//     so it has to be testable without standing up Postgres.
package argusctl

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
)

// AuditRow is one audit_events row, holding exactly the columns
// audit.ComputeHash's formula needs (via audit.NewCoreEvent) plus the row's
// own identity (ID, OccurredAt) and its two stored chain fields (PrevHash,
// Hash) — deliberately not the full audit_events schema (e.g. no
// ActorAuthMethod/SourceIP/Details), since none of those are hash inputs and
// this tool has no other use for them.
type AuditRow struct {
	ID         string
	TenantID   string
	ActorID    *string
	Capability *string
	Scope      map[string]any
	ClusterID  *string
	Outcome    string
	OccurredAt time.Time
	PrevHash   string
	Hash       string
}

// LoadAuditEvents reads every row of audit_events, across every partition,
// in the one stable total order the hash chain was written in.
//
// A plain "SELECT ... FROM audit_events ORDER BY ..." against the
// partitioned parent table already transparently spans every partition in
// Postgres — declarative partitioning is not visible to a query against the
// parent, it's purely a storage-layer detail, so there is nothing extra this
// function needs to do to "reach into" audit_events_default or any future
// sibling partition. (At the time this was written, audit_events_default —
// migration 000008's DEFAULT partition — is still the only partition that
// exists; nothing has ever range-partitioned this table for real yet. That
// doesn't change the correctness argument above, only that it hasn't been
// exercised against more than one partition live — see this package's test
// notes / STATUS.md for how that was confirmed instead.)
//
// occurred_at ASC is the order RecordEvent's chain was actually built in
// (each row's prev_hash is the immediately-preceding INSERT's hash, and
// audit_events' rows are never updated after insert). occurred_at alone
// cannot be relied on as a total order — Postgres's timestamptz has only
// microsecond resolution, and two RecordEvent calls could in principle
// truncate to the same microsecond — but audit_events' primary key is
// (id, occurred_at) and every id is a ULID (internal/domain.NewID), which is
// itself monotonically increasing for IDs minted in quick succession on the
// same process. Ordering by (occurred_at, id) therefore gives a
// deterministic total order that never depends on tie-breaking arbitrarily
// between two rows a naive "ORDER BY occurred_at" alone could return in
// either order from one run to the next.
func LoadAuditEvents(ctx context.Context, conn *pgx.Conn) ([]AuditRow, error) {
	rows, err := conn.Query(ctx, `
		SELECT id, tenant_id, actor_id, capability, scope, cluster_id, outcome,
		       occurred_at, prev_hash, hash
		FROM audit_events
		ORDER BY occurred_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query audit_events: %w", err)
	}
	defer rows.Close()

	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		var scopeRaw []byte
		if err := rows.Scan(
			&r.ID, &r.TenantID, &r.ActorID, &r.Capability, &scopeRaw, &r.ClusterID,
			&r.Outcome, &r.OccurredAt, &r.PrevHash, &r.Hash,
		); err != nil {
			return nil, fmt.Errorf("scan audit_events row: %w", err)
		}
		if len(scopeRaw) > 0 {
			// jsonb's NULL is represented as a zero-length scan here (see the
			// []byte-destination scan note above) rather than the four bytes
			// "null" — a genuine JSON `null` scope value, if one ever existed,
			// would arrive as scopeRaw == []byte("null"), which json.Unmarshal
			// happily turns into a nil map, so both cases end up correctly nil.
			if err := json.Unmarshal(scopeRaw, &r.Scope); err != nil {
				return nil, fmt.Errorf("unmarshal scope for row %s: %w", r.ID, err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit_events rows: %w", err)
	}
	return out, nil
}

// RoleBypassesRLS reports whether the connection's current_user has either
// the BYPASSRLS attribute or is a superuser (Postgres superusers bypass RLS
// regardless of BYPASSRLS or FORCE ROW LEVEL SECURITY). This tool
// specifically REQUIRES a bypassing connection — the inverse of every other
// piece of this codebase, which requires (and startup-checks, in
// internal/data.DB.CheckRLSPreconditions) that the hub's own app connection
// can NOT bypass RLS — see cmd/argusctl's runAuditVerify for how this is
// used (fail loudly rather than silently "verify" an RLS-filtered view).
func RoleBypassesRLS(ctx context.Context, conn *pgx.Conn) (currentUser string, bypasses bool, err error) {
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser); err != nil {
		return "", false, fmt.Errorf("check current_user: %w", err)
	}
	if err := conn.QueryRow(ctx,
		"SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
	).Scan(&bypasses); err != nil {
		return currentUser, false, fmt.Errorf("check rolsuper/rolbypassrls: %w", err)
	}
	return currentUser, bypasses, nil
}

// FailureKind names which of the two independent checks VerifyChain found
// violated on the first divergent row. Both matter and are checked
// separately — see VerifyChain's doc comment for why collapsing them into
// one check would be wrong.
type FailureKind string

const (
	// FailureHashMismatch means recomputing the row's own hash — from its own
	// stored core fields and its own stored prev_hash — did not reproduce its
	// own stored hash. This is the direct "this row's content was altered (or
	// its stored hash was altered) after the fact" signal.
	FailureHashMismatch FailureKind = "hash_mismatch"
	// FailurePrevHashMismatch means this row's stored prev_hash does not equal
	// the immediately preceding row's stored hash (or, for the first row, the
	// documented genesis constant). This is the "the chain was spliced —
	// either this row was inserted somewhere other than where it claims to
	// be, or an earlier row's hash was altered without this row's prev_hash
	// being updated to match" signal. A tamperer who edits one row's hash but
	// forgets to also edit the NEXT row's prev_hash is caught here even if
	// they get the edited row's own hash internally self-consistent.
	FailurePrevHashMismatch FailureKind = "prev_hash_mismatch"
)

// Divergence describes the first row at which the chain fails to verify.
type Divergence struct {
	RowIndex   int // 0-based position in the query's stable order
	ID         string
	OccurredAt time.Time
	Kind       FailureKind
	Expected   string
	Actual     string
}

// Report is VerifyChain's result.
type Report struct {
	RowsChecked int
	Divergence  *Divergence // nil means the chain is intact
}

func (r Report) OK() bool { return r.Divergence == nil }

// VerifyChain re-derives each row's hash from its own stored fields and
// checks the chain end to end, in the order rows is already in (callers must
// pass rows already ordered occurred_at ASC, id ASC — see LoadAuditEvents).
// It is deliberately pure and DB-free so it can be unit-tested without a
// database (internal/argusctl/audit_test.go) — this is the part of the tool
// that actually matters, per lld/05-data-model.md §7 and SR-15.
//
// Two DISTINCT checks are performed per row, deliberately not collapsed into
// one:
//
//  1. Hash check: recompute audit.ComputeHash using THIS row's own stored
//     prev_hash (never a freshly recomputed prev_hash from the prior row —
//     see below for why that distinction matters) plus this row's own core
//     fields and occurred_at, and compare against this row's own stored
//     hash.
//  2. Link check: compare this row's own stored prev_hash against the
//     immediately preceding row's own stored hash (or, for row 0, against
//     audit.GenesisPrevHash).
//
// Why check 1 must use the row's own STORED prev_hash, not a prev_hash this
// function itself just recomputed for the prior row: if it instead threaded
// its own recomputed value forward as "prev_hash" for the next row's check,
// a single tampered row would make every hash after it "verify" against a
// chain of recomputed-not-stored values that was silently re-derived to be
// self-consistent from that point on — exactly the kind of forward
// propagation that would mask the original divergence instead of catching
// it. Using each row's own stored prev_hash for check 1, and comparing that
// SAME stored value against the previous row's stored hash in check 2
// (rather than trusting check 1 to have implicitly covered it), is what
// makes tampering with an EARLIER row still show up as check 2's failure on
// the VERY NEXT row, at the earliest possible point, rather than only
// eventually or not at all.
func VerifyChain(rows []AuditRow) Report {
	var prevStoredHash string
	for i, row := range rows {
		wantPrevHash := audit.GenesisPrevHash
		if i > 0 {
			wantPrevHash = prevStoredHash
		}
		if row.PrevHash != wantPrevHash {
			return Report{
				RowsChecked: i + 1,
				Divergence: &Divergence{
					RowIndex:   i,
					ID:         row.ID,
					OccurredAt: row.OccurredAt,
					Kind:       FailurePrevHashMismatch,
					Expected:   wantPrevHash,
					Actual:     row.PrevHash,
				},
			}
		}

		ev := audit.NewCoreEvent(row.TenantID, row.ActorID, row.Capability, row.Scope, row.ClusterID, row.Outcome)
		recomputed, err := audit.ComputeHash(row.PrevHash, ev, row.OccurredAt)
		if err != nil {
			// A hash-input that can't even be recomputed (e.g. a corrupted scope
			// value that no longer round-trips through JSON) is itself evidence
			// this row diverges from a legitimately-written one — report it as a
			// hash mismatch rather than returning a bare error, since the whole
			// point of this tool is to surface exactly which row is suspect.
			return Report{
				RowsChecked: i + 1,
				Divergence: &Divergence{
					RowIndex:   i,
					ID:         row.ID,
					OccurredAt: row.OccurredAt,
					Kind:       FailureHashMismatch,
					Expected:   row.Hash,
					Actual:     fmt.Sprintf("<could not recompute: %v>", err),
				},
			}
		}
		if recomputed != row.Hash {
			return Report{
				RowsChecked: i + 1,
				Divergence: &Divergence{
					RowIndex:   i,
					ID:         row.ID,
					OccurredAt: row.OccurredAt,
					Kind:       FailureHashMismatch,
					Expected:   row.Hash,
					Actual:     recomputed,
				},
			}
		}

		prevStoredHash = row.Hash
	}
	return Report{RowsChecked: len(rows)}
}
