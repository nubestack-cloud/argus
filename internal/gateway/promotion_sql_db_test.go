package gateway

import (
	"context"
	"testing"
)

// PROJECT.md F31. PromotableFindingSQL renders this package's promotion gate
// as a SQL predicate so GET /api/v1/findings can filter and count by it.
// Nothing about that rendering is checked by the Go compiler: a mis-quoted
// literal, a tuple list Postgres parses differently than intended, or a NULL
// reason taking the wrong CASE branch would all produce a predicate that runs
// fine and silently puts findings in the wrong bucket — an operator reading
// "nothing was suppressed" off a wrong answer is worse than no surface at all.
//
// So this evaluates the predicate INSIDE Postgres, over the gate's entire
// input domain on both sides of the legacy-generic correction, and requires it
// to agree with ExplainStoredFinding on every single row.
//
// It touches no real table: the tuples arrive as a VALUES list aliased
// `findings`, which is exactly the shape the predicate names. Nothing is
// inserted, so there is nothing to clean up and no dbtest fixture needed.
//
// Gated on ARGUS_TEST_DATABASE_URL like the rest of this package's
// *_db_test.go files; a machine without one gets a clean skip. Point it at
// argus_app, never postgres — not that it matters for this particular test,
// which reads no table, but the convention is worth not breaking.
func TestPromotableFindingSQLAgreesWithTheGoGate(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Every reason class the predicate distinguishes: the two prefixes, the
	// exact name, a plain detector reason, and the empty string. A NULL
	// reason is covered separately below because it cannot travel in the same
	// text-typed VALUES column without extra casting noise.
	reasons := []string{"CrashLoopBackOff", "", legacyGenericAnomalyExact}
	for _, prefix := range legacyGenericAnomalyPrefixes {
		reasons = append(reasons, prefix+"Ready")
	}

	type row struct {
		reason, class, confidence, impact string
	}
	var rows []row
	for _, reason := range reasons {
		for _, tuple := range allEvidenceTuples() {
			rows = append(rows, row{reason, tuple[0], tuple[1], tuple[2]})
		}
	}
	if want := len(reasons) * 36; len(rows) != want {
		t.Fatalf("built %d cases, want %d — the domain enumeration is wrong, so agreement here would prove less than it looks like it does", len(rows), want)
	}

	// Parameterised, not interpolated: the predicate under test is the only
	// thing spliced into this statement.
	var values string
	args := make([]any, 0, len(rows)*4)
	for i, r := range rows {
		if i > 0 {
			values += ", "
		}
		n := len(args)
		values += "($" + itoa(n+1) + "::text, $" + itoa(n+2) + "::text, $" + itoa(n+3) + "::text, $" + itoa(n+4) + "::text)"
		args = append(args, r.reason, r.class, r.confidence, r.impact)
	}

	query := `SELECT findings.reason, findings.signal_class, findings.confidence, findings.impact, ` +
		PromotableFindingSQL() + ` AS promotable
	            FROM (VALUES ` + values + `) AS findings(reason, signal_class, confidence, impact)`

	pgRows, err := pool.Query(ctx, query, args...)
	if err != nil {
		t.Fatalf("evaluate PromotableFindingSQL in Postgres: %v\nquery: %s", err, query)
	}
	defer pgRows.Close()

	seen := 0
	for pgRows.Next() {
		var reason, class, confidence, impact string
		var promotable bool
		if err := pgRows.Scan(&reason, &class, &confidence, &impact, &promotable); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		want := ExplainStoredFinding(reason, class, confidence, impact).Promotable
		if promotable != want {
			t.Errorf("reason=%q (%s, %s, %s): SQL says promotable=%v, ExplainStoredFinding says %v",
				reason, class, confidence, impact, promotable, want)
		}
	}
	if err := pgRows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if seen != len(rows) {
		t.Fatalf("Postgres evaluated %d rows, expected %d", seen, len(rows))
	}
}

// TestPromotableFindingSQLHandlesANullReason is the case the VALUES list
// above cannot carry cleanly, and the one most likely to be got wrong:
// findings.reason is nullable, `NULL LIKE 'Generic%'` is NULL rather than
// false, and a CASE whose WHEN is NULL takes the ELSE branch. That happens to
// be the same branch Go's own predicate takes for "" — but "happens to be" is
// not a guarantee, so it is asserted rather than assumed.
func TestPromotableFindingSQLHandlesANullReason(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	for _, tuple := range allEvidenceTuples() {
		var promotable bool
		err := pool.QueryRow(ctx,
			`SELECT `+PromotableFindingSQL()+`
			   FROM (VALUES (NULL::text, $1::text, $2::text, $3::text)) AS findings(reason, signal_class, confidence, impact)`,
			tuple[0], tuple[1], tuple[2]).Scan(&promotable)
		if err != nil {
			t.Fatalf("evaluate with a NULL reason %v: %v", tuple, err)
		}
		// A NULL reason is not a legacy generic mechanism, which is what Go
		// says of the empty string it would be read as.
		if want := ExplainStoredFinding("", tuple[0], tuple[1], tuple[2]).Promotable; promotable != want {
			t.Errorf("NULL reason (%s, %s, %s): SQL says promotable=%v, Go says %v",
				tuple[0], tuple[1], tuple[2], promotable, want)
		}
	}
}

// itoa avoids pulling strconv in for one call in a test file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
