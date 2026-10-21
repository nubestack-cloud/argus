package llm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// The guarantee this file exists to hold: a findings prompt is BOUNDED, whatever
// the incident's history looks like.
//
// It has to be DB-backed. The bound is a property of a query plus a loop over
// real rows, and the bug it replaces was invisible in every unit test precisely
// because no test ever put 2400 findings in front of it. The live failure was
// `fork/exec: argument list too long` — cmd/cli-runner passes the prompt as one
// argv element and Linux caps a single argument at MAX_ARG_STRLEN (32 pages =
// 131,072 bytes), so a prompt past 128 KiB cannot be executed at all.
//
// Uses the same ARGUS_TEST_DATABASE_URL harness as internal/gateway's DB tests.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed findings-prompt bound test (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// maxArgStrLen is the OS limit that actually bit, stated here rather than in a
// comment so the assertion below is against the real constraint and not against
// a number somebody liked.
const maxArgStrLen = 32 * 4096

func TestBuildFindingsPromptStaysExecutable(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Rolled back: this test only needs the rows to exist for the length of its
	// own transaction, and leaving 2500 findings behind in a dev database is how
	// the next person's fleet counts go wrong.
	defer func() { _ = tx.Rollback(ctx) }()

	tenant, cluster, incident := seedIncident(ctx, t, tx)

	// 2500 findings across three reasons — modelled on the real incident
	// (inc_01m0xfwwjjgk1hexrsnqc00m7e: 2405 rows, 824,647 bytes), with the same
	// shape that made it big: one reason repeating thousands of times with a
	// long kubelet message.
	const longMessage = "Unable to retrieve some image pull secrets (registry-225346); attempting to pull the image may not succeed."
	reasons := []string{"FailedToRetrieveImagePullSecret", "ErrImagePull", "PendingTimeout"}
	for i := 0; i < 2500; i++ {
		reason := reasons[i%len(reasons)]
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, incident_id, detector_id, detector_version, gvk,
			                       namespace, object_name, reason, message, severity, occurrence_count, occurred_at, fingerprint)
			 VALUES ($1,$2,$3,$4,'k8s-warning-events','1','v1/Pod','argus-test',$5,$6,$7,'medium',$8, now() - ($9::int * interval '1 second'), $10)`,
			fmt.Sprintf("fnd_bound_%04d", i), tenant, cluster, incident,
			fmt.Sprintf("nolimits-d68cd9bb6-%04d", i), reason, longMessage, i+1, i, fmt.Sprintf("fp_%04d", i),
		); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
	}

	header := "Cluster: test\nIncident fingerprint: fp, severity: medium, seen 2500 time(s)\n\nFindings:\n"
	prompt, err := BuildFindingsPrompt(ctx, tx, incident, header)
	if err != nil {
		t.Fatalf("BuildFindingsPrompt: %v", err)
	}

	// 1. THE BOUND. This is the assertion that would have caught the live bug.
	if len(prompt) >= maxArgStrLen {
		t.Errorf("prompt is %d bytes, at or past the %d-byte single-argument exec limit — this incident would be permanently un-analysable, which is exactly the bug this bound exists to prevent",
			len(prompt), maxArgStrLen)
	}
	// And comfortably inside it, not merely under by a hair: the system prompt
	// and flags share the command line.
	if len(prompt) > maxFindingsPromptBytes+len(header)+4096 {
		t.Errorf("prompt is %d bytes, past its own %d-byte budget plus header — the byte backstop is not holding", len(prompt), maxFindingsPromptBytes)
	}

	// 2. EVERY DISTINCT REASON SURVIVES the cap. Dropping the repetition is the
	// point; dropping a whole class of fault would make the analysis wrong.
	for _, reason := range reasons {
		if !strings.Contains(prompt, reason) {
			t.Errorf("reason %q is absent from the prompt — the cap dropped an entire distinct fault, not just repetition", reason)
		}
	}

	// 3. THE TRUTH ABOUT WHAT WAS OMITTED. A model handed a silently truncated
	// history will reason about a fault volume it was never shown.
	if !strings.Contains(prompt, "of 2500 findings") {
		t.Errorf("prompt does not state how many findings it is showing out of the true total; got tail:\n%s", tail(prompt))
	}
	for _, reason := range reasons {
		if !strings.Contains(prompt, reason+": ") {
			t.Errorf("prompt does not report a per-reason total for %q — the caller cannot tell repetition from volume", reason)
		}
	}
}

// TestBuildFindingsPromptSaysNothingWhenNothingIsOmitted: the caveat must not
// appear on a small incident, or it becomes noise that trains the reader (and
// the model) to ignore it on the incidents where it matters.
func TestBuildFindingsPromptSaysNothingWhenNothingIsOmitted(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tenant, cluster, incident := seedIncident(ctx, t, tx)
	for i := 0; i < 3; i++ {
		if _, err := tx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, incident_id, detector_id, detector_version, gvk,
			                       namespace, object_name, reason, message, severity, occurrence_count, occurred_at, fingerprint)
			 VALUES ($1,$2,$3,$4,'k8s-warning-events','1','v1/Pod','argus-test','pod-a','ErrImagePull','boom','medium',1, now(), $5)`,
			fmt.Sprintf("fnd_small_%d", i), tenant, cluster, incident, fmt.Sprintf("fp_small_%d", i),
		); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
	}

	prompt, err := BuildFindingsPrompt(ctx, tx, incident, "header\n")
	if err != nil {
		t.Fatalf("BuildFindingsPrompt: %v", err)
	}
	if strings.Contains(prompt, "Showing") || strings.Contains(prompt, "omitted") {
		t.Errorf("prompt carries a truncation caveat for an incident where nothing was truncated:\n%s", prompt)
	}
}

// seedIncident inserts the organisation/cluster/incident rows findings need,
// and returns the ids. No ON CONFLICT anywhere: every insert happens inside a
// transaction the caller rolls back, so these rows cannot pre-exist — and
// `incidents` has no single-column unique constraint for ON CONFLICT (id) to
// match anyway.
//
// The tenant used to be "the first row in organisations", read via `SELECT id
// FROM organisations ORDER BY id LIMIT 1` on the theory that ULID's
// timestamp-encoded prefix guarantees the permanent bootstrap org
// (org_01m0fsktfmqj6z7vwstk1423gp, created 2026-08-20) always sorts first.
// That theory silently assumed every row in the table shares the `org_`
// prefix. It doesn't: internal/authz/permissions_db_test.go's
// insertTestOrganisation mints throwaway orgs via domain.NewID("f19org") — a
// custom prefix — and "f19org_..." < "org_..." lexicographically (ASCII 'f' <
// 'o'), regardless of either row's timestamp. For however briefly that row is
// alive (both its insert and its t.Cleanup delete are bare, un-transacted
// pool.Exec calls — genuinely committed against the shared table, not rolled
// back), `ORDER BY id LIMIT 1` here would pick it over the bootstrap org, and
// then find it deleted out from under this transaction's own FK check —
// BUGS.md 126's `clusters_tenant_id_fkey` flake, root-caused via Postgres
// statement logging (log_statement=all) across two reproductions of `go test
// -count=1 ./...`: the throwaway org's insert/delete pair (from
// internal/authz's cluster-group isolation test) is genuinely committed and
// racing this package's own borrow-the-first-org read, sometimes directly and
// sometimes via the delete blocking on a FOR KEY SHARE lock this SAME
// package's other seedIncident call took out by referencing that same
// borrowed org for the ~1s its own transaction (2500 sequential finding
// inserts) stays open.
//
// Rather than fix the race by making the other side's ordering promise hold
// (which any future test touching organisations could break again the same
// way), this creates and scopes its OWN throwaway organisation, inside the
// SAME transaction the caller already rolls back — so it needs no separate
// cleanup, and no other package's use of `organisations` can ever affect it.
func seedIncident(ctx context.Context, t *testing.T, tx pgx.Tx) (tenant, cluster, incident string) {
	t.Helper()
	tenant = domain.NewID(domain.PrefixOrganisation)
	if _, err := tx.Exec(ctx, `INSERT INTO organisations (id, name) VALUES ($1, $2)`, tenant, "prompt-findings-test"); err != nil {
		t.Fatalf("insert throwaway organisation: %v", err)
	}
	cluster, incident = "cl_promptbound", "inc_promptbound"
	if err := data.SetRequestScope(ctx, tx, tenant, []string{cluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1,$2,'prompt bound','Active','shard-test',$3)`,
		cluster, tenant, "fp-"+cluster); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1,$2,$3,'fp_promptbound','medium','Detected', now(), now(), 2500)`,
		incident, tenant, cluster); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	return tenant, cluster, incident
}

func tail(s string) string {
	if len(s) < 600 {
		return s
	}
	return "..." + s[len(s)-600:]
}
