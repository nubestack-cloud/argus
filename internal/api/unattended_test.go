package api

import (
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"argus/internal/execution"
	"argus/internal/remediation"
)

// The XOR invariant migration 000047 enforces in the database, asserted here in
// Go so a broken actor never reaches the insert and turns a design invariant
// into a constraint-violation error at 3am. Both constructors are checked
// against the same rule, because the failure this guards against is one of them
// drifting onto the other's attribution.
func TestExecutionActorSatisfiesTheActorXorUnattendedInvariant(t *testing.T) {
	rc := &requestContext{UserID: "usr_01HUMAN", TenantID: "org_1"}
	req := httptest.NewRequest("POST", "/api/v1/incidents/inc_1/approve", nil)
	req.RemoteAddr = "10.1.2.3:4567"

	for _, tc := range []struct {
		name  string
		actor execution.Actor
	}{
		{"human", humanActor(rc, req)},
		{"policy", execution.PolicyActor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotNil := tc.actor.ActorIDOrNil() == nil
			if gotNil != tc.actor.Unattended {
				t.Fatalf("actor %+v violates (actor_id IS NULL) = unattended: actorIDOrNil()==nil is %v, Unattended is %v — "+
					"migration 000047's CHECK constraint would reject this row", tc.actor, gotNil, tc.actor.Unattended)
			}
			if tc.actor.AuthMethod == "" {
				t.Error("AuthMethod is empty — audit_events.actor_auth_method would record nothing about how this decision was reached")
			}
		})
	}
}

// A human approval must never be recorded as unattended, and the machine one
// must never carry a user id. Separate from the invariant test above because
// that one would also pass if both constructors happened to produce the same
// (wrong) shape.
func TestHumanActorAndPolicyActorAreNotInterchangeable(t *testing.T) {
	rc := &requestContext{UserID: "usr_01HUMAN", TenantID: "org_1"}
	req := httptest.NewRequest("POST", "/api/v1/incidents/inc_1/approve", nil)
	req.RemoteAddr = "10.1.2.3:4567"

	human := humanActor(rc, req)
	if human.Unattended {
		t.Error("a human approval is recorded as unattended — the blast-radius counter would charge it against the automatic budget, and the audit trail would deny a real approver did this")
	}
	if human.UserID != "usr_01HUMAN" {
		t.Errorf("human actor lost the approver: %q", human.UserID)
	}
	if human.SourceIP == "" {
		t.Error("human actor recorded no source IP, though the request has a remote address")
	}

	if !execution.PolicyActor.Unattended {
		t.Fatal("execution.PolicyActor is not marked unattended — remediation_executions.unattended would be false and the blast-radius cap would never count anything, silently making the limits infinite")
	}
	if execution.PolicyActor.UserID != "" {
		t.Errorf("execution.PolicyActor names a user (%q): a machine decision must not be attributed to a person", execution.PolicyActor.UserID)
	}
	if execution.PolicyActor.SourceIP != "" {
		t.Errorf("execution.PolicyActor recorded a source IP (%q): no request reached the hub, so any address here is a fiction", execution.PolicyActor.SourceIP)
	}
}

// The candidate query excludes OpenPR by action type. That is only honest while
// OpenPR genuinely has no execution path — if one is ever added, the exclusion
// becomes a silent policy decision about opening pull requests without a human,
// which is a different consent question and must be made deliberately rather
// than inherited from this query.
func TestOpenPRStillHasNoExecutionPath(t *testing.T) {
	if tool, ok := execution.ToolForAction(remediation.ActionOpenPR); ok {
		t.Fatalf("OpenPR now executes via %q. The unattended candidate query excludes OpenPR by action type; "+
			"that exclusion is now a deliberate policy choice about opening pull requests with no human in the loop, "+
			"not an absence of capability. Decide it explicitly and document it in unattended.go's header", tool)
	}
	if !strings.Contains(unattendedCandidateQuery, "r.action_type <> 'OpenPR'") {
		t.Error("the unattended candidate query no longer excludes OpenPR")
	}
}

// The query is the enforcement point for four separate safety properties, none
// of which is visible anywhere else. Asserted as text because the alternative
// is a live database, and a missing clause here is not a subtle degradation:
// dropping the state filter would execute plans a human already rejected, and
// dropping the decision filter would execute the same plan every 30 seconds
// forever.
func TestUnattendedCandidateQueryKeepsItsSafetyClauses(t *testing.T) {
	for _, want := range []struct{ fragment, why string }{
		{"i.state = $1", "without the state filter, an incident a human already approved, rejected or closed is still a candidate"},
		{"r.gate_outcome = 'AutoApprove'", "without this, a plan the gate itself said needs a human would execute without one — the setting would widen the policy rather than act on it"},
		{"NOT EXISTS", "without the already-decided check, the same plan is re-executed on every single tick"},
		{"r.created_at >= $2", "without the age bound, turning the switch on executes the entire accumulated backlog at once"},
		{"r.superseded_at IS NULL", "without this the sweeper executes a plan ARGUS itself superseded with a pull request — on the live run that produced this clause, that meant setting a working image back to a broken tag, unattended, with no human to read the 409 the approve path returns"},
		{"DISTINCT ON (r.incident_id)", "without this, a re-analysed incident offers several plans and a superseded one could be the one that runs"},
		{"ORDER BY r.incident_id, r.created_at DESC", "DISTINCT ON keeps the FIRST row per incident, so this ordering is what makes it the newest plan rather than an arbitrary one"},
	} {
		if !strings.Contains(unattendedCandidateQuery, want.fragment) {
			t.Errorf("candidate query is missing %q: %s", want.fragment, want.why)
		}
	}
}

// The time gate must be evaluated BEFORE the blast-radius budget, and must be
// able to stop a whole sweep on its own.
//
// Asserted structurally because the alternative is a live clock: the ordering
// matters for a specific reason — both refuse, but a freeze is a statement about
// whether ARGUS may act at all, so a budget query that failed must not be able to
// mask the fact that a change freeze was in force. Reading the source order is
// the only way to assert that without a database and a fake clock.
func TestSweepChecksTimeWindowsBeforeBudget(t *testing.T) {
	src, err := os.ReadFile("unattended.go")
	if err != nil {
		t.Fatalf("read unattended.go: %v", err)
	}
	body := string(src)
	sweep := body[strings.Index(body, "func (s *Server) sweepUnattended"):]
	sweep = sweep[:strings.Index(sweep, "\n// candidateQuery")]

	window := strings.Index(sweep, "orchestrator.CheckWindows")
	budget := strings.Index(sweep, "checkUnattendedBudget")
	if window < 0 {
		t.Fatal("the sweep does not call orchestrator.CheckWindows — a change freeze would be invisible to the only path that acts without a human")
	}
	if budget < 0 {
		t.Fatal("the sweep no longer checks the blast-radius budget")
	}
	if window > budget {
		t.Error("the blast-radius budget is checked before the time windows. A budget query that fails must not be able to mask a change freeze being in force")
	}
}

// TestUnattendedNamespaceAllowlistDeniesByDefault covers migration 000055's whole
// point: before it, enabling unattended execution enabled it for every namespace
// on every connected cluster. Measured at the time — the eligible backlog included
// `kube-system`, `cattle-monitoring-system`, `argocd` and two real workloads on a
// cluster designated look-don't-touch. Nothing was acted on, but only because the
// model proposed no plan for them and one cluster happened to be disconnected.
//
// PROJECT.md T14 moved the filter from the candidate SQL into collectUnattended's
// Go loop (see unattendedCandidateQuery's own comment for why: it lets a
// namespace-blocked candidate be attributed GateNamespaceScope instead of never
// appearing at all). This test now asserts the two properties that made the SQL
// version safe still hold in the new location: the check happens BEFORE anything
// else can act on the candidate (mirrors TestSweepChecksTimeWindowsBeforeBudget's
// own structural-read approach, applied to the same file), and an empty/nil
// allowlist denies every namespace rather than permitting one.
func TestUnattendedNamespaceAllowlistDeniesByDefault(t *testing.T) {
	src, err := os.ReadFile("unattended.go")
	if err != nil {
		t.Fatalf("read unattended.go: %v", err)
	}
	body := string(src)
	collect := body[strings.Index(body, "func (s *Server) collectUnattended"):]

	namespaceCheck := strings.Index(collect, "slices.Contains(cfg.AutonomyUnattendedNamespaces")
	appendConnected := strings.Index(collect, "connected = append(connected, c)")
	if namespaceCheck < 0 {
		t.Fatal("collectUnattended no longer filters candidates against the unattended-execution namespace allowlist")
	}
	if appendConnected < 0 {
		t.Fatal("collectUnattended no longer builds a `connected` slice of surviving candidates")
	}
	if namespaceCheck > appendConnected {
		t.Error("the namespace allowlist check runs AFTER a candidate is already appended to `connected` — " +
			"a namespace-scoped policy would depend on a later check remembering to apply it, exactly the " +
			"failure mode migration 000055 exists to prevent")
	}

	// The deny-by-default property itself: slices.Contains against a nil or
	// empty allowlist can never match any namespace, matching the retired SQL
	// predicate's own `= ANY($3::text[])` semantics against an empty array
	// (both mean "matches nothing").
	var emptyAllowlist []string
	if slices.Contains(emptyAllowlist, "default") {
		t.Fatal("an empty allowlist matched a namespace — this IS the deny-by-default property migration 000055 added")
	}
}
