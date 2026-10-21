package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/llm"
)

// TestHandleListIncidentsRejectsInvalidState is the DB-free slice of
// handleListIncidents' new ?state= filter: an unrecognized value must be
// rejected with 400 before any query ever reaches rc.Tx (a nil Tx here would
// panic if the handler tried) — matching how ?clusterId= has never needed
// validation (any string is a legal, if possibly-matching-nothing, cluster
// id) while ?state= has a fixed enum to validate against. Valid values and
// "absent" both fall through to the real query, which needs a live
// Postgres connection and is covered by scripts/smoke-test.sh instead.
func TestHandleListIncidentsRejectsInvalidState(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?state=NotARealState", nil)
	rec := httptest.NewRecorder()

	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// --- BACKLOG P10: server-side sort ---
//
// The cases below all resolve to a 400 before handleListIncidents ever
// touches rc.Tx, exactly like TestHandleListIncidentsRejectsInvalidState
// above — a nil Tx would panic if any of them fell through to the real
// query. Sort-by-real-data (severity/state's rank order, keyset pagination
// continuity, RLS) needs a live Postgres and is covered by
// TestHandleListIncidentsSearchSortCountsAndRLS below.

// TestHandleListIncidentsRejectsInvalidSortKey guards the same "unknown
// value is an error, not a silent fallback" contract ?state= already has:
// a typo'd ?sort= must not quietly resolve to the default ordering, which
// would look like a working sort that just never took effect.
func TestHandleListIncidentsRejectsInvalidSortKey(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?sort=notARealColumn", nil)
	rec := httptest.NewRecorder()

	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleListIncidentsRejectsInvalidDirection(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?sort=severity&direction=sideways", nil)
	rec := httptest.NewRecorder()

	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleListIncidentsRejectsCursorFromADifferentSort is the defensive
// check BACKLOG P10 called out explicitly: a cursor minted while sorting by
// severity must not be silently applied to a request now sorting by state —
// the two values are not comparable, and doing so would mis-paginate rather
// than error. encodeIncidentSortCursor embeds the sort key precisely so this
// is catchable.
func TestHandleListIncidentsRejectsCursorFromADifferentSort(t *testing.T) {
	staleCursor := encodeIncidentSortCursor("inc_01test", "severity", "3")
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?sort=state&cursor="+staleCursor, nil)
	rec := httptest.NewRecorder()

	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s) — a severity cursor must not be accepted for a state sort", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleListIncidentsRejectsMalformedSortCursor covers decode failures
// for the non-lastSeen cursor shape, matching
// TestDecodeIncidentCursorRejectsGarbage's coverage of the pre-existing one.
func TestHandleListIncidentsRejectsMalformedSortCursor(t *testing.T) {
	for _, cursor := range []string{
		"not base64 at all !!",
		base64.RawURLEncoding.EncodeToString([]byte("no pipes here")),
		base64.RawURLEncoding.EncodeToString([]byte("|severity|3")),
		base64.RawURLEncoding.EncodeToString([]byte("inc_1||3")),
	} {
		s := &Server{}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?sort=severity&cursor="+url.QueryEscape(cursor), nil)
		rec := httptest.NewRecorder()

		s.handleListIncidents(rec, req, &requestContext{})

		if rec.Code != http.StatusBadRequest {
			t.Errorf("cursor %q: status = %d, want %d (body: %s)", cursor, rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	}
}

// TestEncodeDecodeIncidentSortCursorRoundTrip is the pure encode/decode
// coverage for the five non-lastSeen sort keys' shared cursor shape —
// lastSeen keeps using (and is already covered by)
// TestIncidentCursorRoundTrip's pre-existing pair, untouched by this
// feature.
func TestEncodeDecodeIncidentSortCursorRoundTrip(t *testing.T) {
	cases := []struct {
		id, sortKey, value string
	}{
		{"inc_01m0kf0ckgkjk21yz6d77gd131", "severity", "3"},
		{"inc_01m0kf0ckgkjk21yz6d77gd132", "state", "0"},
		{"inc_01m0kf0ckgkjk21yz6d77gd133", "occurrences", "42"},
		{"inc_01m0kf0ckgkjk21yz6d77gd134", "cluster", "prod-eu"},
		{"inc_01m0kf0ckgkjk21yz6d77gd135", "failure", "OOMKilled · payments-api"},
		// A value containing a literal "|" must still round-trip: it is the
		// LAST field in the payload and is never itself split further.
		{"inc_01m0kf0ckgkjk21yz6d77gd136", "failure", "reason | with a pipe · object|name"},
	}
	for _, c := range cases {
		gotID, gotSortKey, gotValue, err := decodeIncidentSortCursor(encodeIncidentSortCursor(c.id, c.sortKey, c.value))
		if err != nil {
			t.Fatalf("decode(encode(%+v)): %v", c, err)
		}
		if gotID != c.id || gotSortKey != c.sortKey || gotValue != c.value {
			t.Errorf("round-tripped to (%q, %q, %q), want (%q, %q, %q)", gotID, gotSortKey, gotValue, c.id, c.sortKey, c.value)
		}
	}
}

// TestRankCaseExprOrdersBySequenceNotAlphabet is the DB-free half of the
// severity/state ranking coverage: it asserts the CASE expression assigns
// ranks in `order`'s own sequence, which for severity is NOT alphabetical
// (low < medium < high < critical, not critical < high < low < medium) —
// the same mistake internal/remediation.riskRank exists to prevent for
// RiskLevel. The expression's actual effect on ORDER BY needs a live
// Postgres and is covered by TestHandleListIncidentsSearchSortCountsAndRLS's
// "severity and state sort by rank, not alphabetically" subtest.
func TestRankCaseExprOrdersBySequenceNotAlphabet(t *testing.T) {
	expr := rankCaseExpr("incidents.severity", severityOrder)
	for _, want := range []string{"WHEN 'low' THEN 0", "WHEN 'medium' THEN 1", "WHEN 'high' THEN 2", "WHEN 'critical' THEN 3", "ELSE 4"} {
		if !strings.Contains(expr, want) {
			t.Errorf("rankCaseExpr(severity) = %q, want it to contain %q", expr, want)
		}
	}
}

// TestSqlQuoteLiteralEscapesSingleQuotes: rankCaseExpr's literals are always
// this file's own package vars (severityOrder/stateOrder) rather than
// request input, but the quoting function itself is still tested directly —
// an unescaped quote here would produce a syntax error deep inside a
// dynamically built query string, which is a much worse place to discover it
// than a unit test.
func TestSqlQuoteLiteralEscapesSingleQuotes(t *testing.T) {
	if got, want := sqlQuoteLiteral("O'Brien"), "'O''Brien'"; got != want {
		t.Errorf("sqlQuoteLiteral(%q) = %q, want %q", "O'Brien", got, want)
	}
}

// TestEscapeLikePatternEscapesWildcards: a search for a literal "%" or "_"
// (both appear in real k8s names) must not be interpreted as an ILIKE
// wildcard once wrapped in %...%.
func TestEscapeLikePatternEscapesWildcards(t *testing.T) {
	cases := map[string]string{
		"50%":        `50\%`,
		"my_service": `my\_service`,
		`back\slash`: `back\\slash`,
	}
	for in, want := range cases {
		if got := escapeLikePattern(in); got != want {
			t.Errorf("escapeLikePattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestValidIncidentStatesMatchesMigration guards against the enum drifting
// from internal/migrations/000005_incidents_and_analysis.up.sql's CHECK
// constraint, widened by migration 000062 to add Diagnosed
// (lld/08-remediation-contracts.md §12.7), by migration 000081 to add
// ExecutionUnknown (BACKLOG.md C8 / BUGS.md 104), by migration 000094 to
// add ValidationUnknown (a fix ARGUS applied and could not confirm held — see
// internal/orchestrator's StateValidationUnknown) and by migration 000095 to
// add PlanRejected (a human refused the proposed fix; the incident stays open
// because the fault does) — hand-transcribed here
// (see validIncidentStates' doc comment) rather than read from the DB at
// request time.
func TestValidIncidentStatesMatchesMigration(t *testing.T) {
	want := []string{
		"Detected", "Investigating", "RecommendationReady", "NeedsHumanInvestigation",
		"AwaitingApproval", "Executing", "AwaitingMerge", "Validating",
		"Resolved", "Failed", "Reopened", "Dismissed", "Diagnosed", "ExecutionUnknown",
		"ValidationUnknown", "PlanRejected", "Expired",
	}
	if len(validIncidentStates) != len(want) {
		t.Fatalf("validIncidentStates has %d entries, want %d", len(validIncidentStates), len(want))
	}
	for i, w := range want {
		if validIncidentStates[i] != w {
			t.Errorf("validIncidentStates[%d] = %q, want %q", i, validIncidentStates[i], w)
		}
	}
}

// --- the findings history: one row per reason, repeats collapsed ---
//
// DB-free by construction, like the ownership cases below: the query does the
// counting (verified against a live Postgres, where an 84-finding incident sent
// 10 rows and a 23-finding one sent 13 across two reasons), and this function
// does the only part with a decision in it — which reason leads, and which of
// the repeated totals rows survives.

// findingRow builds one scanned row: the finding, plus the totals its reason
// carries on every row of that reason.
func findingRow(reason, occurredAt string, total int, first, last string) findingWithReasonTotals {
	return findingWithReasonTotals{
		Finding: findingSummary{ID: reason + occurredAt, Reason: reason, OccurredAt: occurredAt},
		Totals:  findingReasonGroup{Reason: reason, Count: total, FirstSeen: first, LastSeen: last},
	}
}

// The shape the whole feature exists for: the 81-event incident from
// BUGS.md item 30, arriving newest-first with each reason's
// repeats bounded. The current symptom leads, and every count describes the
// whole history rather than the handful of rows that came with it.
func TestGroupFindingsByReasonCollapsesRepeatsNewestReasonFirst(t *testing.T) {
	rows := []findingWithReasonTotals{
		findingRow("ImagePullBackOff", "2026-08-21T21:15:00Z", 34, "2026-08-21T17:02:00Z", "2026-08-21T21:15:00Z"),
		findingRow("ErrImagePull", "2026-08-21T21:15:00Z", 34, "2026-08-21T17:02:00Z", "2026-08-21T21:15:00Z"),
		findingRow("ImagePullBackOff", "2026-08-21T21:10:00Z", 34, "2026-08-21T17:02:00Z", "2026-08-21T21:15:00Z"),
		findingRow("Failed", "2026-08-21T20:44:00Z", 13, "2026-08-21T17:02:00Z", "2026-08-21T20:44:00Z"),
		findingRow("ErrImagePull", "2026-08-21T20:44:00Z", 34, "2026-08-21T17:02:00Z", "2026-08-21T21:15:00Z"),
	}

	findings, groups := groupFindingsByReason(rows)

	if len(findings) != len(rows) {
		t.Fatalf("findings has %d entries, want all %d rows — the flat list is the expandable evidence, nothing may be dropped from it", len(findings), len(rows))
	}
	for i, f := range findings {
		if f.ID != rows[i].Finding.ID {
			t.Errorf("findings[%d].ID = %q, want %q — the query's recency order must survive grouping", i, f.ID, rows[i].Finding.ID)
		}
	}

	want := []findingReasonGroup{
		{Reason: "ImagePullBackOff", Count: 34, FirstSeen: "2026-08-21T17:02:00Z", LastSeen: "2026-08-21T21:15:00Z"},
		{Reason: "ErrImagePull", Count: 34, FirstSeen: "2026-08-21T17:02:00Z", LastSeen: "2026-08-21T21:15:00Z"},
		{Reason: "Failed", Count: 13, FirstSeen: "2026-08-21T17:02:00Z", LastSeen: "2026-08-21T20:44:00Z"},
	}
	if len(groups) != len(want) {
		t.Fatalf("groups = %+v, want one group per distinct reason (%d)", groups, len(want))
	}
	for i := range want {
		if groups[i] != want[i] {
			t.Errorf("groups[%d] = %+v, want %+v", i, groups[i], want[i])
		}
	}
}

// The counts are the query's, never len(events): a group whose repeats were
// bounded away must still report the total, because "34 times since 17:02" is
// the fact an operator reads to tell an accelerating symptom from a settling
// one. A count meaning "of the ones we happened to send" would be worse than
// none.
func TestGroupFindingsByReasonReportsWholeHistoryNotWhatWasSent(t *testing.T) {
	rows := make([]findingWithReasonTotals, 0, maxFindingsPerReason)
	for i := 0; i < maxFindingsPerReason; i++ {
		rows = append(rows, findingRow("ServiceNoEndpoints", fmt.Sprintf("2026-08-21T22:%02d:00Z", 9-i), 80,
			"2026-08-21T17:21:19Z", "2026-08-21T22:09:15Z"))
	}

	findings, groups := groupFindingsByReason(rows)

	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want exactly one", groups)
	}
	if len(findings) != maxFindingsPerReason {
		t.Errorf("findings has %d entries, want the %d the query kept", len(findings), maxFindingsPerReason)
	}
	if groups[0].Count != 80 {
		t.Errorf("group count = %d, want 80 — the stored total, not the %d rows sent", groups[0].Count, len(findings))
	}
	if groups[0].FirstSeen != "2026-08-21T17:21:19Z" {
		t.Errorf("group firstSeen = %q, want the first of all 80 occurrences, not of the newest 10", groups[0].FirstSeen)
	}
}

// An incident with no findings yet must send two empty arrays, not two nulls:
// IncidentDetailPage maps over both, and its "no findings recorded yet" empty
// state keys off length.
func TestGroupFindingsByReasonEmitsEmptyArraysForNoFindings(t *testing.T) {
	findings, groups := groupFindingsByReason(nil)

	encoded, err := json.Marshal(map[string]any{"findings": findings, "findingGroups": groups})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(encoded), `{"findingGroups":[],"findings":[]}`; got != want {
		t.Errorf("encoded = %s, want %s", got, want)
	}
}

// --- deriveOwnership: "will the fix hold" ---
//
// Every case below is DB-free by construction: the derivation reads only the
// analysis response's own causal chain, which is the whole point of deriving it
// from recorded evidence rather than re-querying the cluster (see
// deriveOwnership's doc comment).

// gitopsCall/describeCall build the two recorded-tool-call shapes the
// derivation reads, so each test below states only what it is actually about.
func gitopsCall(gvk, namespace, name, resultJSON string) llm.ToolCallRecord {
	return llm.ToolCallRecord{
		Tool:   "get_gitops_ownership",
		Args:   json.RawMessage(fmt.Sprintf(`{"gvk":%q,"namespace":%q,"name":%q}`, gvk, namespace, name)),
		Result: json.RawMessage(resultJSON),
	}
}

func describeCall(gvk, namespace, name, annotationsJSON string) llm.ToolCallRecord {
	return llm.ToolCallRecord{
		Tool:   "describe_resource",
		Args:   json.RawMessage(fmt.Sprintf(`{"gvk":%q,"namespace":%q,"name":%q}`, gvk, namespace, name)),
		Result: json.RawMessage(fmt.Sprintf(`{"object":{"metadata":{"annotations":%s}},"events":[]}`, annotationsJSON)),
	}
}

func analysisWithCalls(plan *planView, calls ...llm.ToolCallRecord) *analysisResponse {
	return &analysisResponse{
		Status:      "complete",
		CausalChain: []llm.CausalStep{{Step: 1, Hypothesis: "h", ToolCalls: calls}},
		Plan:        plan,
	}
}

var checkoutFindings = []findingSummary{{Namespace: "payments", ObjectName: "checkout-abc123", GVK: "v1/Pod"}}

// The Argo CD/Flux half: a positive get_gitops_ownership result is taken at
// face value, app_ref and all, whatever object it was asked about.
func TestDeriveOwnershipFromGitOpsToolResult(t *testing.T) {
	got := deriveOwnership(analysisWithCalls(nil,
		gitopsCall("apps/v1/Deployment", "payments", "checkout",
			`{"managed_by":"argocd","app_ref":{"kind":"Application","namespace":"argocd","name":"shop-apps"}}`),
	), checkoutFindings)

	if got == nil {
		t.Fatal("deriveOwnership returned nil for a managed_by: argocd result")
	}
	want := ownershipSummary{
		ManagedBy: managedByArgoCD, SourceKind: "Application", SourceName: "shop-apps", SourceNamespace: "argocd",
		ObjectGVK: "apps/v1/Deployment", ObjectNamespace: "payments", ObjectName: "checkout",
	}
	if *got != want {
		t.Errorf("ownership = %+v, want %+v", *got, want)
	}
}

// The Helm half — the case that actually matters on the cluster this repo is
// tested against, where no GitOps controller is deployed and every application
// is a plain Helm release. The signal is Helm's own apply-time annotation on an
// object the investigation described for its own reasons.
func TestDeriveOwnershipFromHelmAnnotation(t *testing.T) {
	got := deriveOwnership(analysisWithCalls(nil,
		describeCall("apps/v1/Deployment", "payments", "checkout",
			`{"meta.helm.sh/release-name":"shop-apps","meta.helm.sh/release-namespace":"payments","deployment.kubernetes.io/revision":"7"}`),
	), checkoutFindings)

	if got == nil {
		t.Fatal("deriveOwnership returned nil for an object carrying meta.helm.sh/release-name")
	}
	want := ownershipSummary{
		ManagedBy: managedByHelm, SourceKind: "Release", SourceName: "shop-apps", SourceNamespace: "payments",
		ObjectGVK: "apps/v1/Deployment", ObjectNamespace: "payments", ObjectName: "checkout",
	}
	if *got != want {
		t.Errorf("ownership = %+v, want %+v", *got, want)
	}
}

// The three ways the evidence can fail to say anything, all of which must come
// back nil so the UI shows nothing. A false "this will be reverted" on an
// unmanaged object is what teaches an operator to ignore the true ones.
func TestDeriveOwnershipStaysSilentWithoutPositiveEvidence(t *testing.T) {
	failedCall := gitopsCall("apps/v1/Deployment", "payments", "checkout", `{"managed_by":"argocd"}`)
	failedCall.Result = nil
	errText := "resource not found"
	failedCall.Error = &errText

	cases := []struct {
		name     string
		analysis *analysisResponse
	}{
		{"no analysis at all", nil},
		{"empty causal chain (the cli backend contributes none)", &analysisResponse{Status: "complete"}},
		{"managed_by: none", analysisWithCalls(nil,
			gitopsCall("apps/v1/Deployment", "payments", "checkout", `{"managed_by":"none"}`))},
		{"ownership never asked about", analysisWithCalls(nil,
			describeCall("apps/v1/Deployment", "payments", "checkout", `{"deployment.kubernetes.io/revision":"7"}`))},
		{"the ownership call itself failed", analysisWithCalls(nil, failedCall)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveOwnership(tc.analysis, checkoutFindings); got != nil {
				t.Errorf("ownership = %+v, want nil", *got)
			}
		})
	}
}

// The Helm signal's relevance gate: an investigation that describes something in
// another namespace on its way past must not name that namespace's release as
// the thing about to revert this incident's fix.
func TestDeriveOwnershipIgnoresHelmAnnotationOutsideTheIncident(t *testing.T) {
	got := deriveOwnership(analysisWithCalls(nil,
		describeCall("apps/v1/Deployment", "kube-system", "metrics-server",
			`{"meta.helm.sh/release-name":"metrics-server"}`),
	), checkoutFindings)

	if got != nil {
		t.Errorf("ownership = %+v, want nil — kube-system is not a namespace this incident is about", *got)
	}
}

// With several managed objects in one chain, the fact about the object the
// operator is about to have ARGUS mutate wins — even though the Argo CD fact
// below outranks a Helm one on every other axis, and came later in the chain.
func TestDeriveOwnershipPrefersThePlanTarget(t *testing.T) {
	plan := &planView{ActionType: "ScaleDeployment", TargetNamespace: "payments", TargetName: "checkout"}
	got := deriveOwnership(analysisWithCalls(plan,
		describeCall("apps/v1/Deployment", "payments", "checkout",
			`{"meta.helm.sh/release-name":"shop-apps"}`),
		gitopsCall("apps/v1/StatefulSet", "payments", "ledger",
			`{"managed_by":"flux","app_ref":{"kind":"HelmRelease","name":"ledger"}}`),
	), checkoutFindings)

	if got == nil {
		t.Fatal("deriveOwnership returned nil despite two positive ownership facts")
	}
	if got.ObjectName != "checkout" || got.ManagedBy != managedByHelm {
		t.Errorf("ownership = %+v, want the Helm fact about the plan's target checkout", *got)
	}
}

// Absent a plan to anchor on, a deliberate ownership answer outranks an
// incidental annotation: Flux's helm-controller leaves BOTH traces on the same
// object, and the HelmRelease is the one whose source repo holds the durable
// fix.
func TestDeriveOwnershipPrefersTheDeliberateOwnershipAnswer(t *testing.T) {
	got := deriveOwnership(analysisWithCalls(nil,
		gitopsCall("apps/v1/Deployment", "payments", "checkout",
			`{"managed_by":"flux","app_ref":{"kind":"HelmRelease","namespace":"flux-system","name":"shop-apps"}}`),
		describeCall("apps/v1/Deployment", "payments", "checkout",
			`{"meta.helm.sh/release-name":"shop-apps"}`),
	), checkoutFindings)

	if got == nil {
		t.Fatal("deriveOwnership returned nil despite a managed_by: flux result")
	}
	if got.ManagedBy != managedByFlux || got.SourceKind != "HelmRelease" {
		t.Errorf("ownership = %+v, want the Flux HelmRelease fact", *got)
	}
}

// TestStoredOwnership covers the preferred ownership source: what the hub
// itself asked the cluster (migration 000038), rather than what the model
// happened to record. It exists because deriving it from an analysis's causal
// chain is null on the cli backend, which is a real deployment configuration —
// verified against a live cluster, where ownership came back null on a
// genuinely Helm-managed workload.
func TestStoredOwnership(t *testing.T) {
	findings := []findingSummary{{GVK: "apps/v1/Deployment", Namespace: "apps", ObjectName: "checkout"}}

	t.Run("helm release is reported with its object", func(t *testing.T) {
		got := storedOwnership([]byte(`{"managed_by":"helm","app_ref":{"kind":"Release","name":"shop-apps","namespace":"flux-system"}}`), findings, nil)
		if got == nil {
			t.Fatal("expected an ownership summary")
		}
		if got.ManagedBy != "helm" || got.SourceName != "shop-apps" || got.SourceNamespace != "flux-system" {
			t.Errorf("got %+v", got)
		}
		if got.ObjectName != "checkout" || got.ObjectNamespace != "apps" {
			t.Errorf("object identity should come from the incident's findings, got %+v", got)
		}
	})

	// The honesty rule: anything that is not a recognised owner renders nothing.
	// A false "this will be reverted" on an unmanaged object teaches operators
	// to ignore the warning, which is worse than omitting it.
	for name, raw := range map[string]string{
		"nothing owns it":    `{"managed_by":"none"}`,
		"unrecognised owner": `{"managed_by":"kapp"}`,
		"empty managed_by":   `{"managed_by":""}`,
		"unparseable":        `not json`,
		"absent":             ``,
	} {
		t.Run("nil for "+name, func(t *testing.T) {
			if got := storedOwnership([]byte(raw), findings, nil); got != nil {
				t.Errorf("storedOwnership(%q) = %+v, want nil", raw, got)
			}
		})
	}

	t.Run("plan target wins over the first finding", func(t *testing.T) {
		analysis := &analysisResponse{Plan: &planView{
			TargetGVK: "apps/v1/StatefulSet", TargetNamespace: "data", TargetName: "metrics-store",
		}}
		got := storedOwnership([]byte(`{"managed_by":"argocd","app_ref":{"kind":"Application","name":"apps"}}`), findings, analysis)
		if got == nil {
			t.Fatal("expected an ownership summary")
		}
		// An operator is about to change the plan's target, so that is the
		// object the caveat must name.
		if got.ObjectName != "metrics-store" || got.ObjectNamespace != "data" {
			t.Errorf("got %+v, want the plan's target", got)
		}
	})
}

// TestIncidentPageLimit covers BACKLOG P9's bound. The behaviour that matters is
// that a too-large limit is REFUSED rather than clamped: clamping silently would
// let a caller keep asking for everything and be told nothing about the cap, which
// is how the unbounded behaviour would survive the fix.
func TestIncidentPageLimit(t *testing.T) {
	cases := []struct {
		raw     string
		want    int
		wantErr bool
		why     string
	}{
		{"", defaultIncidentPageLimit, false, "no parameter is the ordinary case and must not error"},
		{"1", 1, false, "the smallest useful page"},
		{"250", 250, false, "an ordinary explicit page size"},
		{strconv.Itoa(maxIncidentPageLimit), maxIncidentPageLimit, false, "the cap itself is allowed"},
		{strconv.Itoa(maxIncidentPageLimit + 1), 0, true, "one past the cap is refused, not clamped"},
		{"100000", 0, true, "the old unbounded behaviour must not be reachable by asking loudly"},
		{"0", 0, true, "a zero page is a caller mistake, not an empty result"},
		{"-5", 0, true, "negative would become an unbounded query in SQL"},
		{"lots", 0, true, "non-numeric is a caller mistake"},
		{"1.5", 0, true, "a float is a caller mistake, not a truncation"},
	}
	for _, c := range cases {
		got, err := incidentPageLimit(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("incidentPageLimit(%q) = %d, want an error (%s)", c.raw, got, c.why)
			}
			continue
		}
		if err != nil {
			t.Errorf("incidentPageLimit(%q): unexpected error %v (%s)", c.raw, err, c.why)
			continue
		}
		if got != c.want {
			t.Errorf("incidentPageLimit(%q) = %d, want %d (%s)", c.raw, got, c.want, c.why)
		}
	}
}

// TestIncidentCursorRoundTrip asserts the cursor survives encoding at full
// precision. Sub-second precision is the point: two incidents re-seen in the same
// storm can share a last_seen to the second, and a cursor that rounded would
// compare them equal and skip rows.
func TestIncidentCursorRoundTrip(t *testing.T) {
	for _, want := range []time.Time{
		time.Date(2026, 8, 23, 11, 45, 6, 571161000, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 23, 11, 45, 6, 1, time.UTC),
	} {
		id := "inc_01m0kf0ckgkjk21yz6d77gd131"
		gotTime, gotID, err := decodeIncidentCursor(encodeIncidentCursor(want, id))
		if err != nil {
			t.Fatalf("decode(encode(%s)): %v", want, err)
		}
		if !gotTime.Equal(want) {
			t.Errorf("time round-tripped to %s, want %s — a cursor that loses precision skips rows tied on last_seen", gotTime, want)
		}
		if gotID != id {
			t.Errorf("id round-tripped to %q, want %q", gotID, id)
		}
	}
}

// TestDecodeIncidentCursorRejectsGarbage: a bad cursor must be a 400, never a
// silent fall back to "start from the beginning" — a client looping on nextCursor
// would then never terminate.
func TestDecodeIncidentCursorRejectsGarbage(t *testing.T) {
	for _, cursor := range []string{
		"not base64 at all !!",
		base64.RawURLEncoding.EncodeToString([]byte("no separator here")),
		base64.RawURLEncoding.EncodeToString([]byte("|inc_123")),
		base64.RawURLEncoding.EncodeToString([]byte("2026-08-23T11:45:06Z|")),
		base64.RawURLEncoding.EncodeToString([]byte("yesterday|inc_123")),
		base64.RawURLEncoding.EncodeToString([]byte("")),
	} {
		if _, _, err := decodeIncidentCursor(cursor); err == nil {
			t.Errorf("decodeIncidentCursor(%q) succeeded, want an error", cursor)
		}
	}
}

// TestIncidentCursorIsIndependentOfTheAuditCursor: the two are the same shape on
// purpose but must stay separate functions, so changing one list's sort key cannot
// silently invalidate the other's outstanding tokens. This test exists to fail if
// someone "de-duplicates" them into one.
func TestIncidentCursorIsIndependentOfTheAuditCursor(t *testing.T) {
	ts := time.Date(2026, 8, 23, 11, 45, 6, 571161000, time.UTC)
	if encodeIncidentCursor(ts, "x") != encodeAuditCursor(ts, "x") {
		// Identical output today is fine and expected; the point is that they are
		// two functions, so this is a note rather than a failure.
		t.Log("the two cursor encodings have diverged, which is allowed — they are deliberately separate")
	}
	if _, _, err := decodeIncidentCursor(encodeAuditCursor(ts, "x")); err != nil {
		t.Errorf("today the formats are compatible, so this should decode: %v", err)
	}
}

// --- BACKLOG P10: search/sort/counts against a real Postgres, RLS included ---
//
// Gated on ARGUS_TEST_DATABASE_URL exactly like internal/orchestrator/db_test.go
// and this file's own auth_test.go sibling (see authTestPool's doc comment) — a
// machine without one gets a clean skip. What none of the DB-free tests above can
// show: that the search ILIKE, the ranked severity/state ORDER BY, and the counts
// aggregate all actually run correctly against real rows, and — the non-negotiable
// this whole feature exists inside — that none of the three ever surfaces a row on
// a cluster the caller's own transaction was never scoped to.

// incidentSearchFixture is a small, throwaway fleet: four incidents on one
// cluster with distinct severities (deliberately including "low", so
// alphabetical order and rank order actually disagree — see the ordering
// subtest below) and one incident on a SECOND cluster the request
// transaction is never scoped to, carrying a search term that also appears
// on the visible cluster's own incident. If RLS ever stopped applying to
// this endpoint's new queries, that incident is what would leak.
type incidentSearchFixture struct {
	tenantID                      string
	visibleCluster, hiddenCluster string
	critical, high, medium, low   string
	hiddenIncident                string
}

func setupIncidentSearchFixture(t *testing.T, pool *pgxpool.Pool) incidentSearchFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	f := incidentSearchFixture{
		tenantID:       tenantID,
		visibleCluster: domain.NewID(domain.PrefixCluster),
		hiddenCluster:  domain.NewID(domain.PrefixCluster),
		critical:       domain.NewID(domain.PrefixIncident),
		high:           domain.NewID(domain.PrefixIncident),
		medium:         domain.NewID(domain.PrefixIncident),
		low:            domain.NewID(domain.PrefixIncident),
		hiddenIncident: domain.NewID(domain.PrefixIncident),
	}
	// Both clusters, so the setup inserts themselves satisfy RLS's WITH
	// CHECK (migration 000009's policies have no FOR clause, so the USING
	// expression governs INSERT too) — the actual test below opens its own,
	// narrower-scoped transaction against these same rows.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.visibleCluster, f.hiddenCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	for _, c := range []struct{ id, name string }{
		{f.visibleCluster, "p10-search-visible-" + f.visibleCluster},
		{f.hiddenCluster, "p10-search-hidden-" + f.hiddenCluster},
	} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c.id, tenantID, c.name, "fp-"+c.id); err != nil {
			t.Fatalf("insert cluster %s: %v", c.id, err)
		}
	}

	now := time.Now()
	insert := func(id, clusterID, severity, state, reason, objectKey string, occurrences int, lastSeen time.Time) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			id, tenantID, clusterID, "p10fp-"+id, severity, state, now, lastSeen, occurrences, reason, objectKey); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	insert(f.critical, f.visibleCluster, "critical", "Detected", "OOMKilled",
		"apps/v1/Deployment|payments|payments-api-p10searchmarker", 5, now.Add(4*time.Minute))
	insert(f.high, f.visibleCluster, "high", "AwaitingApproval", "CrashLoopBackOff",
		"apps/v1/Deployment|checkout|checkout-worker", 2, now.Add(3*time.Minute))
	insert(f.medium, f.visibleCluster, "medium", "Resolved", "ImagePullBackOff",
		"batch/v1/CronJob|billing|billing-cron", 1, now.Add(2*time.Minute))
	insert(f.low, f.visibleCluster, "low", "Dismissed", "NodeNotReady",
		"v1/Node||some-node", 1, now.Add(1*time.Minute))
	insert(f.hiddenIncident, f.hiddenCluster, "critical", "Detected", "OOMKilled",
		"apps/v1/Deployment|secret-ns|p10searchmarker-should-not-leak", 9, now.Add(5*time.Minute))

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Logf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		clusterIDs := []string{f.visibleCluster, f.hiddenCluster}
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, clusterIDs); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM incidents WHERE cluster_id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete incidents: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM clusters WHERE id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete clusters: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return f
}

// callListIncidents opens its OWN transaction, scoped only to
// visibleClusterIDs (never the hidden cluster), and calls the real handler —
// exactly the request-scoping every real request goes through
// (requireAuth), just constructed by hand the way this package's other
// DB-backed handler tests do.
func callListIncidents(t *testing.T, pool *pgxpool.Pool, f incidentSearchFixture, rawQuery string) (int, map[string]any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.visibleCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListIncidents(rec, req, &requestContext{Tx: tx, TenantID: f.tenantID})

	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

func incidentIDsFrom(body map[string]any) []string {
	raw, _ := body["incidents"].([]any)
	ids := make([]string, 0, len(raw))
	for _, item := range raw {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func TestHandleListIncidentsSearchSortCountsAndRLS(t *testing.T) {
	pool := authTestPool(t)
	f := setupIncidentSearchFixture(t, pool)

	t.Run("counts are exact and never include the hidden cluster", func(t *testing.T) {
		code, body := callListIncidents(t, pool, f, "limit=1")
		if code != http.StatusOK {
			t.Fatalf("status = %d, body: %+v", code, body)
		}
		counts, _ := body["counts"].(map[string]any)
		if counts == nil {
			t.Fatal("response has no \"counts\" field")
		}
		// all=4, requiresAction=2 (Detected and AwaitingApproval; medium is
		// Resolved and low is Dismissed), critical=1, high=1, medium=1 — every
		// number over the visible cluster's four incidents, NOT the hidden
		// cluster's fifth, and NOT limited by ?limit=1 above (proving counts
		// are never truncated by the page size).
		//
		// The key was "open" until the review's finding 9. It is not a rename
		// of the same number: see TestIncidentCountsAskWhoOwesWorkNotWhoIsOpen
		// for the states where the two definitions actually disagree, which is
		// the whole reason the name changed with them.
		want := map[string]float64{"all": 4, "requiresAction": 2, "critical": 1, "high": 1, "medium": 1}
		for key, wantVal := range want {
			got, ok := counts[key].(float64)
			if !ok || got != wantVal {
				t.Errorf("counts[%q] = %v, want %v (counts: %+v)", key, counts[key], wantVal, counts)
			}
		}
	})

	t.Run("search matches the visible incident and never leaks the hidden one", func(t *testing.T) {
		code, body := callListIncidents(t, pool, f, "search=p10searchmarker")
		if code != http.StatusOK {
			t.Fatalf("status = %d, body: %+v", code, body)
		}
		ids := incidentIDsFrom(body)
		if len(ids) != 1 || ids[0] != f.critical {
			t.Errorf("search results = %v, want exactly [%s] — the hidden cluster's incident shares the same search term and must never appear", ids, f.critical)
		}
	})

	t.Run("search across the opening reason and the cluster id both work, not just the object name", func(t *testing.T) {
		_, body := callListIncidents(t, pool, f, "search=CrashLoopBackOff")
		if ids := incidentIDsFrom(body); len(ids) != 1 || ids[0] != f.high {
			t.Errorf("search by opening reason = %v, want exactly [%s]", ids, f.high)
		}

		_, body = callListIncidents(t, pool, f, "search="+f.visibleCluster)
		ids := incidentIDsFrom(body)
		if len(ids) != 4 {
			t.Errorf("search by cluster id = %v, want all 4 of the visible cluster's incidents", ids)
		}
	})

	t.Run("severity and state sort by rank, not alphabetically", func(t *testing.T) {
		// Alphabetically ascending this would be critical, high, low, medium.
		// By rank (low < medium < high < critical) it is low, medium, high,
		// critical — the two disagree, so this only passes under the
		// intended ranking.
		code, body := callListIncidents(t, pool, f, "sort=severity&direction=asc")
		if code != http.StatusOK {
			t.Fatalf("status = %d, body: %+v", code, body)
		}
		want := []string{f.low, f.medium, f.high, f.critical}
		if got := incidentIDsFrom(body); !equalStrings(got, want) {
			t.Errorf("sort=severity&direction=asc = %v, want %v (rank order, not alphabetical)", got, want)
		}

		// state DESC: validIncidentStates' own order, reversed. Dismissed and
		// Resolved sit near the end of that enum, AwaitingApproval and
		// Detected nearer the front — the point is that this is the SAME
		// order ?state= validates against, not a second one that could drift.
		code, body = callListIncidents(t, pool, f, "sort=state&direction=desc")
		if code != http.StatusOK {
			t.Fatalf("status = %d, body: %+v", code, body)
		}
		got := incidentIDsFrom(body)
		wantOrder := map[string]int{}
		for i, s := range validIncidentStates {
			wantOrder[s] = i
		}
		stateOf := map[string]string{f.critical: "Detected", f.high: "AwaitingApproval", f.medium: "Resolved", f.low: "Dismissed"}
		for i := 1; i < len(got); i++ {
			if wantOrder[stateOf[got[i-1]]] < wantOrder[stateOf[got[i]]] {
				t.Errorf("sort=state&direction=desc = %v, not in descending validIncidentStates rank order", got)
				break
			}
		}
	})

	t.Run("keyset pagination over a non-lastSeen sort key visits every row exactly once", func(t *testing.T) {
		seen := []string{}
		query := "sort=occurrences&direction=desc&limit=2"
		for i := 0; i < 5; i++ { // hard cap so a cursor bug can't spin the test forever
			code, body := callListIncidents(t, pool, f, query)
			if code != http.StatusOK {
				t.Fatalf("status = %d, body: %+v", code, body)
			}
			seen = append(seen, incidentIDsFrom(body)...)
			nextCursor, ok := body["nextCursor"].(string)
			if !ok || nextCursor == "" {
				break
			}
			query = "sort=occurrences&direction=desc&limit=2&cursor=" + nextCursor
		}
		want := []string{f.critical, f.high, f.medium, f.low} // occurrence_count 5,2,1,1 desc; medium/low tie-broken by id
		sortedSeen := append([]string{}, seen...)
		sort.Strings(sortedSeen)
		sortedWant := append([]string{}, want...)
		sort.Strings(sortedWant)
		if !equalStrings(sortedSeen, sortedWant) {
			t.Fatalf("paginated through %v (as a set), want exactly %v — a row was skipped or repeated across pages", seen, want)
		}
		if len(seen) != len(want) {
			t.Fatalf("paginated through %d rows total, want %d — duplicate row across pages", len(seen), len(want))
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
