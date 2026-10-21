package api

// openapi_contract_test.go and its _db_test.go sibling are PROJECT.md T12's
// drift detector: `docs/openapi.yaml` is a HAND-AUTHORED spec, verified
// against `internal/api`'s real handlers at the time it was written — see
// that file's own top-level `description` for why hand-authoring (rather
// than generating the spec FROM the handlers) was the right call here, and
// what is and isn't covered. A hand-authored spec that nobody re-checks
// against the handlers is worth almost nothing; what makes it worth
// something is that THIS file (and its DB-backed sibling) decode real
// handler responses and validate them against the spec's own JSON Schema,
// via github.com/getkin/kin-openapi — so a handler that adds, removes,
// renames, or retypes a field in a response this spec claims to describe
// fails a test here, not a rendering bug three hops away in the browser.
//
// This file covers the paths reachable with NO database at all — every
// validation branch in these handlers that returns before touching
// `rc.Tx`. Import for a database-backed handler's real 200 response ARE
// covered too, in openapi_contract_db_test.go — see that file for the other
// half (and for why it's split this way: this half runs in CI, which this
// repo deliberately keeps Postgres-free; the DB half runs wherever
// ARGUS_TEST_DATABASE_URL is set, same convention as every other
// `*_db_test.go` in this package).
//
// TestOpenAPIContractValidatorRejectsShapeDrift below is the permanent proof
// that this mechanism is a real validator and not a schema-well-formedness
// check that always passes: it feeds the validator a shape a handler could
// plausibly regress into and asserts that specific shape is REJECTED. A
// live demonstration against a real handler (temporarily deleting a field
// from incidentSummary, confirming this file's tests fail, then reverting)
// was also run by hand while authoring this suite — see PROJECT.md T12's
// closing report for that transcript; it is not re-run automatically because
// it requires editing production code to a broken state, which a permanent
// test must never do.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

var (
	openAPISpecOnce sync.Once
	openAPISpecDoc  *openapi3.T
	openAPISpecErr  error
)

// loadOpenAPISpec parses and validates docs/openapi.yaml exactly once per
// test binary run. The relative path assumes `go test`'s convention of
// running with the package directory (internal/api) as the working
// directory.
func loadOpenAPISpec(t *testing.T) *openapi3.T {
	t.Helper()
	openAPISpecOnce.Do(func() {
		loader := openapi3.NewLoader()
		openAPISpecDoc, openAPISpecErr = loader.LoadFromFile("../../docs/openapi.yaml")
		if openAPISpecErr == nil {
			openAPISpecErr = openAPISpecDoc.Validate(context.Background())
		}
	})
	if openAPISpecErr != nil {
		t.Fatalf("load docs/openapi.yaml: %v", openAPISpecErr)
	}
	return openAPISpecDoc
}

// schemaByName looks up a component schema by name, failing loudly if the
// spec doesn't have one — a typo in a test's schema name must not silently
// pass as "well, SOMETHING didn't error".
func schemaByName(t *testing.T, name string) *openapi3.Schema {
	t.Helper()
	doc := loadOpenAPISpec(t)
	ref, ok := doc.Components.Schemas[name]
	if !ok || ref.Value == nil {
		t.Fatalf("docs/openapi.yaml has no component schema named %q", name)
	}
	return ref.Value
}

// matchesSchema reports whether body (raw JSON bytes) satisfies the named
// component schema, returning the validation error for the caller to act
// on. Split from the asserting wrapper below so
// TestOpenAPIContractValidatorRejectsShapeDrift can inspect a FAILURE
// without failing itself.
func matchesSchema(t *testing.T, schemaName string, body []byte) error {
	t.Helper()
	schema := schemaByName(t, schemaName)
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response body is not valid JSON: %v\nbody: %s", err, body)
	}
	return schema.VisitJSON(decoded)
}

// assertMatchesSchema is this suite's core assertion: body must satisfy the
// named schema in docs/openapi.yaml, or the test fails with the concrete
// validation error (which field, what was expected) and the offending body.
func assertMatchesSchema(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	if err := matchesSchema(t, schemaName, body); err != nil {
		t.Fatalf("response does not match docs/openapi.yaml schema %q: %v\nbody: %s", schemaName, err, body)
	}
}

// assertMatchesProblemSchema is assertMatchesSchema against the shared RFC
// 9457 Problem schema every error response in this API must satisfy.
func assertMatchesProblemSchema(t *testing.T, body []byte) {
	t.Helper()
	assertMatchesSchema(t, "Problem", body)
}

// TestOpenAPIContractValidatorRejectsShapeDrift is the permanent, always-run
// (no database needed) proof that matchesSchema actually catches drift
// rather than trivially passing everything: three payloads that are each
// exactly one realistic handler regression away from the real shape — a
// dropped required field, a renamed field, and a value outside its
// documented enum — are asserted to FAIL validation against the schemas
// this spec claims to describe. If a future change to this test file (or to
// kin-openapi's API) ever made these payloads pass, that would mean the
// contract test suite had quietly become a no-op, which is exactly the
// failure mode this item exists to prevent.
func TestOpenAPIContractValidatorRejectsShapeDrift(t *testing.T) {
	t.Run("dropped required field", func(t *testing.T) {
		// A real MeResponse always carries authMethod (internal/api/auth.go's
		// handleMe always sets it) — this payload is what a handler would
		// produce if that field were accidentally dropped from the response
		// struct.
		body := []byte(`{"userId":"usr_1","email":"a@example.com"}`)
		if err := matchesSchema(t, "MeResponse", body); err == nil {
			t.Fatalf("expected validation to reject a MeResponse missing authMethod, got no error")
		}
	})

	t.Run("field renamed out from under the spec", func(t *testing.T) {
		// If a handler renamed effectiveRiskLevel back to something else (the
		// exact class of regression BACKLOG.md D11 #1 was about), this is the
		// shape it would now produce. additionalProperties is unset (so
		// permitted), but the schema's own `required` list still names
		// effectiveRiskLevel explicitly.
		body := []byte(`{
			"id":"plan_1","actionType":"ScaleDeployment","targetGvk":"apps/v1/Deployment",
			"targetNamespace":"default","targetName":"api","params":{},"reversible":true,
			"riskLevel":"low","summary":"x","gateOutcome":"NeedsApproval","gateReason":"x",
			"createdAt":"2026-01-01T00:00:00Z"
		}`)
		if err := matchesSchema(t, "RemediationPlan", body); err == nil {
			t.Fatalf("expected validation to reject a RemediationPlan missing effectiveRiskLevel, got no error")
		}
	})

	t.Run("value outside its documented enum", func(t *testing.T) {
		body := []byte(`{"type":"https://argus.io/errors/not-found","title":"x","status":404,"detail":"x"}`)
		// Sanity: the well-formed version must pass first, so a failure below
		// is attributable to the mutation, not to some other spec problem.
		assertMatchesSchema(t, "Problem", body)

		badOutcome := []byte(`{
			"id":"aud_1","occurredAt":"2026-01-01T00:00:00Z","actorId":null,"actorEmail":null,
			"actorDisplayName":null,"actorAuthMethod":"","sourceIp":null,"capability":null,
			"clusterId":null,"clusterDisplayName":null,"outcome":"bogus","action":"","detailsSummary":""
		}`)
		if err := matchesSchema(t, "AuditEventSummary", badOutcome); err == nil {
			t.Fatalf("expected validation to reject outcome %q, got no error", "bogus")
		}
	})
}

// --- no-database contract tests: every validation branch these handlers
// reach before ever touching rc.Tx, run against a bare &Server{}. ---

func TestOpenAPIContract_ListIncidentsInvalidSort(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?sort=not-a-real-sort-key", nil)
	rec := httptest.NewRecorder()
	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_ListIncidentsInvalidLimit(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?limit=0", nil)
	rec := httptest.NewRecorder()
	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_ListIncidentsInvalidCursorForSort(t *testing.T) {
	s := &Server{}
	// A cursor minted under one ?sort= must be rejected under another — see
	// docs/openapi.yaml's pagination section.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?sort=severity&cursor=not-a-real-cursor", nil)
	rec := httptest.NewRecorder()
	s.handleListIncidents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_ListApprovalsInvalidActionType(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals?actionType=NotARealActionType", nil)
	rec := httptest.NewRecorder()
	s.handleListApprovals(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_ListApprovalsInvalidDirection(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals?direction=sideways", nil)
	rec := httptest.NewRecorder()
	s.handleListApprovals(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_RejectIncidentBlankReason(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_1/reject", httpBody(`{"reason":"   "}`))
	req.SetPathValue("id", "inc_1")
	rec := httptest.NewRecorder()
	s.handleRejectIncident(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_LoginMalformedBody(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", httpBody(`{not valid json`))
	rec := httptest.NewRecorder()
	s.handleLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_ListAuditEventsInvalidOutcome(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?outcome=not-a-real-outcome", nil)
	rec := httptest.NewRecorder()
	s.handleListAuditEvents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

func TestOpenAPIContract_ExportAuditEventsMissingWindow(t *testing.T) {
	s := &Server{}
	// since/until are BOTH required for the export route (unlike the list
	// route) — see docs/openapi.yaml's description of this endpoint.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events/export", nil)
	rec := httptest.NewRecorder()
	s.handleExportAuditEvents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	assertMatchesProblemSchema(t, rec.Body.Bytes())
}

// httpBody is a tiny helper so the malformed-body tests above read as what
// they are, rather than a bare strings.NewReader call repeated at each site.
func httpBody(s string) *strings.Reader { return strings.NewReader(s) }
