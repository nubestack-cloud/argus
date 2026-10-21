package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/scm"
)

// These mirror TestHandleListIncidentsRejectsInvalidState's own pattern
// (incidents_test.go): a request rejected before rc.Tx is ever touched can
// be tested with a nil Tx — which would panic if the handler fell through
// to a real query — so the DB-free slice of handleCreateRepositoryBinding's
// new BACKLOG.md F19 validation is covered here, and the live-database
// write/round-trip is covered by internal/scm's own SaveBinding tests
// instead.
//
// scm.ObjectMapping.Validate() runs INSIDE SaveBinding, before any tx call
// (see store.go: it runs right after checkProviderImplemented, well before
// the first tx.QueryRow) — so a request with a malformed objectMappings
// entry never reaches rc.Tx at all, exactly like the existing ?state=/
// ?sort= cases.
func newRepositoriesTestServer() *Server {
	return &Server{scmStore: scm.NewStore(nil)}
}

func repositoriesTestRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/api/v1/repositories", strings.NewReader(body))
}

func TestHandleCreateRepositoryBinding_RejectsObjectMappingWithNoPath(t *testing.T) {
	s := newRepositoriesTestServer()
	body := `{
		"provider": "github",
		"url": "https://github.com/acme/platform-config",
		"token": "faketoken-not-a-real-credential-1234567890",
		"objectMappings": [{"releaseName": "payments", "namespace": "prod"}]
	}`
	rec := httptest.NewRecorder()
	s.handleCreateRepositoryBinding(rec, repositoriesTestRequest(body), &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "path is required") {
		t.Errorf("body = %s, want it to name the missing path", rec.Body.String())
	}
}

func TestHandleCreateRepositoryBinding_RejectsBothFormsAtOnce(t *testing.T) {
	s := newRepositoriesTestServer()
	body := `{
		"provider": "github",
		"url": "https://github.com/acme/platform-config",
		"token": "faketoken-not-a-real-credential-1234567890",
		"objectMappings": [{
			"releaseName": "payments", "namespace": "prod",
			"labelSelector": {"team": "payments"},
			"path": "envs/prod/payments"
		}]
	}`
	rec := httptest.NewRecorder()
	s.handleCreateRepositoryBinding(rec, repositoriesTestRequest(body), &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "EITHER") {
		t.Errorf("body = %s, want it to say the two forms are mutually exclusive", rec.Body.String())
	}
}

func TestHandleCreateRepositoryBinding_RejectsNeitherFormSupplied(t *testing.T) {
	s := newRepositoriesTestServer()
	body := `{
		"provider": "github",
		"url": "https://github.com/acme/platform-config",
		"token": "faketoken-not-a-real-credential-1234567890",
		"objectMappings": [{"path": "envs/prod/payments"}]
	}`
	rec := httptest.NewRecorder()
	s.handleCreateRepositoryBinding(rec, repositoriesTestRequest(body), &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateRepositoryBinding_RejectsReleaseNameWithoutNamespace(t *testing.T) {
	s := newRepositoriesTestServer()
	body := `{
		"provider": "github",
		"url": "https://github.com/acme/platform-config",
		"token": "faketoken-not-a-real-credential-1234567890",
		"objectMappings": [{"releaseName": "payments", "path": "envs/prod/payments"}]
	}`
	rec := httptest.NewRecorder()
	s.handleCreateRepositoryBinding(rec, repositoriesTestRequest(body), &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// A well-formed objectMappings list must decode cleanly and pass the same
// Validate() every entry goes through inside SaveBinding — proven here
// without a server or a Tx at all; the actual write (and that it comes back
// out again on the next registration) is covered by internal/scm's own
// DB-backed SaveBinding tests, since that needs a real transaction to mean
// anything.
func TestCreateRepositoryBindingRequest_DecodesWellFormedObjectMappings(t *testing.T) {
	body := `{
		"provider": "github",
		"url": "https://github.com/acme/platform-config",
		"token": "faketoken-not-a-real-credential-1234567890",
		"objectMappings": [
			{"releaseName": "payments", "namespace": "prod", "path": "envs/prod/payments"},
			{"labelSelector": {"team": "checkout"}, "path": "envs/prod/checkout"}
		]
	}`
	var req createRepositoryBindingRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if len(req.ObjectMappings) != 2 {
		t.Fatalf("ObjectMappings = %+v, want exactly 2", req.ObjectMappings)
	}
	for i, m := range req.ObjectMappings {
		if err := m.Validate(); err != nil {
			t.Errorf("mapping %d = %+v failed Validate(): %v", i, m, err)
		}
	}
}
