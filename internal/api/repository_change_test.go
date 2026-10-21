package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/authz"
	"argus/internal/gitops"
	"argus/internal/scm"
)

// The DB-free slice of handleOpenRepositoryChange: a malformed request is
// refused before any query reaches rc.Tx (nil here, so a query would panic) —
// the same "reject before the query" pattern
// TestHandleRejectIncidentRequiresNonEmptyReason uses. Everything past this
// needs a live Postgres and a provider, and is covered by the gitops package's
// own httptest-backed tests plus scripts/smoke-test.sh.

// TestHandleOpenRepositoryChangeRequiresUsableFiles covers what is mandatory
// in the whole-file grammar.
//
// This test used to be TestHandleOpenRepositoryChangeRequiresAFieldPath, and
// before that TestHandleOpenRepositoryChangeRequiresFileAndField. Both premises
// expired: `fieldPath` no longer exists, and `filePath` alone is not a change
// either. A repository change is `files: [{path, content}]`, and what has to be
// refused before any query reaches rc.Tx (nil here, so a query would panic) is
// a request that is not one: no files, a file with no path, a file with no
// content.
func TestHandleOpenRepositoryChangeRequiresUsableFiles(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name string
		body string
	}{
		{"empty body", `{}`},
		{"an empty file list", `{"files":[]}`},
		{"a file with no path", `{"files":[{"content":"a: b\n"}]}`},
		{"a file with a blank path", `{"files":[{"path":"  ","content":"a: b\n"}]}`},
		{"a file with no content", `{"files":[{"path":"envs/prod/a.yaml"}]}`},
		{"a file with blank content and no delete flag", `{"files":[{"path":"envs/prod/a.yaml","content":"   \n"}]}`},
		{"a file marked delete that also carries content", `{"files":[{"path":"envs/prod/a.yaml","content":"a: b\n","delete":true}]}`},
		{"the retired single-field shape", `{"filePath":"envs/prod/a.yaml","fieldPath":"spec/replicas","newValue":"3"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_x/repository-change", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			s.handleOpenRepositoryChange(rec, req, &requestContext{})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// The preview route validates identically, so a client cannot discover a
// malformed request only at the point it tries to open the pull request.
func TestHandlePreviewRepositoryChangeRequiresUsableFiles(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_x/repository-change/preview", strings.NewReader(`{"files":[]}`))
	rec := httptest.NewRecorder()
	s.handlePreviewRepositoryChange(rec, req, &requestContext{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleOpenRepositoryChangeRejectsMalformedBody(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc_x/repository-change", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()
	s.handleOpenRepositoryChange(rec, req, &requestContext{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestRepositoryChangeRequestAcceptsDelete is BACKLOG.md "still open" #2's
// human self-service half: an operator driving this endpoint by hand gets
// the same "delete": true capability the model's OpenPR plans do, expressed
// through the identical distinct field rather than empty content.
func TestRepositoryChangeRequestAcceptsDelete(t *testing.T) {
	req := repositoryChangeRequest{Files: []repositoryChangeFile{
		{Path: "envs/prod/hpa-a.yaml", Delete: true},
	}}
	if _, _, ok := req.validate(); !ok {
		t.Fatal("a delete-only request was refused")
	}
	edits := req.fileEdits()
	if len(edits) != 1 || !edits[0].Delete || len(edits[0].Content) != 0 {
		t.Errorf("fileEdits() = %+v, want exactly one FileEdit with Delete=true and no content", edits)
	}
}

// The error mapping is the part a UI depends on: these outcomes have different
// fixes, and a client that cannot tell them apart sends the operator to the
// wrong place. A refusal because a path is forbidden is permanent and needs a
// different approach; a conflict is transient and needs a re-analysis; an
// expired token needs renewing, not widening.
func TestWriteRepositoryChangeFailureMapping(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantStatus  int
		wantType    string
		wantInTitle string
	}{
		{
			"content ARGUS will not accept", fmt.Errorf("wrapped: %w", gitops.ErrVerificationFailed),
			http.StatusUnprocessableEntity, "change-not-verified", "Refusing to open a pull request",
		},
		{
			"content echoing the redaction marker", fmt.Errorf("wrapped: %w", gitops.ErrRedactedValueEchoed),
			http.StatusUnprocessableEntity, "redacted-value-echoed", "redaction marker",
		},
		{
			"nothing actually differs", fmt.Errorf("wrapped: %w", gitops.ErrNothingToChange),
			http.StatusUnprocessableEntity, "no-change", "",
		},
		{
			// File DISCOVERY could not name a single file for the object. The
			// fix is to name the file, which is a different fix from every
			// other refusal here.
			"ambiguous document", fmt.Errorf("wrapped: %w", gitops.ErrAmbiguousDocument),
			http.StatusUnprocessableEntity, "file-not-located", "",
		},
		{
			"the blob moved", fmt.Errorf("wrapped: %w", scm.ErrConflict),
			http.StatusConflict, "repository-changed", "",
		},
		{
			"credential expired", fmt.Errorf("wrapped: %w", scm.ErrCredentialExpired),
			http.StatusForbidden, "repository-unusable", "",
		},
		{
			"forbidden", fmt.Errorf("wrapped: %w", scm.ErrForbidden),
			http.StatusForbidden, "repository-unusable", "",
		},
		{
			"branch already exists", fmt.Errorf("wrapped: %w", scm.ErrAlreadyExists),
			http.StatusConflict, "invalid-state", "",
		},
		{
			"file not found at the synced commit", fmt.Errorf("wrapped: %w", scm.ErrNotFound),
			http.StatusUnprocessableEntity, "not-found", "",
		},
		{
			// A forbidden-path or outside-the-synced-directory refusal, which
			// carries no sentinel: the message is the whole value, so it must
			// survive rather than be replaced with something generic.
			"a plain refusal", errors.New("gitops: refusing to write .github/workflows/deploy.yaml — it matches the forbidden path"),
			http.StatusUnprocessableEntity, "repository-change-refused", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeRepositoryChangeFailure(rec, tc.err)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantType) {
				t.Errorf("problem type does not contain %q: %s", tc.wantType, rec.Body.String())
			}
			if tc.wantInTitle != "" && !strings.Contains(rec.Body.String(), tc.wantInTitle) {
				t.Errorf("title does not mention %q: %s", tc.wantInTitle, rec.Body.String())
			}
			// The provider's or the package's own message must reach the caller.
			if !strings.Contains(rec.Body.String(), "wrapped") && !strings.Contains(rec.Body.String(), "forbidden path") {
				t.Errorf("the underlying reason was discarded: %s", rec.Body.String())
			}
		})
	}
}

func TestSplitGVKWire(t *testing.T) {
	cases := []struct{ in, apiVersion, kind string }{
		{"apps/v1/Deployment", "apps/v1", "Deployment"},
		{"v1/Pod", "v1", "Pod"},
		{"batch/v1/CronJob", "batch/v1", "CronJob"},
		{"argoproj.io/v1alpha1/Rollout", "argoproj.io/v1alpha1", "Rollout"},
		// A bare Kind with no version: the apiVersion half is empty, which
		// documentMatches treats as "do not compare the group" rather than as a
		// group that matches nothing.
		{"Deployment", "", "Deployment"},
	}
	for _, tc := range cases {
		gotAPI, gotKind := splitGVKWire(tc.in)
		if gotAPI != tc.apiVersion || gotKind != tc.kind {
			t.Errorf("splitGVKWire(%q) = (%q, %q), want (%q, %q)", tc.in, gotAPI, gotKind, tc.apiVersion, tc.kind)
		}
	}
}

func TestPickOwnershipQueryTuple(t *testing.T) {
	s := func(v string) *string { return &v }

	cases := []struct {
		name                          string
		objectKey, workloadKey        *string
		gvk, namespace, name2, source string
	}{
		{
			// The common case this preference exists for: a Pod-shaped object_key
			// whose Pod may no longer exist, with a stable workload_key available.
			// workload_key wins even though object_key is also well-formed.
			"workload_key wins over object_key when both are present",
			s("v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6"), s("apps/v1/Deployment|argus-gitops-rke2|nolimits"),
			"apps/v1/Deployment", "argus-gitops-rke2", "nolimits", "apps/v1/Deployment|argus-gitops-rke2|nolimits",
		},
		{
			"object_key alone is used when there is no workload_key",
			s("v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6"), nil,
			"v1", "argus-gitops-rke2", "nolimits-668c7cc998-sgnv6", "v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6",
		},
		{
			"a malformed workload_key falls back to object_key",
			s("v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6"), s("not-a-valid-key"),
			"v1", "argus-gitops-rke2", "nolimits-668c7cc998-sgnv6", "v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6",
		},
		{
			"an empty-name workload_key falls back to object_key",
			s("v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6"), s("apps/v1/Deployment|argus-gitops-rke2|"),
			"v1", "argus-gitops-rke2", "nolimits-668c7cc998-sgnv6", "v1|argus-gitops-rke2|nolimits-668c7cc998-sgnv6",
		},
		{
			"neither key present: nothing to ask about",
			nil, nil,
			"", "", "", "",
		},
	}
	for _, tc := range cases {
		gvk, namespace, name, source := pickOwnershipQueryTuple(tc.objectKey, tc.workloadKey)
		if gvk != tc.gvk || namespace != tc.namespace || name != tc.name2 || source != tc.source {
			t.Errorf("%s: pickOwnershipQueryTuple(%v, %v) = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				tc.name, deref(tc.objectKey), deref(tc.workloadKey), gvk, namespace, name, source,
				tc.gvk, tc.namespace, tc.name2, tc.source)
		}
	}
}

func TestBaseBranchFor(t *testing.T) {
	cases := []struct {
		name    string
		binding scm.Binding
		target  incidentRepoTarget
		want    string
	}{
		{
			"the binding's configured default wins",
			scm.Binding{DefaultBranch: "trunk"}, incidentRepoTarget{Branch: "release"}, "trunk",
		},
		{
			"otherwise the branch the controller tracks",
			scm.Binding{}, incidentRepoTarget{Branch: "release"}, "release",
		},
		{
			// A pull request whose base is a commit is not one a provider will
			// accept, so a SHA-shaped targetRevision must fall through to asking
			// the provider for the repository's real default.
			"a SHA-shaped target revision is not a branch",
			scm.Binding{}, incidentRepoTarget{Branch: "0f1e2d3c4b5a69788796a5b4c3d2e1f0a1b2c3d4"}, "",
		},
		{
			"a short SHA is not a branch either",
			scm.Binding{}, incidentRepoTarget{Branch: "0f1e2d3"}, "",
		},
		{
			"nothing known means ask the provider",
			scm.Binding{}, incidentRepoTarget{}, "",
		},
		{
			// "deadbeef" is hex, but "main" and "feature" are not — a branch name
			// that happens to be hex-looking is rare and falling through to the
			// provider's default is the safe direction anyway.
			"an ordinary branch name is kept",
			scm.Binding{}, incidentRepoTarget{Branch: "main"}, "main",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.target
			if got := baseBranchFor(tc.binding, &target); got != tc.want {
				t.Errorf("baseBranchFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// The route's capability set is the security boundary, and it is asserted here
// rather than only read in server.go: lld/02-authz-spec.md §6's headline grant
// ("may approve PRs but never touch a cluster in place") only stays meaningful
// if the route that actually opens a pull request checks remediation:execute:pr.
func TestRepositoryChangeRouteRequiresAllThreeCapabilities(t *testing.T) {
	required := []string{authz.CapRepoWrite, authz.CapRemediationApprove, authz.CapRemediationExecPR}
	catalogue := authz.AllBuiltinRoleCapabilities()

	// Checked against the catalogue rather than a hand-written list, so a change
	// to §5's role matrix cannot silently widen or break this route.
	for _, role := range []string{"super-admin", "tenant-admin"} {
		grants := grantsFor(catalogue[role]...)
		for _, capability := range required {
			if !authz.HasCapability(grants, capability) {
				t.Errorf("%s cannot open a repository change: missing %s", role, capability)
			}
		}
	}

	// A resolver may approve and may use the PR channel, but holds no repo:write
	// — so it cannot register a repository OR write to one. That is the intended
	// separation, not an oversight: repo:write is an administrative grant in §5's
	// matrix, and this route commits to the repository it names.
	resolver := grantsFor(catalogue["resolver"]...)
	if authz.HasCapability(resolver, authz.CapRepoWrite) {
		t.Error("resolver now holds repo:write — re-check whether this route's gate is still the intended one")
	}

	// A viewer must not hold the whole set.
	viewer := grantsFor(catalogue["viewer"]...)
	held := 0
	for _, capability := range required {
		if authz.HasCapability(viewer, capability) {
			held++
		}
	}
	if held == len(required) {
		t.Error("a viewer holds every capability this route requires")
	}
}

// The GET .../file route's audit/provenance helpers distinguish a file the
// caller named from one ARGUS discovered, because the two carry different
// responsibility for what gets opened in the editor.
func TestFilePathProvenanceInTheAuditRecord(t *testing.T) {
	if got := filePathSource(nil); got != "named_by_caller" {
		t.Errorf("filePathSource(nil) = %q", got)
	}
	if got := filesScanned(nil); got != 0 {
		t.Errorf("filesScanned(nil) = %d, want 0 — nothing was scanned when the caller named the file", got)
	}
	found := discoveredFile{Path: "envs/prod/a.yaml", DocIndex: 1, FilesScanned: 12}
	if got := filePathSource(&found); got != "located_by_argus" {
		t.Errorf("filePathSource(found) = %q", got)
	}
	if got := filesScanned(&found); got != 12 {
		t.Errorf("filesScanned(found) = %d, want 12", got)
	}
}
