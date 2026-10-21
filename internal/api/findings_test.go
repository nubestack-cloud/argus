package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"argus/internal/authz"
)

// The DB-free half of GET /api/v1/findings (PROJECT.md F31): the auth and
// capability gating, and the pure parsing helpers. findings_db_test.go covers
// the query, the dispositions, the counts and the RLS scoping.
//
// Structure mirrors cluster_groups_test.go / custom_roles_test.go, including
// the "a case that clears the gate goes on to touch a nil rc.Tx and panics,
// which is caught and treated as passed-the-gate" trick — that is what lets
// the gate be proved without a database behind it.

// TestFindingsRouteRequiresAuth: the route is wrapped in requireAuth, so a
// request with no bearer token is refused before the handler or the database
// is reached. A fleet-wide list of raw detection output is not a thing to
// leave reachable unauthenticated.
func TestFindingsRouteRequiresAuth(t *testing.T) {
	s := &Server{}
	handler := s.requireAuth(s.requireCapability(authz.CapIncidentRead, s.handleListFindings))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestFindingsRouteRequiresCapability: incident:read, and nothing else, opens
// it. The "unrelated capability" case is the one that matters — a route
// wrapped with requireAuth but not requireCapability would pass the first and
// third cases and fail only this one.
func TestFindingsRouteRequiresCapability(t *testing.T) {
	cases := []struct {
		name       string
		grants     []authz.EffectiveGrant
		wantDenied bool
	}{
		{"no grants at all", nil, true},
		{"a grant for an unrelated capability", grantsFor(authz.CapClusterRead), true},
		{"holds incident:read", grantsFor(authz.CapIncidentRead), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := serverWithUnreachableAuditDB(t)
			handler := s.requireCapability(authz.CapIncidentRead, s.handleListFindings)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
			rec := httptest.NewRecorder()

			passedGate := false
			func() {
				defer func() {
					if recover() != nil {
						passedGate = true
					}
				}()
				handler(rec, req, &requestContext{Grants: tc.grants})
			}()

			denied := !passedGate && rec.Code == http.StatusForbidden
			if denied != tc.wantDenied {
				t.Fatalf("denied=%v (status %d, passedGate=%v), want denied=%v — body: %s",
					denied, rec.Code, passedGate, tc.wantDenied, rec.Body.String())
			}
			if tc.wantDenied && !strings.Contains(rec.Body.String(), authz.CapIncidentRead) {
				t.Errorf("403 body does not name the missing capability: %s", rec.Body.String())
			}
		})
	}
}

// TestFindingWindowFor pins the defaulting and the validation, including the
// ordering check — a ?until= before ?since= is a filter that can only ever
// return nothing, and silently returning nothing reads to an operator as
// "ARGUS saw nothing", which is the single worst answer this endpoint can
// give wrongly.
func TestFindingWindowFor(t *testing.T) {
	t.Run("defaults to the standard window", func(t *testing.T) {
		before := time.Now().Add(-defaultFindingWindow)
		since, until, invalid := findingWindowFor("", "")
		if invalid != "" {
			t.Fatalf("unexpected rejection: %s", invalid)
		}
		if until != nil {
			t.Errorf("until = %v, want open-ended", until)
		}
		if since.Before(before.Add(-time.Minute)) || since.After(time.Now()) {
			t.Errorf("since = %v, want roughly %v", since, before)
		}
	})

	t.Run("accepts RFC 3339", func(t *testing.T) {
		since, until, invalid := findingWindowFor("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z")
		if invalid != "" {
			t.Fatalf("unexpected rejection: %s", invalid)
		}
		if since.UTC().Format(time.RFC3339) != "2026-09-01T00:00:00Z" || until == nil {
			t.Fatalf("since = %v, until = %v", since, until)
		}
	})

	for _, tc := range []struct{ name, since, until string }{
		{"an unparseable since", "yesterday", ""},
		{"an unparseable until", "", "tomorrow"},
		{"a date-only since", "2026-09-01", ""},
		{"until before since", "2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			if _, _, invalid := findingWindowFor(tc.since, tc.until); invalid == "" {
				t.Error("accepted, want a rejection message")
			}
		})
	}
}

// TestFindingCursorRoundTrips: the token carries full timestamp precision.
// Second-resolution would be a live bug rather than a rounding one — several
// detectors legitimately report the same object in the same second (migration
// 000036's measured case), so a truncated cursor would re-serve or skip the
// tied rows on every page boundary.
func TestFindingCursorRoundTrips(t *testing.T) {
	when := time.Date(2026, 9, 23, 14, 5, 6, 123456789, time.UTC)
	gotWhen, gotID, err := decodeFindingCursor(encodeFindingCursor(when, "fnd_abc"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotWhen.Equal(when) {
		t.Errorf("timestamp round-tripped as %v, want %v", gotWhen, when)
	}
	if gotID != "fnd_abc" {
		t.Errorf("id round-tripped as %q", gotID)
	}

	for _, bad := range []string{"", "!!!not-base64!!!", "bm8tc2VwYXJhdG9y", "fHdpdGhvdXQtYS10aW1l"} {
		if _, _, err := decodeFindingCursor(bad); err == nil {
			t.Errorf("decodeFindingCursor(%q) accepted a malformed token", bad)
		}
	}
}

// TestFindingPageLimit: rejects rather than clamps, so a caller asking for
// everything is told about the cap instead of quietly getting a page.
func TestFindingPageLimit(t *testing.T) {
	if got, err := findingPageLimit(""); err != nil || got != defaultFindingPageLimit {
		t.Errorf("default = (%d, %v), want (%d, nil)", got, err, defaultFindingPageLimit)
	}
	if got, err := findingPageLimit("50"); err != nil || got != 50 {
		t.Errorf("limit=50 = (%d, %v)", got, err)
	}
	for _, bad := range []string{"0", "-1", "abc", "1001"} {
		if _, err := findingPageLimit(bad); err == nil {
			t.Errorf("limit=%s was accepted", bad)
		}
	}
}

// TestFindingDispositionsAreCoveredBySQL: every disposition the API accepts
// as a ?disposition= value must have a SQL clause, and every clause must
// belong to an accepted value. A vocabulary entry with no clause would panic
// or silently drop the filter; a clause with no vocabulary entry is a bucket
// the counts report and nobody can list.
func TestFindingDispositionsAreCoveredBySQL(t *testing.T) {
	if len(findingDispositionClauses) != len(validFindingDispositions) {
		t.Fatalf("%d clauses for %d dispositions", len(findingDispositionClauses), len(validFindingDispositions))
	}
	for _, disposition := range validFindingDispositions {
		clause, ok := findingDispositionClauses[disposition]
		if !ok {
			t.Errorf("disposition %q has no SQL clause", disposition)
			continue
		}
		if !strings.Contains(clause, "findings.incident_id") {
			t.Errorf("disposition %q's clause never looks at incident_id, which is what makes a finding correlated or not: %s", disposition, clause)
		}
	}
}
