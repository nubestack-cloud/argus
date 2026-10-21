package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/authz"
)

// TestValidateCircuitBreakerRequest exercises validateCircuitBreakerRequest's
// documented rules directly, the same style TestValidateAutonomySettingsRequest
// (settings_test.go) uses for the sibling maxUnattendedPerCluster/
// maxUnattendedFleetWide/unattendedWindowSeconds fields — this is BACKLOG.md
// R5's own validation, deliberately mirroring that precedent rather than
// inventing a new shape.
func TestValidateCircuitBreakerRequest(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"empty body accepted (nothing to change)", `{}`, false},
		{"enabled alone accepted", `{"enabled":false}`, false},
		{"a coherent explicit set accepted", `{"enabled":true,"maxPerCluster":2,"maxFleetWide":8,"windowSeconds":1800}`, false},
		{"per-cluster equal to fleet-wide accepted (reachable, if only by one cluster)", `{"maxPerCluster":5,"maxFleetWide":5}`, false},

		{"zero per-cluster rejected (would silently become the default)", `{"maxPerCluster":0}`, true},
		{"zero fleet-wide rejected", `{"maxFleetWide":0}`, true},
		{"zero window rejected", `{"windowSeconds":0}`, true},
		{"negative per-cluster rejected", `{"maxPerCluster":-1}`, true},
		{"negative window rejected", `{"windowSeconds":-30}`, true},

		// Only checked when BOTH are present in the same request — see
		// validateCircuitBreakerRequest's own doc comment for why this is
		// narrower than validateAutonomySettingsRequest's resolved-against-
		// defaults version.
		{"per-cluster above an explicit fleet-wide cap rejected", `{"maxPerCluster":20,"maxFleetWide":10}`, true},
		{"per-cluster alone, no fleet-wide in this request, accepted (nothing decidable without the DB)", `{"maxPerCluster":20}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var req putCircuitBreakerRequest
			if err := json.Unmarshal([]byte(c.body), &req); err != nil {
				t.Fatalf("unmarshal %q: %v", c.body, err)
			}
			err := validateCircuitBreakerRequest(req)
			if c.wantErr && err == nil {
				t.Errorf("validateCircuitBreakerRequest(%+v) = nil error, want a validation error", req)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateCircuitBreakerRequest(%+v) = %v, want no error", req, err)
			}
		})
	}
}

// TestPutCircuitBreakerRequestPointerSemantics locks in the per-field
// leave-unchanged contract itself: a key absent from the JSON body and a key
// present as literal null both decode to the same nil pointer, matching
// putLLMSettingsRequest.APIKey/putNotifySettingsRequest.WebhookURL's already-
// established convention — this is the same shape BUGS.md 97 found missing
// on the sibling "autonomy" section's RequireReversibleForAutoApprove field
// (fixed by making it a *bool too, migration 000085), and this test is the
// guard against reintroducing that mistake here.
func TestPutCircuitBreakerRequestPointerSemantics(t *testing.T) {
	var absent putCircuitBreakerRequest
	if err := json.Unmarshal([]byte(`{"windowSeconds":60}`), &absent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if absent.Enabled != nil || absent.MaxPerCluster != nil || absent.MaxFleetWide != nil {
		t.Errorf("fields absent from the body must decode to nil (unchanged), got %+v", absent)
	}
	if absent.WindowSeconds == nil || *absent.WindowSeconds != 60 {
		t.Errorf("windowSeconds present in the body must decode to a non-nil 60, got %+v", absent.WindowSeconds)
	}

	var explicitNull putCircuitBreakerRequest
	if err := json.Unmarshal([]byte(`{"enabled":null,"windowSeconds":60}`), &explicitNull); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if explicitNull.Enabled != nil {
		t.Errorf("enabled present as literal JSON null must decode to nil (unchanged) exactly like an absent key, got %+v", explicitNull.Enabled)
	}
}

// TestPutBreakerRouteRequiresCapability is the request-level 403 half of
// BACKLOG.md R5's test requirement, matching TestRequireAnyCapability
// (middleware_test.go) and TestHandleOpenRepositoryChangeRequiresAFieldPath's
// sibling capability tests' style: wrap the real handler in the real
// middleware and prove a caller holding nothing but an unrelated capability
// is refused before the handler (and therefore any database write) ever
// runs. serverWithUnreachableAuditDB is safe here specifically because a
// denied request's only DB use is the best-effort audit write inside
// recordCapabilityDenial — no code path under test ever needs a working
// database to be reached.
func TestPutBreakerRouteRequiresCapability(t *testing.T) {
	s := serverWithUnreachableAuditDB(t)

	cases := []struct {
		name       string
		grants     []authz.EffectiveGrant
		wantStatus int
		wantCalled bool
	}{
		{"holds org:settings:write", grantsFor(authz.CapOrgSettingsWrite), http.StatusOK, true},
		{"holds an unrelated capability", grantsFor(authz.CapIncidentRead), http.StatusForbidden, false},
		{"holds nothing at all", nil, http.StatusForbidden, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			handler := s.requireCapability(authz.CapOrgSettingsWrite, func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
				called = true
				writeJSON(w, http.StatusOK, map[string]string{"ok": "yes"})
			})

			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodPut, "/api/v1/admin/circuit-breaker", nil), &requestContext{Grants: c.grants})

			if called != c.wantCalled {
				t.Errorf("handler called = %v, want %v", called, c.wantCalled)
			}
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, c.wantStatus, rec.Body.String())
			}
		})
	}
}
