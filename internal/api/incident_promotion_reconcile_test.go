package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/orchestrator"
)

// TestReconcilePromotionRefusesToApplyWithoutANote pins the safeguard, and
// pins that it is checked BEFORE anything reads the database: rc.Tx is nil
// here, so a handler that scanned first would panic rather than 400.
// Dismissed is terminal and this closes incidents nobody read one at a time —
// the note is the only thing that makes the decision auditable afterwards.
func TestReconcilePromotionRefusesToApplyWithoutANote(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/reconcile-promotion",
		strings.NewReader(`{"apply": true}`))
	rec := httptest.NewRecorder()

	s.handleReconcilePromotion(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestReconcilePromotionCanCloseEveryStateItWillAttempt is the invariant the
// handler's skip logic rests on and that nothing else in the codebase asserts.
//
// The handler closes exactly the requires-action states, in ONE hop, and never
// invents an intermediate walk the way closeIncidentsForDecommission has to —
// which is only safe while every requires-action state actually has a direct
// edge to Dismissed. That is true today, and it is the kind of thing that
// silently stops being true when somebody adds a state: it would not fail, it
// would quietly leave a class of incident permanently unreconcilable, counted
// as "skipped" for a reason that reads like a race.
func TestReconcilePromotionCanCloseEveryStateItWillAttempt(t *testing.T) {
	for _, state := range incidentStatesFromCheckConstraint {
		if !orchestrator.RequiresAction(state) {
			continue
		}
		if !orchestrator.CanTransition(state, orchestrator.StateDismissed) {
			t.Errorf("state %q requires action but has no direct edge to %s — the promotion reconciliation would skip it forever",
				state, orchestrator.StateDismissed)
		}
	}
}
