package api

import (
	"reflect"
	"strings"
	"testing"
)

// handleGetIncident used to build its response as a hand-written map literal while
// handleListIncidents marshals []incidentSummary directly. That asymmetry dropped a field
// three separate times: the group ids and the object identity split, then resolutionKind,
// then resolutionKind again after a branch merge reverted the fix. Each time the list
// endpoint stayed correct, so the two endpoints disagreed about the same incident — and the
// last one rendered an incident ARGUS had fixed through a merged pull request as "Closed
// with no ARGUS fix linked".
//
// THE FIRST VERSION OF THIS TEST DID NOT CATCH THAT, and the reason is worth keeping: it
// compared incidentSummary's json tags against a second hand-maintained list inside the
// test, so it guarded "a new struct field was forgotten in the test's list" and not "the
// handler lost a field". It passed while the handler was missing resolutionKind.
//
// So this exercises the REAL code path instead. incidentSummaryFields is what the handler
// calls, and it is the only thing standing between the two endpoints.
func TestIncidentDetailCarriesEverySummaryField(t *testing.T) {
	// Every field populated, so nothing is dropped by omitempty and the check is about
	// presence rather than about this fixture's zero values.
	s := "x"
	inc := incidentSummary{
		ID: "inc_1", ClusterID: "cl_1", ClusterDisplayName: "prod", Fingerprint: "fp",
		Severity: "high", State: "Resolved", OccurrenceCount: 1,
		FleetGroupID: &s, WorkloadGroupID: &s, WorkloadKey: &s, OpeningReason: &s,
		ObjectGVK: &s, ObjectNamespace: &s, ObjectName: &s, ResolvedAt: &s,
		ObjectGroupID: &s, RelatedWorkloadKey: &s, ResolutionKind: &s,
		ImportanceExplanation: []string{"why"},
		// Added when the list grew a Route column. This fixture's contract is
		// "every field populated" — a new nullable field left nil here is
		// dropped by omitempty and the guard silently stops guarding it.
		Route: &s,
	}

	body, err := incidentSummaryFields(inc)
	if err != nil {
		t.Fatalf("incidentSummaryFields: %v", err)
	}

	typ := reflect.TypeOf(incidentSummary{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		if _, ok := body[name]; !ok {
			t.Errorf("GET /incidents/{id} does not carry %q (incidentSummary field %s), "+
				"which GET /incidents does. The two endpoints must not disagree about the "+
				"same incident.", name, typ.Field(i).Name)
		}
	}

	// The specific field whose absence was user-visible, asserted by name so a reader of a
	// failure knows which regression they are looking at.
	if got := body["resolutionKind"]; got != "x" {
		t.Errorf("resolutionKind = %v, want \"x\" — this is the field whose absence made a "+
			"remediated incident render as self-healed", got)
	}
}
