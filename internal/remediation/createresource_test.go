package remediation

import (
	"errors"
	"strings"
	"testing"

	"argus/internal/redact"
)

// --- CreateResourcePermitted: allowlist permission/refusal --------------

func TestCreateResourcePermitted_ConfigMapAllowed(t *testing.T) {
	if _, err := CreateResourcePermitted("v1/ConfigMap"); err != nil {
		t.Fatalf("CreateResourcePermitted(v1/ConfigMap) = %v, want no error", err)
	}
}

func TestCreateResourcePermitted_EverythingElseRefused(t *testing.T) {
	// Deliberately including kinds that are legitimate targets for OTHER
	// action types (Pod/Job for deleteResource, Deployment/StatefulSet for
	// annotateResource/labelResource) to confirm createResource's allowlist
	// is not accidentally inherited from a sibling mechanism.
	for _, gvk := range []string{"v1/Secret", "v1/Pod", "batch/v1/Job", "apps/v1/Deployment", "apps/v1/StatefulSet", "v1/Namespace", "v1/PersistentVolumeClaim"} {
		t.Run(gvk, func(t *testing.T) {
			if _, err := CreateResourcePermitted(gvk); err == nil {
				t.Errorf("CreateResourcePermitted(%q) succeeded, want refusal", gvk)
			}
		})
	}
}

// TestCreateResourceAllowlistEntries_EveryRowHasAJustification mirrors this
// package's existing requirement for patchfield.go/deleteresource.go/
// annotatelabel.go's own tables: every reviewed row must carry a non-empty
// Why, since an allowlist entry with no stated reason is not actually
// reviewed.
func TestCreateResourceAllowlistEntries_EveryRowHasAJustification(t *testing.T) {
	entries := CreateResourceAllowlistEntries()
	if len(entries) == 0 {
		t.Fatal("CreateResourceAllowlistEntries() is empty")
	}
	for _, e := range entries {
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("allowlist entry for %s has no Why", e.GVK)
		}
	}
}

// --- CreateResourceParams.Validate: positive/negative --------------------

func TestCreateResourceParams_Validate_Valid(t *testing.T) {
	p := CreateResourceParams{Data: map[string]string{"RETRY_LIMIT": "3", "config.yaml": "key: value\n"}}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestCreateResourceParams_Validate_EmptyDataRefused(t *testing.T) {
	p := CreateResourceParams{}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded for an empty Data map, want refusal")
	}
}

func TestCreateResourceParams_Validate_TooManyKeysRefused(t *testing.T) {
	data := make(map[string]string, maxCreateResourceDataKeys+1)
	for i := 0; i < maxCreateResourceDataKeys+1; i++ {
		data[strings.Repeat("k", 1)+string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
	}
	p := CreateResourceParams{Data: data}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded with more keys than the bound, want refusal")
	}
}

func TestCreateResourceParams_Validate_MalformedKeyRefused(t *testing.T) {
	for _, key := range []string{"", "has a space", "has/a/slash", "has\nnewline"} {
		t.Run(key, func(t *testing.T) {
			p := CreateResourceParams{Data: map[string]string{key: "v"}}
			if err := p.Validate(); err == nil {
				t.Errorf("Validate() succeeded for malformed key %q, want refusal", key)
			}
		})
	}
}

func TestCreateResourceParams_Validate_OversizedValueRefused(t *testing.T) {
	p := CreateResourceParams{Data: map[string]string{"big": strings.Repeat("x", maxCreateResourceValueBytes+1)}}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded for a value over the per-key byte bound, want refusal")
	}
}

func TestCreateResourceParams_Validate_OversizedTotalRefused(t *testing.T) {
	// Several keys individually within the per-key bound, but summing over
	// the total-bytes bound.
	data := map[string]string{}
	perKey := maxCreateResourceValueBytes
	needed := maxCreateResourceTotalBytes/perKey + 2
	for i := 0; i < needed; i++ {
		data["key"+string(rune('a'+i))] = strings.Repeat("y", perKey)
	}
	p := CreateResourceParams{Data: data}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded over the total-bytes bound, want refusal")
	}
}

// TestCreateResourceParams_Validate_RedactionMarkerRefused is BUGS.md 112's
// guard, carried here for the same defense-in-depth reason
// AnnotateResourceParams/LabelResourceParams/PatchFieldParams/OpenPRParams
// all keep it unconditionally: a model must never be able to write back the
// sentinel that stood in for a value it was never shown.
func TestCreateResourceParams_Validate_RedactionMarkerRefused(t *testing.T) {
	p := CreateResourceParams{Data: map[string]string{"secret_ref": redact.Marker}}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() succeeded for a value echoing redact.Marker, want refusal")
	}
	if !errors.Is(err, ErrNewValueEchoesRedactionMarker) {
		t.Errorf("error does not wrap ErrNewValueEchoesRedactionMarker: %v", err)
	}
}

// --- RemediationPlan.Validate: CreateResource-specific checks ------------

func createResourcePlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_10example",
		AnalysisID:      "an_10example",
		ActionType:      ActionCreateResource,
		TargetGVK:       "v1/ConfigMap",
		TargetNamespace: "payments",
		TargetName:      "checkout-api-config",
		Params:          CreateResourceParams{Data: map[string]string{"RETRY_LIMIT": "3"}},
		Reversible:      false,
		RiskLevel:       RiskMedium,
	}
}

func TestRemediationPlan_Validate_CreateResource_Valid(t *testing.T) {
	if err := createResourcePlan().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestRemediationPlan_Validate_CreateResource_DisallowedKindRefused(t *testing.T) {
	p := createResourcePlan()
	p.TargetGVK = "v1/Secret"
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded for a Secret target, want refusal")
	}
}

// TestRemediationPlan_Validate_CreateResource_ReversibleRefused mirrors
// TestRemediationPlan_Validate_DeleteResource's own reversibility check in
// the opposite direction: a CreateResource plan has no representable
// rollback through this codebase's reviewed delete mechanism (ConfigMap is
// not in deleteResource's own allowlist), so claiming Reversible=true must
// be refused outright rather than silently accepted.
func TestRemediationPlan_Validate_CreateResource_ReversibleRefused(t *testing.T) {
	p := createResourcePlan()
	p.Reversible = true
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded for Reversible=true, want refusal")
	}
}

func TestRemediationPlan_Validate_CreateResource_WrongParamsTypeRefused(t *testing.T) {
	p := createResourcePlan()
	p.Params = DeleteResourceParams{}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded with mismatched params type, want refusal")
	}
}

// TestRemediationPlan_Validate_CreateResource_InvalidDataRefused confirms
// CreateResourceParams.Validate is actually reached from
// RemediationPlan.Validate's selfValidatingParams dispatch, not just
// callable on its own.
func TestRemediationPlan_Validate_CreateResource_InvalidDataRefused(t *testing.T) {
	p := createResourcePlan()
	p.Params = CreateResourceParams{}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() succeeded with empty Data, want refusal")
	}
}

// TestRemediationPlan_Validate_CreateResource_DisallowedKindReportsTheKindReason
// is PROJECT.md B145's regression test: a plan naming BOTH a disallowed kind
// AND empty Data (the natural shape for a kind with no data concept at all,
// e.g. a ServiceAccount — reproduced live 2026-09-06 re-running SCHED-054)
// must be refused with the reason that actually explains it — the kind is
// categorically out of CreateResource's scope — not the generic "data is
// required" message, which is technically true but tells an operator the
// wrong thing to fix.
func TestRemediationPlan_Validate_CreateResource_DisallowedKindReportsTheKindReason(t *testing.T) {
	p := createResourcePlan()
	p.TargetGVK = "v1/ServiceAccount"
	p.Params = CreateResourceParams{} // empty Data: ServiceAccount has no data concept

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() succeeded for a ServiceAccount target with empty Data, want refusal")
	}
	if strings.Contains(err.Error(), "data is required") {
		t.Errorf("Validate() = %q — reports the generic data-shape reason even though the target kind is categorically disallowed; want the CreateResourcePermitted allowlist reason instead", err.Error())
	}
}

// TestParamsOnlyValidationFailure_CreateResource_AllowlistRefusalNotCorrectable
// mirrors the DeleteResource/PatchField/StructuredPatch/AnnotateResource/
// LabelResource cases: a kind refusal is a policy refusal of the TARGET KIND
// itself, independent of anything else in the plan, so it must be excluded
// from correction eligibility.
func TestParamsOnlyValidationFailure_CreateResource_AllowlistRefusalNotCorrectable(t *testing.T) {
	p := createResourcePlan()
	p.TargetGVK = "v1/Secret"
	_, ok := p.ParamsOnlyValidationFailure()
	if ok {
		t.Fatal("ParamsOnlyValidationFailure() = true for a disallowed-kind refusal, want false (not correctable)")
	}
}

// TestParamsOnlyValidationFailure_CreateResource_InvalidDataIsCorrectable
// confirms an empty/oversized Data map — a problem with the VALUE, not the
// kind — falls into the generic selfValidatingParams branch and is reported
// as correctable, the same as an invalid PatchResourceLimits/PatchField
// value.
func TestParamsOnlyValidationFailure_CreateResource_InvalidDataIsCorrectable(t *testing.T) {
	p := createResourcePlan()
	p.Params = CreateResourceParams{}
	reason, ok := p.ParamsOnlyValidationFailure()
	if !ok {
		t.Fatal("ParamsOnlyValidationFailure() = false for an invalid Data map, want true (correctable)")
	}
	if strings.TrimSpace(reason) == "" {
		t.Error("reason is empty")
	}
}
