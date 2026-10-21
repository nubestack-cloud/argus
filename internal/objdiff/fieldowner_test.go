package objdiff

import (
	"encoding/json"
	"testing"
)

// A real managedFields block, in the shape the API server actually writes — taken
// from the structure a live preflight already showed in its suppressed-paths list
// (`metadata.managedFields[0].fieldsV1.f:spec.f:template.f:spec.f:containers.k:{"name":"web"}.f:image`).
func liveObject(t *testing.T) map[string]any {
	t.Helper()
	const raw = `{
	  "metadata": {
	    "name": "web",
	    "managedFields": [
	      {
	        "manager": "argocd-controller",
	        "operation": "Apply",
	        "fieldsV1": {
	          "f:spec": {
	            "f:replicas": {},
	            "f:template": {
	              "f:spec": {
	                "f:containers": {
	                  "k:{\"name\":\"web\"}": {
	                    "f:image": {},
	                    "f:resources": { "f:limits": { "f:memory": {} } }
	                  }
	                }
	              }
	            }
	          }
	        }
	      },
	      {
	        "manager": "kube-controller-manager",
	        "operation": "Update",
	        "fieldsV1": { "f:status": {} }
	      },
	      {
	        "manager": "hand-edit",
	        "operation": "Update",
	        "fieldsV1": { "f:metadata": { "f:annotations": {} } }
	      }
	    ]
	  }
	}`
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	return out
}

// The question F11 needs answered, and the negative case is the valuable one:
// "nothing owns this field" means an in-place patch will hold, and today's
// object-level guardrail cannot distinguish that from "a controller will revert
// this".
func TestOwnersOfFindsTheManagerOfAField(t *testing.T) {
	obj := liveObject(t)
	for _, tc := range []struct {
		path        string
		wantManager string
		wantExact   bool
		why         string
	}{
		{"spec.replicas", "argocd-controller", true, "claimed as a leaf"},
		{"spec.template.spec.containers[web].image", "argocd-controller", true, "a keyed list element's field — the encoding this is all for"},
		{"spec.template.spec.containers[web].resources.limits.memory", "argocd-controller", true, "nested under a keyed element"},
		{"metadata.annotations", "hand-edit", true, "a different manager entirely"},
		// Ownership by CONTAINMENT: the manager owns f:status with an empty
		// object, which means everything below it.
		{"status.readyReplicas", "kube-controller-manager", false, "an empty node means the whole subtree, so this is owned without being named"},
		{"status.conditions[Available].status", "kube-controller-manager", false, "containment reaches arbitrarily deep, including through keyed elements"},
	} {
		owners := OwnersOf(obj, tc.path)
		if len(owners) == 0 {
			t.Errorf("OwnersOf(%q) = none, want %s — %s", tc.path, tc.wantManager, tc.why)
			continue
		}
		if owners[0].Manager != tc.wantManager {
			t.Errorf("OwnersOf(%q)[0].Manager = %q, want %q", tc.path, owners[0].Manager, tc.wantManager)
		}
		if owners[0].Exact != tc.wantExact {
			t.Errorf("OwnersOf(%q)[0].Exact = %v, want %v — %s", tc.path, owners[0].Exact, tc.wantExact, tc.why)
		}
	}
}

// The case that makes this worth building: a field on an Argo-managed object that
// Argo does NOT own. Today's guardrail refuses (pending confirmation) every patch
// to such an object; this is how it learns to tell the difference.
func TestUnownedFieldsReportNoOwner(t *testing.T) {
	obj := liveObject(t)
	for _, path := range []string{
		"spec.paused",                                  // Argo owns spec.replicas and spec.template, not this
		"spec.template.spec.containers[web].env",       // owns image and resources under this container, not env
		"spec.template.spec.containers[sidecar].image", // a different container entirely
		"metadata.labels",                              // hand-edit owns annotations, not labels
	} {
		if owners := OwnersOf(obj, path); len(owners) != 0 {
			t.Errorf("OwnersOf(%q) = %+v, want none. A false positive here refuses a patch that would have held", path, owners)
		}
	}
}

// Two managers can own overlapping paths, and the exact claim must be reported
// first — a message naming the manager that owns an ancestor when another set the
// field itself points the operator at the wrong controller.
func TestExactClaimsRankBeforeContainment(t *testing.T) {
	const raw = `{"metadata":{"managedFields":[
	  {"manager":"broad","operation":"Update","fieldsV1":{"f:spec":{}}},
	  {"manager":"precise","operation":"Apply","fieldsV1":{"f:spec":{"f:replicas":{}}}}
	]}}`
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		t.Fatal(err)
	}
	owners := OwnersOf(obj, "spec.replicas")
	if len(owners) != 2 {
		t.Fatalf("got %d owners, want both", len(owners))
	}
	if owners[0].Manager != "precise" || !owners[0].Exact {
		t.Errorf("owners[0] = %+v, want the exact claim first", owners[0])
	}
	if owners[1].Manager != "broad" || owners[1].Exact {
		t.Errorf("owners[1] = %+v, want the containing claim second", owners[1])
	}
}

// This function must NOT predict whether the value comes back, and the reason is
// live evidence rather than taste: a real Argo CD installation claims
// spec.replicas with operation **Update**, and WORKLOG §145 watched Argo revert
// exactly that field in twenty seconds. Reversion is a property of the controller
// (self-heal reconciles regardless of apply mode), so concluding it from
// `operation` is unsound in the dangerous direction.
func TestDescribeContentionDoesNotPredictReversionFromOperation(t *testing.T) {
	// The real-world case: an Update manager that DOES revert.
	update := []FieldOwner{{Manager: "argocd-controller", Operation: "Update", Exact: true}}
	msg := DescribeContention("spec.replicas", update)
	if !contains(msg, "argocd-controller") || !contains(msg, "spec.replicas") {
		t.Errorf("message = %q, want it to name both the field and the manager", msg)
	}
	for _, forbidden := range []string{"overwrites", "one-off", "wrote once"} {
		if contains(msg, forbidden) {
			t.Errorf("message %q implies the patch would stick, from an Update operation on a manager that demonstrably reverts", msg)
		}
	}

	// An Apply manager produces the same statement — the operation must not change
	// the conclusion, because it does not determine it.
	apply := []FieldOwner{{Manager: "argocd-controller", Operation: "Apply", Exact: true}}
	if DescribeContention("spec.replicas", apply) != msg {
		t.Error("Apply and Update produce different messages; the operation must not change what is claimed, since it does not determine whether the value returns")
	}
}

// Empty means "nothing contends", never "we could not tell" — the caller acts on
// that distinction, so it must not be ambiguous.
func TestDescribeContentionIgnoresARGUSItself(t *testing.T) {
	owners := []FieldOwner{{Manager: "argus-remediate", Operation: "Apply", Exact: true}}
	if msg := DescribeContention("spec.replicas", owners, "argus-remediate"); msg != "" {
		t.Errorf("DescribeContention reported contention with ARGUS's own manager: %q. A field ARGUS set last is not contended — it is exactly what we expect after a previous execution", msg)
	}
	if msg := DescribeContention("spec.replicas", nil); msg != "" {
		t.Errorf("no owners produced %q, want empty", msg)
	}
}

// A malformed set must not be read as ownership: a false positive refuses a patch
// that would have been fine, which is the direction that costs the operator.
func TestMalformedManagedFieldsClaimNothing(t *testing.T) {
	for _, raw := range []string{
		`{"metadata":{"managedFields":[{"manager":"m","operation":"Apply","fieldsV1":{"f:spec":{"f:replicas":"not-an-object"}}}]}}`,
		`{"metadata":{"managedFields":[{"manager":"","operation":"Apply","fieldsV1":{"f:spec":{}}}]}}`,
		`{"metadata":{"managedFields":[{"manager":"m","operation":"Apply"}]}}`,
		`{"metadata":{"managedFields":"not-a-list"}}`,
		`{"metadata":{}}`,
		`{}`,
	} {
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		if owners := OwnersOf(obj, "spec.replicas"); len(owners) != 0 {
			t.Errorf("malformed managedFields %s produced owners %+v", raw, owners)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
