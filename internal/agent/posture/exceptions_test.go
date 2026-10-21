package posture

import "testing"

func TestApplyExceptions(t *testing.T) {
	res := &ScanResults{
		Findings: []Finding{
			{Kind: "Deployment", Namespace: "a", Name: "web", CheckID: "runAsRoot", Category: CategorySecurity, Severity: SeverityDanger},
			{Kind: "Deployment", Namespace: "a", Name: "web", CheckID: "noLimits", Category: CategoryEfficiency, Severity: SeverityWarning},
			{Kind: "Deployment", Namespace: "b", Name: "db", CheckID: "noLimits", Category: CategoryEfficiency, Severity: SeverityWarning},
		},
		EvaluatedByNamespace: map[string]map[string]int{"runAsRoot": {"a": 1}, "noLimits": {"a": 1, "b": 1}},
	}
	got := ApplyExceptions(res,
		map[ObjectKey]string{{"Deployment", "a", "web"}: "RunAsRoot, other"}, // case-insensitive, list
		map[string]string{"b": "*"})

	if got.Summary.Excepted != 2 || got.Summary.Danger != 0 || got.Summary.Warning != 1 {
		t.Fatalf("summary = %+v, want 2 excepted, 0 danger, 1 warning", got.Summary)
	}
	if len(got.Findings) != 3 || !got.Findings[0].Excepted || got.Findings[1].Excepted || !got.Findings[2].Excepted {
		t.Fatalf("excepted findings must stay listed and flagged: %+v", got.Findings)
	}
	// An excepted subject is neither a pass nor a failure.
	if c := got.CheckCounts["runAsRoot"]; c.Evaluated != 0 {
		t.Fatalf("runAsRoot counts = %+v, want the excepted subject out of the denominator", c)
	}
	if res.Findings[0].Excepted || res.EvaluatedByNamespace["runAsRoot"]["a"] != 1 {
		t.Fatal("input was modified")
	}
	if IgnoresCheck("", "x") || IgnoresCheck("a,b", "x") {
		t.Fatal("an empty or non-matching annotation must not except")
	}
}
