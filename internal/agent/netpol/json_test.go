package netpol

import (
	"encoding/json"
	"testing"
)

// Tool results carry verdicts and effects as words; an enum ordinal in the
// JSON would be meaningless to the model and to the evidence renderer.
func TestVerdictAndExplanationJSON(t *testing.T) {
	v := Verdict{Kind: Denied, Direction: DirectionIngress, Policies: []string{"shop/deny-all"}}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"verdict":"denied","direction":"ingress","decidingPolicies":["shop/deny-all"]}`; got != want {
		t.Errorf("verdict JSON = %s, want %s", got, want)
	}

	b, err = json.Marshal(Verdict{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"verdict":"unknown"}`; got != want {
		t.Errorf("zero verdict JSON = %s, want %s", got, want)
	}

	for e, want := range map[Effect]string{
		NotApplicable: `"notApplicable"`,
		Admits:        `"admits"`,
		DoesNotAdmit:  `"doesNotAdmit"`,
		Undecidable:   `"undecidable"`,
	} {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Errorf("Effect %v JSON = %s, want %s", e, b, want)
		}
	}
}
