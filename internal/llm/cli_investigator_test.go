package llm

import (
	"strings"
	"testing"
)

// These tests cover the CLI backend's answer-parsing tolerance. They exist
// because a real 62-second, 16-iteration investigation against a live cluster
// was thrown away as "malformed_final_answer" for the single reason that
// `claude -p` prefixed one conversational sentence before the JSON it had been
// told to emit alone. The strict whole-string parse is right for the api
// backend (which owns its own loop and last message) and wrong for a harness
// this process does not control — so the tolerance is asserted here rather
// than left to be rediscovered the same expensive way.

const validFinalJSON = `{
  "rootCause": {"statement": "PVC is unbound because no StorageClass provisioner exists"},
  "confidence": 0.82,
  "ruledOut": []
}`

func TestExtractFinalAnalysisPureJSON(t *testing.T) {
	got, err := extractFinalAnalysis(validFinalJSON)
	if err != nil {
		t.Fatalf("pure JSON should parse: %v", err)
	}
	if !strings.Contains(got.RootCause.Statement, "no StorageClass provisioner") {
		t.Errorf("root cause not carried through: %q", got.RootCause.Statement)
	}
	if got.Confidence != 0.82 {
		t.Errorf("confidence = %v, want 0.82", got.Confidence)
	}
}

func TestExtractFinalAnalysisTolerates(t *testing.T) {
	// Each of these is a shape a real agentic CLI plausibly emits. The strict
	// parser rejects every one of them; all of them contain a complete,
	// unambiguous verdict.
	cases := map[string]string{
		"leading prose":     "Found the root cause after checking the PVC and its events.\n\n" + validFinalJSON,
		"trailing prose":    validFinalJSON + "\n\nLet me know if you'd like me to investigate further.",
		"prose both sides":  "Here is my analysis:\n" + validFinalJSON + "\nHappy to dig deeper.",
		"fenced with prose": "Analysis complete.\n\n```json\n" + validFinalJSON + "\n```\n",
		// The verdict must win over an earlier illustrative fragment — models
		// narrate before they conclude, so last-first ordering matters.
		"earlier json fragment": "I first considered `{\"phase\": \"Pending\"}` from the PVC status.\n" +
			"That led me here:\n" + validFinalJSON,
		// A bare object that parses but says nothing must not be mistaken for
		// a conclusion just because it is syntactically valid.
		"empty object before verdict": "Checked: {}\n" + validFinalJSON,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := extractFinalAnalysis(content)
			if err != nil {
				t.Fatalf("should have extracted a verdict: %v", err)
			}
			if !strings.Contains(got.RootCause.Statement, "no StorageClass provisioner") {
				t.Errorf("wrong object selected: %q", got.RootCause.Statement)
			}
		})
	}
}

func TestExtractFinalAnalysisBracesInsideStrings(t *testing.T) {
	// A root-cause statement that quotes a manifest or a Go template contains
	// braces. If the scanner counted those as structure it would close the
	// object early and truncate the very verdict being looked for.
	content := `Done.
{
  "rootCause": {"statement": "the chart rendered replicas: {{ .Values.count }} as a literal { string"},
  "confidence": 0.5,
  "ruledOut": []
}`
	got, err := extractFinalAnalysis(content)
	if err != nil {
		t.Fatalf("braces inside a string literal must not break the scan: %v", err)
	}
	if !strings.Contains(got.RootCause.Statement, "{{ .Values.count }}") {
		t.Errorf("statement truncated at an in-string brace: %q", got.RootCause.Statement)
	}
}

func TestExtractFinalAnalysisRejectsNonAnswers(t *testing.T) {
	// Tolerance must not become credulity: with no parsable verdict present,
	// this has to stay an error so the caller records an honest partial
	// instead of inventing a conclusion.
	for name, content := range map[string]string{
		"prose only":        "I was unable to determine the root cause.",
		"empty":             "",
		"object no verdict": `{"note": "still investigating", "confidence": 0.9}`,
		"empty object":      "{}",
		"unbalanced":        `{"rootCause": {"statement": "truncated`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := extractFinalAnalysis(content); err == nil {
				t.Errorf("expected an error for %q", content)
			}
		})
	}
}

func TestJSONObjectCandidatesOnlyTopLevel(t *testing.T) {
	// Nested objects are never the verdict, so they must not be offered as
	// separate candidates — otherwise a sub-object could outrank its parent.
	got := jsonObjectCandidates(`prefix {"a": {"b": 1}} middle {"c": 2} suffix`)
	want := []string{`{"a": {"b": 1}}`, `{"c": 2}`}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeCostBasisNeverInventsMetered(t *testing.T) {
	for _, in := range []string{"", "bogus", "METERED", "free"} {
		if got := normalizeCostBasis(in); got == CostBasisMetered {
			t.Errorf("normalizeCostBasis(%q) = metered; an unrecognized basis must never become measured spend", in)
		}
	}
	if got := normalizeCostBasis(CostBasisSubscription); got != CostBasisSubscription {
		t.Errorf("subscription basis mangled to %q", got)
	}
}

func TestTruncateForLogBounds(t *testing.T) {
	if got := truncateForLog("  short  ", 100); got != "short" {
		t.Errorf("got %q, want trimmed %q", got, "short")
	}
	long := strings.Repeat("x", 500)
	got := truncateForLog(long, 100)
	if len(got) >= len(long) {
		t.Errorf("expected truncation, got %d bytes", len(got))
	}
	if !strings.Contains(got, "500 bytes total") {
		t.Errorf("truncation should report the real size, got %q", got)
	}
}
