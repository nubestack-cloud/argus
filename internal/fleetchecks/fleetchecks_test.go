package fleetchecks

import (
	"encoding/json"
	"testing"
)

func TestSummarizeCertificatesSortsDueAndCountsTheRest(t *testing.T) {
	raw := json.RawMessage(`{"truncated":true,"certificates":[
		{"name":"later","namespace":"a","daysLeft":200},
		{"name":"soon","namespace":"a","daysLeft":20},
		{"name":"expired","namespace":"b","daysLeft":-3},
		{"name":"edge","namespace":"b","daysLeft":90},
		{"name":"unknown","namespace":"c"}
	]}`)
	s, err := summarizeCertificates(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Listed != 5 || s.Later != 1 || s.Unknown != 1 || s.DueTotal != 3 || !s.Truncated {
		t.Fatalf("counts: %+v", s)
	}
	if len(s.Due) != 3 || s.Due[0].Name != "expired" || s.Due[1].Name != "soon" || s.Due[2].Name != "edge" {
		t.Fatalf("due order: %+v", s.Due)
	}
}

func TestSummarizeCertificatesCapsRowsButNotTheCount(t *testing.T) {
	var certs []map[string]any
	for i := 0; i < maxDuePins+10; i++ {
		certs = append(certs, map[string]any{"name": "c", "namespace": "n", "daysLeft": i})
	}
	raw, _ := json.Marshal(map[string]any{"certificates": certs})
	s, err := summarizeCertificates(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Due) != maxDuePins || s.DueTotal != maxDuePins+10 {
		t.Fatalf("got %d rows of %d", len(s.Due), s.DueTotal)
	}
}

// An agent without per-category posture has not answered; zeros would read
// as a clean cluster.
func TestSummarizePostureRefusesAMissingSummary(t *testing.T) {
	if _, err := summarizePosture(json.RawMessage(`{"results":[]}`)); err == nil {
		t.Fatal("want an error for an answer with no category summary")
	}
	s, err := summarizePosture(json.RawMessage(`{"summary":{"danger":3,"warning":7,"categories":{"Security":{"danger":3,"warning":2,"passing":9}}}}`))
	if err != nil || s.Danger != 3 || s.Warning != 7 || s.Categories["Security"].Passing != 9 {
		t.Fatalf("got %+v, %v", s, err)
	}
}

func TestSummarizeHelmUsesTheUIsFailingRule(t *testing.T) {
	raw := json.RawMessage(`{"total":7,"releases":[
		{"status":"deployed","health":"healthy"},
		{"status":"failed"},
		{"status":"pending-upgrade"},
		{"status":"uninstalling"},
		{"status":"deployed","lastOperation":{"kind":"upgrade"}},
		{"status":"deployed","lastOperation":null,"health":"degraded"}
	]}`)
	s, err := summarizeHelm(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 7 || s.Listed != 6 || s.Failing != 5 || !s.Truncated {
		t.Fatalf("got %+v", s)
	}
}

func TestSummarizeGitOpsCountsProblemsAmongListed(t *testing.T) {
	s, err := summarizeGitOps(json.RawMessage(`{"counts":{"total":3},"apps":[{"problem":true},{"problem":false}]}`))
	if err != nil || s.Total != 3 || s.Listed != 2 || s.Problems != 1 || !s.Truncated {
		t.Fatalf("got %+v, %v", s, err)
	}
}
