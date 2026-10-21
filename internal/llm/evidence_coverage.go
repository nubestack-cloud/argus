package llm

import (
	"encoding/json"
	"strings"
)

// EvidenceCoverage says what an investigation could and could not read
// (PROJECT.md IN6), so "could not determine" names what was missing. Counted
// from the real recorded tool calls, never from the model's account of them.
type EvidenceCoverage struct {
	// Answered: calls that returned something to reason from.
	Answered int `json:"answered"`
	// Empty: calls that worked and found nothing.
	Empty int `json:"empty"`
	// Denied: calls the cluster refused (RBAC).
	Denied int `json:"denied"`
	// Failed: calls that did not complete — a timeout, the agent offline.
	Failed int `json:"failed"`
	// Truncated: answered calls whose output was capped.
	Truncated int `json:"truncated"`
	// NotOffered: tools this investigation could not use at all because the
	// cluster lacks what they need: "metrics" (no Prometheus), "dryRun" (no
	// dry-run grant), "repository" (no readable repository).
	NotOffered []string `json:"notOffered"`
}

// partialEvidenceConfidenceCeiling caps a conclusion whose reads were mostly
// refused or failed: it was reached on part of the evidence.
const partialEvidenceConfidenceCeiling = 0.6

type coverageCall struct {
	err    string
	isErr  bool
	result json.RawMessage
}

func coverageFrom(calls []coverageCall, av toolAvailability) *EvidenceCoverage {
	c := &EvidenceCoverage{NotOffered: []string{}}
	for _, call := range calls {
		switch {
		case call.isErr && isDenied(call.err):
			c.Denied++
		case call.isErr:
			c.Failed++
		case len(call.result) == 0 || !toolResultHasEvidence(call.result):
			c.Empty++
		default:
			c.Answered++
			if resultTruncated(call.result) {
				c.Truncated++
			}
		}
	}
	if !av.metrics {
		c.NotOffered = append(c.NotOffered, "metrics")
	}
	if !av.dryRun {
		c.NotOffered = append(c.NotOffered, "dryRun")
	}
	if !av.repo {
		c.NotOffered = append(c.NotOffered, "repository")
	}
	return c
}

// mostlyMissing: as many reads were refused or failed as answered.
func (c *EvidenceCoverage) mostlyMissing() bool {
	return c != nil && c.Answered > 0 && c.Denied+c.Failed >= c.Answered
}

func isDenied(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "permission denied") || strings.Contains(m, "forbidden") || strings.Contains(m, "not allowed")
}

func resultTruncated(raw json.RawMessage) bool {
	var v struct {
		Truncated bool `json:"truncated"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Truncated
}

func coverageFromChain(chain []CausalStep, av toolAvailability) *EvidenceCoverage {
	var calls []coverageCall
	for _, step := range chain {
		for _, tc := range step.ToolCalls {
			cc := coverageCall{result: tc.Result}
			if tc.Error != nil {
				cc.isErr, cc.err = true, *tc.Error
			}
			calls = append(calls, cc)
		}
	}
	return coverageFrom(calls, av)
}

func coverageFromRecorded(real []RecordedToolCall, av toolAvailability) *EvidenceCoverage {
	calls := make([]coverageCall, 0, len(real))
	for _, r := range real {
		cc := coverageCall{result: r.Result}
		if r.Outcome == "error" {
			cc.isErr, cc.err = true, string(r.Result)
		}
		calls = append(calls, cc)
	}
	return coverageFrom(calls, av)
}
