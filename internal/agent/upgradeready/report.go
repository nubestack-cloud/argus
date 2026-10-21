package upgradeready

import (
	"fmt"
	"slices"
	"strings"
)

// report is a check being written. It starts passed with its passing
// summary; the scan decides blocked, warning or review from its findings at
// the end, so a check only ever says what happens when it found nothing.
type report struct{ Check }

func newReport(id, category, title, scope, passing string) *report {
	return &report{Check{ID: id, Category: category, Title: title, Scope: scope, Status: CheckPassed, Summary: passing}}
}

// since records the release a check's change arrives in; findings inherit
// it.
func (r *report) since(release string) *report {
	r.AppliesFrom = release
	return r
}

func (r *report) citing(rs ...[]Reference) *report {
	r.References = refs(rs...)
	return r
}

// unknown and notApplicable end a check that cannot, or need not, judge.
func (r *report) unknown(summary string) Check {
	r.Status, r.Summary = CheckUnknown, summary
	return r.Check
}

func (r *report) notApplicable(summary string) Check {
	r.Status, r.Summary = CheckNotApplicable, summary
	return r.Check
}

// caveat adds to what the check could not see.
func (r *report) caveat(text string) { r.Caveat = joinSentences(r.Caveat, text) }

func (r *report) note(text string) { r.EvidenceNote = joinSentences(r.EvidenceNote, text) }

// flag records a finding against the check's own ID, release and
// references; the caller adjusts the returned finding when one differs.
// The pointer is good until the next flag.
func (r *report) flag(level Level, title string, at *ResourceRef, ev Evidence, impact, fix string) *Finding {
	r.Findings = append(r.Findings, Finding{
		RuleID: r.ID, Title: title, Level: level, Resource: at, Evidence: ev,
		AppliesFrom: r.AppliesFrom, Impact: impact, Remediation: fix, References: refs(r.References),
	})
	return &r.Findings[len(r.Findings)-1]
}

func (r *report) found() int { return len(r.Findings) }

// finish words the summary once the evidence is in: found describes the
// findings when there are any; with none, a caveat means the clean result
// cannot be trusted and the check is unknown with summary incomplete
// (incomplete "" keeps the passing summary and status).
func (r *report) finish(found func(n int) string, incomplete string) Check {
	switch {
	case r.found() > 0:
		r.Summary = found(r.found())
	case r.Caveat != "" && incomplete != "":
		r.Status, r.Summary = CheckUnknown, incomplete
	}
	return r.Check
}

func joinSentences(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " " + b
}

// count writes "1 node" or "3 nodes".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// either picks the singular or plural form for n.
func either(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// shortList sorts and dedupes values and names the first five, with a
// count of the rest.
func shortList(values []string, sep string) string {
	v := slices.Compact(slices.Sorted(slices.Values(values)))
	if len(v) <= 5 {
		return strings.Join(v, sep)
	}
	return fmt.Sprintf("%s%sand %d more", strings.Join(v[:5], sep), sep, len(v)-5)
}

func nodeRef(name string) *ResourceRef { return &ResourceRef{Kind: "Node", Name: name} }

func podRef(ns, name string) *ResourceRef {
	return &ResourceRef{Kind: "Pod", Namespace: ns, Name: name}
}

func live(path, detail string) Evidence { return Evidence{Source: "live", Path: path, Detail: detail} }
