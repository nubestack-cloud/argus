package pathtrace

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// headline renders the one sentence a reader needs before the hop list: for
// a broken or degraded path, the hop where it breaks and the finding that
// explains it; for an unknown path, why it can't be verified; for a healthy
// path, what was checked - stated as a static check, since no traffic was
// sent.
func headline(t *Trace) string {
	switch t.Verdict {
	case VerdictBroken:
		if f, hop, ok := breakFinding(t); ok {
			return fmt.Sprintf("Breaks at: %s - %s", refLabel(&hop), findingSummary(f))
		}
		return "Broken: " + firstNonEmpty(t.Reason, "a critical problem was found on the path")
	case VerdictDegraded:
		if f, hop, ok := breakFinding(t); ok {
			return fmt.Sprintf("Degraded at: %s - %s", refLabel(&hop), findingSummary(f))
		}
		if f, hop, ok := worstUpstreamFinding(t); ok {
			return fmt.Sprintf("Degraded entry: %s - %s", refLabel(&hop), findingSummary(f))
		}
		return "Degraded: " + firstNonEmpty(t.Reason, "a problem was found on the path")
	case VerdictUnknown:
		return "Can't verify: " + firstNonEmpty(t.Reason, "the path can't be verified from declared state alone")
	case VerdictHealthy:
		return healthyHeadline(t)
	}
	return ""
}

// breakFinding picks the finding the headline names. With BrokenAt set it is
// the worst finding on that hop (findings are sorted worst-first), so the
// headline and the marked hop always agree; otherwise it is the primary
// problem anywhere downstream.
func breakFinding(t *Trace) (Finding, ResourceRef, bool) {
	if t.BrokenAt >= 0 && t.BrokenAt < len(t.Downstream) {
		h := t.Downstream[t.BrokenAt]
		for _, f := range h.Findings {
			if f.Severity == SeverityCritical || f.Severity == SeverityWarning {
				return f, h.Resource, true
			}
		}
	}
	return primaryProblemFinding(t)
}

// primaryProblemFinding is the problem the headline names when BrokenAt does
// not settle it. Only critical and warning findings count, and only within
// the branch holding BrokenAt (or from it on), so a sibling route's problem
// is never given as this route's cause; with nothing there, the whole
// downstream. The best candidate is the most severe, then one naming a
// specific object (the root cause, a crashing Pod) over a hop-level symptom,
// then the deeper hop, then code order.
func primaryProblemFinding(t *Trace) (Finding, ResourceRef, bool) {
	type candidate struct {
		f     Finding
		at    ResourceRef
		depth int
	}
	collect := func(from, to int) []candidate {
		var out []candidate
		for i := from; i < to; i++ {
			h := t.Downstream[i]
			for _, f := range h.Findings {
				if f.Severity == SeverityCritical || f.Severity == SeverityWarning {
					out = append(out, candidate{f, h.Resource, i})
				}
			}
		}
		return out
	}
	var cands []candidate
	if b := t.BrokenAt; b >= 0 && b < len(t.Downstream) {
		from, to := b, len(t.Downstream)
		if span, ok := branchContaining(t.Downstream, b); ok {
			from, to = span.start, span.end
		}
		cands = collect(from, to)
	}
	if len(cands) == 0 {
		cands = collect(0, len(t.Downstream))
	}
	if len(cands) == 0 {
		return Finding{}, ResourceRef{}, false
	}
	named := func(c candidate) int {
		if c.f.Resource != nil {
			return 1
		}
		return 0
	}
	best := slices.MinFunc(cands, func(a, b candidate) int {
		return cmp.Or(
			cmp.Compare(severityRank(b.f.Severity), severityRank(a.f.Severity)),
			cmp.Compare(named(b), named(a)),
			cmp.Compare(b.depth, a.depth),
			strings.Compare(a.f.Code, b.f.Code),
		)
	})
	return best.f, best.at, true
}

func worstUpstreamFinding(t *Trace) (Finding, ResourceRef, bool) {
	for _, sev := range []string{SeverityCritical, SeverityWarning} {
		for _, h := range t.Upstreams {
			for _, f := range nonMissingRefFindings(h.Findings) {
				if f.Severity == sev {
					return f, h.Resource, true
				}
			}
		}
	}
	return Finding{}, ResourceRef{}, false
}

// findingSummary is the finding's message, with its cause appended when the
// cause adds something (a Service symptom linked to the crashing pod).
func findingSummary(f Finding) string {
	msg := firstNonEmpty(f.Message, f.Cause)
	if f.Cause != "" && f.Cause != msg {
		msg += " (cause: " + f.Cause + ")"
	}
	return msg
}

func healthyHeadline(t *Trace) string {
	const suffix = " (declared state only; no traffic was sent)"
	switch t.Subject.Kind {
	case "Service":
		for _, h := range t.Downstream {
			if h.Edge == "Service->ExternalName" {
				return fmt.Sprintf("No break found: Service resolves to external host %s, which is not traced further%s", h.Resource.Name, suffix)
			}
			if h.Edge == "Service->Pods" {
				ready, _ := h.Meta["ready"].(int)
				return fmt.Sprintf("No break found: %s has %s%s", refLabel(&t.Subject), plural(ready, "ready endpoint"), suffix)
			}
		}
	case "Ingress", "HTTPRoute", "GRPCRoute":
		n := len(downstreamBranches(t.Downstream))
		if n == 0 {
			return fmt.Sprintf("No break found: %s routes to no backend Service%s", refLabel(&t.Subject), suffix)
		}
		return fmt.Sprintf("No break found: %s reaches ready endpoints on %s%s", refLabel(&t.Subject), plural(n, "backend"), suffix)
	case "Gateway":
		n := len(downstreamBranches(t.Downstream))
		return fmt.Sprintf("No break found: %s has %s attached, none reporting problems%s", refLabel(&t.Subject), plural(n, "route"), suffix)
	}
	return "No break found" + suffix
}

func refLabel(r *ResourceRef) string {
	if r == nil {
		return "the path"
	}
	name := r.Name
	if r.Namespace != "" && r.Name != "" {
		name = r.Namespace + "/" + r.Name
	}
	if r.Kind != "" && name != "" {
		return r.Kind + " " + name
	}
	if r.Kind != "" {
		return r.Kind
	}
	return name
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// plural renders "1 route" / "3 routes".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
