package knowledge

import (
	"fmt"
	"strconv"
	"strings"
)

// BuildEmbeddedText assembles the exact text this package embeds, per
// DESIGN.md §910: "Resolved incidents — embedding of (symptom, root cause,
// fix, outcome)." A pure function on purpose — every piece of DB-specific
// logic (what counts as "the symptom," how "fix" is rendered, whether
// "outcome" is known yet) lives in store.go's queryEmbeddingInputs, which
// resolves each of the four strings and hands them here already decided.
// That split is what makes this function trivial to unit test against fixed
// fixtures without a database.
//
// Each argument may be empty (an analysis can genuinely lack a root cause —
// see llm.Investigation's partial-result case — or a plan, or a known
// outcome); BuildEmbeddedText renders an honest placeholder for an empty
// argument rather than an empty line, so the embedded text never implies
// "the model looked and found nothing" when what actually happened is "this
// isn't known yet."
func BuildEmbeddedText(symptom, rootCause, fix, outcome string) string {
	symptom = orPlaceholder(symptom, "unknown")
	rootCause = orPlaceholder(rootCause, "not determined")
	fix = orPlaceholder(fix, "no plan (guidance only)")
	outcome = orPlaceholder(outcome, "not yet known")
	return fmt.Sprintf("Symptom: %s\nRoot cause: %s\nFix: %s\nOutcome: %s", symptom, rootCause, fix, outcome)
}

func orPlaceholder(s, placeholder string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return placeholder
	}
	return s
}

// splitObjectKey parses gateway.objectCorrelationKey's `gvk|namespace|name`
// shape — the same format internal/api/tolerations.go's splitObjectKey
// parses, duplicated here as a small private helper rather than imported:
// internal/api imports this package (to trigger embedding after
// PersistAnalysis), so the reverse import would cycle, and this is a
// three-line string split, not a shape worth a shared package for.
func splitObjectKey(key string) (gvk, namespace, name string) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return "", "", key
	}
	return parts[0], parts[1], parts[2]
}

// buildSymptom renders an incident's opening finding as a short, human
// description — the "symptom" component of the embedded text. objectKey may
// be empty (an incident predating that column, or a fleet-group synthetic
// incident with no single object) — degrades to just the reason, or "unknown"
// if that's empty too, rather than producing a string with dangling
// separators.
func buildSymptom(openingReason, objectKey string) string {
	openingReason = strings.TrimSpace(openingReason)
	objectKey = strings.TrimSpace(objectKey)
	if objectKey == "" {
		return openingReason
	}
	_, namespace, name := splitObjectKey(objectKey)
	target := name
	if namespace != "" {
		target = namespace + "/" + name
	}
	if openingReason == "" {
		return target
	}
	return fmt.Sprintf("%s on %s", openingReason, target)
}

// buildFix renders a proposed remediation's action type, target and params
// into the "fix" component, folding in whether it was ever approved when
// that's already known by the time this is called (see the doc comment on
// the caller, queryEmbeddingInputs, for why this is allowed to be stale —
// the same outcome_final re-embed sweep that catches up an incident's
// outcome also catches up its plan's approval state, since in practice an
// incident does not reach a terminal state while its own plan is still
// awaiting a decision).
func buildFix(actionType, targetGVK, targetNamespace, targetName, paramsJSON, verdict string) string {
	if actionType == "" {
		return ""
	}
	target := targetName
	if targetNamespace != "" {
		target = targetNamespace + "/" + targetName
	}
	fix := fmt.Sprintf("%s on %s %s (params: %s)", actionType, targetGVK, target, paramsJSON)
	switch verdict {
	case "approved":
		fix += " — approved"
	case "rejected":
		fix += " — rejected"
	}
	return fix
}

// vectorLiteral renders v in pgvector's own text input format, e.g.
// "[0.1,0.2,0.3]" — passed as a plain string parameter and cast with
// `::vector` in the INSERT itself (store.go), rather than pulling in a
// dedicated pgvector Go driver: retrieval (querying by distance) is the
// deferred half of L2 and needs no Go-side vector type yet, so a driver
// dependency has nothing to earn its place doing here today. strconv's
// shortest round-trippable representation ('f', -1, 32) is used for each
// component so the stored value matches what Ollama returned, not a
// truncated approximation of it.
func vectorLiteral(v []float32) string {
	parts := make([]string, len(v))
	for i, f := range v {
		parts[i] = strconv.FormatFloat(float64(f), 'f', -1, 32)
	}
	return "[" + strings.Join(parts, ",") + "]"
}
