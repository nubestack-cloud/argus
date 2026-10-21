package gitops

import (
	"strconv"

	"gopkg.in/yaml.v3"
)

// BUGS.md 114: a confidence-0.95, AutoApprove-gated OpenPR plan raised a
// readinessProbe's failureThreshold from 1 to 180 to "fix" a Pod that had
// never once passed that probe. That change is provably inert — see the
// package-level reasoning below — and it sailed through the gate because the
// gate asks only whether a change is SAFE to apply, never whether applying it
// accomplishes anything.
//
// This file is the mechanical part of that fix: detecting, from the YAML a
// whole-file OpenPR edit proposes, that a container's readinessProbe
// failureThreshold is being raised. internal/api's inert_readiness_guard.go
// is the other half — deciding, from a LIVE cluster read, whether that
// container has ever actually passed its readiness probe, which is what
// makes the raise inert or not.
//
// # Why this covers ONLY readinessProbe, not livenessProbe
//
// BUGS.md 114's own text bundles "readinessProbe.failureThreshold or
// livenessProbe.failureThreshold" together, but the two do not share the
// property this guard depends on, and applying the same guard to both would
// be wrong, not just imprecise:
//
//   - readinessProbe: a container's Ready condition starts false and stays
//     false until the probe first SUCCEEDS. failureThreshold only governs
//     the transition from an ALREADY-Ready container back to NotReady, so
//     every failure before the first success is absorbed identically
//     regardless of what failureThreshold is set to — raising it while the
//     container has never once succeeded changes nothing observable.
//   - livenessProbe: failureThreshold governs restart-on-failure from the
//     very first probe, with no "first success" gate at all. A container
//     that has never yet passed its liveness probe and is approaching
//     failureThreshold consecutive failures WILL be restarted at that count
//     regardless of readiness history — raising it delays that restart. That
//     is the ordinary, effective (if second-best to a startupProbe) fix for
//     a liveness probe that is too impatient with a slow-starting container.
//
// Refusing a livenessProbe raise on the readinessProbe reasoning would
// therefore block a real, working fix. So this guard is scoped to
// readinessProbe only — narrower than BUGS.md 114's literal wording, and
// deliberately so.
type FailureThresholdRaise struct {
	// ContainerName is the container's own name, matched between the before
	// and after documents — not a positional index, because a whole-file
	// edit is under no obligation to keep containers in the same order.
	ContainerName string
	// OldValue and NewValue are the readinessProbe.failureThreshold values
	// before and after this edit. NewValue is always > OldValue: this type
	// only ever represents a RAISE, never a lowering or an unrelated edit.
	OldValue, NewValue int
}

// DetectReadinessFailureThresholdRaises compares the readinessProbe
// failureThreshold of every same-named container in the document (within
// original/content) that declares object, before and after this edit, and
// reports every container whose value was raised.
//
// Best-effort by design, matching this package's convention for advisory-
// grade checks (see files.go's ApplyFileEdit): a file that is not plain YAML,
// that does not declare object, or that declares it more than once yields no
// result and no error — this function is a detector, not a verifier, and its
// caller treats "found nothing" as "nothing to check" rather than as a
// refusal. The refusal, when there is one, is internal/api's to make, once it
// has also checked whether the raise is inert against live cluster state.
func DetectReadinessFailureThresholdRaises(original, content []byte, object ObjectRef) []FailureThresholdRaise {
	if object.Kind == "" || object.Name == "" {
		// No object identity to anchor the comparison to a single document —
		// e.g. a values.yaml, or a plan whose object could not be resolved.
		// Nothing to compare against nothing.
		return nil
	}
	before := soleMatchingDocument(original, object)
	after := soleMatchingDocument(content, object)
	if before == nil || after == nil {
		return nil
	}

	beforeContainers := findNamedContainers(before)
	afterContainers := findNamedContainers(after)
	if len(beforeContainers) == 0 || len(afterContainers) == 0 {
		return nil
	}

	var raises []FailureThresholdRaise
	for name, afterContainer := range afterContainers {
		beforeContainer, ok := beforeContainers[name]
		if !ok {
			// A container that did not exist before this edit has no "before"
			// value to compare — added, not raised.
			continue
		}
		oldValue, oldOK := readinessFailureThreshold(beforeContainer)
		newValue, newOK := readinessFailureThreshold(afterContainer)
		if oldOK && newOK && newValue > oldValue {
			raises = append(raises, FailureThresholdRaise{ContainerName: name, OldValue: oldValue, NewValue: newValue})
		}
	}
	return raises
}

// soleMatchingDocument parses src and returns the single document matching
// object, or nil if src does not parse, or object is declared zero or more
// than once. Ambiguity is treated the same as "no answer": this is a
// detector deciding whether to run a live check at all, and a live check run
// against the wrong document would be worse than not running one.
func soleMatchingDocument(src []byte, object ObjectRef) *yaml.Node {
	docs, err := parseDocumentsStrict(src)
	if err != nil {
		return nil
	}
	var match *yaml.Node
	for _, d := range docs {
		if documentMatches(d.node, object) {
			if match != nil {
				return nil // declared twice — ambiguous, refuse to pick one
			}
			match = d.node
		}
	}
	return match
}

// findNamedContainers walks doc looking for every "containers:" sequence,
// at any depth, and indexes each entry by its own "name" field.
//
// A recursive, path-agnostic walk rather than a hardcoded
// spec.template.spec.containers (Deployment/StatefulSet/DaemonSet) or
// spec.containers (a bare Pod) or spec.jobTemplate.spec.template.spec.containers
// (CronJob): the whole-file edit grammar this guards does not know or care
// which kind it is looking at, and a container's identity within one object
// is its name regardless of how deep the pod template sits.
func findNamedContainers(doc *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i], n.Content[i+1]
				if key.Value == "containers" && val.Kind == yaml.SequenceNode {
					for _, c := range val.Content {
						if c.Kind != yaml.MappingNode {
							continue
						}
						if name := scalarAt(c, "name"); name != "" {
							out[name] = c
						}
					}
					// containers entries are walked for their name/probe
					// fields above, not recursed into further — a container
					// spec has no nested "containers" key of its own.
					continue
				}
				walk(val)
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c)
			}
		}
	}
	walk(doc)
	return out
}

// readinessFailureThreshold reads container.readinessProbe.failureThreshold as
// an int. ok is false when the container has no readinessProbe, or the field
// is absent, non-scalar, or not an integer — every one of which means there is
// nothing here to compare, not that the value is zero.
func readinessFailureThreshold(container *yaml.Node) (value int, ok bool) {
	probe := mappingValue(container, "readinessProbe")
	if probe == nil {
		return 0, false
	}
	raw := scalarAt(probe, "failureThreshold")
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}
