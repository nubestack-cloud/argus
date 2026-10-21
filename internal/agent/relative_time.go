package agent

import "time"

// This file is the fix for BUGS.md 105 / BACKLOG.md C9: a real, freshly-issued
// cert-manager Certificate whose status.renewalTime was ~41 minutes in the
// FUTURE (relative to the analysis's own createdAt) was investigated and
// confidently (0.75) reported as having a renewal time that "passed over 30
// minutes ago" — the exact opposite of the truth, because the model had to do
// its own date arithmetic on two raw RFC3339 strings in its own reasoning and
// got the sign backwards. It then built an entire fabricated "stalled
// controller" root cause on top of that false premise and proposed a real,
// non-reversible RestartPod against the cluster's shared cert-manager pod.
//
// The chosen fix (BACKLOG.md C9's option (a), not the narrower per-rule
// option (b)): never let the model compute "how long until/since this" for
// itself. Any tool result carrying a raw RFC3339 timestamp the investigation
// might reason "relative to now" about gets an ALREADY-COMPUTED, signed
// second count alongside it, worked out here, server-side, at the exact
// moment the tool result is built (time.Now(), never a value the model could
// supply or influence) — so the model reads a signed number instead of
// subtracting two ISO-8601 strings itself. This fixes the general class (the
// next timestamp-bearing field needs one new map entry below, not a new code
// path), not just certificate-expiry-imminent's own renewalTime/notAfter.

// relativeTimeFieldPolicy names every RFC3339-timestamp-bearing JSON field
// this package's tool results know to annotate, and which direction the
// model should read it in. Kubernetes has no consistent naming convention for
// "this is a timestamp" (Time/Timestamp suffixes both appear, and plenty of
// fields carry neither), so this is matched by literal key, not a suffix
// heuristic — deliberately explicit over deliberately clever, the same
// tradeoff supportedGVKs above already makes for which Kinds this package
// will operate on at all.
//
//   - "until": the field is conventionally FUTURE-facing (a renewal or expiry
//     time) — secondsUntil is positive while it's still ahead of now, and
//     negative once it's already passed. This is exactly the reading the
//     model got backwards in BUGS.md 105.
//   - "since": the field is conventionally PAST-facing (a creation,
//     transition or deletion mark) — secondsSince is positive once it has
//     happened, and negative would mean "this is actually still in the
//     future", which the model should treat as suspicious (clock skew, a
//     server default, bad data) rather than silently normalize away.
//
// Adding coverage for a new field anywhere in this package's tool surface is
// one line here: annotateRelativeTimestamps (describe_resource's generic
// path) and the two typed call sites (get_events' LastTimestamp,
// list_resources' CreationTimestamp) all read this same table, so there is
// exactly one place a future field gets registered, never a per-tool
// decision to remember to add it.
var relativeTimeFieldPolicy = map[string]string{
	// cert-manager Certificate.status — the exact fields BUGS.md 105 was
	// about. renewalTime/notAfter are when something is DUE; notBefore is
	// when the certificate's validity period started, which has already
	// happened for any Certificate actually in use.
	"renewalTime": relativeUntil,
	"notAfter":    relativeUntil,
	"notBefore":   relativeSince,

	// Any object's own metadata, and any status.conditions[] entry — the
	// deletionTimestamp/lastTransitionTime shape rules.go's own
	// "*-stuck-terminating" rules already reason about server-side (see
	// evaluateCondition's field-vs-field comparators), and creationTimestamp
	// is on every object this package ever returns.
	"creationTimestamp":  relativeSince,
	"deletionTimestamp":  relativeSince,
	"lastTransitionTime": relativeSince,
	"lastProbeTime":      relativeSince,
	"lastHeartbeatTime":  relativeSince,

	// Event (get_events) and its optional series sub-object.
	"lastTimestamp":    relativeSince,
	"firstTimestamp":   relativeSince,
	"lastObservedTime": relativeSince,

	// Pod/Job status.
	"startTime":      relativeSince,
	"completionTime": relativeSince,
}

const (
	relativeUntil = "until"
	relativeSince = "since"
)

// secondsUntil/secondsSince are this package's one shared definition of "how
// far a timestamp is from now" — every computed relative value anywhere in
// this file (get_events' LastTimestampSecondsSince, list_resources'
// CreationTimestampSecondsSince, describe_resource's generic per-field
// annotation) is built from one of these two, truncating toward zero at
// whole seconds, so there is exactly one place that decides the sign
// convention and no way for two call sites — or a future third one — to
// quietly disagree. A timestamp that falls in the same second as now yields
// exactly 0 from either function: neither future nor past, the boundary
// BACKLOG.md C9 asks to be tested explicitly.
func secondsUntil(t, now time.Time) int64 { return int64(t.Sub(now).Seconds()) }
func secondsSince(t, now time.Time) int64 { return int64(now.Sub(t).Seconds()) }

// annotateRelativeTimestamps walks an arbitrary decoded-JSON value — the same
// map[string]any/[]any/scalar tree unstructured.Unstructured.Object already
// is — and, for every map key found in relativeTimeFieldPolicy whose value is
// an RFC3339-parseable string, injects a sibling "<key>SecondsUntil" or
// "<key>SecondsSince" key holding the signed integer second count, computed
// against `now` (the caller's single snapshot of time.Now() for this whole
// tool call, not re-read per field — so every field annotated by one call
// agrees on what "now" meant). A value that is not a recognized field, is not
// a string, or does not parse as RFC3339 is left exactly as it was: this
// function only ever ADDS a sibling key, never rewrites or removes the raw
// timestamp the model can still read for itself.
//
// Mutates and returns the same structure in place, matching
// unstructured.Unstructured's own convention of a mutable map[string]any
// tree — safe here because every caller (describeResource) owns a
// freshly-fetched object nothing else retains a reference to.
func annotateRelativeTimestamps(now time.Time, v any) any {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if dir, ok := relativeTimeFieldPolicy[k]; ok {
				if s, ok := child.(string); ok {
					if t, err := time.Parse(time.RFC3339, s); err == nil {
						switch dir {
						case relativeUntil:
							val[k+"SecondsUntil"] = secondsUntil(t, now)
						case relativeSince:
							val[k+"SecondsSince"] = secondsSince(t, now)
						}
					}
				}
			}
			val[k] = annotateRelativeTimestamps(now, child)
		}
		return val
	case []any:
		for i, item := range val {
			val[i] = annotateRelativeTimestamps(now, item)
		}
		return val
	default:
		return v
	}
}
