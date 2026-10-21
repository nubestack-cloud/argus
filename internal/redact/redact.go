// Package redact strips secret material out of cluster data at the point the
// agent captures it, before that data crosses the tunnel.
//
// # Where this must be called, and why it is not negotiable
//
// This package exists to implement BACKLOG.md G8 / BUGS.md 84, and the whole
// value of it is *where* it runs. lld/01-threat-model.md's own correction
// banner makes the argument: classification and redaction attach at the point
// evidence is captured — in the agent, before boundary B3 — not later at the
// point of use. A hub-side filter that produced byte-identical output would
// not be the same control, because by the time the hub can act the data has
// already left the customer's cluster, crossed the tunnel, and landed in the
// hub's process memory. "We filter it on read" is how you end up with the
// plaintext copy in analyses.causal_chain that BUGS.md 84 is about.
//
// So: every caller of this package is in internal/agent, on the path between a
// Kubernetes API response and a tunnel write. Do not add a hub-side caller and
// consider the rule satisfied. Do not add a caller that runs when the data is
// rendered.
//
// # Why whole field classes, not pattern matching
//
// The owner's decision (2026-08-24, recorded in BACKLOG.md G8) was to drop
// whole risky field classes structurally, and to treat patterns as a bounded
// second layer for text that has no structure to exploit. Pattern-only was
// rejected for a specific failure mode rather than on taste: it fails open on
// anything unnamed. A connection string with an embedded password in an
// environment variable called DB_URL matches no "password"-ish key name and
// sails straight through. Dropping the class — every literal env value,
// whatever it is called — cannot fail that way.
//
// The two layers, in the order they matter:
//
//  1. Structural (primary). Depth-independent, key-name-driven drops applied to
//     any decoded object: every env[*].value, every data/stringData value, and
//     the kubectl.kubernetes.io/last-applied-configuration annotation. These
//     are field *classes* — the rule does not care what the value looks like.
//  2. Pattern (secondary, bounded). A small fixed set of high-confidence
//     patterns applied to freeform strings — log lines, event and condition
//     messages, container args. These have no structure to exploit, so there is
//     no class to drop; a bounded pattern set is the only available control and
//     is explicitly a backstop, not the primary one.
//
// # Accepted cost — do not optimise this away
//
// ARGUS gets worse at diagnosing "the environment variable holds the wrong
// value" faults. That trade was made deliberately and accepted in writing. If
// a future change appears to need the plaintext value back, the answer is not a
// bypass, a config flag, an allowlist of "safe" variable names, or an
// unredacted path for admins. There is no such flag by design, and adding one
// would reintroduce exactly the defect this package closes.
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Marker replaces every value this package removes.
//
// A marker rather than deleting the key, because the shape is the diagnostic
// signal the owner's decision explicitly preserves. "This container has an env
// var named DATABASE_PASSWORD whose value was set literally rather than via a
// secretKeyRef" is real, useful evidence about how the workload is configured,
// and it is the *shape* — not the bytes — that carries it. Deleting the key
// would leave the model unable to distinguish "set to something we won't show
// you" from "not set at all", which invites it to reason from an absence that
// isn't real (non-negotiable 8's evidence discipline, and the "never render a
// missing value as 0" lesson in the same family).
//
// Deliberately loud and fixed. It is the string an operator greps for in
// analyses.causal_chain to prove the control is live, so it must not be
// spelled several ways or made configurable.
const Marker = "[REDACTED]"

// maxDepth bounds the structural walk.
//
// Not defensive padding: a CustomResource's schema is whatever its author
// says it is, and cluster data is untrusted input (non-negotiable 10). An
// object nested past this depth is replaced wholesale with Marker rather than
// walked, which fails closed — the alternative to a depth cap is either
// unbounded recursion on hostile input or, worse, giving up on the walk and
// passing the object through unredacted.
const maxDepth = 64

// sensitiveKeySuffix matches an ad-hoc key=value or key: value pair in freeform
// text whose KEY implies the value is a credential.
//
// Anchored at the end of the key on purpose. A naive substring match on
// "secret" also matches `--secret-name=payments-db`, redacting a resource name
// that is ordinary diagnostic evidence and no kind of credential. Requiring the
// sensitive word to END the key keeps `--secret-name=` readable while still
// catching `db-password=`, `API_KEY=`, `authToken:` and friends.
//
// The value alternation `(?:Marker|[^\s",;)}\]])+` is what makes this rule —
// and therefore Text — idempotent, and it is not cosmetic. The value's
// character class excludes `]` so a match stops at a JSON/array closer; a bare
// `[^\s",;)}\]]+` therefore matches `[REDACTED` out of an already-marked
// `token=[REDACTED]` and leaves the closing bracket behind, so the rewrite
// emits `token=[REDACTED]]` and grows another `]` on every further pass.
// Allowing a whole Marker as one alternative inside the repetition means an
// already-redacted value is consumed entire and replaced by an identical
// Marker. Quantifying the alternation (rather than putting the Marker in front
// of the class as a prefix) is deliberate: `token=[REDACTED]realsecret` is then
// one match covering both halves, so echoing the marker back cannot be used to
// shield the bytes after it.
//
// This bug was never only about calling Text twice. The specific patterns above
// this rule insert Markers of their own, and this rule runs LAST over their
// output, so `Authorization: Bearer sk-...` came out of a SINGLE pass as
// `Authorization: [REDACTED]]`.
var sensitiveKeySuffix = regexp.MustCompile(
	`(?i)([A-Za-z0-9_.\-]*(?:pass|passwd|password|pwd|secret|token|apikey|api[_\-]?key|credential|credentials|auth|authorization|bearer|access[_\-]?key|secret[_\-]?key|private[_\-]?key|dsn|connection[_\-]?string|sasl[_\-]?password))(\s*[:=]\s*)("?)((?:` + regexp.QuoteMeta(Marker) + `|[^\s",;)}\]])+)`)

// freeformPatterns is the bounded second layer, applied to string values in
// the order listed. Each entry pairs a pattern with its replacement template,
// because some of these must preserve surrounding context to stay diagnostic
// while others replace the whole match.
//
// Bounded is the operative word — this is deliberately NOT a growing regex
// zoo, and it deliberately omits generic high-entropy/base64 detection. A
// "long random-looking string" rule would redact image digests
// (sha256:...), resourceVersions, object UIDs and node names, all of which are
// load-bearing diagnostic evidence, and it would still fail open on anything
// short. Each entry below matches a format that is a credential essentially by
// construction, so a hit is close to certain rather than probabilistic.
//
// **Order is load-bearing, and getting it wrong leaks.** The specific,
// structurally-recognisable formats run FIRST and the generic
// sensitive-key-name heuristic runs LAST. A test caught the reverse: on
// `Authorization: Bearer sk-abc...`, the generic rule matched the key
// "Authorization" with the value "Bearer", replaced the word "Bearer", and left
// the actual token sitting in the string — where the bearer pattern could no
// longer recognise it, because its "bearer" anchor had just been redacted
// away. Any new pattern that consumes a whole credential belongs above the
// generic rule, not below it.
var freeformPatterns = []struct {
	re     *regexp.Regexp
	repl   string
	reason string
}{
	{
		// PEM private key blocks, including the OPENSSH/RSA/EC variants.
		// First because it is the only multi-line match: letting a
		// single-line rule chew on the base64 body would fragment the block
		// and stop this from matching at all.
		re:     regexp.MustCompile(`(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----`),
		repl:   Marker,
		reason: "PEM private key block",
	},
	{
		// An explicit bearer credential in a header-ish string. Above the
		// generic rule for the reason described in this var's doc comment.
		re:     regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}`),
		repl:   Marker,
		reason: "bearer credential",
	},
	{
		// JWTs — three base64url segments. Matched structurally (the leading
		// "eyJ" is a base64 '{"'), so it does not depend on a key name.
		re:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+`),
		repl:   Marker,
		reason: "JWT",
	},
	{
		// AWS access key IDs — a fixed prefix set plus 16 base32 chars.
		re:     regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`),
		repl:   Marker,
		reason: "AWS access key ID",
	},
	{
		// Credentials embedded in a URL's userinfo: scheme://user:password@host.
		// The password half only — the scheme, user and host stay readable,
		// which is usually the diagnostic part ("it is talking to the right
		// host").
		re:     regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+):([^\s@/]+)@`),
		repl:   "${1}:" + Marker + "@",
		reason: "credential in URL userinfo",
	},
	{
		// The generic catch-all, LAST by design. Keeps the key and separator
		// so the reader still learns which setting was redacted.
		re:     sensitiveKeySuffix,
		repl:   "${1}${2}${3}" + Marker,
		reason: "value of a credential-implying key",
	},
}

// Text applies the bounded pattern layer to one freeform string.
//
// This is the layer for data with no structure to exploit: pod log lines,
// Kubernetes event messages, and the condition text detectors copy into
// Finding.Message. There is no field class to drop in a log line — the whole
// line is the payload — so patterns are the only available control here, and
// they are a backstop rather than a guarantee. Callers should not read a
// successful return as "this string is now safe"; they should read it as "the
// formats we can recognise with confidence are gone."
//
// # Idempotent: Text(Text(s)) == Text(s), for every pattern
//
// A caller may redact the same string twice without corrupting it. That is a
// property callers are entitled to rely on and several already do: the hub's
// slog handler (internal/logging) runs this over log text that may already
// carry a Marker applied in the agent, and internal/api's diagnostics bundle
// substitutes known secret values with the Marker and then runs this over the
// result. Neither can know whether it is the first pass, so neither can be
// asked to remember. TestTextIsIdempotent pins it across the whole pattern set
// and fails if a new pattern is added without a case.
func Text(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, p := range freeformPatterns {
		out = p.re.ReplaceAllString(out, p.repl)
	}
	return out
}

// Object applies both layers to one JSON document captured from the cluster.
//
// Fails closed. If the input does not decode, the input is NOT returned —
// there is no path through this function that emits bytes it did not walk.
// That matters more than it looks: a tool returning something this package
// cannot parse is precisely the case where a reviewer's instinct ("just pass it
// through, it's probably fine") reintroduces the defect. Unparseable input
// comes back as a marker object explaining itself, which is a visible,
// debuggable failure instead of a silent leak.
func Object(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return json.RawMessage(`{"redacted":"` + Marker +
			`","reason":"capture-time redaction could not parse this payload, so it was dropped rather than forwarded"}`)
	}
	walked := walk(decoded, 0)
	out, err := json.Marshal(walked)
	if err != nil {
		return json.RawMessage(`{"redacted":"` + Marker +
			`","reason":"capture-time redaction could not re-encode this payload, so it was dropped rather than forwarded"}`)
	}
	return out
}

// droppedAnnotations are annotation keys removed outright rather than marked.
//
// last-applied-configuration is a complete second copy of the object as it was
// submitted — including every env value the structural rules below strip from
// the live spec. Redacting the live fields while forwarding this annotation
// would defeat the entire exercise, which is why BUGS.md 84 names it
// specifically. Dropped whole rather than marked per-field, because the
// annotation's value is JSON-inside-a-string: walking into it would mean
// re-implementing this walk against a different encoding for no diagnostic
// gain (the live object it duplicates is right there, already redacted).
var droppedAnnotations = map[string]bool{
	"kubectl.kubernetes.io/last-applied-configuration": true,
}

// valueBearingKeys are the map keys whose VALUES are dropped as a class,
// keeping the surrounding keys so the shape survives.
//
// data/stringData cover ConfigMap payloads (which routinely hold credentials
// nobody classified as such) and any CRD that borrowed the same convention.
// Keys are kept, values marked: "the config map has no database.url key at
// all" and "it has one whose contents we won't show you" are different
// diagnoses, and the key names are not the secret.
//
// Secret is a narrow, separate exception, added 2026-08-29 (BACKLOG.md
// "still open" #1) and NOT handled by this rule. describe_resource can now
// look up one Secret by name, but internal/agent/tools.go's
// secretMetadataOnly rebuilds the response from nothing but
// metadata/type before it ever reaches this package — a field-level
// omission, deliberately stricter than this rule's usual "keep the key,
// mark the value" behavior. This package never sees a Secret's data/
// stringData at all, marked or otherwise; there is nothing for the rule
// below to do on that path, and it must stay that way — do not "simplify"
// by routing Secret through this generic markValues path instead.
var valueBearingKeys = map[string]bool{
	"data":       true,
	"stringData": true,
}

// walk applies the structural rules to a decoded JSON tree, then the pattern
// layer to whatever strings survive.
//
// Key-name-driven and depth-independent by design. The rules must fire on
// spec.containers[*].env[*].value, and equally on
// spec.template.spec.containers[*].env[*].value in a Deployment,
// spec.jobTemplate.spec.template.spec.containers[*].env[*].value in a CronJob,
// initContainers, and ephemeralContainers. Enumerating those paths is how this
// fix would quietly fail open the first time someone describes a kind whose
// pod template sits somewhere new — a describe_resource on a Deployment
// leaking every env value while the Pod path looked correct in tests. Matching
// on the key wherever it appears cannot drift that way.
func walk(node any, depth int) any {
	if depth > maxDepth {
		return Marker
	}
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			if droppedAnnotations[key] {
				continue
			}
			switch {
			case key == "env":
				out[key] = redactEnvList(child, depth+1)
			case valueBearingKeys[key]:
				out[key] = markValues(child, depth+1)
			default:
				out[key] = walk(child, depth+1)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = walk(child, depth+1)
		}
		return out
	case string:
		return Text(v)
	default:
		// Numbers, bools and nil carry no secret material and no structure to
		// walk. json.Unmarshal into `any` yields float64 for every number, so
		// there is no integer case to handle separately.
		return v
	}
}

// redactEnvList implements the primary rule: drop every literal env value,
// keep name and valueFrom.
//
// valueFrom is preserved deliberately and is the reason this rule costs less
// diagnostic power than it first appears. A secretKeyRef/configMapKeyRef tells
// the investigator where the value comes from — which Secret, which key —
// without ever containing it, and "the env var references a Secret key that
// does not exist" is a fault ARGUS can still diagnose completely after this
// change. What is lost is only the plaintext of a value inlined directly into
// the spec.
func redactEnvList(node any, depth int) any {
	if depth > maxDepth {
		return Marker
	}
	list, ok := node.([]any)
	if !ok {
		// Not the shape we expected. Something else in the tree uses the key
		// "env" for something that is not a container env list — walk it
		// normally rather than assuming, but do not pass it through unwalked.
		return walk(node, depth)
	}
	out := make([]any, len(list))
	for i, entry := range list {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			out[i] = walk(entry, depth+1)
			continue
		}
		redacted := make(map[string]any, len(entryMap))
		for key, child := range entryMap {
			if key == "value" {
				// Marked unconditionally — no inspection of the name, no
				// exemption for values that "look harmless". That
				// unconditionality is the entire point of choosing a
				// structural drop over pattern matching.
				redacted[key] = Marker
				continue
			}
			redacted[key] = walk(child, depth+1)
		}
		out[i] = redacted
	}
	return out
}

// markValues replaces every value in a data/stringData map, keeping its keys.
func markValues(node any, depth int) any {
	if depth > maxDepth {
		return Marker
	}
	m, ok := node.(map[string]any)
	if !ok {
		// A "data" key holding something other than a string map — several
		// CRDs do this. Walk it rather than trusting it.
		return walk(node, depth)
	}
	out := make(map[string]any, len(m))
	for key := range m {
		out[key] = Marker
	}
	return out
}

// ContainsMarker reports whether s carries evidence that redaction fired.
//
// For tests and for the operator-facing verification path, so neither has to
// hardcode the marker string.
func ContainsMarker(s string) bool { return strings.Contains(s, Marker) }

// # AggressiveObject — the unreviewed-kind pass (BACKLOG.md E13)
//
// Object's structural rules are keyed on field NAMES — env, data/stringData,
// last-applied-configuration — because they were written against the shapes
// of the ~30 Kinds internal/agent/tools.go's supportedGVKs actually lists,
// and reviewed there. BACKLOG.md E13 made internal/agent's describe_resource/
// list_resources tools reachable for a kind found only via discovery — an
// arbitrary CRD nobody on this project has ever looked at. Object's rule
// "drop known-risky field classes by name" does not extend to a schema it
// has never seen: a CRD is free to put a credential in any field, under any
// name, at any depth, and there is no field-name list that can promise to
// have named it.
//
// AggressiveObject is the answer for exactly that case: instead of dropping
// named field classes, it keeps a small, fixed ALLOWLIST of identity fields
// (apiVersion, kind, and the handful of metadata fields Kubernetes itself
// gives a fixed, non-free-form shape — see aggressiveIdentityMetadataFields)
// and reduces literally everything else to shape: keys and array lengths
// survive, every leaf scalar (string, number, bool) does not. labels/
// annotations are a deliberate middle case — their KEYS are identity-shaped
// and useful ("this object is labeled team=payments"), but their VALUES are
// exactly as free-form as a spec field, so they get Object's
// keep-key-drop-value treatment rather than either extreme.
//
// This is strictly more aggressive than Object, and it is meant to be:
// AggressiveObject costs real diagnostic power (an unreviewed CRD's status
// becomes "these fields are present" rather than "these fields are present
// and here is what they say") in exchange for a guarantee that does not
// depend on this package's authors having ever reviewed the schema in
// question. See internal/agent/tools.go's describeResource/listResources for
// the caller that decides, per object, whether a kind is "reviewed"
// (supportedGVKs — use Object) or "discovered" (use AggressiveObject
// instead). Secret is never routed through either path via discovery — see
// that file's resolveDescribableResource.
//
// Like Object, this fails closed: unparseable input becomes a marker object,
// never a passthrough of the original bytes.
func AggressiveObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return json.RawMessage(`{"redacted":"` + Marker +
			`","reason":"aggressive redaction could not parse this payload, so it was dropped rather than forwarded"}`)
	}

	var out any
	if m, ok := decoded.(map[string]any); ok {
		top := make(map[string]any, len(m))
		for key, child := range m {
			switch key {
			case "apiVersion", "kind":
				// Plain identity strings this package's callers already treat
				// as safe to log/display everywhere else (e.g. the tunnel's
				// own Finding.GVK) — never free-form, never operator-supplied
				// beyond picking which CRD to install.
				top[key] = child
			case "metadata":
				top[key] = aggressiveMetadata(child)
			default:
				top[key] = aggressiveWalk(child, 1)
			}
		}
		out = top
	} else {
		// Not a JSON object at the top level. A real Kubernetes object
		// always is one; this branch exists so malformed input still fails
		// toward "shape only, no values" rather than being passed through.
		out = aggressiveWalk(decoded, 0)
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage(`{"redacted":"` + Marker +
			`","reason":"aggressive redaction could not re-encode this payload, so it was dropped rather than forwarded"}`)
	}
	return encoded
}

// aggressiveIdentityMetadataFields are the only metadata.* keys
// AggressiveObject keeps the VALUE of. Each one has a shape Kubernetes
// itself fixes (a DNS-1123 name/namespace, a UID, an opaque resourceVersion
// token, an int64 generation, an RFC3339 timestamp) — there is no room in any
// of them for a CRD author to embed arbitrary credential material the way
// there is in a label value, an annotation value, or anything under spec/
// status/data. Deliberately a short, explicit list rather than "everything
// except labels/annotations": a future metadata field this list has not
// named falls through to aggressiveWalk below and loses its value, which is
// the fail-closed direction to err in.
var aggressiveIdentityMetadataFields = map[string]bool{
	"name":              true,
	"namespace":         true,
	"uid":               true,
	"resourceVersion":   true,
	"generation":        true,
	"creationTimestamp": true,
}

// aggressiveMetadata applies AggressiveObject's rules to one object's
// metadata block: aggressiveIdentityMetadataFields pass their values through
// unchanged, labels/annotations keep their keys but not their values (the
// same shape Object's own valueBearingKeys rule uses, for the same reason —
// see that var's doc comment), and anything else (ownerReferences,
// finalizers, managedFields, or a future field this function does not know
// about) is walked with every leaf value dropped, same as spec/status/data
// below.
func aggressiveMetadata(node any) any {
	m, ok := node.(map[string]any)
	if !ok {
		return aggressiveWalk(node, 0)
	}
	out := make(map[string]any, len(m))
	for key, child := range m {
		switch {
		case aggressiveIdentityMetadataFields[key]:
			out[key] = child
		case key == "labels" || key == "annotations":
			out[key] = aggressiveMarkValuesKeepKeys(child)
		default:
			out[key] = aggressiveWalk(child, 1)
		}
	}
	return out
}

// aggressiveMarkValuesKeepKeys is aggressiveMetadata's labels/annotations
// rule, factored out because it is exactly markValues' shape (keep the key,
// drop the value) applied one level higher up the object than Object's own
// valueBearingKeys rule reaches.
func aggressiveMarkValuesKeepKeys(node any) any {
	m, ok := node.(map[string]any)
	if !ok {
		return aggressiveWalk(node, 0)
	}
	out := make(map[string]any, len(m))
	for key := range m {
		out[key] = Marker
	}
	return out
}

// aggressiveWalk is AggressiveObject's default rule for anything outside the
// small identity allowlist above: keep map keys and array structure, replace
// every leaf scalar with Marker. Unlike walk (Object's own recursive rule),
// this never inspects a key name to decide what to do — there is no key name
// this function trusts on an unreviewed schema, which is the entire
// difference between the two passes.
func aggressiveWalk(node any, depth int) any {
	if depth > maxDepth {
		return Marker
	}
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[key] = aggressiveWalk(child, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = aggressiveWalk(child, depth+1)
		}
		return out
	case nil:
		return nil
	default:
		// string, float64 (every JSON number, per encoding/json's decode into
		// `any`), and bool all become Marker uniformly. A bool cannot hold a
		// credential, but treating it differently from string/number would
		// be an inconsistency this function's callers cannot see or rely on,
		// for no real gain.
		return Marker
	}
}
