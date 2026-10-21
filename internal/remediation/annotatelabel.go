package remediation

// annotateResource and labelResource — BACKLOG.md F9's two metadata-only
// action types, built "against the new model" F9's own text asks for: the
// same shape patchfield.go's header argues for at length (a GENERIC
// mechanism — set a key to a value — with an ENUMERATED, reviewed policy
// deciding which keys and which values), not a bespoke action per fault.
//
// # Why these are not just PatchField with a different name
//
// PatchField already carries a generic "set this field path to this value"
// mechanism, and its own allowlist is keyed by dot/bracket notation
// (fieldPathMatches, normaliseFieldPath). Annotation and label KEYS do not
// fit that notation at all: a real key is routinely itself
// "prefix.with.dots/name-with-dashes" (argus.io/incident-id,
// app.kubernetes.io/name), and PatchField's path grammar treats every "."
// as a path separator. Reusing it here would silently mis-split
// "argus.io/incident-id" into segments ["argus", "io/incident-id"], which
// would either falsely deny a legitimate key or — worse — falsely match one
// that was never reviewed. So this file does not extend
// patchFieldAllowlist; it is a second, narrower table keyed directly by
// (GVK, exact key string), with the key never split, dot-normalised, or
// pattern-matched as a path.
//
// # Why the value is constrained too, not just the key
//
// "Any value for an approved key" would still be an arbitrary-write escape
// hatch — the annotation/label VALUE is exactly the kind of thing a
// compromised or prompt-injected model could otherwise use to smuggle
// something. So every entry below also carries either an exact set of
// AllowedValues or a ValuePattern the proposed value must match. There is
// no entry with neither: annotationOrLabelPermitted refuses to match an
// entry that declares no constraint at all (see its own doc comment), which
// is this file's equivalent of patchfield.go's "every path is written out,
// reviewed, and justified in place."
//
// # Why the starter set is this narrow
//
// BACKLOG.md's own evidence table (the fault catalogue, CAPABILITIES.md,
// FAILURE_MODES.md) names no specific finding that wants a particular
// annotation or label value — unlike, say, PatchField's Service/Ingress
// rows, each keyed to a named live-tested fault. So this starter set is
// deliberately provenance/traceability metadata the product itself has an
// obvious use for, rather than a guess at an operational convention nobody
// asked for yet: recording that ARGUS touched an object, when, and for
// which incident. `RestartPod` already sets a comparable provenance
// annotation (`argus.io/restartedAt`, on the pod TEMPLATE) — these two
// action types generalise that same idea to the OBJECT's own metadata,
// under the same `argus.io/` namespace.
//
// Deployment and StatefulSet only, for now: both are already RBAC-patch-
// granted (deploy/helm/argus-agent/templates/clusterrole.yaml's
// remediate.enabled section), so neither action type needs any new RBAC
// verb — the same `patch` that already lands a strategic-merge Patch for
// scale/restart/resource-limits/revert also lands one that touches only
// `metadata.annotations`/`metadata.labels`. Widening to Service/Ingress/
// HPA/PDB/CronJob (patchfield.go's five kinds) is a future row, not a
// structural limit of this mechanism.
//
// # Approval
//
// Both action types are approval-only by construction (risk.go's
// neverAutoApprove), for the identical reason PatchField/StructuredPatch
// are: the value is chosen by whoever authored the plan, not derived from
// the API, so there is always a human judgement in it even though the KEY
// is enumerated and the VALUE is pattern-bounded. Their risk FLOOR is
// separately low (risk.go's baseRiskFloors) — DESIGN.md §9.3 names "add a
// label" verbatim as its low-risk example — which is a genuinely different
// axis: PatchResourceLimits is medium-risk and also manual-only, so "low
// risk" and "never auto-approved" are not in tension for these two either.
import (
	"fmt"
	"regexp"
	"strings"

	"argus/internal/redact"
)

// AnnotateResourceParams is ActionAnnotateResource's typed parameter struct:
// one key and the value to set it to, on the plan's own TargetGVK/
// TargetNamespace/TargetName object.
type AnnotateResourceParams struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (AnnotateResourceParams) actionType() ActionType { return ActionAnnotateResource }

// LabelResourceParams is ActionLabelResource's typed parameter struct — the
// same shape as AnnotateResourceParams, kept as its own named type (rather
// than one struct shared between the two action types) for the identical
// reason RestartPodParams is its own type even though it carries no fields:
// ActionType and the concrete Params type must stay independently,
// mechanically checkable (RemediationPlan.Validate's params/actionType
// mismatch check), which a shared struct would silently defeat.
type LabelResourceParams struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (LabelResourceParams) actionType() ActionType { return ActionLabelResource }

// maxAnnotationOrLabelValueLength bounds a proposed value before any
// allowlist lookup even runs — the same "make a runaway value impossible to
// smuggle through" reasoning PatchFieldParams.Validate's 512-character bound
// carries, applied here identically. A real Kubernetes label value is
// already bounded far below this (63 characters); this is a backstop for
// annotations, which have no such built-in ceiling.
const maxAnnotationOrLabelValueLength = 512

// annotationKeyRE / labelKeyRE are Kubernetes' own qualified-name grammar for
// an annotation/label KEY: an optional "prefix/" (a DNS subdomain) followed
// by a name of alphanumerics, '-', '_', '.', starting and ending
// alphanumeric. Both maps share this exact grammar in real Kubernetes; two
// constants rather than one only so a future divergence (there is none
// today) does not require renaming a shared identifier.
var (
	annotationKeyRE = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	labelKeyRE      = annotationKeyRE
)

// labelValueRE is Kubernetes' own label VALUE grammar — empty, or
// alphanumeric-bounded with '-', '_', '.' in the middle, at most 63
// characters. Annotation values carry no equivalent built-in shape (a
// annotation value is an arbitrary string up to
// maxAnnotationOrLabelValueLength), which is why this bound is declared only
// once, for labels.
var labelValueRE = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)

// validateKeyValueShape is the generic, allowlist-independent bound both
// params types share: a well-formed key, a non-empty value within the
// length bound, no newline (an annotation/label value is a single scalar,
// never a multi-line blob — the newline check mirrors PatchFieldParams.
// Validate's identical reasoning for NewValue), and no echo of
// redact.Marker (BUGS.md 112's guard, carried here for the same
// defense-in-depth reason PatchFieldParams.Validate keeps it even though no
// entry in this file's own allowlist reaches a redacted field class today:
// a future entry might, and this guard costs nothing to keep unconditional).
func validateKeyValueShape(keyRE *regexp.Regexp, key, value string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("key is required")
	}
	if !keyRE.MatchString(key) {
		return fmt.Errorf("key %q is not a well-formed Kubernetes annotation/label key (optional \"prefix/\" DNS subdomain, then alphanumerics/-/_/. starting and ending alphanumeric)", key)
	}
	if strings.TrimSpace(value) == "" {
		// Matching PatchFieldParams.Validate's own reasoning: an empty string
		// and an absent key are different states, and this action sets a
		// value — it cannot express "clear/remove this key". Requiring a
		// non-empty value keeps that honest rather than silently treating an
		// empty string as a deletion nobody asked for.
		return fmt.Errorf("value is required — this action sets a value and cannot clear a key")
	}
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("value spans more than one line")
	}
	if len(value) > maxAnnotationOrLabelValueLength {
		return fmt.Errorf("value is %d characters, longer than any value this action sets (max %d)", len(value), maxAnnotationOrLabelValueLength)
	}
	if strings.Contains(value, redact.Marker) {
		return fmt.Errorf("%w: value contains %q — this value was withheld from the model at capture time (internal/redact), so the model has no basis to know or reproduce it; a human must supply the real value, not the marker that stood in for it", ErrNewValueEchoesRedactionMarker, redact.Marker)
	}
	return nil
}

// Validate checks the shape any AnnotateResource plan must satisfy on its
// own, independent of TargetGVK — the (GVK, key) permission and the
// value-pattern check both need the target kind, which is not available
// here, and live in AnnotationPermitted, called from
// RemediationPlan.Validate.
func (p AnnotateResourceParams) Validate() error {
	return validateKeyValueShape(annotationKeyRE, p.Key, p.Value)
}

// Validate is LabelResourceParams' own shape check — see
// AnnotateResourceParams.Validate's doc comment; the only difference is the
// key regex (identical today, kept separate per this file's own header) and
// the additional Kubernetes label-VALUE shape bound, which annotations do
// not carry.
func (p LabelResourceParams) Validate() error {
	if err := validateKeyValueShape(labelKeyRE, p.Key, p.Value); err != nil {
		return err
	}
	if !labelValueRE.MatchString(p.Value) {
		return fmt.Errorf("value %q is not a well-formed Kubernetes label value (at most 63 characters, alphanumeric with -/_/. in the middle, starting and ending alphanumeric)", p.Value)
	}
	return nil
}

// metadataAllowlistEntry is one row of either table below.
type metadataAllowlistEntry struct {
	// GVK is the exact target kind, matching patchableField.GVK's own
	// reasoning: not a prefix, not a wildcard.
	GVK string
	// Key is the exact annotation/label key this row authorises — the whole
	// key, never split or pattern-matched, for the reason this file's header
	// comment gives.
	Key string
	// Risk is this key's floor, matching patchableField.Risk's per-field
	// reasoning: an incident-id marker and a "needs review" triage label are
	// not necessarily the same blast radius, even though both are low today.
	Risk RiskLevel
	// AllowedValues, when non-empty, is the exact closed set of values this
	// key may be set to. Mutually exclusive with ValuePattern in practice
	// (an entry uses one or the other) — both are checked when both happen to
	// be set, which is stricter, never looser.
	AllowedValues []string
	// ValuePattern, when non-nil, is the regular expression a proposed value
	// must match. Used instead of AllowedValues for values with a real shape
	// (a timestamp, an incident ID) rather than a small closed set.
	ValuePattern *regexp.Regexp
	// Why is the reviewed justification — required by this package's own
	// test, matching patchfield.go's identical requirement.
	Why string
}

// incidentIDPattern matches domain.NewID(domain.PrefixAnalysis)-style IDs —
// "inc_" followed by the ULID-ish alphanumeric body this codebase already
// generates (internal/domain.NewID) — bounding the value to something that
// is structurally an incident ID rather than an arbitrary string typed into
// the same field.
var incidentIDPattern = regexp.MustCompile(`^inc_[0-9A-Za-z]{1,40}$`)

// rfc3339Pattern is a permissive but real bound on an RFC 3339 timestamp
// (the shape time.Time.Format(time.RFC3339) produces) — permissive because
// this is a backstop against garbage, not a full RFC 3339 validator; a value
// this loose already rules out anything that is obviously not a timestamp.
var rfc3339Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

// annotateAllowlist is AnnotateResource's enumerated permission set — see
// this file's header comment for why it is this narrow, and why the values
// are constrained rather than free text.
var annotateAllowlist = []metadataAllowlistEntry{
	{
		GVK: "apps/v1/Deployment", Key: "argus.io/last-remediated-at", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Provenance: records when ARGUS last changed this workload, in the same argus.io/ namespace " +
			"RestartPod already uses for its own rollout-restart annotation (on the pod template, not the " +
			"object — this is the object-level equivalent). Lets an operator or a future rule ask \"has " +
			"ARGUS touched this recently\" without scanning the audit log.",
	},
	{
		GVK: "apps/v1/StatefulSet", Key: "argus.io/last-remediated-at", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Same provenance marker as the Deployment row above, for a StatefulSet.",
	},
	{
		GVK: "apps/v1/Deployment", Key: "argus.io/incident-id", Risk: RiskLow, ValuePattern: incidentIDPattern,
		Why: "Correlates the object with the incident that caused a remediation — discoverable with a " +
			"plain kubectl get -o jsonpath, without granting ARGUS any new read it didn't already have.",
	},
	{
		GVK: "apps/v1/StatefulSet", Key: "argus.io/incident-id", Risk: RiskLow, ValuePattern: incidentIDPattern,
		Why: "Same correlation marker as the Deployment row above, for a StatefulSet.",
	},
	// GitOps quick actions (docs/CLUSTER_INSIGHT_SPECS.md CI-S15). Each asks a
	// controller to act now and changes no desired state, so it is compatible
	// with the GitOps rule (non-negotiable 5): the result is whatever Git
	// already says.
	{
		GVK: "argoproj.io/v1alpha1/Application", Key: "argocd.argoproj.io/refresh", Risk: RiskLow, AllowedValues: []string{"normal", "hard"},
		Why: "Asks Argo CD to re-read the Application's source now (hard also re-renders its manifests) " +
			"instead of waiting for the next poll — confirms a merged fix without changing what is deployed.",
	},
	{
		GVK: "kustomize.toolkit.fluxcd.io/v1/Kustomization", Key: "reconcile.fluxcd.io/requestedAt", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Asks Flux to reconcile a Flux Kustomization now, the same request `flux reconcile` makes; desired state is unchanged.",
	},
	{
		GVK: "helm.toolkit.fluxcd.io/v2/HelmRelease", Key: "reconcile.fluxcd.io/requestedAt", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Asks Flux to reconcile a Flux HelmRelease now, the same request `flux reconcile` makes; desired state is unchanged.",
	},
	{
		GVK: "source.toolkit.fluxcd.io/v1/GitRepository", Key: "reconcile.fluxcd.io/requestedAt", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Asks Flux to reconcile a Flux GitRepository now, the same request `flux reconcile` makes; desired state is unchanged.",
	},
	{
		GVK: "source.toolkit.fluxcd.io/v1/HelmRepository", Key: "reconcile.fluxcd.io/requestedAt", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Asks Flux to reconcile a Flux HelmRepository now, the same request `flux reconcile` makes; desired state is unchanged.",
	},
	{
		GVK: "source.toolkit.fluxcd.io/v1beta2/OCIRepository", Key: "reconcile.fluxcd.io/requestedAt", Risk: RiskLow, ValuePattern: rfc3339Pattern,
		Why: "Asks Flux to reconcile a Flux OCIRepository now, the same request `flux reconcile` makes; desired state is unchanged.",
	},
}

// labelAllowlist is LabelResource's enumerated permission set.
//
// Deliberately a boolean marker rather than the richer provenance data the
// annotation rows above carry: a Kubernetes label VALUE has its own strict
// syntax (63 characters, no colons, no slashes — labelValueRE above), which
// an incident ID or a timestamp fits awkwardly at best. A label's actual
// value is what makes it useful for selection (`kubectl get deploy -l
// argus.io/remediated=true`), which a fixed AllowedValues set of exactly
// one value serves better than a pattern would.
var labelAllowlist = []metadataAllowlistEntry{
	{
		GVK: "apps/v1/Deployment", Key: "argus.io/remediated", Risk: RiskLow, AllowedValues: []string{"true"},
		Why: "A selectable marker: `kubectl get deploy -l argus.io/remediated=true` finds everything " +
			"ARGUS has touched, without needing the richer (but not selector-friendly) provenance data " +
			"the annotation rows above carry.",
	},
	{
		GVK: "apps/v1/StatefulSet", Key: "argus.io/remediated", Risk: RiskLow, AllowedValues: []string{"true"},
		Why: "Same selectable marker as the Deployment row above, for a StatefulSet.",
	},
}

// valueAllowed reports whether value satisfies entry's own constraint. An
// entry with neither AllowedValues nor ValuePattern set never matches
// anything — see annotationOrLabelPermitted's doc comment for why that is
// deliberate rather than a bug waiting to be hit. Matches AllowedValues's own
// doc comment: when only one of AllowedValues/ValuePattern is set, that one
// alone decides; when BOTH are set, value must satisfy both — stricter, never
// looser, never a future entry silently widened to "either constraint will
// do" by an OR.
func (e metadataAllowlistEntry) valueAllowed(value string) bool {
	if len(e.AllowedValues) == 0 && e.ValuePattern == nil {
		return false
	}
	if len(e.AllowedValues) > 0 {
		matched := false
		for _, allowed := range e.AllowedValues {
			if value == allowed {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if e.ValuePattern != nil && !e.ValuePattern.MatchString(value) {
		return false
	}
	return true
}

// annotationOrLabelPermitted is the shared lookup AnnotationPermitted/
// LabelPermitted below both call — one table format, one matching function,
// so the two action types cannot silently diverge in HOW a row is matched
// (only in WHICH table they read).
//
// An entry with neither AllowedValues nor ValuePattern is refused for ANY
// value, not treated as "any value permitted" — the mirror image of
// patchfield.go's own "every path is written out, reviewed, and justified":
// an unconstrained entry would be exactly the arbitrary-write escape hatch
// this mechanism exists to avoid, so this function itself makes one
// impossible to use even if a future edit accidentally added one.
func annotationOrLabelPermitted(table []metadataAllowlistEntry, kind, gvk, key, value string) (metadataAllowlistEntry, error) {
	for _, entry := range table {
		if entry.GVK != gvk || entry.Key != key {
			continue
		}
		if len(entry.AllowedValues) == 0 && entry.ValuePattern == nil {
			return metadataAllowlistEntry{}, fmt.Errorf("%s %q on %s declares no value constraint — refusing to treat an unconstrained entry as \"any value permitted\" (internal/remediation/annotatelabel.go)", kind, key, gvk)
		}
		if !entry.valueAllowed(value) {
			return metadataAllowlistEntry{}, fmt.Errorf("%q is not a permitted value for %s %q on %s — this is a permission decision, not a missing feature: the allowed values/pattern are enumerated in internal/remediation/annotatelabel.go", value, kind, key, gvk)
		}
		return entry, nil
	}
	return metadataAllowlistEntry{}, fmt.Errorf("%s may not set %s %q on %s — that pair is not in the reviewed allowlist (internal/remediation/annotatelabel.go). This is a permission decision, not a missing feature: the allowlist is enumerated so the cluster-side admission policy can enumerate the same set", kind, kind, key, gvk)
}

// AnnotationPermitted reports whether gvk may have annotation key set to
// value by an AnnotateResource plan, and at what risk floor.
func AnnotationPermitted(gvk, key, value string) (metadataAllowlistEntry, error) {
	return annotationOrLabelPermitted(annotateAllowlist, "annotation", gvk, key, value)
}

// LabelPermitted reports whether gvk may have label key set to value by a
// LabelResource plan, and at what risk floor.
func LabelPermitted(gvk, key, value string) (metadataAllowlistEntry, error) {
	return annotationOrLabelPermitted(labelAllowlist, "label", gvk, key, value)
}

// AnnotateAllowlistEntries / LabelAllowlistEntries expose the two tables for
// tests and for a future admission-policy generator, matching
// PatchFieldAllowlistEntries' own reasoning: the permitted set should never
// be transcribed by hand into a second place.
func AnnotateAllowlistEntries() []metadataAllowlistEntry {
	out := make([]metadataAllowlistEntry, len(annotateAllowlist))
	copy(out, annotateAllowlist)
	return out
}

func LabelAllowlistEntries() []metadataAllowlistEntry {
	out := make([]metadataAllowlistEntry, len(labelAllowlist))
	copy(out, labelAllowlist)
	return out
}
