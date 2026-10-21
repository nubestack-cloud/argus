package agent

// This file is BACKLOG.md E9: a declarative rule format for the common
// detection shapes, evaluated by a generic engine, ALONGSIDE — not instead
// of — the 17 hand-written Go checkers in sweep_detector.go (BACKLOG.md item
// #6, 2026-08-29, added checkOrphanedPVC/checkIngressHostPathCollision to the
// prior 13) and the one
// CRD-backed checker in syncfailure.go. Those stay exactly as they are; this
// is a fourth, additive mechanism feeding the SAME sweep loop.
//
// # Scope, and what this deliberately is NOT
//
// This is NOT lld/06-detection-framework.md §3's fuller Detector plugin
// interface (a shared-watch registry fanning one watch out to many
// Evaluate() calls) — that is P4, deliberately deferred, a different and
// unrelated refactor about *who shares a watch*, not *who can add a
// detector*. This is also NOT a general expression language: RuleCondition
// below is a small, closed set of shapes, chosen because they cover the
// common catalogue patterns STATUS.md/BACKLOG.md name — "field X != field Y,
// sustained N minutes", "this points at nothing", "this field is missing
// entirely", and "every object in this set agrees on a value" — without
// growing into a programming language a rule author could use to express
// something as subtle as checkReplicaFailure's owner-suppression logic. A
// condition that needs more than these shapes belongs in Go, exactly as
// BACKLOG.md's E9 entry says: "the 13 existing Go checkers stay in Go —
// several are subtle enough that re-expressing them would grow the rule
// language into a programming language."
//
// # BACKLOG.md E10: two more shapes, added 2026-09-01
//
// E9's original five comparators (eq/ne/lt/lte/gt/gte, expiresWithin,
// selectorMatchesNoPods) all answer "what does THIS object's own field say".
// E10's review of the issue catalogue's remaining dark territory found two
// more genuinely distinct predicate KINDS neither of those five shapes can
// express, and both are added here rather than left to Go, because — unlike
// E10's other four still-open rows (see BACKLOG.md's E10 entry for the full,
// honest accounting of which of those turned out to already be covered, and
// which genuinely aren't) — both fit this file's existing per-object sweep
// loop with no new bookkeeping:
//
//   - "notPresent" (field-compare mode, no Value/CompareField): fires when
//     Field is ABSENT from the object entirely, the exact inverse of every
//     other field-compare comparator's existing "not found → never a match"
//     tolerance. This is E10's "posture audit of a healthy object" kind —
//     issue-catalog AP1/JOB-003 ("Job hangs forever, no
//     spec.activeDeadlineSeconds"), live-confirmed as a real, currently
//     invisible fault in CAPABILITIES.md §6bi before this rule existed: no
//     Warning event, no failed condition, nothing wrong in status at any
//     moment — the fault is a missing SPEC field, which is a fundamentally
//     different shape from every other rule in this file, all of which fire
//     on a value that IS present and IS wrong.
//
//   - "allPodsSameValue" (a third mode: SelectorField + AggregateField, no
//     Field/CompareField/Value/PerMapKey): SelectorField names a
//     metav1.LabelSelector-shaped field (the same convention selector mode
//     already uses), which is resolved to the object's own live Pods, exactly
//     like selectorMatchesNoPods already does; AggregateField is then read
//     off EACH of those Pods (not the primary object) and the condition
//     matches when at least two Pods were found and every one of them has
//     the identical value there. This is E10's "a property of a SET of
//     objects" kind — issue-catalog AV1/DEPL-019 ("every replica on one
//     node": AggregateField "spec.nodeName"), live-confirmed the same way in
//     CAPABILITIES.md §6bm. No per-object predicate, however thorough, can
//     see this: it is a relationship that exists only ACROSS the set, not
//     within any one Pod's own fields — which is exactly why it needs its own
//     mode rather than fitting inside field-compare's existing shape.
//
// Deliberately NOT built as part of this same pass, with the reasoning kept
// in BACKLOG.md's E10 entry rather than repeated here: a genuine AND-of-
// conditions primitive (needed for E10's "control loop flat against its own
// boundary" kind, HPA-006/AS1) and anything that would need indexing into an
// array field by a sub-key (e.g. status.currentMetrics[type=Resource], or
// DEPL-024's own per-CONTAINER readinessProbe) — both real, larger extensions
// this pass explicitly left unbuilt rather than forcing a bad fit.
//
// # Output contract
//
// A firing rule becomes exactly the same sweepCandidate shape the hand-written
// checkers already produce (see evaluateRule below) — never a second output
// shape — so it flows through runOneSweep's existing
// recordSweepCandidates/sustainedLongEnough/sendSweepFinding pipeline
// unmodified: same fingerprint algorithm (candidateFingerprint), same
// firstObserved/lastSent bookkeeping, same cooldown. A rule's condition
// becoming true is observed by this detector exactly like a hand-written
// checker's condition becoming true — there is deliberately no per-rule
// sustain duration or per-rule bookkeeping; every rule uses the ONE
// sustainedThreshold and ONE firstObserved map runSweepDetector already
// carries, because building a second bookkeeping system per rule is exactly
// the kind of scope creep this task was told not to do (a rule-level
// RemediationPolicy-ish CRD is S4, and S4 explicitly defers to this file).
//
// # Where rules come from
//
// Agent-local config, not a hub-pushed list. internal/tunnel/protocol.go's
// own doc comment says so explicitly as of this writing ("ExecutionPlan/
// ConfigUpdate ... still have nothing to carry — no remediation layer exists
// in this repo yet" — re-read there was true when checked for this change,
// confirmed by grepping ServerMessage/ClientMessage for anything resembling a
// config-push field: there is none). That matches how the sweep detector's
// own two timing knobs already work (Config.SweepInterval/
// SweepSustainedThreshold: agent-side, env-configured, restart-required) —
// same reasoning applies here even more strongly, since a spoke that has
// lost contact with the hub must keep detecting on its LAST KNOWN rules, not
// wait to be told new ones. Building a hub-push channel is real, separate,
// larger work and is deliberately out of scope here.
//
// LoadRules resolves a rule set from (in order): an explicit file path
// (Config.DetectionRulesPath, ARGUS_DETECTION_RULES_FILE) if set, else the
// default set embedded in the binary at build time (defaultRulesYAML below)
// — so every agent ships with SOME rule coverage out of the box, and an
// operator who wants to add/replace rules can point at their own file
// without a rebuild.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"argus/internal/agent/posture"
	"argus/internal/tunnel"

	_ "embed"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"gopkg.in/yaml.v3"
)

//go:embed rules/default-rules.yaml
var defaultRulesYAML []byte

// Rule is one declarative detection rule — the Go type (and, via the tags
// below, its YAML/JSON encoding) BACKLOG.md E9 asks for. GVK uses exactly the
// same "[group/]version/Kind" wire string sweepCandidate.GVK and
// parseGVKString already use elsewhere in this package (tools.go), so a
// rule's GVK is not a third convention to learn.
type Rule struct {
	// ID names this rule for logs and for candidateFingerprint's dedup key
	// (via Reason, not ID directly — see evaluateRule). Required and must be
	// unique within a loaded set; LoadRules rejects a duplicate rather than
	// silently shadowing one rule with another.
	ID string `yaml:"id" json:"id"`

	// GVK is the object kind this rule watches, in the same
	// "[group/]version/Kind" form as sweepCandidate.GVK (e.g.
	// "policy/v1/PodDisruptionBudget", "v1/ResourceQuota"). Must already be a
	// key in tools.go's supportedGVKs — LoadRules validates this at load
	// time, not at first evaluation, so a misconfigured rule fails the agent's
	// startup log loudly instead of silently never firing.
	GVK string `yaml:"gvk" json:"gvk"`

	// Reason is this rule's Finding.Reason — the same field every
	// hand-written checker's reasonXxx constant fills, and what
	// candidateFingerprint keys on alongside namespace/kind/name. Required.
	Reason string `yaml:"reason" json:"reason"`

	// Severity is one of "low"|"medium"|"high"|"critical" — validated against
	// validRuleSeverities at load time.
	Severity string `yaml:"severity" json:"severity"`

	// Class states whether a matching rule proves an active fault or identifies
	// a configuration risk. It is declarative policy, not a Kind switch in the
	// gateway. An omitted class is an anomaly and therefore remains visible as
	// a Finding without opening an Incident.
	Class string `yaml:"class,omitempty" json:"class,omitempty"`

	// Message is a text/template string rendered against ruleTemplateData
	// once per firing object. Kept deliberately small (five fields — see
	// ruleTemplateData) rather than exposing the whole unstructured object to
	// the template, so a rule author cannot accidentally template in a field
	// this repo's redaction discipline would have stripped from a Finding.Message
	// built any other way (internal/redact's pattern layer still runs over the
	// rendered string before it leaves the agent, same as every other
	// detector's Message — see internal/agent/client.go's tunnel writer).
	Message string `yaml:"message" json:"message"`

	// Condition is the one shape this rule evaluates. See RuleCondition.
	Condition RuleCondition `yaml:"condition" json:"condition"`
}

// RuleCondition is the closed set of shapes evaluateCondition knows how to
// evaluate. Exactly one of the three "modes" below applies to a given
// condition, decided by which fields are set:
//
//   - Field-compare mode (Field is set, SelectorField/AggregateField are
//     not): read Field (a dot path into the object's JSON —
//     "status.disruptionsAllowed") and compare it against either Value (a
//     literal) or, when PerMapKey is true, every key CompareField shares
//     with it (both must then be string-keyed maps of scalar values), or —
//     comparator "notPresent" only, added for BACKLOG.md E10 — against
//     nothing at all: it fires when Field is ABSENT, the inverse of every
//     other comparator's "not found → never a match" tolerance. This is the
//     backlog's "field X != field Y, sustained N minutes" shape, generalized
//     to also cover "field X == literal", "map A's values vs map B's, per
//     key", and now "field X is missing entirely" (E10's "posture audit of a
//     healthy object" kind — see this file's package doc).
//
//   - Selector mode (SelectorField is set, AggregateField is not):
//     SelectorField names a metav1.LabelSelector-shaped field on the object
//     (e.g. NetworkPolicy's spec.podSelector). The only comparator this mode
//     supports today is "selectorMatchesNoPods" — the backlog's "this points
//     at nothing" shape. A deliberately empty selector (selects every pod in
//     the namespace — a common, intentional "apply to everything" policy) is
//     skipped, never flagged.
//
//   - Set-aggregate mode (SelectorField AND AggregateField are both set) —
//     added for BACKLOG.md E10's "a property of a SET of objects" kind (see
//     this file's package doc). SelectorField resolves to the object's own
//     live Pods exactly as selector mode does; AggregateField (a dot path,
//     same convention as Field, but read off each MATCHED POD rather than
//     the primary object) is then compared ACROSS that whole set. The only
//     comparator this mode supports today is "allPodsSameValue": matches
//     when at least two Pods were found and every one shares the identical
//     value at AggregateField.
//
// Comparator is always required; which other fields are required depends on
// it — see validateRule.
type RuleCondition struct {
	Field        string `yaml:"field,omitempty" json:"field,omitempty"`
	CompareField string `yaml:"compareField,omitempty" json:"compareField,omitempty"`
	PerMapKey    bool   `yaml:"perMapKey,omitempty" json:"perMapKey,omitempty"`
	Value        string `yaml:"value,omitempty" json:"value,omitempty"`

	// AbsentFieldMeansZero is BUGS.md 129's fix: an explicit, opt-in,
	// per-rule assertion that Field (and, symmetrically, CompareField when
	// the condition compares against one) is a plain numeric Kubernetes
	// status field tagged `json:",omitempty"` on its Go type, where the API
	// server's own JSON serialization omits the field the instant its real
	// value is exactly zero — so "absent from this object" and "present and
	// zero" are the SAME real-world state for this specific field, on this
	// specific rule. apps/v1 DaemonSetStatus.UpdatedNumberScheduled and
	// DeploymentStatus/StatefulSetStatus.UpdatedReplicas are exactly this
	// shape (confirmed against k8s.io/api/apps/v1 itself, not assumed) —
	// which is why daemonset-rollout-stalled, statefulset-rollout-stalled
	// and deployment-rollout-stalled set this to true in
	// rules/default-rules.yaml, and is also exactly why this is a field on
	// RuleCondition rather than a change to evaluateCondition's default
	// behavior: a bare "not found" is deliberately left meaning "does not
	// match" for every other comparator on every other rule (a string
	// field, a boolean, a ResourceQuota's status.used map where a missing
	// KEY is a different claim than a zero one — see PerMapKey below), and
	// BUGS.md 129 explicitly warns against widening that silently. Only
	// meaningful with a numeric-shaped comparator (eq/ne/lt/lte/gt/gte —
	// fieldCompareComparators); validateRule rejects it on notPresent
	// (whose entire job is "absence IS the signal" — this flag would
	// silently invert that rule's own healthy case),
	// expiresWithin/selector/set-aggregate modes (a different shape
	// entirely), and PerMapKey (a map's per-key absence is not the field
	// itself being a scalar omitempty zero, and this codebase has no
	// evidence every quantity-shaped status/spec map pair shares that
	// property the way these three scalar counters do).
	AbsentFieldMeansZero bool `yaml:"absentFieldMeansZero,omitempty" json:"absentFieldMeansZero,omitempty"`

	SelectorField string `yaml:"selectorField,omitempty" json:"selectorField,omitempty"`

	// AggregateField is set-aggregate mode's own field, read off each Pod
	// SelectorField resolves to (never off the primary object) — see
	// RuleCondition's own doc comment and comparatorAllPodsSameValue.
	AggregateField string `yaml:"aggregateField,omitempty" json:"aggregateField,omitempty"`

	// Comparator is one of: eq, ne, lt, lte, gt, gte, notPresent
	// (field-compare mode — notPresent against nothing, the rest against
	// Value or, with PerMapKey, CompareField's matching key) —
	// expiresWithin (field-compare mode, Field must be an RFC3339 timestamp
	// string, Value a Go duration string: fires when that time is at or
	// before now+Value) — selectorMatchesNoPods (selector mode) —
	// allPodsSameValue (set-aggregate mode).
	Comparator string `yaml:"comparator" json:"comparator"`
}

// validRuleSeverities mirrors the four severities every hand-written checker
// in this package already uses (sweep_detector.go, pod_conditions_detector.go,
// detector.go) — there is no shared exported constant for this set anywhere
// in the package to reuse, so this is named here rather than invented a
// second time silently.
var validRuleSeverities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
var validRuleClasses = map[string]bool{"": true, tunnel.FindingClassFault: true, tunnel.FindingClassRisk: true, tunnel.FindingClassAnomaly: true}

// fieldCompareComparators and the two other comparator sets partition
// RuleCondition.Comparator so validateRule can check a rule's other fields
// are consistent with the mode its comparator implies, without duplicating
// the same switch in two places.
var fieldCompareComparators = map[string]bool{"eq": true, "ne": true, "lt": true, "lte": true, "gt": true, "gte": true}

const comparatorExpiresWithin = "expiresWithin"
const comparatorSelectorMatchesNoPods = "selectorMatchesNoPods"

// comparatorNotPresent and comparatorAllPodsSameValue are BACKLOG.md E10's
// two additions — see rules.go's package doc and RuleCondition's own doc
// comment for what each fires on and why neither fits the original five.
const comparatorNotPresent = "notPresent"
const comparatorAllPodsSameValue = "allPodsSameValue"

// LoadRules resolves this agent's rule set: the file at path if path is
// non-empty, else the embedded default set (rules/default-rules.yaml). Every
// rule is validated (unique ID, known GVK already present in supportedGVKs,
// known comparator, fields consistent with that comparator's mode, known
// severity) before being returned — a bad rule fails LoadRules outright
// rather than silently never firing, matching this package's existing
// "log and use a safe default" tolerance for a bad env var (see
// cmd/agent/main.go's positiveSecondsFromEnv) EXCEPT here there is no safe
// per-rule default to fall back to, so the caller (internal/agent.Run) is
// expected to log LoadRules' error and continue with zero rule-based checks
// rather than fail agent startup over a rules file typo — see Run's call
// site.
func LoadRules(path string) ([]Rule, error) {
	raw := defaultRulesYAML
	source := "the embedded default rule set"
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading detection rules file %s: %w", path, err)
		}
		raw = b
		source = path
	}

	var doc struct {
		Rules []Rule `yaml:"rules" json:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing detection rules from %s: %w", source, err)
	}

	seen := make(map[string]bool, len(doc.Rules))
	for _, r := range doc.Rules {
		if err := validateRule(r); err != nil {
			return nil, fmt.Errorf("detection rules from %s: rule %q: %w", source, r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("detection rules from %s: duplicate rule id %q", source, r.ID)
		}
		seen[r.ID] = true
	}
	return doc.Rules, nil
}

// validateRule checks one rule is well-formed enough to evaluate, at load
// time rather than discovering a typo the first time the sweep loop runs it.
func validateRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("missing id")
	}
	if r.Reason == "" {
		return fmt.Errorf("missing reason")
	}
	if !validRuleSeverities[r.Severity] {
		return fmt.Errorf("severity %q must be one of low|medium|high|critical", r.Severity)
	}
	if !validRuleClasses[r.Class] {
		return fmt.Errorf("class %q must be one of fault|risk|anomaly", r.Class)
	}
	if r.Message == "" {
		return fmt.Errorf("missing message")
	}
	if _, err := template.New(r.ID).Parse(r.Message); err != nil {
		return fmt.Errorf("message is not a valid template: %w", err)
	}

	gvk, err := parseGVKString(r.GVK)
	if err != nil {
		return fmt.Errorf("gvk: %w", err)
	}
	if _, ok := supportedGVKs[gvk]; !ok {
		return fmt.Errorf("gvk %q is not in supportedGVKs — an incident this rule raises could never be investigated afterward; add it there first", r.GVK)
	}

	c := r.Condition
	switch {
	case c.Comparator == comparatorSelectorMatchesNoPods:
		if c.SelectorField == "" {
			return fmt.Errorf("condition: selectorMatchesNoPods requires selectorField")
		}
		if c.Field != "" || c.CompareField != "" || c.Value != "" || c.AggregateField != "" {
			return fmt.Errorf("condition: selectorMatchesNoPods takes only selectorField")
		}
	case c.Comparator == comparatorAllPodsSameValue:
		// BACKLOG.md E10's set-aggregate mode — see RuleCondition's own doc
		// comment. Requires both SelectorField (to resolve the Pod set) and
		// AggregateField (what to compare across it); none of field-compare
		// or selector mode's other fields apply here.
		if c.SelectorField == "" || c.AggregateField == "" {
			return fmt.Errorf("condition: allPodsSameValue requires selectorField and aggregateField")
		}
		if c.Field != "" || c.CompareField != "" || c.Value != "" || c.PerMapKey {
			return fmt.Errorf("condition: allPodsSameValue takes only selectorField and aggregateField")
		}
	case c.Comparator == comparatorNotPresent:
		// BACKLOG.md E10's "posture audit" addition to field-compare mode —
		// see RuleCondition's own doc comment. Fires on absence alone, so
		// nothing to compare against and no other mode's fields apply.
		if c.Field == "" {
			return fmt.Errorf("condition: notPresent requires field")
		}
		if c.CompareField != "" || c.Value != "" || c.PerMapKey || c.SelectorField != "" || c.AggregateField != "" {
			return fmt.Errorf("condition: notPresent takes only field")
		}
	case c.Comparator == comparatorExpiresWithin:
		if c.Field == "" {
			return fmt.Errorf("condition: expiresWithin requires field")
		}
		if _, err := time.ParseDuration(c.Value); err != nil {
			return fmt.Errorf("condition: expiresWithin value %q must be a Go duration: %w", c.Value, err)
		}
		if c.PerMapKey || c.CompareField != "" {
			return fmt.Errorf("condition: expiresWithin does not support compareField/perMapKey")
		}
	case fieldCompareComparators[c.Comparator]:
		if c.Field == "" {
			return fmt.Errorf("condition: %s requires field", c.Comparator)
		}
		if c.PerMapKey {
			if c.CompareField == "" {
				return fmt.Errorf("condition: perMapKey requires compareField")
			}
			if c.Value != "" {
				return fmt.Errorf("condition: perMapKey compares field to compareField, not value")
			}
			if c.AbsentFieldMeansZero {
				return fmt.Errorf("condition: absentFieldMeansZero is not supported with perMapKey — a map's missing key is a different claim than a zero value, and this codebase has no evidence every quantity map pair shares the single-scalar omitempty-zero property this flag exists for")
			}
		} else if c.CompareField == "" && c.Value == "" {
			return fmt.Errorf("condition: %s requires value or compareField", c.Comparator)
		}
	default:
		return fmt.Errorf("condition: unknown comparator %q", c.Comparator)
	}
	if c.AbsentFieldMeansZero && !fieldCompareComparators[c.Comparator] {
		// Only the notPresent/expiresWithin/selectorMatchesNoPods/
		// allPodsSameValue cases above can reach this line (the
		// fieldCompareComparators and default cases both already return
		// before falling out of the switch) — this flag only makes sense
		// for the numeric six, so reject it here rather than silently
		// ignoring it on any other comparator.
		return fmt.Errorf("condition: absentFieldMeansZero is only supported with eq/ne/lt/lte/gt/gte, not %q", c.Comparator)
	}
	return nil
}

// evaluateRule is one rule's sweepChecker-equivalent: list every live object
// of the rule's GVK via the dynamic client (used for every rule, even core
// types like ResourceQuota, so this evaluator has exactly one code path
// regardless of which of the four representative rules or any future one is
// running) and return a sweepCandidate for every object the condition
// currently matches. Errors are returned rather than swallowed, same
// contract as sweepChecker.fn and dynamicSweepChecker.fn, so runOneSweep's
// per-check error handling covers this uniformly.
func evaluateRule(ctx context.Context, dyn dynamic.Interface, clientset kubernetes.Interface, rule Rule, now time.Time, plan sweepReadPlan) ([]sweepCandidate, error) {
	gvk, err := parseGVKString(rule.GVK)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	res, ok := supportedGVKs[gvk]
	if !ok {
		// validateRule already checked this at load time; re-checked here
		// only in case supportedGVKs itself changed between load and this
		// sweep, which cannot happen in the running process but costs
		// nothing to guard.
		return nil, fmt.Errorf("rule %s: gvk %q is not in supportedGVKs", rule.ID, rule.GVK)
	}

	// Watch-cache read by default (sweepListOptions, PROJECT.md P17(b)): a
	// rule's candidates go through recordSweepCandidates like every other
	// sweep result, so none of them can fire on a single observation and
	// none needs a quorum read. The plan can downgrade it to a paginated
	// read (PROJECT.md P17(c)) when this rule's own kind is too large to
	// decode whole in what is left of the agent's memory limit — which on
	// this path is the difference between the rule running and the rule
	// being skipped, since this loop only runs at all when the shared
	// snapshot was already unaffordable.
	list, err := listPaged(ctx, plan, func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if res.namespaced {
			return dyn.Resource(res.gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		}
		return dyn.Resource(res.gvr).List(ctx, opts)
	})
	if err != nil {
		// No CRD installed (e.g. no cert-manager on this cluster) is the
		// common case for a CRD-backed rule, not an error — same tolerance
		// checkArgoSyncFailed already has for "Argo CD isn't installed here".
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return nil, nil
		}
		if apierrors.IsForbidden(err) {
			return nil, fmt.Errorf("rule %s: listing %s is forbidden — the agent's ClusterRole needs get,list,watch on this GVK: %w", rule.ID, rule.GVK, err)
		}
		return nil, err
	}

	objs := make([]*unstructured.Unstructured, len(list.Items))
	for i := range list.Items {
		objs[i] = &list.Items[i]
	}
	return evaluateRuleObjects(ctx, clientsetPodSource{clientset: clientset}, rule, objs, now)
}

// rulePodSource is how a rule's two Pod-shaped comparators
// (selectorMatchesNoPods, allPodsSameValue) reach Pods. It exists because
// those two are the only place a rule reads a kind OTHER than its own, and
// because the sweep and the single-rule tool path have to reach them
// differently:
//
//   - During a sweep, the pass' shared unstructured snapshot already holds
//     every Pod on the cluster (PROJECT.md P28). Issuing one namespace-scoped
//     Pod list per Deployment/NetworkPolicy/PodDisruptionBudget on top of
//     that was a read count that scaled with the number of objects, not with
//     the number of rules — measured at three extra Pod lists per pass on a
//     fixture holding one object of each kind, and one per matching object
//     on a real cluster.
//   - reevaluate_rule (BACKLOG.md V3) re-runs one rule against one live
//     object with no sweep in progress, so it has no snapshot and must ask
//     the API server.
//
// The interface is what keeps those from becoming two copies of the
// comparator logic.
type rulePodSource interface {
	// podsMatchingSelector returns the Pods in namespace that selector
	// selects. An implementation that cannot answer returns an error and
	// NEVER an empty slice — "I could not look" must not reach a comparator
	// as "nothing matched" (PROJECT.md B185).
	podsMatchingSelector(ctx context.Context, namespace string, selector labels.Selector) ([]*unstructured.Unstructured, error)
}

// clientsetPodSource asks the API server, server-side
// (metav1.LabelSelectorAsSelector), scoped to one namespace — the original
// behaviour, still exactly right for the single-rule tool path where there
// is nothing already in memory to read instead.
type clientsetPodSource struct{ clientset kubernetes.Interface }

func (s clientsetPodSource) podsMatchingSelector(ctx context.Context, namespace string, selector labels.Selector) ([]*unstructured.Unstructured, error) {
	list, err := s.clientset.CoreV1().Pods(namespace).List(ctx, sweepListOptionsFor(selector.String()))
	if err != nil {
		return nil, err
	}
	out := make([]*unstructured.Unstructured, 0, len(list.Items))
	for i := range list.Items {
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&list.Items[i])
		if err != nil {
			return nil, fmt.Errorf("converting pod %s/%s: %w", list.Items[i].Namespace, list.Items[i].Name, err)
		}
		out = append(out, &unstructured.Unstructured{Object: m})
	}
	return out, nil
}

// snapshotPodSource answers from the Pods the pass has already read, with no
// API call at all.
//
// Refuses rather than answers when the pass did not read Pods — the memory
// guard declined the read, or RBAC denies it. Every caller of this treats an
// empty result as a positive claim about the cluster ("this NetworkPolicy
// selects nothing", "every replica is on one node"), so answering "none"
// from a Pod list that was never read would turn a permission or memory
// boundary into a finding about someone's cluster (PROJECT.md B185).
//
// byNamespace is built once, on first use: without it, one rule over N
// Deployments would scan every Pod on the cluster N times. Built lazily
// because most passes never reach a selector-shaped comparator at all.
type snapshotPodSource struct {
	snap        *unstructuredSnapshot
	byNamespace map[string][]*unstructured.Unstructured
}

func (s *snapshotPodSource) podsMatchingSelector(_ context.Context, namespace string, selector labels.Selector) ([]*unstructured.Unstructured, error) {
	if !s.snap.readable("Pod") {
		return nil, fmt.Errorf("this sweep pass has no Pod list to match a selector against: %s", s.snap.unreadableReason("Pod"))
	}
	if s.byNamespace == nil {
		s.byNamespace = make(map[string][]*unstructured.Unstructured)
		for _, pod := range s.snap.objectsOf("Pod") {
			s.byNamespace[pod.GetNamespace()] = append(s.byNamespace[pod.GetNamespace()], pod)
		}
	}
	var out []*unstructured.Unstructured
	for _, pod := range s.byNamespace[namespace] {
		if selector.Matches(labels.Set(pod.GetLabels())) {
			out = append(out, pod)
		}
	}
	return out, nil
}

// evaluateRuleObjects is evaluateRule with the listing already done —
// PROJECT.md P28's whole point. The sweep calls this with the objects the
// pass' shared unstructured snapshot already holds, so the 37 rules add no
// API reads at all; evaluateRule above calls it with a list it issued
// itself, which is the path reevaluate_rule (tools.go, BACKLOG.md V3) still
// needs, since that tool re-runs ONE rule against ONE live object with no
// sweep in progress and no snapshot to read from.
//
// pods is how the two Pod-shaped comparators reach Pods — from the same
// snapshot during a sweep, from the API server on the single-rule path. The
// two answer identically; they differ only in what they cost and in what
// they can refuse (see rulePodSource).
func evaluateRuleObjects(ctx context.Context, pods rulePodSource, rule Rule, objs []*unstructured.Unstructured, now time.Time) ([]sweepCandidate, error) {
	var out []sweepCandidate
	ruleClass := rule.Class
	if ruleClass == "" {
		ruleClass = tunnel.FindingClassAnomaly
	}
	ruleImpact := tunnel.FindingImpactDegraded
	if ruleClass != tunnel.FindingClassFault {
		ruleImpact = tunnel.FindingImpactPotential
	}
	for _, obj := range objs {
		tmplData, matched, err := evaluateCondition(ctx, pods, obj, rule.Condition, now)
		if err != nil {
			logger.Warn("sweep detector rule evaluation failed for an object",
				slog.String("rule_id", rule.ID), slog.String("namespace", obj.GetNamespace()), slog.String("name", obj.GetName()), logging.Err(err))
			continue
		}
		if !matched {
			continue
		}
		// A risk the object's owner has set aside with argus.io/ignore-checks
		// is not reported; a fault is reported whatever the annotation says
		// (PROJECT.md PG11).
		if ruleClass != tunnel.FindingClassFault && posture.IgnoresCheck(obj.GetAnnotations()[posture.IgnoreChecksAnnotation], rule.ID) {
			continue
		}
		msg, err := renderRuleMessage(rule, tmplData)
		if err != nil {
			logger.Warn("sweep detector rule: rendering message failed", slog.String("rule_id", rule.ID), logging.Err(err))
			continue
		}
		out = append(out, sweepCandidate{
			GVK:             rule.GVK,
			Namespace:       obj.GetNamespace(),
			Name:            obj.GetName(),
			UID:             string(obj.GetUID()),
			ResourceVersion: obj.GetResourceVersion(),
			Reason:          rule.Reason,
			Message:         msg,
			Severity:        rule.Severity,
			Class:           ruleClass,
			Confidence:      tunnel.FindingConfidenceVerified,
			Impact:          ruleImpact,
			// BACKLOG.md V3: the one piece of information that lets the hub
			// later ask THIS agent to re-run THIS exact rule against the live
			// object — see tunnel.Finding.RuleID's doc comment.
			RuleID: rule.ID,
			// What this object produces, so a pod waiting on it joins this
			// incident (PROJECT.md IN5).
			References: producedReferences(obj),
			// No SustainedFrom: none of this file's shapes read an
			// authoritative "since when" timestamp off the object (unlike
			// checkDeploymentReplicas' condition.LastTransitionTime), so — the
			// same as checkStatefulSetReplicas/checkDaemonSetReplicas/
			// checkServiceNoEndpoints — runOneSweep's sustainedLongEnough gates
			// on how long THIS detector has observed the condition instead. See
			// this file's package doc for why no rule gets its own sustain
			// clock.
			OccurredAt: now,
		})
	}
	return out, nil
}

// ruleTemplateData is everything a rule's Message template may reference —
// deliberately small and named, not the raw unstructured object, so a rule
// cannot template in an arbitrary field this codebase's redaction discipline
// never got a chance to classify.
type ruleTemplateData struct {
	Namespace    string
	Name         string
	Value        string
	CompareValue string
	MatchedKey   string
	// Count is set only by set-aggregate mode (BACKLOG.md E10) — how many
	// Pods the condition matched, so a rule's Message can say "N pods" rather
	// than just the shared value.
	Count int
}

func renderRuleMessage(rule Rule, data ruleTemplateData) (string, error) {
	tmpl, err := template.New(rule.ID).Parse(rule.Message)
	if err != nil {
		// Unreachable in practice — validateRule already parsed this same
		// string at load time — but handled rather than assumed, since a
		// panic here would take down the whole sweep.
		return "", err
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// evaluateCondition dispatches to the field-compare, selector-matches-no-pods,
// or set-aggregate (BACKLOG.md E10) shape and returns the template data the
// caller will render Message against, plus whether the condition matched at
// all.
func evaluateCondition(ctx context.Context, pods rulePodSource, obj *unstructured.Unstructured, c RuleCondition, now time.Time) (ruleTemplateData, bool, error) {
	data := ruleTemplateData{Namespace: obj.GetNamespace(), Name: obj.GetName()}

	if c.Comparator == comparatorSelectorMatchesNoPods {
		matched, err := evaluateSelectorMatchesNoPods(ctx, pods, obj, c.SelectorField)
		return data, matched, err
	}

	if c.Comparator == comparatorAllPodsSameValue {
		return evaluateAllPodsSameValue(ctx, pods, obj, c.SelectorField, c.AggregateField, data)
	}

	fieldVal, found, err := unstructured.NestedFieldNoCopy(obj.Object, strings.Split(c.Field, ".")...)
	if err != nil {
		return data, false, fmt.Errorf("reading field %q: %w", c.Field, err)
	}
	if !found {
		// The field simply isn't set on this object. For every comparator
		// EXCEPT notPresent, that is not a match and not an error: a
		// ResourceQuota with no status.used yet (freshly created) is exactly
		// this case. notPresent is the one comparator (BACKLOG.md E10 —
		// see this file's package doc) whose whole job is to fire exactly
		// when the field is absent — a posture audit of a healthy object,
		// not a failure signal.
		if c.Comparator == comparatorNotPresent {
			return data, true, nil
		}
		if !c.AbsentFieldMeansZero {
			return data, false, nil
		}
		// BUGS.md 129: this rule has explicitly opted in (validateRule
		// already confirmed the comparator is one of the numeric six and
		// PerMapKey is false) — Field is asserted to be an
		// omitempty-tagged numeric Kubernetes status field where "absent"
		// and "present and zero" are the same real-world state, so treat
		// a miss here as a literal zero rather than "no match" and fall
		// through to the normal comparison below. See RuleCondition's own
		// doc comment on AbsentFieldMeansZero for the full reasoning and
		// which rules use it.
		fieldVal = int64(0)
	}
	if c.Comparator == comparatorNotPresent {
		// The field IS present — the healthy case for this comparator, never
		// a match.
		data.Value = formatFieldValue(fieldVal)
		return data, false, nil
	}
	data.Value = formatFieldValue(fieldVal)

	if c.Comparator == comparatorExpiresWithin {
		matched, err := evaluateExpiresWithin(fieldVal, c.Value, now)
		return data, matched, err
	}

	if c.PerMapKey {
		compareVal, found, err := unstructured.NestedFieldNoCopy(obj.Object, strings.Split(c.CompareField, ".")...)
		if err != nil {
			return data, false, fmt.Errorf("reading compareField %q: %w", c.CompareField, err)
		}
		if !found {
			return data, false, nil
		}
		matched, key, actual, compare, err := evaluatePerMapKey(fieldVal, compareVal, c.Comparator)
		if err != nil {
			return data, false, err
		}
		data.MatchedKey = key
		data.Value = actual
		data.CompareValue = compare
		return data, matched, nil
	}

	// Field-vs-value or field-vs-compareField, both scalar.
	var compareTo interface{}
	if c.CompareField != "" {
		v, found, err := unstructured.NestedFieldNoCopy(obj.Object, strings.Split(c.CompareField, ".")...)
		if err != nil {
			return data, false, fmt.Errorf("reading compareField %q: %w", c.CompareField, err)
		}
		if !found {
			if !c.AbsentFieldMeansZero {
				return data, false, nil
			}
			// Same reasoning as the primary Field's own !found branch
			// above, applied symmetrically to CompareField: none of this
			// file's three affected rules actually need this in practice
			// (their CompareField side — status.desiredNumberScheduled,
			// spec.replicas — is either never omitempty-tagged or always
			// defaulted by the API server before this object is ever
			// read), but a rule that opted into AbsentFieldMeansZero is
			// asserting the omitempty-zero-ambiguity property for this
			// CONDITION, not for one hardcoded side of it, so both sides
			// honor the same flag rather than leaving CompareField as a
			// silent exception.
			v = int64(0)
		}
		compareTo = v
		data.CompareValue = formatFieldValue(v)
	} else {
		compareTo = c.Value
		data.CompareValue = c.Value
	}
	matched, err := compareScalar(fieldVal, c.Comparator, compareTo)
	return data, matched, err
}

// evaluateSelectorMatchesNoPods reads a metav1.LabelSelector-shaped field
// (e.g. NetworkPolicy's spec.podSelector) and lists Pods in the object's own
// namespace with that selector, server-side (metav1.LabelSelectorAsSelector),
// exactly the pattern objectref.go's resolveRelatedWorkloadForSelector already
// uses for the same reason: cheap, and scoped to one namespace rather than a
// client-side scan.
//
// A deliberately empty selector (selects every pod in the namespace) is
// skipped rather than flagged — that is a common, intentional "apply to
// everything" policy, not a misconfiguration, and this file has no reliable
// way to distinguish "correctly empty" from "accidentally empty" the way it
// can for a non-empty selector matching nothing.
func evaluateSelectorMatchesNoPods(ctx context.Context, pods rulePodSource, obj *unstructured.Unstructured, field string) (bool, error) {
	matched, ok, err := podsMatchingSelectorField(ctx, pods, obj, field)
	if err != nil {
		return false, err
	}
	if !ok {
		// Field absent, or deliberately empty (selects everything) — see
		// podsMatchingSelectorField's own doc comment for both cases.
		return false, nil
	}
	return len(matched) == 0, nil
}

// podsMatchingSelectorField is evaluateSelectorMatchesNoPods and (BACKLOG.md
// E10) evaluateAllPodsSameValue's shared plumbing: read a
// metav1.LabelSelector-shaped field (e.g. Deployment's spec.selector,
// NetworkPolicy's spec.podSelector) and resolve the Pods in the object's own
// namespace that it selects, through whichever rulePodSource the caller
// supplied.
//
// The returned bool is false (with no Pods and a nil error) in exactly two
// cases callers must treat identically — "there is no meaningful Pod set to
// evaluate here", not "zero pods matched":
//   - the field is absent from the object entirely;
//   - the field is a deliberately empty selector (selects every pod in the
//     namespace) — a common, intentional "apply to everything" policy, not a
//     misconfiguration, and this file has no reliable way to distinguish
//     "correctly empty" from "accidentally empty" the way it can for a
//     non-empty selector matching nothing.
//
// A source that cannot answer returns an error, which the caller propagates
// rather than converting into "no pods matched" — the distinction PROJECT.md
// B185 is about, applied to the one place a rule reads a kind other than its
// own.
func podsMatchingSelectorField(ctx context.Context, pods rulePodSource, obj *unstructured.Unstructured, field string) ([]*unstructured.Unstructured, bool, error) {
	raw, found, err := unstructured.NestedMap(obj.Object, strings.Split(field, ".")...)
	if err != nil {
		return nil, false, fmt.Errorf("reading selectorField %q: %w", field, err)
	}
	if !found {
		return nil, false, nil
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return nil, false, fmt.Errorf("selectorField %q: %w", field, err)
	}
	var sel metav1.LabelSelector
	if err := json.Unmarshal(b, &sel); err != nil {
		return nil, false, fmt.Errorf("selectorField %q is not a valid label selector: %w", field, err)
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return nil, false, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		return nil, false, fmt.Errorf("selectorField %q: %w", field, err)
	}

	matched, err := pods.podsMatchingSelector(ctx, obj.GetNamespace(), selector)
	if err != nil {
		return nil, false, err
	}
	return matched, true, nil
}

// evaluateAllPodsSameValue implements BACKLOG.md E10's set-aggregate mode —
// see rules.go's package doc and RuleCondition's own doc comment for the
// predicate kind this exists for (issue-catalog AV1/DEPL-019, "every replica
// on one node", live-verified in CAPABILITIES.md).
//
// Requires at least two matched Pods before it will ever match at all: with
// zero or one Pod, "every Pod agrees" is trivially true and would be
// worthless noise (and, for one Pod, meaningless — nothing to agree WITH).
// If AggregateField is absent on ANY matched Pod, this returns no match
// rather than guessing — the same fail-closed posture selectorMatchesNoPods'
// empty-selector case already uses, since "are they all the same" cannot be
// honestly answered when one of them has no answer at all.
func evaluateAllPodsSameValue(ctx context.Context, pods rulePodSource, obj *unstructured.Unstructured, selectorField, aggregateField string, data ruleTemplateData) (ruleTemplateData, bool, error) {
	matched, ok, err := podsMatchingSelectorField(ctx, pods, obj, selectorField)
	if err != nil {
		return data, false, err
	}
	if !ok || len(matched) < 2 {
		return data, false, nil
	}

	var common string
	for i, pod := range matched {
		v, found, err := unstructured.NestedFieldNoCopy(pod.Object, strings.Split(aggregateField, ".")...)
		if err != nil {
			return data, false, fmt.Errorf("reading aggregateField %q on pod %s/%s: %w", aggregateField, pod.GetNamespace(), pod.GetName(), err)
		}
		if !found {
			// Can't honestly claim "all the same" when one Pod has no value
			// at all here (e.g. spec.nodeName before the scheduler has
			// bound it yet).
			return data, false, nil
		}
		s := formatFieldValue(v)
		if i == 0 {
			common = s
			continue
		}
		if s != common {
			return data, false, nil
		}
	}

	data.Value = common
	data.Count = len(matched)
	return data, true, nil
}

// evaluateExpiresWithin fires when fieldVal (an RFC3339 timestamp, e.g.
// cert-manager's status.notAfter) is at or before now+window — matching a
// point already past just as much as one about to arrive, since an already-
// expired certificate is certainly "within" any warning window.
func evaluateExpiresWithin(fieldVal interface{}, windowStr string, now time.Time) (bool, error) {
	s, ok := fieldVal.(string)
	if !ok {
		return false, fmt.Errorf("expiresWithin requires a string (RFC3339) field, got %T", fieldVal)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return false, fmt.Errorf("expiresWithin field %q is not RFC3339: %w", s, err)
	}
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		return false, err
	}
	return !t.After(now.Add(window)), nil
}

// evaluatePerMapKey implements the ResourceQuota shape: fieldVal and
// compareVal are both string-keyed maps of Kubernetes quantity strings
// (status.used/status.hard's actual encoding — "4", "500m", "2Gi", never bare
// floats), and the condition matches if comparator holds for ANY key present
// in both maps — quantity-aware (resource.ParseQuantity), because "500m" and
// "1" are the same magnitude relationship string comparison would get wrong.
// Returns the first matching key (sorted, for determinism across runs) so
// the caller can name it in the rendered message.
func evaluatePerMapKey(fieldVal, compareVal interface{}, comparator string) (matched bool, key, actualStr, compareStr string, err error) {
	fieldMap, ok := toStringMap(fieldVal)
	if !ok {
		return false, "", "", "", fmt.Errorf("perMapKey field must be a map, got %T", fieldVal)
	}
	compareMap, ok := toStringMap(compareVal)
	if !ok {
		return false, "", "", "", fmt.Errorf("perMapKey compareField must be a map, got %T", compareVal)
	}

	keys := make([]string, 0, len(fieldMap))
	for k := range fieldMap {
		if _, ok := compareMap[k]; ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		a, err1 := resource.ParseQuantity(fmt.Sprintf("%v", fieldMap[k]))
		b, err2 := resource.ParseQuantity(fmt.Sprintf("%v", compareMap[k]))
		if err1 != nil || err2 != nil {
			// Not a quantity-shaped pair for this key — skip it rather than
			// failing the whole rule over one unexpected key.
			continue
		}
		cmp := a.Cmp(b) // -1 a<b, 0 a==b, 1 a>b
		if comparatorHolds(comparator, cmp) {
			return true, k, fmt.Sprintf("%v", fieldMap[k]), fmt.Sprintf("%v", compareMap[k]), nil
		}
	}
	return false, "", "", "", nil
}

// comparatorHolds interprets a three-way Cmp result (-1/0/1) against one of
// the six field-compare comparators.
func comparatorHolds(comparator string, cmp int) bool {
	switch comparator {
	case "eq":
		return cmp == 0
	case "ne":
		return cmp != 0
	case "lt":
		return cmp < 0
	case "lte":
		return cmp <= 0
	case "gt":
		return cmp > 0
	case "gte":
		return cmp >= 0
	default:
		return false
	}
}

// compareScalar implements the plain field-vs-literal-or-field shape (no
// perMapKey). actual comes off the live object (typically float64/int64/bool/
// string, per unstructured's JSON-shaped decoding); compareTo is either
// another such value (field-vs-field) or a raw string literal from the rule
// (field-vs-value) — numericValue below normalizes either into a float64
// when possible, falling back to a string comparison (eq/ne only) when it
// isn't a number.
func compareScalar(actual interface{}, comparator string, compareTo interface{}) (bool, error) {
	if af, aok := numericValue(actual); aok {
		if bf, bok := numericValue(compareTo); bok {
			return comparatorHolds(comparator, cmpFloat(af, bf)), nil
		}
	}
	// Fall back to string comparison — only eq/ne are meaningful without a
	// defined ordering.
	as, bs := formatFieldValue(actual), formatFieldValue(compareTo)
	switch comparator {
	case "eq":
		return as == bs, nil
	case "ne":
		return as != bs, nil
	default:
		return false, fmt.Errorf("comparator %q needs a numeric field, got %q vs %q", comparator, as, bs)
	}
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// numericValue normalizes the handful of shapes a JSON/unstructured number or
// a rule's own literal string can arrive in.
func numericValue(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// formatFieldValue renders any field value (or rule literal) as a string for
// template data / string-fallback comparison — %v is deliberately used
// rather than a type switch: this is display-only, and it already handles
// every type numericValue does, plus bool and nil.
func formatFieldValue(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// toStringMap accepts what unstructured.NestedFieldNoCopy hands back for a
// JSON object field: map[string]interface{}.
func toStringMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

// findRule looks up one rule by ID in an already-loaded set — the small
// linear scan tools.go's reevaluate_rule needs (BACKLOG.md V3) to turn a
// hub-supplied rule ID back into the Rule evaluateRule can run. A loaded
// rule set is at most a handful of entries (LoadRules rejects duplicate
// IDs), so this is not worth a map: the set is read-mostly, rebuilt only on
// process start or SetRules, and a map would just be one more thing to keep
// in sync with it.
func findRule(rules []Rule, id string) (Rule, bool) {
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
