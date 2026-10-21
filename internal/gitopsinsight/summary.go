package gitopsinsight

import (
	"strings"
	"time"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Tool values match the ManagedBy vocabulary of get_gitops_ownership.
const (
	ToolArgoCD = "argocd"
	ToolFlux   = "flux"
)

// Output caps. Managed resources follow the CI-S7 cap; conditions and message
// lengths bound a pathological object (Argo has been seen to embed whole
// rendered manifests in a message) well inside the tool frame budget.
const (
	MaxManagedResources = 200
	MaxConditions       = 32
	MaxMessageRunes     = 4096
	// MaxHistory (PG3, 2026-10-13 parity review) bounds the operation/release
	// history list — Argo keeps unlimited history by default on some
	// installs, and this is an operator-facing log, not raw forensics.
	MaxHistory = 20
)

// Summary is the state of one Argo CD Application/ApplicationSet or Flux
// object, as its controller reports it.
type Summary struct {
	Tool      string `json:"tool,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Sync      string `json:"sync,omitempty"`
	Health    string `json:"health,omitempty"`
	// OperationPhase/OperationMessage are Argo's status.operationState; the
	// message has gRPC envelopes stripped, and RawOperationMessage holds the
	// original only when stripping changed it.
	OperationPhase      string `json:"operationPhase,omitempty"`
	OperationMessage    string `json:"operationMessage,omitempty"`
	RawOperationMessage string `json:"rawOperationMessage,omitempty"`
	// Source is "repoURL · path · chart" for Argo, "<Kind>/<name>" of the
	// sourceRef for Flux.
	Source         string `json:"source,omitempty"`
	TargetRevision string `json:"targetRevision,omitempty"`
	LastRevision   string `json:"lastRevision,omitempty"`
	LastReconcile  string `json:"lastReconcile,omitempty"`
	// AutoSync is "Manual", "Auto", "Auto · prune", "Auto · self-heal",
	// "Auto · prune · self-heal" for an Argo Application, "Auto" or
	// "Suspended" for Flux, and empty for an ApplicationSet (whose sync policy
	// belongs to the Applications it generates).
	AutoSync             string   `json:"autoSync,omitempty"`
	Terminating          bool     `json:"terminating,omitempty"`
	TerminationStartedAt string   `json:"terminationStartedAt,omitempty"`
	Finalizers           []string `json:"finalizers,omitempty"`

	Conditions          []Condition `json:"conditions,omitempty"`
	ConditionsTruncated bool        `json:"conditionsTruncated,omitempty"`

	// ManagedResources come from Argo status.resources or Flux
	// status.inventory, capped at MaxManagedResources. ManagedResourcesTotal
	// is the uncapped count. A Flux HelmRelease keeps no inventory, so an
	// empty list there means "not reported", not "manages nothing".
	ManagedResources      []ManagedResource `json:"managedResources,omitempty"`
	ManagedResourcesTotal int               `json:"managedResourcesTotal"`
	Truncated             bool              `json:"truncated,omitempty"`

	// ResourceHealthUnavailable is true when Argo CD itself reports
	// status.resourceHealthSource == "appTree" (Argo CD 3.x's default) —
	// per-resource Health above is then never populated, by Argo's own
	// design, not a read failure here. ARGUS does not call argocd-server
	// (docs/CLUSTER_INSIGHT_SPECS.md §5), so there is no fallback read; this
	// flag is what tells a caller to say "unavailable" rather than show a
	// blank or infer Healthy from silence (PG3, 2026-10-13 parity review).
	ResourceHealthUnavailable bool `json:"resourceHealthUnavailable,omitempty"`

	// History is the controller's own past-operation/past-release log —
	// Argo's status.history, or a Flux HelmRelease's own status.history
	// (Flux Kustomizations keep no such field). Newest first, capped at
	// MaxHistory. Never ARGUS's own reconstruction: a field this struct
	// cannot populate from the controller's own status stays empty on each
	// entry rather than guessed.
	History          []HistoryEntry `json:"history,omitempty"`
	HistoryTruncated bool           `json:"historyTruncated,omitempty"`
}

// HistoryEntry is one past (or currently in-flight) sync/release, read
// verbatim from the controller's own history — see Summary.History's own
// doc comment for why some fields are legitimately empty on some entries.
type HistoryEntry struct {
	Revision    string `json:"revision,omitempty"`
	DeployedAt  string `json:"deployedAt,omitempty"`
	InitiatedBy string `json:"initiatedBy,omitempty"`
	// Outcome is the controller's own stated result for this entry. Set
	// unconditionally for a Flux HelmRelease (status.history[].status, e.g.
	// "deployed", "failed", "superseded"). For Argo, set ONLY on the entry
	// matching the currently tracked operation (Summary.LastRevision) from
	// Summary.OperationPhase — Argo's own history entries carry no
	// per-entry outcome field at all, so every other entry leaves this
	// empty rather than inventing one.
	Outcome string `json:"outcome,omitempty"`
}

func (s *Summary) appendHistory(e HistoryEntry) {
	if len(s.History) >= MaxHistory {
		s.HistoryTruncated = true
		return
	}
	s.History = append(s.History, e)
}

// Condition is one status.conditions entry plus operator guidance. Action is
// set for recognised Argo condition types, and for Flux conditions that
// signal failure (Ready/Healthy/Released/TestSuccess False, Stalled True).
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	Action  string `json:"action,omitempty"`

	lastTransitionTime string
}

// ManagedResource is one object the GitOps controller manages. Status and
// Health are Argo's per-resource sync status and health; Flux's inventory
// carries neither.
type ManagedResource struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Status    string `json:"status,omitempty"`
	Health    string `json:"health,omitempty"`
}

// DetectTool returns ToolArgoCD for argoproj.io objects, ToolFlux for
// *.toolkit.fluxcd.io objects, and "" for anything else.
func DetectTool(obj *unstructured.Unstructured) string {
	if obj == nil {
		return ""
	}
	group, _, _ := strings.Cut(obj.GetAPIVersion(), "/")
	switch {
	case group == "argoproj.io":
		return ToolArgoCD
	case strings.HasSuffix(group, ".fluxcd.io"):
		return ToolFlux
	}
	return ""
}

// Summarize reads an Argo CD or Flux object into a Summary. An object of any
// other kind gets identity and lifecycle fields only.
func Summarize(obj *unstructured.Unstructured) Summary {
	if obj == nil {
		return Summary{}
	}
	tool := DetectTool(obj)
	s := Summary{
		Tool:      tool,
		Kind:      obj.GetKind(),
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
	// Surfaced even on healthy objects: a pending deletion explains why
	// nothing the controller does seems to stick.
	if dt := obj.GetDeletionTimestamp(); dt != nil && !dt.IsZero() {
		s.Terminating = true
		s.TerminationStartedAt = dt.UTC().Format(time.RFC3339)
		s.Finalizers = obj.GetFinalizers()
	}
	switch tool {
	case ToolArgoCD:
		summarizeArgo(obj, &s)
	case ToolFlux:
		summarizeFlux(obj, &s)
	}
	return s
}

func summarizeArgo(obj *unstructured.Unstructured, s *Summary) {
	s.Sync, _, _ = unstructured.NestedString(obj.Object, "status", "sync", "status")
	s.Health, _, _ = unstructured.NestedString(obj.Object, "status", "health", "status")
	s.OperationPhase, _, _ = unstructured.NestedString(obj.Object, "status", "operationState", "phase")
	opMessage, _, _ := unstructured.NestedString(obj.Object, "status", "operationState", "message")
	msg, raw := CleanArgoControllerMessageWithRaw(opMessage)
	s.OperationMessage, s.RawOperationMessage = capRunes(msg), capRunes(raw)
	s.TargetRevision, _, _ = unstructured.NestedString(obj.Object, "status", "sync", "revision")
	s.LastRevision, _, _ = unstructured.NestedString(obj.Object, "status", "operationState", "syncResult", "revision")
	s.LastReconcile, _, _ = unstructured.NestedString(obj.Object, "status", "reconciledAt")
	source, _, _ := unstructured.NestedMap(obj.Object, "spec", "source")
	if len(source) == 0 {
		if sources, _, _ := unstructured.NestedSlice(obj.Object, "spec", "sources"); len(sources) > 0 {
			source, _ = sources[0].(map[string]any)
		}
	}
	s.Source = joinNonEmpty(stringValue(source["repoURL"]), stringValue(source["path"]), stringValue(source["chart"]))
	s.AutoSync = describeArgoAutoSync(obj)

	for _, c := range readConditions(obj) {
		msg := CleanArgoControllerMessage(c.Message)
		if c.Type == "" && msg == "" {
			continue
		}
		c.Message = msg
		c.Action = ActionForCondition(c.Type)
		s.appendCondition(c)
	}

	resources, _, _ := unstructured.NestedSlice(obj.Object, "status", "resources")
	for _, item := range resources {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		r := ManagedResource{
			Group:     stringValue(m["group"]),
			Kind:      stringValue(m["kind"]),
			Namespace: stringValue(m["namespace"]),
			Name:      stringValue(m["name"]),
			Status:    stringValue(m["status"]),
		}
		if h, ok := m["health"].(map[string]any); ok {
			r.Health = stringValue(h["status"])
		}
		if r.Kind == "" || r.Name == "" {
			continue
		}
		s.appendManaged(r)
	}

	if rhs, _, _ := unstructured.NestedString(obj.Object, "status", "resourceHealthSource"); rhs == "appTree" {
		s.ResourceHealthUnavailable = true
	}

	// PG3 (2026-10-13 parity review): status.history is append-only oldest
	// first, so walk it backwards for newest-first. "Outcome" is attached
	// only to the entry matching the currently tracked operation — see
	// HistoryEntry's own doc comment for why every other entry leaves it
	// empty rather than guessing.
	hist, _, _ := unstructured.NestedSlice(obj.Object, "status", "history")
	for i := len(hist) - 1; i >= 0; i-- {
		m, ok := hist[i].(map[string]any)
		if !ok {
			continue
		}
		e := HistoryEntry{Revision: stringValue(m["revision"]), DeployedAt: stringValue(m["deployedAt"])}
		if ib, ok := m["initiatedBy"].(map[string]any); ok {
			if automated, _ := ib["automated"].(bool); automated {
				e.InitiatedBy = "automated"
			} else {
				e.InitiatedBy = stringValue(ib["username"])
			}
		}
		if e.Revision != "" && e.Revision == s.LastRevision {
			e.Outcome = s.OperationPhase
		}
		s.appendHistory(e)
	}
}

func summarizeFlux(obj *unstructured.Unstructured, s *Summary) {
	st := FluxStatus(obj)
	s.Sync, s.Health = st.Sync, st.Health
	s.TargetRevision, _, _ = unstructured.NestedString(obj.Object, "status", "lastAttemptedRevision")
	s.LastRevision, _, _ = unstructured.NestedString(obj.Object, "status", "lastAppliedRevision")
	s.LastReconcile, _, _ = unstructured.NestedString(obj.Object, "status", "lastHandledReconcileAt")
	conds := readConditions(obj)
	if s.LastReconcile == "" {
		for _, c := range conds {
			if c.lastTransitionTime > s.LastReconcile {
				s.LastReconcile = c.lastTransitionTime
			}
		}
	}
	if ref, ok := sourceRef(obj, "spec", "sourceRef"); ok {
		s.Source = ref
	} else if ref, ok := sourceRef(obj, "spec", "chart", "spec", "sourceRef"); ok {
		s.Source = ref
	}
	if suspended, _, _ := unstructured.NestedBool(obj.Object, "spec", "suspend"); suspended {
		s.AutoSync = "Suspended"
	} else {
		s.AutoSync = "Auto"
	}

	for _, c := range conds {
		if fluxConditionFailing(c) {
			c.Action = ActionForFluxReason(c.Reason)
		}
		s.appendCondition(c)
	}

	entries, _, _ := unstructured.NestedSlice(obj.Object, "status", "inventory", "entries")
	for _, item := range entries {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		group, kind, ns, name, ok := ParseFluxInventoryID(stringValue(m["id"]))
		if !ok {
			continue
		}
		s.appendManaged(ManagedResource{Group: group, Kind: kind, Namespace: ns, Name: name})
	}

	// PG3 (2026-10-13 parity review): only HelmRelease carries status.history
	// (Flux's own Snapshot type) — a Kustomization has no equivalent field,
	// so this is deliberately absent for every other Flux kind rather than
	// approximated from the inventory above. Flux's history is also newest
	// first already, unlike Argo's.
	if obj.GetKind() == "HelmRelease" {
		hist, _, _ := unstructured.NestedSlice(obj.Object, "status", "history")
		for _, item := range hist {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			s.appendHistory(HistoryEntry{
				Revision:   stringValue(m["chartVersion"]),
				DeployedAt: stringValue(m["lastDeployed"]),
				Outcome:    stringValue(m["status"]),
			})
		}
	}
}

// fluxConditionFailing is true for the condition states that mean the
// object is not in its desired state, the ones that warrant guidance.
func fluxConditionFailing(c Condition) bool {
	switch {
	case c.Status == "False":
		return c.Type == "Ready" || c.Type == "Healthy" || c.Type == "Released" || c.Type == "TestSuccess"
	case c.Status == "True":
		return c.Type == "Stalled"
	}
	return false
}

func (s *Summary) appendCondition(c Condition) {
	if len(s.Conditions) >= MaxConditions {
		s.ConditionsTruncated = true
		return
	}
	c.Message = capRunes(c.Message)
	s.Conditions = append(s.Conditions, c)
}

func (s *Summary) appendManaged(r ManagedResource) {
	s.ManagedResourcesTotal++
	if len(s.ManagedResources) >= MaxManagedResources {
		s.Truncated = true
		return
	}
	s.ManagedResources = append(s.ManagedResources, r)
}

// describeArgoAutoSync formats spec.syncPolicy.automated as a label. Only a
// real bool true counts for prune/selfHeal, so a mangled string value is not
// reported as enabled.
func describeArgoAutoSync(obj *unstructured.Unstructured) string {
	// An ApplicationSet's syncPolicy is about creating and deleting the
	// Applications it generates, and never has `automated`.
	if obj.GetKind() == "ApplicationSet" {
		return ""
	}
	v, _, _ := unstructured.NestedFieldNoCopy(obj.Object, "spec", "syncPolicy", "automated")
	automated, ok := v.(map[string]any)
	if !ok {
		return "Manual"
	}
	out := "Auto"
	for _, opt := range []struct{ field, label string }{{"prune", "prune"}, {"selfHeal", "self-heal"}} {
		if on, _ := automated[opt.field].(bool); on {
			out += " · " + opt.label
		}
	}
	return out
}

// FailureFor returns the parsed Argo operation failure when the object is an
// Argo Application whose last operation ended Failed or Error, else nil.
func FailureFor(obj *unstructured.Unstructured) *ParsedFailure {
	if DetectTool(obj) != ToolArgoCD {
		return nil
	}
	phase, _, _ := unstructured.NestedString(obj.Object, "status", "operationState", "phase")
	if phase != "Failed" && phase != "Error" {
		return nil
	}
	msg, _, _ := unstructured.NestedString(obj.Object, "status", "operationState", "message")
	p := ParseArgoOperationError(CleanArgoControllerMessage(msg))
	return &p
}

func readConditions(obj *unstructured.Unstructured) []Condition {
	raw, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	out := make([]Condition, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, Condition{
			Type:               stringValue(m["type"]),
			Status:             stringValue(m["status"]),
			Reason:             stringValue(m["reason"]),
			Message:            stringValue(m["message"]),
			lastTransitionTime: stringValue(m["lastTransitionTime"]),
		})
	}
	return out
}

func sourceRef(obj *unstructured.Unstructured, fields ...string) (string, bool) {
	m, ok, _ := unstructured.NestedMap(obj.Object, fields...)
	if !ok {
		return "", false
	}
	kind, name := stringValue(m["kind"]), stringValue(m["name"])
	if kind == "" || name == "" {
		return "", false
	}
	return kind + "/" + name, true
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func joinNonEmpty(values ...string) string {
	var parts []string
	for _, v := range values {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " · ")
}

// capRunes truncates s to MaxMessageRunes runes, marking the cut with "…".
func capRunes(s string) string {
	if utf8.RuneCountInString(s) <= MaxMessageRunes {
		return s
	}
	r := []rune(s)
	return string(r[:MaxMessageRunes]) + "…"
}
