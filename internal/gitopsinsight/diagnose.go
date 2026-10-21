// Package gitopsinsight turns Argo CD and Flux objects into structured facts:
// a summary of the controller's state, the plain-language reason behind an
// Argo operation error, and field-level drift between desired and live
// manifests. It is pure (no cluster access) so the agent and the hub can both
// import it; each caller maps these facts onto its own output shape.
package gitopsinsight

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// FailureClass names a recognised Argo operation-error pattern. The set is
// closed; an unrecognised message yields FailureClassUnrecognized and the
// caller still surfaces the raw text.
type FailureClass string

const (
	FailureClassNamespaceNotFound      FailureClass = "namespaceNotFound"
	FailureClassAnnotationsTooLong     FailureClass = "annotationsTooLong"
	FailureClassLabelsTooLong          FailureClass = "labelsTooLong"
	FailureClassWebhookUnreachable     FailureClass = "webhookUnreachable"
	FailureClassHookFailed             FailureClass = "hookFailed"
	FailureClassAdmissionDenied        FailureClass = "admissionDenied"
	FailureClassRBACForbidden          FailureClass = "rbacForbidden"
	FailureClassAlreadyExists          FailureClass = "alreadyExists"
	FailureClassNoMatchesForKind       FailureClass = "noMatchesForKind"
	FailureClassClusterUnreachable     FailureClass = "clusterUnreachable"
	FailureClassFieldImmutable         FailureClass = "fieldImmutable"
	FailureClassUnableToRecognize      FailureClass = "unableToRecognize"
	FailureClassConcurrentModification FailureClass = "concurrentModification"
	FailureClassUnrecognized           FailureClass = "unrecognized"
)

// ParsedFailure carries the structure extracted from an Argo
// status.operationState.message. It only adds structure: the raw message stays
// the caller's to show, because a pattern match is an interpretation.
type ParsedFailure struct {
	Class FailureClass `json:"class"`
	// Cause is the plain-language reading of Class; empty when unrecognised.
	Cause        string `json:"cause,omitempty"`
	AffectedKind string `json:"affectedKind,omitempty"`
	AffectedName string `json:"affectedName,omitempty"`
	// MissingNamespace is set for FailureClassNamespaceNotFound: the namespace
	// the Application targets that does not exist.
	MissingNamespace string `json:"missingNamespace,omitempty"`
	RetryCount       int    `json:"retryCount,omitempty"`
	// Stuck is true once Argo's retry count reaches StuckRetryThreshold: the
	// controller has exhausted its default retry budget and will not recover
	// on its own.
	Stuck bool `json:"stuck,omitempty"`
}

// StuckRetryThreshold is Argo's default retry limit. A failure that has used
// it up will not clear without someone acting.
const StuckRetryThreshold = 5

var (
	// A named object in an error: Kind, optionally .group, then the quoted
	// name — `Service "billing"`, `Job.batch "migrate"`. The group is not
	// kept; kind and name are what a reader recognises.
	objectRefRE = regexp.MustCompile(`\b([A-Z][A-Za-z0-9]*)(?:\.[A-Za-z0-9.-]+)?\s+"([^"]+)"`)
	// The "(retried N times)" Argo appends once its retry policy has run.
	retriedRE = regexp.MustCompile(`\(retried (\d+) times?\)`)
	// The namespace an apply needed that was not there.
	missingNamespaceRE = regexp.MustCompile(`namespaces "([^"]+)" not found`)
	// One gRPC transport wrapper, "rpc error: code = X desc = ".
	grpcWrapperRE = regexp.MustCompile(`(?i)rpc error:\s*code\s*=\s*\S+\s+desc\s*=\s*`)
)

// signatures recognise Argo operation errors, first match winning, so the
// narrower reading of a message always comes before a broader one: the
// missing namespace before anything else that says "not found", an
// unreachable webhook before the hook patterns (whose \bhook\b cannot match
// inside "webhook"), "no matches for kind" before "unable to recognize".
var signatures = []struct {
	class FailureClass
	re    *regexp.Regexp
	cause string
}{
	{FailureClassNamespaceNotFound, missingNamespaceRE,
		"The Application deploys into a namespace that does not exist. Create the namespace, or add CreateNamespace=true to the Application's syncOptions so Argo creates it."},
	{FailureClassAnnotationsTooLong, regexp.MustCompile(`metadata\.annotations: *Too long`),
		"The manifest's annotations are over Kubernetes' 256 KB total — usually client-side apply storing a large object in last-applied-configuration. Use server-side apply (ServerSideApply=true) or trim the annotation."},
	{FailureClassLabelsTooLong, regexp.MustCompile(`metadata\.labels: *Too long`),
		"A label is over Kubernetes' length limit: 63 characters for the name part of a key and for a value. Shorten it."},
	{FailureClassWebhookUnreachable, regexp.MustCompile(`(?i)(failed (calling|to call) webhook|webhook\b).*(no endpoints available|connection refused|i/o timeout|context deadline exceeded|no route to host|EOF)`),
		"The API server could not reach an admission webhook to check the apply: the webhook's Service has no ready endpoints or does not answer. The controller that serves the webhook is probably down — look at its Deployment and Service."},
	{FailureClassHookFailed, regexp.MustCompile(`(?i)\b(presync|sync|postsync|syncfail|postdelete)\b.*\b(hook|phase)\b.*\b(failed|error)`),
		"A sync hook failed. The hook's Job or Pod has the events and logs that say why."},
	{FailureClassHookFailed, regexp.MustCompile(`(?i)\bhook\b.*\bfailed\b`),
		"A sync hook failed. The hook's Job or Pod has the events and logs that say why."},
	{FailureClassAdmissionDenied, regexp.MustCompile(`admission webhook "[^"]*" denied the request`),
		"An admission webhook refused the apply. Its message says which policy; change the manifest to satisfy it, or the policy."},
	{FailureClassRBACForbidden, regexp.MustCompile(`is forbidden: *User`),
		"Kubernetes RBAC refused the request: the Argo CD controller's ServiceAccount is not allowed to do this to this resource."},
	{FailureClassAlreadyExists, regexp.MustCompile(`already exists`),
		"Something of the same kind and name already exists — made by hand, or managed by another Application — so Argo cannot create its own."},
	{FailureClassNoMatchesForKind, regexp.MustCompile(`no matches for kind`),
		"The cluster has no CustomResourceDefinition for this kind. Install the operator that provides it, or sync it first (a sync wave)."},
	{FailureClassClusterUnreachable, regexp.MustCompile(`(?i)dial tcp.*(i/o timeout|connection refused|no route to host)`),
		"The Argo CD controller cannot reach the destination cluster's API server. Check the network path and the cluster's registered address."},
	{FailureClassFieldImmutable, regexp.MustCompile(`field is immutable`),
		"The change edits a field Kubernetes does not allow to change after creation. Revert it, or replace the object (Replace=true, or delete and sync)."},
	{FailureClassUnableToRecognize, regexp.MustCompile(`unable to recognize`),
		"The cluster does not serve the manifest's apiVersion for its kind. Check the apiVersion against what the cluster has installed."},
	{FailureClassConcurrentModification, regexp.MustCompile(`Operation cannot be fulfilled.*the object has been modified`),
		"Something else changed the object between Argo's read and its write. Usually the next attempt succeeds; if it keeps happening, another controller is fighting Argo over the object."},
}

// ParseArgoOperationError reads an Argo status.operationState.message. An
// empty message gives the zero value; one no signature recognises is
// FailureClassUnrecognized, still with whatever object, retry and namespace
// facts the text holds.
func ParseArgoOperationError(msg string) ParsedFailure {
	if msg == "" {
		return ParsedFailure{}
	}
	out := ParsedFailure{Class: FailureClassUnrecognized}
	for _, sig := range signatures {
		if sig.re.MatchString(msg) {
			out.Class, out.Cause = sig.class, sig.cause
			break
		}
	}
	if m := objectRefRE.FindStringSubmatch(msg); m != nil && !isHTTPVerb(m[1]) {
		out.AffectedKind, out.AffectedName = m[1], m[2]
	}
	if m := retriedRE.FindStringSubmatch(msg); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			out.RetryCount, out.Stuck = n, n >= StuckRetryThreshold
		}
	}
	if m := missingNamespaceRE.FindStringSubmatch(msg); m != nil {
		out.MissingNamespace = m[1]
	}
	return out
}

// CleanArgoControllerMessage removes the gRPC wrappers ("rpc error: code = X
// desc = ") Argo nests around its messages and keeps every layer of
// explanation between them. If nothing would be left, the original text is
// returned instead.
func CleanArgoControllerMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if cleaned := strings.TrimLeft(strings.TrimSpace(grpcWrapperRE.ReplaceAllString(msg, "")), " :"); cleaned != "" {
		return cleaned
	}
	return msg
}

// CleanArgoControllerMessageWithRaw is CleanArgoControllerMessage plus the
// original, which is returned only when cleaning changed it.
func CleanArgoControllerMessageWithRaw(msg string) (cleaned, raw string) {
	msg = strings.TrimSpace(msg)
	if cleaned = CleanArgoControllerMessage(msg); cleaned != msg {
		raw = msg
	}
	return cleaned, raw
}

// isHTTPVerb rejects a request line (`PATCH "https://..."`) read as an object.
func isHTTPVerb(s string) bool {
	return slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, strings.ToUpper(s))
}

// SeverityForConditionType rates an Application status.conditions[].type by
// Argo's own naming: a type ending in Error is critical, one ending in
// Warning a warning. Anything else is info with recognized false, so a caller
// can leave out an unknown type that has nothing to say.
func SeverityForConditionType(condType string) (token string, recognized bool) {
	if strings.HasSuffix(condType, "Error") {
		return "critical", true
	}
	if strings.HasSuffix(condType, "Warning") {
		return "warning", true
	}
	return "info", false
}

// conditionActions is what to do about each Application condition type ARGUS
// knows.
var conditionActions = map[string]string{
	"ComparisonError":         "Argo could not render or compare the source. Check the repository URL, the revision and its credentials, and look in the argocd-repo-server logs for the fetch or render error.",
	"InvalidSpecError":        "The Application spec itself is wrong: check its destination, its source and the AppProject it names.",
	"SyncError":               "The last sync failed. Its operation message says why; fix that and sync again.",
	"OrphanedResourceWarning": "The destination namespace holds objects no Application declares. Bring them under an Application, or mark them to be ignored.",
	"RepeatedResourceWarning": "The same object is declared more than once in this Application's source. Keep one declaration.",
	"ExcludedResourceWarning": "A declared object is of a kind the Argo controller is configured to exclude (resource.exclusions), so it is never synced. Change the exclusion or drop the object.",
	"SharedResourceWarning":   "Another Application also tracks this object. Give it one owner.",
}

// ActionForCondition is the guidance for an Application condition type, or ""
// for a type without any.
func ActionForCondition(condType string) string { return conditionActions[condType] }

// fluxActions is what to do about each Flux Ready reason ARGUS knows.
var fluxActions = map[string]string{
	"DependencyNotReady": "This object waits for everything in its spec.dependsOn to be Ready; look at those first.",
	"ArtifactFailed":     "The source could not produce an artifact. Look at the Flux source object (GitRepository, OCIRepository, HelmRepository) and reconcile it.",
	"ChartNotReady":      "The Helm chart is not available yet. Look at the HelmChart and its source, and reconcile them.",
	"BuildFailed":        "Rendering the manifests failed. Check that the path exists in the source and that its kustomization builds.",
	"HealthCheckFailed":  "Applied, but the health checks did not pass in time. Open the unhealthy objects for their events and status.",
	"InstallFailed":      "The Helm install failed. The HelmRelease's conditions and the helm-controller's events give the Helm error.",
	"UpgradeFailed":      "The Helm upgrade failed. The HelmRelease's conditions and the helm-controller's events give the Helm error.",
	"TestFailed":         "The release's Helm tests failed. Look at the test pods' logs.",
}

// ActionForFluxReason is the guidance for a Flux condition reason; a reason
// without its own gets general advice, never "".
func ActionForFluxReason(reason string) string {
	if a, ok := fluxActions[reason]; ok {
		return a
	}
	return "Read the object's conditions and events for the cause, fix it at the source, then reconcile."
}
