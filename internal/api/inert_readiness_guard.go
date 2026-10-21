package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"argus/internal/gitops"
	"argus/internal/logging"
)

// BUGS.md 114: a confidence-0.95, AutoApprove-gated OpenPR plan raised a
// readinessProbe's failureThreshold from 1 to 180 to "fix" a Pod that had
// never once passed that probe — a change with zero effect on when the Pod
// actually becomes Ready, because failureThreshold only governs the
// transition FROM an already-Ready container back to NotReady. The plan was
// safe, reversible, and completely inert, and it sailed through the gate
// because that gate's three conditions (reversible, risk low, confidence
// above threshold) are entirely about the SAFETY of applying a change, never
// about whether applying it accomplishes anything.
//
// internal/gitops/probe_threshold.go is the mechanical, cluster-independent
// half of this fix: detecting, from a whole-file OpenPR edit, that a named
// container's readinessProbe.failureThreshold is being raised — see that
// file's header for why this is scoped to readinessProbe and not
// livenessProbe, which does not share the property this guard depends on.
// This file is the other half: deciding, from a LIVE cluster read, whether
// the specific container a raise targets has ever actually passed its
// readiness probe, which is what makes a detected raise inert or not.
//
// # Where this is wired in, and where it deliberately is not
//
// Only proposeFromApprovedPlan (the OpenPR execution path a human approves a
// MODEL's plan through) calls checkReadinessThresholdNotInert. That is a
// narrower footprint than "every route that can open a pull request":
// handleOpenRepositoryChange (the self-service endpoint where a human types
// or pastes the file content themselves) is deliberately left uncovered —
// BUGS.md 114 is about a model's plan being auto-evaluated as safe and an
// operator trusting that evaluation, not about a human who is already
// directly authoring the diff they are about to open a pull request for.
// execution.PreparePlan's PatchField/StructuredPatch execution path is also not
// touched: readinessProbe/livenessProbe fields are not in
// internal/remediation/patchfield.go's allowlist at all today, and that
// action type is kept off the model's tool dispatch entirely (F11) — there
// is no live path through which a PatchField plan could carry this field, so
// a guard there would be unreachable code, not future-proofing.
//
// # Why this can refuse outright rather than only floor risk
//
// BUGS.md 114 offers "refuse the plan, or at minimum floor its risk higher,
// forcing human review" as the two acceptable shapes for this fix. OpenPR
// already requires a human to call the approve endpoint before this function
// runs in this build (see argus-context's "Current delivery phase": the
// unattended executor reaches exactly one action type, ScaleDeployment, under
// default policy) — flooring the risk of a plan a human is already the one
// approving would change nothing about what happens next. A hard refusal at
// the point the pull request would otherwise be opened is the version of
// this fix that actually stops the reported scenario from recurring.

// errInertReadinessThresholdRefused is the sentinel behind the refusal below.
// Deliberately its own type, wrapping neither gitops.ErrVerificationFailed
// nor any other existing sentinel: openPRRefusalCorrectionEligible
// (openpr_correction.go) keys the one-shot model-correction retry to
// errors.Is(err, gitops.ErrVerificationFailed) specifically, and a refusal
// here must NOT be eligible for that retry. The correction mechanism exists
// for malformed CONTENT a model could plausibly re-author correctly; this
// refusal is about a semantically inert field choice, and letting the same
// model re-guess a number at the field it already got wrong is exactly the
// "narrow verification becoming the request grammar" this codebase's own
// conventions warn against — a human needs to look again, not get a second
// automated guess.
var errInertReadinessThresholdRefused = errors.New("refusing a pull request that raises a readinessProbe failureThreshold against a container that has never once passed its readiness probe")

// maxReadinessGuardPods bounds how many live pods this check reads per
// container raise. A cost bound, not a security boundary: a workload with
// more replicas than this either has enough OTHER live pods to answer the
// question, or is large enough that reading every replica on an approval
// path would be disproportionate to what this check is for.
const maxReadinessGuardPods = 20

// checkReadinessThresholdNotInert scans every changed file for a raised
// readinessProbe.failureThreshold (internal/gitops.DetectReadinessFailureThresholdRaises)
// and, for each one found, checks live cluster state to see whether the
// named container has ever actually passed its readiness probe. Returns a
// wrapped errInertReadinessThresholdRefused for the first raise it can
// positively confirm is inert.
//
// Best-effort in the direction that matters for not blocking a legitimate
// change: whenever the live check cannot positively confirm inertness (no
// live pods found, more than one container in a pod so the aggregate Ready
// condition cannot be attributed to one of them, a gateway call fails), this
// proceeds as if there were nothing to refuse. A guard whose false positives
// block real fixes is worse than one that occasionally lets the reported
// scenario's exact shape through unblocked when the live state genuinely
// cannot be read — the live rke2 reproduction this fix was verified against
// is squarely the case this DOES catch.
func (s *Server) checkReadinessThresholdNotInert(ctx context.Context, clusterID string, object gitops.ObjectRef, changed []gitops.FileChange) error {
	for _, f := range changed {
		for _, raise := range gitops.DetectReadinessFailureThresholdRaises(f.Original, f.Content, object) {
			inert, checked, err := s.readinessRaiseIsInert(ctx, clusterID, object, raise.ContainerName)
			if err != nil {
				logger.WarnContext(ctx, "could not verify a container against live state; proceeding without the inert-readiness guard",
					slog.String("container", raise.ContainerName), slog.String("kind", object.Kind),
					slog.String("namespace", object.Namespace), slog.String("name", object.Name), logging.Err(err))
				continue
			}
			if !checked || !inert {
				continue
			}
			return fmt.Errorf("%w: %s proposes raising container %q's readinessProbe.failureThreshold from %d to %d, but that container has never once passed its readiness probe on the live cluster. failureThreshold only governs the transition from an ALREADY-Ready container back to NotReady — every failure before the first success is absorbed identically regardless of this value, so this change would not affect when the container actually becomes Ready. If the container is genuinely slow to start, the fix is a longer initialDelaySeconds/periodSeconds or a startupProbe, not a higher failureThreshold",
				errInertReadinessThresholdRefused, f.Path, raise.ContainerName, raise.OldValue, raise.NewValue)
		}
	}
	return nil
}

// readinessRaiseIsInert is checkReadinessThresholdNotInert's live-read half,
// split out so the decision logic below (readinessNeverSucceeded) stays a
// pure function a unit test can drive with a hand-built livePodStatus,
// matching this package's established split between a live gateway call and
// the pure interpretation of its result (interpretAbsenceCheckResult,
// interpretDryRunResult).
//
// checked reports whether at least one live pod could be positively
// evaluated for containerName at all; inert is only meaningful when checked
// is true.
func (s *Server) readinessRaiseIsInert(ctx context.Context, clusterID string, object gitops.ObjectRef, containerName string) (inert, checked bool, err error) {
	pods, err := s.livePodsForWorkload(ctx, clusterID, object)
	if err != nil {
		return false, false, err
	}
	for _, p := range pods {
		status, ferr := s.describeLivePodStatus(ctx, clusterID, p.namespace, p.name)
		if ferr != nil {
			logger.WarnContext(ctx, "describing a pod for the inert-readiness guard failed",
				slog.String("namespace", p.namespace), slog.String("name", p.name), logging.Err(ferr))
			continue
		}
		never, known := status.readinessNeverSucceeded(containerName)
		if !known {
			continue
		}
		checked = true
		if never {
			return true, true, nil
		}
	}
	return false, checked, nil
}

// liveObjectRef is a bare namespace/name pair for a live lookup — narrower
// than gitops.ObjectRef, which also carries the GVK identity this doesn't
// need once it already knows it is naming a Pod.
type liveObjectRef struct {
	namespace string
	name      string
}

// livePodsForWorkload resolves the live Pod(s) behind object: object itself
// when it already IS a Pod, otherwise every Pod matching the live object's
// own spec.selector.matchLabels.
//
// Reads object's live spec fresh via the same describe_resource tool
// fetchPreconditionWithObject uses — the incident's stored belief about this
// object may be stale by the time a plan is approved, and this check exists
// specifically to compare against CURRENT live state, not a remembered one.
func (s *Server) livePodsForWorkload(ctx context.Context, clusterID string, object gitops.ObjectRef) ([]liveObjectRef, error) {
	if strings.EqualFold(object.Kind, "Pod") {
		return []liveObjectRef{{namespace: object.Namespace, name: object.Name}}, nil
	}
	if object.APIVersion == "" || object.Name == "" {
		return nil, fmt.Errorf("no usable GVK/name for %+v", object)
	}
	gvk := object.APIVersion + "/" + object.Kind
	_, spec, _, err := s.exec().FetchPreconditionWithObject(ctx, clusterID, gvk, object.Namespace, object.Name)
	if err != nil {
		return nil, fmt.Errorf("read live %s %s/%s: %w", object.Kind, object.Namespace, object.Name, err)
	}
	selector, ok := matchLabelsSelector(spec)
	if !ok {
		return nil, fmt.Errorf("%s %s/%s has no spec.selector.matchLabels to find its live pods with", object.Kind, object.Namespace, object.Name)
	}
	argsJSON, err := json.Marshal(map[string]any{
		"kind": "Pod", "namespace": object.Namespace, "labelSelector": selector, "limit": maxReadinessGuardPods,
	})
	if err != nil {
		return nil, fmt.Errorf("build list_resources args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "list_resources", argsJSON)
	if err != nil {
		return nil, fmt.Errorf("list pods for %s %s/%s: %w", object.Kind, object.Namespace, object.Name, err)
	}
	var result struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("decode list_resources result: %w", err)
	}
	out := make([]liveObjectRef, 0, len(result.Items))
	for _, it := range result.Items {
		out = append(out, liveObjectRef{namespace: object.Namespace, name: it.Name})
	}
	return out, nil
}

// matchLabelsSelector renders spec.selector.matchLabels (already decoded into
// a plain map[string]any by fetchPreconditionWithObject) as a comma-joined
// "k=v" label selector, sorted so the result is deterministic. ok is false
// when there is no usable selector to build — absent, empty, or holding a
// non-string value this convention does not expect — which the caller treats
// as "cannot find this workload's pods," not as an empty-selector match-all.
func matchLabelsSelector(spec map[string]any) (string, bool) {
	selector, ok := spec["selector"].(map[string]any)
	if !ok {
		return "", false
	}
	matchLabels, ok := selector["matchLabels"].(map[string]any)
	if !ok || len(matchLabels) == 0 {
		return "", false
	}
	keys := make([]string, 0, len(matchLabels))
	for k := range matchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok := matchLabels[k].(string)
		if !ok {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ","), true
}

// livePodStatus is the narrow slice of a live Pod's status this guard reads:
// its containers' names (to know whether the pod-level Ready condition can be
// attributed to a single, specific container), and the readiness signal
// itself.
type livePodStatus struct {
	containerNames []string
	creationTime   time.Time
	startTime      *time.Time
	// readyStatus/readyLastTransition come from status.conditions, preferring
	// ContainersReady (purely about container probes) and falling back to
	// Ready (also gated on any pod readiness gates) when a live object
	// reports no ContainersReady condition at all. readyStatus is "" when
	// neither condition is present.
	readyStatus         string
	readyLastTransition time.Time
}

// describeLivePodStatus reads one Pod via the same read-only describe_resource
// tool every other precondition fetch in this package uses, and reduces it to
// the fields readinessNeverSucceeded needs.
func (s *Server) describeLivePodStatus(ctx context.Context, clusterID, namespace, name string) (livePodStatus, error) {
	_, _, live, err := s.exec().FetchPreconditionWithObject(ctx, clusterID, "v1/Pod", namespace, name)
	if err != nil {
		return livePodStatus{}, err
	}
	return decodeLivePodStatus(live)
}

// decodeLivePodStatus is describeLivePodStatus's decoding, split out so it is
// directly unit-testable against a hand-built describe_resource payload
// without a live gateway — the same testability reason
// fetchPreconditionWithObject's own callers elsewhere in this package split
// live I/O from decoding.
func decodeLivePodStatus(raw json.RawMessage) (livePodStatus, error) {
	var obj struct {
		Metadata struct {
			CreationTimestamp time.Time `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			Containers []struct {
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			StartTime  *time.Time `json:"startTime,omitempty"`
			Conditions []struct {
				Type               string    `json:"type"`
				Status             string    `json:"status"`
				LastTransitionTime time.Time `json:"lastTransitionTime"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return livePodStatus{}, fmt.Errorf("decode pod status: %w", err)
	}
	out := livePodStatus{creationTime: obj.Metadata.CreationTimestamp, startTime: obj.Status.StartTime}
	for _, c := range obj.Spec.Containers {
		out.containerNames = append(out.containerNames, c.Name)
	}
	var haveReady, haveContainersReady bool
	var readyStatus, containersReadyStatus string
	var readyTransition, containersReadyTransition time.Time
	for _, c := range obj.Status.Conditions {
		switch c.Type {
		case "Ready":
			readyStatus, readyTransition, haveReady = c.Status, c.LastTransitionTime, true
		case "ContainersReady":
			containersReadyStatus, containersReadyTransition, haveContainersReady = c.Status, c.LastTransitionTime, true
		}
	}
	switch {
	case haveContainersReady:
		out.readyStatus, out.readyLastTransition = containersReadyStatus, containersReadyTransition
	case haveReady:
		out.readyStatus, out.readyLastTransition = readyStatus, readyTransition
	}
	return out, nil
}

// readinessTransitionTolerance is how close a Ready/ContainersReady
// condition's lastTransitionTime must be to the pod's own start reference to
// count as "never transitioned since creation" — i.e. never having been
// Ready. Generous on purpose: kubelet does not set a Pod's initial
// conditions at the exact instant of metadata.creationTimestamp (API object
// acceptance) or status.startTime (first container start) — scheduling and
// image pulls add real seconds — so a tight tolerance would misread an
// ordinary startup delay as a transition that already happened. This is a
// heuristic, verified only against the derivation in BUGS.md 114's own
// write-up and general Kubernetes condition semantics, not a documented
// Kubernetes constant.
const readinessTransitionTolerance = 2 * time.Minute

// readinessNeverSucceeded reports whether containerName's readiness has
// never once succeeded, using the pod-level Ready/ContainersReady condition
// as a proxy for that one container's own probe history.
//
// (never, known). known is false whenever the pod-level signal cannot be
// trusted for THIS container specifically:
//
//   - the pod has more than one container: ContainersReady/Ready is an
//     AGGREGATE across every container in the pod, and a live Pod's
//     containerStatuses carries no per-container transition history to
//     disambiguate which container a False aggregate is actually about —
//     Kubernetes has no first-class "has this specific container ever been
//     ready" field. Rather than guess which container is at fault in a
//     multi-container pod, this reports unknown and lets the caller skip it.
//   - the pod's one container is not even the one named — nothing to say
//     about a different container from this pod.
//   - the pod reports no Ready/ContainersReady condition at all (very early
//     in scheduling, or an agent/API shape this did not anticipate).
//
// When known is true, the mechanical signal is exactly BUGS.md 114's own
// derivation: a container's Ready condition starts False at pod creation and
// its lastTransitionTime only moves when the condition's VALUE flips.
//
//   - Currently True: the container has obviously been ready. Not never.
//   - Currently False and lastTransitionTime is still within
//     readinessTransitionTolerance of the pod's own start reference: the
//     condition has never flipped at all since creation — never succeeded.
//     This is the reported fixture's exact shape.
//   - Currently False and lastTransitionTime is materially LATER than the
//     start reference: the condition must have flipped at least twice
//     (False->True->False) to be False again now, which proves the
//     container WAS ready at some point. Deliberately treated as "not
//     never" — this is the legitimate flapping-probe-tolerance-increase case
//     BUGS.md 114 asks to leave alone.
func (p livePodStatus) readinessNeverSucceeded(containerName string) (never, known bool) {
	if len(p.containerNames) != 1 || p.containerNames[0] != containerName {
		return false, false
	}
	if p.readyStatus == "" {
		return false, false
	}
	if p.readyStatus == "True" {
		return false, true
	}
	ref := p.creationTime
	if p.startTime != nil && p.startTime.After(ref) {
		ref = *p.startTime
	}
	if ref.IsZero() {
		return false, false
	}
	delta := p.readyLastTransition.Sub(ref)
	if delta < 0 {
		delta = -delta
	}
	return delta <= readinessTransitionTolerance, true
}
