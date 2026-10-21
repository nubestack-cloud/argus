package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"argus/internal/remediation"
)

// ---------------------------------------------------------------- upgrade_agent
//
// Moves this cluster's agent onto a new image (PROJECT.md AD10). Served only
// by the remediate identity (tunnel.writeToolRoles), whose chart Role names
// exactly the two agent Deployments, and only when the chart enabled it,
// which also sets the one image repository an upgrade may come from. The
// request is a hub-signed plan targeting the investigate Deployment with its
// resourceVersion, so a forged or replayed request is refused before any
// write. Only the `agent` container's image changes; the existing admission
// policy on this identity already refuses any other field.

var imageRefPattern = regexp.MustCompile(`^[a-z0-9]+([._/-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*(@sha256:[a-f0-9]{64}|:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$`)

// upgradeImagePermitted reports whether image is a well-formed reference in
// the one repository this cluster's chart allows upgrades from.
func upgradeImagePermitted(image, allowedRepo string) error {
	if allowedRepo == "" {
		return errors.New("self-upgrade is not enabled on this cluster's agent chart (selfUpgrade.enabled)")
	}
	if !imageRefPattern.MatchString(image) {
		return fmt.Errorf("%q is not an image reference", image)
	}
	if !strings.HasPrefix(image, allowedRepo+"@") && !strings.HasPrefix(image, allowedRepo+":") {
		return fmt.Errorf("image %q is not from the repository this chart allows upgrades from", image)
	}
	return nil
}

func (e *ToolExecutor) upgradeAgent(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, remediation.ActionUpgradeAgent)
	if err != nil {
		return nil, false, err
	}
	if gvr.Resource != "deployments" {
		return nil, false, fmt.Errorf("upgrade_agent targets a Deployment, not %q", gvr.Resource)
	}
	var params struct {
		Image           string `json:"image"`
		RemediateName   string `json:"remediateDeployment"`
		InvestigateName string `json:"investigateDeployment"`
	}
	if err := json.Unmarshal(plan.Params, &params); err != nil {
		return nil, false, fmt.Errorf("invalid upgrade params: %w", err)
	}
	if err := upgradeImagePermitted(params.Image, os.Getenv("ARGUS_SELF_UPGRADE_REPOSITORY")); err != nil {
		return nil, false, err
	}
	ns := os.Getenv("ARGUS_POD_NAMESPACE")
	if ns == "" || plan.TargetNamespace != ns || plan.TargetName != params.InvestigateName {
		return nil, false, errors.New("upgrade_agent may only change this agent's own Deployments")
	}
	containerPatch := func(rv string) ([]byte, error) {
		body := map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "agent", "image": params.Image}}}}}}
		if rv != "" {
			body["metadata"] = map[string]any{"resourceVersion": rv}
		}
		return json.Marshal(body)
	}
	// A named field manager, so the conflict Helm 4's server-side apply reports
	// on the next `helm upgrade` says what changed the image. That upgrade
	// needs --force-conflicts, after which the chart's value wins again.
	opts := metav1.PatchOptions{FieldManager: "argus-hub-upgrade"}
	if plan.DryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	// The investigate Deployment first, under the signed precondition; this
	// remediate Deployment last, because patching it restarts this process.
	p, err := containerPatch(plan.ResourceVersion)
	if err != nil {
		return nil, false, err
	}
	patched, err := e.dynamic.Resource(gvr).Namespace(ns).Patch(ctx, params.InvestigateName, types.StrategicMergePatchType, p, opts)
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	if params.RemediateName != "" {
		p, err := containerPatch("")
		if err != nil {
			return nil, false, err
		}
		if _, err := e.dynamic.Resource(gvr).Namespace(ns).Patch(ctx, params.RemediateName, types.StrategicMergePatchType, p, opts); err != nil {
			return nil, false, sanitizeK8sErr(err)
		}
	}
	return marshalInsight(map[string]any{"image": params.Image, "resourceVersion": patched.GetResourceVersion(), "dryRun": plan.DryRun})
}
