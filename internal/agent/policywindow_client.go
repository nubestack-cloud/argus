package agent

// policywindow_client.go builds the THIRD, independent Kubernetes client
// BACKLOG.md F14 needs: one authenticated as the opt-in argus-policy-controller
// ServiceAccount, never as whatever identity this agent Deployment's own
// serviceAccountName resolves to, and never as the argus-dryrun identity
// dryrun_client.go already builds a second one for.
//
// WHY A THIRD IDENTITY RATHER THAN FOLDING INTO ANY EXISTING ONE
//
// argus-policy-controller's entire reason to exist is that its RBAC is
// exactly one thing — get/list/watch/create/update/patch/delete on
// argus.io/v1 ExecutionWindow objects, and NOTHING on any workload resource —
// which is a materially DIFFERENT grant shape from both existing identities:
// argus-investigate is read-only on workloads and has no write verb
// anywhere; argus-remediate can write a handful of specific workload fields
// but has no RBAC on ValidatingAdmissionPolicy/ValidatingAdmissionPolicyBinding
// or on this CRD at all. Folding this grant into either would either widen
// argus-investigate into a write-capable identity (breaking non-negotiable 1)
// or hand argus-remediate the ability to widen its OWN admission-policy
// bound, which is precisely the "a compromised hub can loosen the one control
// that assumed it might be compromised" shape F14 exists to avoid. See
// deploy/helm/argus-agent/templates/policycontroller.yaml's header for the
// RBAC itself.
//
// Mirrors dryrun_client.go's shape exactly (a second, later-added Secret
// volume mounted into the SAME agent Pod, dispatched over the SAME
// ToolRequest/ToolResult channel, only the credential used for this one
// client differs) — see that file's own header for why a manually-created
// service-account-token Secret, not a projected volume, is the right
// mechanism for a credential belonging to a ServiceAccount other than the
// pod's own.
import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// policyControllerTokenFileName / policyControllerCAFileName mirror
// dryrun_client.go's dryRunTokenFileName/dryRunCAFileName — the standard key
// names a "kubernetes.io/service-account-token" Secret populates.
const (
	policyControllerTokenFileName = "token"
	policyControllerCAFileName    = "ca.crt"
)

// executionWindowGVR identifies the argus.io/v1 ExecutionWindow CRD
// (deploy/helm/argus-agent/templates/executionwindow-crd.yaml) — cluster
// scoped, so callers never call .Namespace() on the resource interface built
// from it.
var executionWindowGVR = schema.GroupVersionResource{Group: "argus.io", Version: "v1", Resource: "executionwindows"}

// executionWindowSingletonName is the one ExecutionWindow object this agent
// ever reads or writes — see internal/agent/policywindow.go's header for why
// a single, list-valued object (rather than one object per open window) is
// this feature's chosen shape.
const executionWindowSingletonName = "argus-execution-windows"

// loadPolicyControllerConfig is loadDryRunConfig's exact structure, retargeted
// at the policy-controller token directory. Three outcomes, deliberately not
// collapsed: tokenDir == "" means this cluster never opted into the pack
// (nil, nil); tokenDir set but unreadable is a real misconfiguration (nil,
// err); tokenDir set and readable builds a *rest.Config from THAT token only,
// consulting baseCfg solely for the API server host/CA.
func loadPolicyControllerConfig(baseCfg *rest.Config, tokenDir string) (*rest.Config, error) {
	if tokenDir == "" {
		return nil, nil
	}
	tokenPath := filepath.Join(tokenDir, policyControllerTokenFileName)
	if _, err := os.Stat(tokenPath); err != nil {
		return nil, fmt.Errorf("argus-policy-controller token file %s: %w", tokenPath, err)
	}

	cfg := rest.CopyConfig(baseCfg)
	cfg.BearerToken = ""
	cfg.BearerTokenFile = tokenPath

	caPath := filepath.Join(tokenDir, policyControllerCAFileName)
	if _, err := os.Stat(caPath); err == nil {
		cfg.TLSClientConfig.CAFile = caPath
		cfg.TLSClientConfig.CAData = nil
	}
	return cfg, nil
}

// newPolicyControllerDynamicClient is newToolExecutor's policy-controller
// half: builds the dynamic client open_execution_window/close_execution_window
// submit through, or (nil, nil) when this cluster never opted in. Mirrors
// newDryRunDynamicClient exactly.
func newPolicyControllerDynamicClient(tokenDir string) (dynamic.Interface, error) {
	if tokenDir == "" {
		return nil, nil
	}
	baseCfg, err := loadKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("no reachable cluster config for the policy-controller identity either: %w", err)
	}
	pcCfg, err := loadPolicyControllerConfig(baseCfg, tokenDir)
	if err != nil {
		return nil, err
	}
	if pcCfg == nil {
		return nil, nil
	}
	dyn, err := dynamic.NewForConfig(pcCfg)
	if err != nil {
		return nil, fmt.Errorf("build argus-policy-controller dynamic client: %w", err)
	}
	return dyn, nil
}

// errPolicyControllerNotConfigured is returned whenever open_execution_window/
// close_execution_window are called but this cluster never mounted an
// argus-policy-controller credential. Mirrors errDryRunNotConfigured's own
// defence-in-depth reasoning: internal/api never calls these tools unless a
// plan actually needs one (internal/remediation.FieldPathNeedsExecutionWindow),
// but a misconfigured or older cluster must still get a clean, honest answer
// server-side rather than a nil-pointer panic.
var errPolicyControllerNotConfigured = fmt.Errorf("this cluster has not enabled the argus-policy-controller pack (deploy/helm/argus-agent values.yaml's policyController.enabled) — per-execution admission-policy widening is unavailable here, so any plan needing it will be refused before execution")

// executionWindowResource is the cluster-scoped resource interface for the
// ExecutionWindow CRD, built fresh from e.policyDynamic on every call —
// cheap (no state beyond the client itself) and avoids one more field to
// keep in sync with policyDynamic's own nil-ness.
func (e *ToolExecutor) executionWindowResource() dynamic.ResourceInterface {
	return e.policyDynamic.Resource(executionWindowGVR)
}

// policyControllerReachable reports whether this ToolExecutor can talk to
// the ExecutionWindow CRD at all — a nil e or nil e.policyDynamic both mean
// "not configured", checked once here rather than at every call site.
func (e *ToolExecutor) policyControllerReachable() bool {
	return e != nil && e.policyDynamic != nil
}
