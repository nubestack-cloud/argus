package agent

// dryrun_client.go builds the SECOND, independent Kubernetes client
// BACKLOG.md C4's dry_run_patch half needs: one authenticated as the opt-in
// argus-dryrun ServiceAccount, never as whatever identity this agent
// Deployment's own serviceAccountName resolves to.
//
// WHY THIS CANNOT REUSE THE EXISTING CLIENT
//
// Every other tool in this package (including the four real-write
// remediation actions) runs through ToolExecutor's single typed/dynamic pair,
// built by newToolExecutor from rest.InClusterConfig() — i.e. from whatever
// ONE ServiceAccount token kubelet auto-mounted for this pod's own
// spec.serviceAccountName. deploy/helm/argus-agent/values.yaml's header
// comment already documents that trade-off for argus-remediate: this chart
// runs one agent process under one identity (the union of argus-investigate
// and, when remediate.enabled, argus-remediate's ClusterRole), rather than
// lld/03-agent-protocol.md's fuller two-SA/two-tunnel-connection model.
//
// argus-dryrun cannot be folded into that same union the way argus-remediate
// was. lld/04-rbac-profiles.md §5's ValidatingAdmissionPolicy
// (argus-dryrun-enforce-dryrun) is scoped by EXACT identity
// (matchConditions: request.userInfo.username == ".../argus-dryrun") and
// restricts that identity to dryRun=All requests only. RBAC grants are
// additive: if the same ServiceAccount also held argus-remediate's real,
// unrestricted patch/update grant (a second ClusterRoleBinding, exactly the
// mechanism templates/clusterrolebinding.yaml already uses to union
// argus-investigate onto argus-remediate), one of two things would go wrong
// the moment both packs were enabled together:
//
//   - if the dry-run-only admission policy's matchConditions also match that
//     shared identity's REAL remediation writes, scale_deployment/restart_pod/
//     patch_resource_limits/revert_container_image would start being refused
//     unless they too carried dryRun=All — breaking real remediation; or
//   - if the policy is somehow scoped narrowly enough to avoid that, it is no
//     longer "this identity may only ever submit dryRun=All", it is "this
//     identity may only ever submit dryRun=All FOR THE SPECIFIC REQUESTS WE
//     REMEMBERED TO EXCLUDE ARGUS-REMEDIATE FROM" — a much weaker, easier to
//     get wrong claim, and not what ADR-14 decided.
//
// So argus-dryrun has to be a genuinely separate bearer credential, which
// means a genuinely separate volume mount and a genuinely separate
// *rest.Config — but NOT a second tunnel connection or gateway registry (the
// real, larger, and still-unbuilt piece of infrastructure
// values.yaml's header comment flags as out of scope for argus-remediate).
// dry_run_patch is dispatched over the SAME ToolRequest/ToolResult channel as
// every other investigation tool; only the credential used for the one
// Kubernetes API call this tool makes differs.
//
// HOW THE CREDENTIAL GETS HERE
//
// deploy/helm/argus-agent/templates/dryrun.yaml creates a long-lived
// Secret of type kubernetes.io/service-account-token, annotated for the
// argus-dryrun ServiceAccount — the still-supported (if legacy-flavoured)
// mechanism for minting a durable token for an identity OTHER than the one a
// pod's own spec.serviceAccountName grants it a projected token for (the
// projected serviceAccountToken volume source only ever mints a token for
// the pod's OWN assigned ServiceAccount — there is no way to request one for
// a different SA from inside a pod spec). That Secret is mounted as an
// ordinary Secret volume into this SAME agent Pod (Secret volumes carry no
// such restriction), at Config.DryRunTokenDir, containing "token" and
// "ca.crt" alongside the primary in-cluster identity's own files.
import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"os"
	"path/filepath"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"argus/internal/tunnel"
)

// dryRunTokenFileName / dryRunCAFileName are the two files the long-lived
// SA-token Secret populates that this agent reads. Matches Kubernetes' own
// convention for a "kubernetes.io/service-account-token" Secret's default
// keys (the same "token"/"ca.crt" pair the auto-mounted default token
// carries), so templates/dryrun.yaml needs no custom key mapping.
const (
	dryRunTokenFileName = "token"
	dryRunCAFileName    = "ca.crt"
)

// loadDryRunConfig builds a *rest.Config authenticated as whatever identity
// tokenDir's mounted Secret carries, reusing the primary in-cluster config's
// API server host (and its CA, only as a fallback — see below) since it is
// the same cluster's API server either way.
//
// Three distinct outcomes, deliberately not collapsed into one:
//   - tokenDir == "": this cluster never opted into the pack. Returns
//     (nil, nil, nil) — not an error, the ordinary default state.
//   - tokenDir set but the token file is missing/unreadable: a real
//     misconfiguration (dryRun.enabled was set but the Secret/volume did not
//     come up correctly). Returns (nil, nil, err) so the caller logs it
//     rather than silently behaving as if the pack were simply disabled.
//   - tokenDir set and readable: returns a config built from THAT token, not
//     from baseCfg's own bearer token — baseCfg is consulted only for the
//     API server host/CA, never for the credential itself.
func loadDryRunConfig(baseCfg *rest.Config, tokenDir string) (*rest.Config, error) {
	if tokenDir == "" {
		return nil, nil
	}
	tokenPath := filepath.Join(tokenDir, dryRunTokenFileName)
	if _, err := os.Stat(tokenPath); err != nil {
		return nil, fmt.Errorf("argus-dryrun token file %s: %w", tokenPath, err)
	}

	cfg := rest.CopyConfig(baseCfg)
	// The credential is the mounted Secret's token, and ONLY that — never
	// baseCfg's own bearer token/file, which would silently authenticate as
	// this pod's PRIMARY identity instead of argus-dryrun.
	cfg.BearerToken = ""
	cfg.BearerTokenFile = tokenPath
	// client-go re-reads BearerTokenFile on a timer; nothing else here needs
	// to watch it.

	// Prefer the Secret's own ca.crt when present — it is exactly matched to
	// this mount and is what a real "kubernetes.io/service-account-token"
	// Secret always carries. Fall back to baseCfg's CA (the primary
	// identity's own, same cluster) only if it's absent, rather than failing
	// outright: a hand-built Secret in a test fixture may omit it.
	caPath := filepath.Join(tokenDir, dryRunCAFileName)
	if _, err := os.Stat(caPath); err == nil {
		cfg.TLSClientConfig.CAFile = caPath
		cfg.TLSClientConfig.CAData = nil
	}
	return cfg, nil
}

// newDryRunDynamicClient is newToolExecutor's dry-run half: builds the
// dynamic client dry_run_patch submits through, or (nil, nil) when this
// cluster never opted in. Kept separate from newToolExecutor's main
// construction so both call sites (production and
// NewToolExecutorForTestWithDryRun, for tests that need to exercise a fake
// dry-run identity) share exactly one place this decision is made.
func newDryRunDynamicClient(tokenDir string) (dynamic.Interface, error) {
	if tokenDir == "" {
		return nil, nil
	}
	baseCfg, err := loadKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("no reachable cluster config for the dry-run identity either: %w", err)
	}
	dryCfg, err := loadDryRunConfig(baseCfg, tokenDir)
	if err != nil {
		return nil, err
	}
	if dryCfg == nil {
		return nil, nil
	}
	dyn, err := dynamic.NewForConfig(dryCfg)
	if err != nil {
		return nil, fmt.Errorf("build argus-dryrun dynamic client: %w", err)
	}
	return dyn, nil
}

// dryRunAuthorityChecks is gatherRemediationAuthority's own remediationChecks
// table, narrowed to the one grant that actually decides whether
// dry_run_patch is worth offering: can this identity patch a Deployment at
// all (before the admission policy narrows what that patch may contain).
// Asking about every one of argus-dryrun's four resource kinds would answer
// a finer-grained question nothing downstream uses yet — Target.DryRunAvailable
// is a single bool, not a per-resource-kind map — so this mirrors
// gatherRemediationAuthority's own cluster-scoped, single-verb shape rather
// than inventing a second one.
const (
	dryRunCheckVerb     = "patch"
	dryRunCheckGroup    = "apps"
	dryRunCheckResource = "deployments"
)

// gatherClusterDryRunAuthority asks whether THIS cluster's argus-dryrun
// mount is both present and actually granted RBAC, using the SAME
// discipline gatherRemediationAuthority (facts.go) already established for
// BACKLOG B4: ask the API server directly, report Checked=false (never a
// confident "denied") on anything short of a definite answer, and never
// trust the values.yaml toggle that was supposed to grant it.
//
// Deliberately asks the SelfSubjectAccessReview using the DRY-RUN identity's
// own clientset, not the primary one gatherRemediationAuthority uses —
// SelfSubjectAccessReview answers about "myself", so asking with the wrong
// client would report the wrong identity's authority.
func gatherClusterDryRunAuthority(ctx context.Context, tokenDir string) *tunnel.ClusterDryRun {
	if tokenDir == "" {
		// The ordinary, default case: this cluster never enabled the pack.
		// Checked=false with no Error — not a failure, just "not asked
		// because there is nothing to ask".
		return &tunnel.ClusterDryRun{Checked: false}
	}

	baseCfg, err := loadKubeConfig()
	if err != nil {
		logger.Warn("dry-run authority check: no reachable cluster config", logging.Err(err))
		return &tunnel.ClusterDryRun{Checked: false, Error: err.Error()}
	}
	dryCfg, err := loadDryRunConfig(baseCfg, tokenDir)
	if err != nil {
		logger.Warn("dry-run authority check failed", logging.Err(err))
		return &tunnel.ClusterDryRun{Checked: false, Error: err.Error()}
	}
	clientset, err := kubernetes.NewForConfig(dryCfg)
	if err != nil {
		logger.Warn("dry-run authority check: build clientset failed", logging.Err(err))
		return &tunnel.ClusterDryRun{Checked: false, Error: err.Error()}
	}

	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     dryRunCheckVerb,
				Group:    dryRunCheckGroup,
				Resource: dryRunCheckResource,
			},
		},
	}
	res, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("could not ask whether the argus-dryrun identity may perform the given verb/resource — reporting dry-run authority as unknown, not as denied",
			slog.String("verb", dryRunCheckVerb), slog.String("group", dryRunCheckGroup), slog.String("resource", dryRunCheckResource), logging.Err(err))
		return &tunnel.ClusterDryRun{Checked: false, Error: err.Error()}
	}
	logger.Info("dry-run authority as reported by the API server", slog.Bool("patch_deployments_allowed", res.Status.Allowed))
	return &tunnel.ClusterDryRun{Checked: true, Allowed: res.Status.Allowed}
}

// errDryRunNotConfigured is returned by ToolExecutor.dryRunPatch when this
// cluster never mounted an argus-dryrun credential — the ordinary state for
// any cluster that has not opted into BACKLOG.md C4's pack, and the same
// message shape gatherClusterDryRunAuthority's Checked=false conveys to the
// hub, now surfaced directly to whichever caller reached the tool anyway
// (defence in depth: internal/llm is not supposed to ever offer this tool
// here, but a compromised or buggy caller must still be refused server-side,
// per argus-context's non-negotiable 3).
var errDryRunNotConfigured = errors.New("this cluster has not enabled the argus-dryrun pack (deploy/helm/argus-agent values.yaml's dryRun.enabled) — dry_run_patch is unavailable here")
