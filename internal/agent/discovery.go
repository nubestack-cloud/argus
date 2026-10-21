// discovery.go builds BACKLOG.md E11's piece 1: a DISCOVERED watch set,
// computed as the API server's own ServerPreferredResources() intersected
// with what this identity's RBAC actually grants (via a SelfSubjectRulesReview),
// as a replacement for tools.go's hardcoded supportedGVKs map — the map that
// requires a code change for every new kind (a CRD from an operator, KEDA,
// ESO, Gateway API, a mesh) to become visible at all.
//
// **This file IS wired in, as of the E11 rollout.** The paragraph that used to
// stand here said the opposite — "deliberately NOT wired in yet... this
// package's actual detection surface is unchanged" — and that was true when
// written and false by 2026-09-07, which is the worst state for a comment a
// reader uses to decide whether discovery is live. Corrected then.
//
// What actually calls it: runSweepDetector (sweep_detector.go) calls
// enableDiscoveredWatchSet (generic_predicates.go), and the resulting cache is
// read by listWatchedKindObjects (generic_predicates.go) and by two call sites
// in tools.go. The detection surface HAS widened accordingly: measured live on
// 2026-09-07 the resolved watch set was 216 kinds, and Gateway API kinds
// installed that day were picked up with no Gateway-specific code — see
// fixtures/e15-gateway-api/README.md.
//
// Note what is still true from the original sequencing: supportedGVKs itself
// has NOT been replaced by DiscoverWatchSet's output. Discovery widens what the
// kind-agnostic sweep predicates see; the typed read-tool surface is still the
// hardcoded list. Those are two different sets and only one of them is
// discovered.
//
// Why SelfSubjectRulesReview and not per-resource SelfSubjectAccessReview:
// this agent's ClusterRole grants dozens of resources today and would grant
// more once a discovered set widens what's watched — a SelfSubjectAccessReview
// per candidate GVR would be one round trip per resource per refresh, while
// SelfSubjectRulesReview is a single call that returns this identity's whole
// effective rule set (`authorizationv1.SubjectRulesReviewStatus.ResourceRules`),
// which is then checked in memory against every discovered resource. The
// tradeoff, straight from that type's own doc comment, is that the review can
// come back Incomplete (an authorizer that doesn't support rules evaluation) —
// handled below by treating Incomplete as "log it, use what came back," never
// as a hard failure, since an incomplete allow-list is still strictly more
// useful than none and RBAC rules are additive (a rule present in the list is
// safe to trust even when the list itself might be short one).
package agent

import (
	"context"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"sort"
	"strings"
	"sync"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	authzv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// DiscoveredResource is one entry in a discovered watch set: the GVR to use
// with a dynamic/typed client, plus whether it's namespaced — the same two
// facts tools.go's supportedResource carries for its hardcoded map, so a
// future wiring is a value-shape match rather than a rewrite of every call
// site that reads supportedGVKs.
type DiscoveredResource struct {
	GVR        schema.GroupVersionResource
	Namespaced bool
}

// maxDeniedSample bounds how many denied resource names WatchSetCoverage
// carries. This rides the facts refresh (client.go's factsRefreshInterval,
// two minutes) forever, so the list has to be bounded by something: a
// cluster with a large operator estate can deny hundreds of kinds, and an
// unbounded list would make the payload grow with the very problem it
// reports. 40 is enough to recognise WHAT was lost — an operator reading
// "velero.io/backups, cert-manager.io/certificates, …" learns the shape of
// the gap immediately — while the exact count is carried separately and
// exactly by KindsServed/KindsReadable, which are never sampled.
const maxDeniedSample = 40

// WatchSetCoverage is the arithmetic DiscoverWatchSet does anyway, kept
// instead of thrown away — PROJECT.md E11.
//
// Before this, the intersection logged "resolved watch set has 44 kind(s);
// 172 discovered resource(s) excluded because RBAC does not grant
// [get list watch]" into the agent's own pod log and that was the end of it.
// The hub never learned the number, so nothing an operator can reach could
// tell a quiet cluster from one where four fifths of it stopped being
// watched. This is that same line, as data.
//
// Served and Readable are counted at the SAME granularity — one per
// discovered resource that the API server itself says supports
// get+list+watch — so Served-Readable is exactly the set Denied samples
// from. Deliberately NOT len(watchSet), which is keyed by GroupVersionKind
// and can be one smaller when two groups happen to share a Kind name;
// comparing a GVK count against a resource count would understate coverage
// for a reason that has nothing to do with RBAC.
type WatchSetCoverage struct {
	// Served is every resource discovery advertised with get+list+watch —
	// what a cluster-admin-bound agent would resolve.
	Served int
	// Readable is how many of those this identity's RBAC actually grants.
	Readable int
	// Denied is a bounded, sorted sample of the rest as "group/resource"
	// (an empty group renders as "/secrets"), for recognisability. See
	// maxDeniedSample.
	Denied []string
	// DeniedTruncated is true when Denied is a prefix of a longer list.
	DeniedTruncated bool
}

// requiredVerbs is what this mechanism demands both of the API server
// (discovery must advertise the resource supports these verbs) and of RBAC
// (SelfSubjectRulesReview must show this identity is granted every one of
// them). get+list+watch matches what every existing supportedGVKs caller
// actually needs: list_resources/sweep needs list+watch, describe_resource
// and the ownership walk need get. A resource missing any one of the three at
// either layer is excluded — narrower than "discovery knows about it" is the
// whole point of intersecting with RBAC in the first place.
var requiredVerbs = []string{"get", "list", "watch"}

// rulesReviewNamespace is the namespace SelfSubjectRulesReview is asked to
// evaluate against. **Measured live against a real API server (kind
// v1.34.0, 2026-09-02), not assumed:** an empty Spec.Namespace is not "ask
// cluster-wide" — the apiserver rejects it outright with "no namespace on
// request" (`kubectl create -f` a SelfSubjectRulesReview with
// `spec.namespace: ""` reproduces this). Some non-empty, real namespace is
// required, so this uses "default" — present on every cluster since cluster
// bootstrap. Which one is otherwise unimportant for THIS agent's actual RBAC
// shape: argus-investigate is bound via a ClusterRoleBinding
// (deploy/helm/argus-agent/templates/clusterrole.yaml), so the ResourceRules
// it produces don't vary by which existing namespace is named here, and for
// cluster-scoped resources (Nodes, PersistentVolumes, StorageClasses,
// Namespaces) the RBAC authorizer ignores the namespace argument entirely —
// both confirmed by the same live check (a). A deployment that instead binds
// this identity only via namespaced RoleBindings would need to review every
// namespace it cares about and union the results; that's not this agent's
// binding shape today and isn't built here.
const rulesReviewNamespace = "default"

// resourceDiscoverer is the one discovery-client method this file calls,
// factored out as its own interface (rather than depending on the full
// discovery.DiscoveryInterface) so tests can supply a minimal fake that
// returns exactly the partial-result/error shapes ServerPreferredResources
// itself documents, including the interesting one:
// *discovery.ErrGroupDiscoveryFailed carries a non-nil result alongside a
// non-nil error. A real *kubernetes.Clientset's Discovery() satisfies this
// automatically.
type resourceDiscoverer interface {
	ServerPreferredResources() ([]*metav1.APIResourceList, error)
}

// rulesReviewCreator is the one call this file makes against
// AuthorizationV1().SelfSubjectRulesReviews() — factored out the same way and
// for the same reason. authzv1client.SelfSubjectRulesReviewInterface (what a
// real clientset returns) satisfies this today; if that interface grows new
// methods later, this one narrower method is all DiscoverWatchSet actually
// needs.
type rulesReviewCreator interface {
	Create(ctx context.Context, review *authorizationv1.SelfSubjectRulesReview, opts metav1.CreateOptions) (*authorizationv1.SelfSubjectRulesReview, error)
}

var _ resourceDiscoverer = discovery.DiscoveryInterface(nil)
var _ rulesReviewCreator = authzv1client.SelfSubjectRulesReviewInterface(nil)

// DiscoverWatchSet computes the resolved watch set: every GroupVersionKind
// the API server's ServerPreferredResources() advertises AND that
// SelfSubjectRulesReview shows this identity holds get+list+watch on, as a
// cluster-wide grant (namespace "" — see grantIndex.allows' own comment on
// why that's the right scope for an identity bound via ClusterRoleBinding,
// which is how argus-investigate is bound today).
//
// A per-group discovery failure (a broken/unavailable aggregated API service)
// never kills discovery of every other group: ServerPreferredResources
// itself returns a partial, non-nil result alongside
// *discovery.ErrGroupDiscoveryFailed in that case, and this function logs the
// failed groups and proceeds with whatever did come back — the same "fail
// open, degrade gracefully" posture tools.go already uses for e.g. a cluster
// with no metrics-server installed (see facts.go's gatherNodeUsage). Only an
// error of some OTHER shape — the whole discovery call failing outright, or
// the RBAC call itself failing — is treated as this function's own error,
// since at that point there is nothing to intersect against and returning an
// empty set would silently look identical to "RBAC grants nothing."
// The second return value is WatchSetCoverage — the same counting this
// function has always done for its own log line, handed back so it can reach
// an operator instead of dying in a pod log.
func DiscoverWatchSet(ctx context.Context, disc resourceDiscoverer, rules rulesReviewCreator) (map[schema.GroupVersionKind]DiscoveredResource, WatchSetCoverage, error) {
	lists, discErr := disc.ServerPreferredResources()
	if discErr != nil {
		if failed, ok := asGroupDiscoveryFailed(discErr); ok {
			logger.Warn("discovery: some API group(s) failed and were skipped, proceeding with the rest",
				slog.Int("failed_groups", len(failed.Groups)), slog.Any("groups", failed.Groups))
		} else {
			return nil, WatchSetCoverage{}, fmt.Errorf("server preferred resources: %w", discErr)
		}
	}

	review := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: rulesReviewNamespace},
	}
	reviewResult, err := rules.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, WatchSetCoverage{}, fmt.Errorf("self subject rules review: %w", err)
	}
	if reviewResult.Status.Incomplete {
		logger.Warn("discovery: SelfSubjectRulesReview reported an incomplete rule set — proceeding with what it returned, since RBAC rules are additive and a partial allow-list is still safe to trust",
			slog.String("evaluation_error", reviewResult.Status.EvaluationError))
	}
	grants := grantIndex{rules: reviewResult.Status.ResourceRules}

	watchSet := make(map[schema.GroupVersionKind]DiscoveredResource)
	// served counts every candidate — a resource the API server advertises
	// AND says supports get+list+watch — whether or not RBAC then allows it.
	// It is the denominator E11's coverage signal needs, and it is counted
	// here rather than derived later because this loop is the only place
	// that ever sees the full candidate set.
	served := 0
	denied := []string{}
	skippedByRBAC := 0
	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			logger.Warn("discovery: could not parse GroupVersion, skipping this list", slog.String("group_version", list.GroupVersion), logging.Err(err))
			continue
		}

		for _, res := range list.APIResources {
			// Subresources ("pods/status", "deployments/scale", ...) carry a
			// "/" in Name. supportedGVKs' own entries are all whole
			// resources, never subresources — matching that, not a new
			// judgment call.
			if strings.Contains(res.Name, "/") {
				continue
			}
			// The API server itself must advertise support for every verb
			// this mechanism needs — a resource discovery lists but that
			// doesn't even claim to support "watch" (some do — e.g.
			// several metrics/proxy-shaped resources) can never be safely
			// included regardless of what RBAC says.
			if !hasAllVerbs(res.Verbs, requiredVerbs) {
				continue
			}

			group := res.Group
			if group == "" {
				group = gv.Group
			}
			version := res.Version
			if version == "" {
				version = gv.Version
			}

			served++

			if !grants.allows(group, res.Name, requiredVerbs...) {
				skippedByRBAC++
				if len(denied) < maxDeniedSample {
					denied = append(denied, group+"/"+res.Name)
				}
				continue
			}

			gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: res.Kind}
			watchSet[gvk] = DiscoveredResource{
				GVR:        schema.GroupVersionResource{Group: group, Version: version, Resource: res.Name},
				Namespaced: res.Namespaced,
			}
		}
	}

	// Sorted so the sample is stable across refreshes: an operator comparing
	// two facts snapshots is looking for a CHANGE, and a set iterated in map
	// order would show a different arbitrary 40 every two minutes.
	sort.Strings(denied)
	coverage := WatchSetCoverage{
		Served:          served,
		Readable:        served - skippedByRBAC,
		Denied:          denied,
		DeniedTruncated: skippedByRBAC > len(denied),
	}

	logger.Info("discovery: resolved watch set",
		slog.Int("kinds", len(watchSet)), slog.Int("readable", coverage.Readable), slog.Int("served", coverage.Served),
		slog.Int("excluded_by_rbac", skippedByRBAC), slog.Any("required_verbs", requiredVerbs))
	return watchSet, coverage, nil
}

// asGroupDiscoveryFailed reports whether discErr is
// *discovery.ErrGroupDiscoveryFailed — the shape ServerPreferredResources
// documents as "partial result, still usable" — matching
// discovery.IsGroupDiscoveryFailedError's own check (a plain type assertion)
// but also handing back the typed value so the caller can log which groups
// failed.
func asGroupDiscoveryFailed(err error) (*discovery.ErrGroupDiscoveryFailed, bool) {
	failed, ok := err.(*discovery.ErrGroupDiscoveryFailed)
	return failed, ok
}

// hasAllVerbs reports whether the API server's own reported verbs (a
// resource's discovery.APIResource.Verbs) include every verb in need — the
// API-server-side half of the get+list+watch requirement, independent of and
// checked before the RBAC half.
func hasAllVerbs(have []string, need []string) bool {
	set := make(map[string]bool, len(have))
	for _, v := range have {
		set[v] = true
	}
	for _, v := range need {
		if !set[v] {
			return false
		}
	}
	return true
}

// grantIndex answers "does this identity's RBAC grant verbs on
// group/resource" against one SelfSubjectRulesReview's worth of
// ResourceRules, matching the same "*" wildcard semantics
// authorizationv1.ResourceRule documents (an APIGroups/Resources/Verbs entry
// of "*" means "all"). Verbs accumulate ACROSS rules, matching RBAC's own
// additive model — e.g. one rule granting only "get" on a resource and
// another granting only "list"/"watch" on the same resource together satisfy
// allows(..., "get", "list", "watch"), even though neither rule alone would.
type grantIndex struct {
	rules []authorizationv1.ResourceRule
}

func (g grantIndex) allows(group, resource string, verbs ...string) bool {
	need := make(map[string]bool, len(verbs))
	for _, v := range verbs {
		need[v] = true
	}
	for _, r := range g.rules {
		if len(need) == 0 {
			break
		}
		if !matchesAny(r.APIGroups, group) || !matchesAny(r.Resources, resource) {
			continue
		}
		for _, v := range r.Verbs {
			if v == "*" {
				need = map[string]bool{}
				break
			}
			delete(need, v)
		}
	}
	return len(need) == 0
}

// matchesAny reports whether target is "*" or present in candidates.
func matchesAny(candidates []string, target string) bool {
	for _, c := range candidates {
		if c == "*" || c == target {
			return true
		}
	}
	return false
}

// WatchSetCache periodically refreshes a DiscoverWatchSet result rather than
// paying a ServerPreferredResources + SelfSubjectRulesReview round trip on
// every call — see DefaultWatchSetRefreshInterval for why that would be
// wasteful, and why the chosen interval is what it is. Safe for concurrent
// use; Get is the only method a caller needs.
type WatchSetCache struct {
	mu   sync.Mutex
	disc resourceDiscoverer
	auth rulesReviewCreator
	ttl  time.Duration
	now  func() time.Time // overridden in tests; time.Now in production

	fetchedAt time.Time
	set       map[schema.GroupVersionKind]DiscoveredResource
	coverage  WatchSetCoverage
	haveSet   bool
}

// DefaultWatchSetRefreshInterval is how often a WatchSetCache re-runs
// discovery+RBAC.
//
// # Why one minute, and why that is not an arbitrary shortening
//
// This cache has two consumers with very different requirements, and the
// stricter one has to set the interval:
//
//   - The sweep's kind-agnostic predicates ask it which kinds to list, once
//     per pass. Staleness here costs at most one pass of a newly-installed
//     CRD not being watched yet. Minutes are fine.
//   - detector_status.go's detectorDeniedReads reads DeniedReads out of it —
//     the operator-visible signal that this agent's RBAC no longer grants a
//     read a detector needs. Staleness here is PROJECT.md B177: a revoked
//     permission reached the hub within one facts-refresh of the AGENT
//     NOTICING it, not of the revocation, and at the 15 minutes this was
//     previously set to that meant an operator reading the detection-coverage
//     table could not tell a current denial from a quarter-hour-old one.
//
// One minute is chosen to be strictly shorter than factsRefreshInterval
// (client.go, 2 minutes), which is the cadence that actually carries
// DeniedReads to the hub. That relationship is the point, not the number: it
// makes every facts gather re-read rather than serve a cached set, so
// DeniedReads ends up exactly as fresh as factsUpdatedAt and the other
// agent-health fields it is displayed beside. A TTL longer than the facts
// interval adds a second, invisible staleness on top of the visible one,
// which is the defect. TestWatchSetRefreshOutpacesTheFactsThatCarryIt pins
// the relationship so the two cannot drift back apart.
//
// # What that costs, measured rather than assumed
//
// The previous 15 minutes was justified on cost — "discovery plus a rules
// review is meaningfully more expensive than one sweep's List calls" — which
// had never been measured. It is 3 requests and 12ms of wall clock against a
// live cluster (TestLiveWatchSetRefreshCost, 2026-09-25: aggregated
// discovery is two requests on any API server since Kubernetes 1.30, plus
// one SelfSubjectRulesReview). At one minute that is 180 requests and ~2
// seconds of API-server time per agent per hour, and a 200-cluster fleet
// spreads it across 200 separate API servers rather than concentrating it
// anywhere. That is not a cost worth 15 minutes of blind spot.
//
// It is still deliberately NOT tied to DefaultSweepInterval (5 minutes): the
// mistake this cache exists to prevent is discovery becoming an accidental
// "every sweep tick" call, and an interval derived from the sweep's would
// reintroduce exactly that coupling.
const DefaultWatchSetRefreshInterval = time.Minute

// NewWatchSetCache builds a cache around the given discoverer/rules-review
// client with the given refresh interval. Use NewWatchSetCacheFromClientset
// for the real, production kubernetes.Interface case.
func NewWatchSetCache(disc resourceDiscoverer, auth rulesReviewCreator, ttl time.Duration) *WatchSetCache {
	return &WatchSetCache{disc: disc, auth: auth, ttl: ttl, now: time.Now}
}

// NewWatchSetCacheFromClientset is the production constructor: pulls the
// discovery client and the SelfSubjectRulesReviews client straight off a real
// kubernetes.Interface (e.g. the *kubernetes.Clientset newToolExecutor/
// runSweepDetector already build from rest.InClusterConfig()), at
// DefaultWatchSetRefreshInterval.
func NewWatchSetCacheFromClientset(clientset kubernetes.Interface) *WatchSetCache {
	return NewWatchSetCache(clientset.Discovery(), clientset.AuthorizationV1().SelfSubjectRulesReviews(), DefaultWatchSetRefreshInterval)
}

// Get returns the cached watch set, refreshing it first if the cache is empty
// or older than ttl. A refresh failure when a previous good set already
// exists logs and serves the stale set rather than an error — the same
// fail-open posture DiscoverWatchSet itself uses for a partial discovery
// failure, one level up: a transient API-server or RBAC hiccup on refresh
// should never blank out a watch set that was working a moment ago. A
// refresh failure with no prior set (the very first call) has nothing stale
// to fall back to and returns the error.
func (c *WatchSetCache) Get(ctx context.Context) (map[schema.GroupVersionKind]DiscoveredResource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	set, _, err := c.getWithCoverage(ctx)
	return set, err
}

// GetWithCoverage is Get plus the coverage arithmetic of the same
// intersection — PROJECT.md E11's signal. One method rather than two
// independent ones on purpose: the coverage numbers and the watch set they
// describe must come from the SAME refresh, or an operator could be shown
// "44 of 216" next to a set that has since been re-resolved to something
// else.
//
// The bool is false when nothing could be resolved and there is no stale set
// to fall back on — i.e. exactly when the returned error is non-nil, or when
// a stale set is being served whose coverage was never successfully
// computed. A caller must render !ok as unknown, never as zero coverage.
func (c *WatchSetCache) GetWithCoverage(ctx context.Context) (WatchSetCoverage, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, cov, err := c.getWithCoverage(ctx)
	if err != nil {
		return WatchSetCoverage{}, false, err
	}
	return cov, true, nil
}

// getWithCoverage is the shared body. Caller holds c.mu.
func (c *WatchSetCache) getWithCoverage(ctx context.Context) (map[schema.GroupVersionKind]DiscoveredResource, WatchSetCoverage, error) {
	if c.haveSet && c.now().Sub(c.fetchedAt) < c.ttl {
		return c.set, c.coverage, nil
	}

	set, coverage, err := DiscoverWatchSet(ctx, c.disc, c.auth)
	if err != nil {
		if c.haveSet {
			logger.Warn("discovery: refresh failed — serving the previous watch set rather than nothing",
				logging.Err(err), slog.Int("kinds", len(c.set)), slog.Duration("age", c.now().Sub(c.fetchedAt)))
			// The stale COVERAGE goes with the stale set, deliberately:
			// they describe the same resolution, and reporting fresh-looking
			// coverage beside a stale set would be the worse half of both.
			return c.set, c.coverage, nil
		}
		return nil, WatchSetCoverage{}, err
	}

	c.set = set
	c.coverage = coverage
	c.fetchedAt = c.now()
	c.haveSet = true
	return c.set, c.coverage, nil
}
