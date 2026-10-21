package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/redact"
)

// This file is BACKLOG.md E13's own test coverage: describe_resource/
// list_resources widened from supportedGVKs alone to supportedGVKs UNION the
// same discovered watch set generic_predicates.go's kind-agnostic detection
// already uses, with an aggressive, schema-agnostic redaction pass
// (redact.AggressiveObject) standing in for redact.Object on anything found
// only through discovery. Three things need proving, matching this item's
// own "done" checklist: (a) a reviewed kind's behavior is unchanged, (b) an
// unreviewed-but-discoverable kind is now readable, with the aggressive
// redaction actually applied to a credential-shaped value nested at an
// arbitrary field path, (c) Secret stays excluded regardless of discovery.

const canaryE13Credential = "SUPERSECRET-e13-unreviewed-crd-value"

// widgetSourceGVK/widgetSourceGVR are this file's stand-in for "a real CRD
// nobody added to supportedGVKs" — an invented group so there is no risk of
// ever colliding with a real one.
var (
	widgetSourceGVK = schema.GroupVersionKind{Group: "widgets.example.com", Version: "v1", Kind: "WidgetSource"}
	widgetSourceGVR = schema.GroupVersionResource{Group: "widgets.example.com", Version: "v1", Resource: "widgetsources"}
)

// enableDiscoveryForWidgetSource wires discoveredWatchSetCache so
// widgetSourceGVK resolves exactly the way generic_predicates.go's own
// TestListWatchedKindObjects_DiscoveredKindIsUnionedIn wires a discovered
// "Widget" kind: ServerPreferredResources advertises it, and RBAC
// (SelfSubjectRulesReview) grants get/list/watch on it — the same two
// conditions discovery.go's DiscoverWatchSet actually requires.
func enableDiscoveryForWidgetSource(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{{
		GroupVersion: widgetSourceGVK.GroupVersion().String(),
		APIResources: []metav1.APIResource{
			{Name: widgetSourceGVR.Resource, Namespaced: true, Kind: widgetSourceGVK.Kind, Verbs: metav1.Verbs{"get", "list", "watch"}},
		},
	}}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule(widgetSourceGVR.Group, widgetSourceGVR.Resource)}}
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, rules, time.Hour))
}

// widgetSourceFixture builds one WidgetSource instance carrying the canary
// credential at two different, arbitrarily-named field paths — an
// annotation (this task's own live-verification scenario names exactly this
// shape) and a nested spec field several levels deep — plus a status.phase
// value that would leak through list_resources' ordinary Phase projection
// if that projection were ever (wrongly) applied to an unreviewed kind.
func widgetSourceFixture(namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": widgetSourceGVK.GroupVersion().String(),
		"kind":       widgetSourceGVK.Kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"annotations": map[string]any{
				"widgets.example.com/api-credential": canaryE13Credential,
			},
		},
		"spec": map[string]any{
			"connection": map[string]any{
				"upstream": map[string]any{
					"apiToken": canaryE13Credential,
				},
			},
		},
		"status": map[string]any{
			"phase": canaryE13Credential,
		},
	}}
}

// newWidgetSourceTestExecutor builds a ToolExecutor whose dynamic client
// knows how to Get/List WidgetSource objects — dynamicfake needs an explicit
// GVR->ListKind mapping for any GVR outside the real k8s scheme, the same
// requirement gitOpsTestListKinds/newGitOpsTestExecutor already document for
// this package's other CRD-shaped fixtures.
func newWidgetSourceTestExecutor(objs ...runtime.Object) *ToolExecutor {
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{widgetSourceGVR: "WidgetSourceList"}, objs...)
	return &ToolExecutor{typed: k8sfake.NewSimpleClientset(), dynamic: dyn}
}

// --- (a) reviewed kind: unchanged ---

// TestDescribeResource_ReviewedKindUnaffectedByDiscoveryBeingEnabled proves
// supportedGVKs' own reviewed kinds keep describe_resource's exact previous
// behavior — the ordinary redact.Object pass, not the new aggressive one —
// whether or not discoveredWatchSetCache happens to be populated. Byte-for-
// byte identical output is the strongest form of this claim: not merely
// "still works," but "not even incidentally different."
func TestDescribeResource_ReviewedKindUnaffectedByDiscoveryBeingEnabled(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("uid-deploy")},
	}
	args := mustMarshal(describeResourceArgs{GVK: "apps/v1/Deployment", Namespace: "default", Name: "web"})

	discoveredWatchSetCache.Store(nil)
	execWithoutDiscovery, _ := newTestExecutor(deployment)
	withoutDiscovery, _, err := execWithoutDiscovery.describeResource(context.Background(), args)
	if err != nil {
		t.Fatalf("describeResource (discovery disabled): %v", err)
	}

	enableDiscoveryForWidgetSource(t) // an unrelated discovered kind, deliberately not Deployment
	execWithDiscovery, _ := newTestExecutor(deployment)
	withDiscovery, _, err := execWithDiscovery.describeResource(context.Background(), args)
	if err != nil {
		t.Fatalf("describeResource (discovery enabled): %v", err)
	}

	if string(withoutDiscovery) != string(withDiscovery) {
		t.Errorf("a reviewed kind's describe_resource output changed with discovery enabled.\nwithout: %s\nwith:    %s", withoutDiscovery, withDiscovery)
	}
}

// TestListResources_ReviewedKindUnaffectedByDiscoveryBeingEnabled is the same
// claim for list_resources' compact projection, including the Phase/Ready
// fields projectListItem derives — these must still be computed for a
// reviewed kind exactly as before.
func TestListResources_ReviewedKindUnaffectedByDiscoveryBeingEnabled(t *testing.T) {
	pod := testPod("default", "web-1", "Running", 1, 1)
	args := mustMarshal(listResourcesArgs{Kind: "Pod", Namespace: "default"})

	discoveredWatchSetCache.Store(nil)
	execWithoutDiscovery, _ := newTestExecutor(pod)
	withoutDiscovery, _, err := execWithoutDiscovery.listResources(context.Background(), args)
	if err != nil {
		t.Fatalf("listResources (discovery disabled): %v", err)
	}

	enableDiscoveryForWidgetSource(t)
	execWithDiscovery, _ := newTestExecutor(pod)
	withDiscovery, _, err := execWithDiscovery.listResources(context.Background(), args)
	if err != nil {
		t.Fatalf("listResources (discovery enabled): %v", err)
	}

	if string(withoutDiscovery) != string(withDiscovery) {
		t.Errorf("a reviewed kind's list_resources output changed with discovery enabled.\nwithout: %s\nwith:    %s", withoutDiscovery, withDiscovery)
	}

	var result listResourcesResult
	if err := json.Unmarshal(withDiscovery, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Ready != "1/1" {
		t.Errorf("expected the reviewed kind's Ready projection to still be computed, got %+v", result.Items)
	}
}

// --- (b) unreviewed discovered kind: now readable, aggressively redacted ---

// TestDescribeResource_UnreviewedDiscoveredKindIsNowReadable is this item's
// central claim for describe_resource: a gvk that is NOT in supportedGVKs
// but IS in the discovered watch set must now succeed (previously:
// "unsupported gvk"), and the credential-shaped values buried in its
// annotation and its nested spec field must not survive anywhere in the
// output — proving redact.AggressiveObject actually ran, not just that the
// call stopped erroring.
func TestDescribeResource_UnreviewedDiscoveredKindIsNowReadable(t *testing.T) {
	enableDiscoveryForWidgetSource(t)
	executor := newWidgetSourceTestExecutor(widgetSourceFixture("apps", "prod-source"))

	data, _, err := executor.Execute(context.Background(), "describe_resource", mustMarshal(describeResourceArgs{
		GVK:       "widgets.example.com/v1/WidgetSource",
		Namespace: "apps",
		Name:      "prod-source",
	}))
	if err != nil {
		t.Fatalf("describe_resource on a kind found only via discovery: want success, got: %v", err)
	}
	if strings.Contains(string(data), canaryE13Credential) {
		t.Fatalf("describe_resource leaked the unreviewed CRD's credential-shaped value.\noutput: %s", data)
	}
	// Shape must survive even though the values did not — this is what
	// distinguishes AggressiveObject from "omit the object entirely."
	for _, want := range []string{"connection", "upstream", "apiToken", "widgets.example.com/api-credential"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("expected field name %q (shape) to survive redaction, output: %s", want, data)
		}
	}
	if !redact.ContainsMarker(string(data)) {
		t.Errorf("expected the aggressive redaction marker in the output, got: %s", data)
	}

	// Sanity check this test proves what it claims to: without discovery
	// enabled, the identical call must still fail exactly as it did before
	// BACKLOG.md E13.
	discoveredWatchSetCache.Store(nil)
	executorNoDiscovery := newWidgetSourceTestExecutor(widgetSourceFixture("apps", "prod-source"))
	if _, _, err := executorNoDiscovery.describeResource(context.Background(), mustMarshal(describeResourceArgs{
		GVK: "widgets.example.com/v1/WidgetSource", Namespace: "apps", Name: "prod-source",
	})); err == nil {
		t.Fatal("describe_resource for an undiscovered, unsupported gvk: want error, got nil — fixture no longer proves what this test claims")
	}
}

// TestListResources_UnreviewedDiscoveredKindIsNowReadable is (b)'s
// list_resources half: a bare Kind name that resolves only through
// discovery must now enumerate (previously: "unsupported kind"), and the
// compact projection must never surface the arbitrary status.phase value
// this fixture plants — proving projectListItemAggressive's own choice to
// not compute Phase/Ready for an unreviewed kind, rather than merely hoping
// redact.Object's generic pass would have caught it.
func TestListResources_UnreviewedDiscoveredKindIsNowReadable(t *testing.T) {
	enableDiscoveryForWidgetSource(t)
	executor := newWidgetSourceTestExecutor(widgetSourceFixture("apps", "prod-source"))

	data, _, err := executor.Execute(context.Background(), "list_resources", mustMarshal(listResourcesArgs{
		Kind:      "WidgetSource",
		Namespace: "apps",
	}))
	if err != nil {
		t.Fatalf("list_resources on a kind found only via discovery: want success, got: %v", err)
	}
	if strings.Contains(string(data), canaryE13Credential) {
		t.Fatalf("list_resources leaked the unreviewed CRD's status.phase value.\noutput: %s", data)
	}

	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Name != "prod-source" {
		t.Fatalf("expected exactly the one WidgetSource to be listed, got %+v", result.Items)
	}
	if result.Items[0].Phase != "" || result.Items[0].Ready != "" {
		t.Errorf("expected Phase/Ready to be omitted for an unreviewed kind, got Phase=%q Ready=%q", result.Items[0].Phase, result.Items[0].Ready)
	}
}

// --- (c) Secret: excluded regardless of reviewed/discovered ---

// TestListResources_SecretStillRefusedWithDiscoveryEnabled re-runs
// TestListResources_SecretCannotBeEnumerated's own assertion with
// discoveredWatchSetCache populated, so a future change that makes the
// discovery fallback too eager cannot quietly widen Secret's reachability
// even though supportedGVKs still lists it as reviewed=true (Secret is
// resolved on resolveDescribableResource's FIRST branch, so this pins that
// the explicit Secret refusal in listResources still runs afterward).
func TestListResources_SecretStillRefusedWithDiscoveryEnabled(t *testing.T) {
	enableDiscoveryForWidgetSource(t)
	executor, _ := newTestExecutor()

	_, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Secret", Namespace: "apps",
	}))
	if err == nil || !strings.Contains(err.Error(), "does not support Secret") {
		t.Fatalf("list_resources(Secret) with discovery enabled: err = %v, want the explicit Secret refusal", err)
	}
}

// TestResolveDescribableResource_SecretNeverServedViaDiscovery is the
// defense-in-depth case resolveDescribableResource's own doc comment names:
// even if supportedGVKs ever stopped listing the real core/v1 Secret, or
// RBAC ever granted this identity list/watch on it (clusterrole.yaml
// deliberately does not), the discovery fallback must still refuse to
// resolve it — never falling through to "just another unreviewed kind."
func TestResolveDescribableResource_SecretNeverServedViaDiscovery(t *testing.T) {
	original, hadEntry := supportedGVKs[secretGVK]
	delete(supportedGVKs, secretGVK)
	t.Cleanup(func() {
		if hadEntry {
			supportedGVKs[secretGVK] = original
		}
	})
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "secrets", Namespaced: true, Kind: "Secret", Verbs: metav1.Verbs{"get", "list", "watch"}},
		},
	}}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "secrets")}}
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, rules, time.Hour))

	executor, _ := newTestExecutor()
	_, _, err := executor.resolveDescribableResource(context.Background(), secretGVK)
	if err == nil {
		t.Fatal("resolveDescribableResource(Secret) via discovery, with supportedGVKs' own entry removed: want error, got nil")
	}
}
