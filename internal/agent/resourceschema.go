package agent

// get_resource_schema is PROJECT.md B147's mechanism-level fix: a hub-side
// guard (internal/api/repo_tools.go's RefuseSchemaInvalidRepositoryProposals)
// calls this tool once per Kubernetes object an OpenPR plan proposes new
// content for, to confirm every top-level field the model wrote actually
// belongs to that object's own kind — before the plan is ever offered for
// approval.
//
// # Why this, and not a per-kind field list
//
// Found live 2026-09-06 (breadth-campaign CHG-001 fixture): a plan correcting
// a Deployment's drifted image field also wrote syncPolicy — an Argo CD
// Application-level field — as a top-level sibling of the Deployment's own
// spec. Kubernetes silently drops the unrecognized key on apply, but Argo's
// diff engine keeps it in the desired manifest forever, permanently defeating
// the fix. Enumerating "fields that belong to a Deployment" (or worse, "fields
// that do NOT belong to a Deployment") by hand caps the check at whatever list
// someone wrote and drifts the moment the API adds a field — the same
// per-kind enumeration problem this codebase's kind-agnostic predicates
// already exist to avoid. The cluster's own OpenAPI v3 document is the
// authoritative, always-current field list for every kind it knows, and
// this tool's whole job is fetching it — no schema is embedded or guessed.
//
// # Why this is cheap: no new RBAC
//
// /openapi and /openapi/* are non-resource URLs granted by the built-in
// system:discovery ClusterRole, bound by default to the system:authenticated
// group — confirmed live against this project's own rke2 test cluster
// (`kubectl get clusterrolebinding system:discovery -o yaml`). Any
// authenticated ServiceAccount, including argus-investigate with zero
// additional grants, already has this access; this tool adds no new
// ClusterRole rule anywhere.
//
// # Why top-level fields only, not full recursive/typed validation
//
// A full JSON-schema validator (types, formats, enums, oneOf/anyOf,
// x-kubernetes-int-or-string, x-kubernetes-preserve-unknown-fields) is real,
// separately-scoped work with a materially higher false-positive risk — a
// validator that does not correctly special-case every one of those
// Kubernetes-specific OpenAPI quirks will refuse legitimate content, which is
// worse than not checking at all for a mechanism whose whole point is to be
// trusted enough to run unconditionally, before a human ever sees the plan.
// The observed defect (B147) was a field with NO home anywhere on the target
// kind at all — caught completely by confirming the object's OWN top-level
// keys are a subset of its schema's own top-level properties, which needs
// none of that machinery. Depth is a real, acknowledged limit: a wrong value
// nested inside a field that DOES exist (e.g. an extra key several levels
// into spec.template.spec.containers[0]) is not caught by this tool. Recorded
// as a known boundary, not silently overclaimed.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/openapi3"
)

type resourceSchemaArgs struct {
	// GVK is "[group/]version/Kind" — the identical wire convention
	// describe_resource's own gvk argument already uses (parseGVKString).
	GVK string `json:"gvk"`
}

type resourceSchemaResult struct {
	GVK string `json:"gvk"`
	// Found is false when this cluster's OpenAPI document has no schema for
	// this GVK at all (an unrecognized/uninstalled kind, or a CRD this
	// cluster does not have) — the caller's honest signal to skip validation
	// for this object rather than mistake "unknown" for "no fields allowed".
	Found bool `json:"found"`
	// TopLevelFields is the schema's own top-level property names for this
	// kind (typically apiVersion, kind, metadata, spec, status, and nothing
	// else) — everything a caller needs to check "does this document invent
	// a field its own kind's schema has never heard of".
	TopLevelFields []string `json:"topLevelFields,omitempty"`
}

func (e *ToolExecutor) getResourceSchema(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	var args resourceSchemaArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, false, fmt.Errorf("invalid args: %w", err)
	}
	gvk, err := parseGVKString(args.GVK)
	if err != nil {
		return nil, false, err
	}
	fields, found, err := e.topLevelSchemaFields(ctx, gvk)
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	return mustMarshal(resourceSchemaResult{GVK: args.GVK, Found: found, TopLevelFields: fields}), false, nil
}

// openAPIGVDocCache memoizes one GroupVersion's full OpenAPI v3 document —
// package-level and process-lifetime, the same "static enough to cache for
// as long as this agent process runs" reasoning discoveredWatchSetCache
// (generic_predicates.go) already applies to the discovered-kind list. An API
// server's served schema does not change without a version upgrade or a CRD
// change, neither of which happens mid-process, so a stale cache is not a
// real risk here the way it would be for live object state.
var (
	openAPIGVDocCacheMu sync.Mutex
	openAPIGVDocCache   = map[string]map[string]any{} // key: GroupVersion.String()
)

// errFakeDiscoveryMissingOpenAPIV3 mirrors errFakeDynamicClientMissingListKind
// (generic_predicates.go) for the identical reason: a hand-built fake
// discovery client (k8s.io/client-go/discovery/fake) panics with
// "unimplemented" for OpenAPIV3() rather than returning an ordinary error — a
// real API server never does this. Confirmed directly against this file's own
// test suite; not logged when it occurs, matching listOneResource's own
// precedent for the same test-harness-only condition.
var errFakeDiscoveryMissingOpenAPIV3 = errors.New("fake discovery client does not implement OpenAPIV3")

// fetchGVSpecAsMap is topLevelSchemaFields' actual network call, split out
// only so the panic-recovery wrapper (see errFakeDiscoveryMissingOpenAPIV3)
// does not have to surround the cache-lookup logic around it too.
func (e *ToolExecutor) fetchGVSpecAsMap(gv schema.GroupVersion) (doc map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			doc, err = nil, fmt.Errorf("%w: %v", errFakeDiscoveryMissingOpenAPIV3, r)
		}
	}()
	root := openapi3.NewRoot(e.typed.Discovery().OpenAPIV3())
	return root.GVSpecAsMap(gv)
}

// topLevelSchemaFields fetches (and caches) gvk's GroupVersion's OpenAPI v3
// document, then finds the one schema definition tagged
// x-kubernetes-group-version-kind for this exact (group, version, kind) —
// never guessed from a naming convention, since built-in and CRD schemas
// name their definitions differently and only this tag is authoritative for
// either — and returns its top-level property names.
func (e *ToolExecutor) topLevelSchemaFields(ctx context.Context, gvk schema.GroupVersionKind) (fields []string, found bool, err error) {
	gv := gvk.GroupVersion()
	key := gv.String()

	openAPIGVDocCacheMu.Lock()
	doc, cached := openAPIGVDocCache[key]
	openAPIGVDocCacheMu.Unlock()

	if !cached {
		fetched, fetchErr := e.fetchGVSpecAsMap(gv)
		if fetchErr != nil {
			// No document for this GroupVersion at all — an uninstalled CRD's
			// group/version, most likely. Cached as an empty map so a
			// repeated proposal touching the same never-installed kind does
			// not re-fetch every time; distinguished from "fetched but this
			// KIND wasn't in it" only by both returning found=false, which is
			// the same honest answer either way from this function's own
			// caller's perspective.
			openAPIGVDocCacheMu.Lock()
			openAPIGVDocCache[key] = nil
			openAPIGVDocCacheMu.Unlock()
			return nil, false, nil //nolint:nilerr // absence of a schema is Found=false, not a tool error
		}
		doc = fetched
		openAPIGVDocCacheMu.Lock()
		openAPIGVDocCache[key] = doc
		openAPIGVDocCacheMu.Unlock()
	}
	if doc == nil {
		return nil, false, nil
	}
	fields, found = topLevelFieldsFromGVDoc(doc, gvk)
	return fields, found, nil
}

// topLevelFieldsFromGVDoc is topLevelSchemaFields' pure half: no network, no
// cache, no ToolExecutor — an already-fetched OpenAPI v3 GroupVersion
// document (exactly what GVSpecAsMap returns, unmarshaled) in, a field list
// out. Split out so the schema-matching logic (find the one definition
// tagged for this exact GVK, read its top-level properties) is directly
// unit-testable against hand-built fixture documents, the same "test the
// pure half directly" precedent this codebase already follows elsewhere
// (e.g. llm.buildCorrectionPrompt, checkGenericDanglingReference) rather than
// only exercising it through a live or faked discovery client.
//
// Scans every definition in components.schemas for one whose
// x-kubernetes-group-version-kind extension names this exact
// (group, version, kind) — never by definition NAME, since built-in kinds
// and CRDs name their definitions under completely different conventions
// (io.k8s.api.<group>.<version>.<Kind> vs. a CRD's own reversed-domain
// naming) and only this tag is authoritative for either.
func topLevelFieldsFromGVDoc(doc map[string]any, gvk schema.GroupVersionKind) (fields []string, found bool) {
	components, _ := doc["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	for _, raw := range schemas {
		def, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		gvks, ok := def["x-kubernetes-group-version-kind"].([]any)
		if !ok {
			continue
		}
		for _, rawEntry := range gvks {
			entry, ok := rawEntry.(map[string]any)
			if !ok {
				continue
			}
			if entry["group"] != gvk.Group || entry["version"] != gvk.Version || entry["kind"] != gvk.Kind {
				continue
			}
			props, _ := def["properties"].(map[string]any)
			out := make([]string, 0, len(props))
			for name := range props {
				out = append(out, name)
			}
			return out, true
		}
	}
	return nil, false
}
