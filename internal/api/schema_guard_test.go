package api

// Tests for PROJECT.md B147's enforcement point:
// RefuseSchemaInvalidRepositoryProposals.

import (
	"context"
	"encoding/json"
	"testing"

	"argus/internal/llm"
	"argus/internal/remediation"
)

// fakeSchemaFetcher is a hand-built schemaFetcher — no live tunnel, no
// gateway.Gateway construction — returning a fixed field list per GVK string,
// and recording every gvk it was asked about so a test can assert exactly
// which objects this guard actually checked.
type fakeSchemaFetcher struct {
	connected bool
	fields    map[string][]string // gvk string -> top-level fields; absent key means "not found"
	asked     []string
}

func (f *fakeSchemaFetcher) IsConnected(string) bool { return f.connected }

func (f *fakeSchemaFetcher) CallTool(_ context.Context, _ string, tool string, args json.RawMessage) (json.RawMessage, error) {
	if tool != "get_resource_schema" {
		panic("fakeSchemaFetcher: unexpected tool " + tool)
	}
	var parsed struct {
		GVK string `json:"gvk"`
	}
	if err := json.Unmarshal(args, &parsed); err != nil {
		return nil, err
	}
	f.asked = append(f.asked, parsed.GVK)
	fields, ok := f.fields[parsed.GVK]
	if !ok {
		return json.Marshal(resourceSchemaToolResult{Found: false})
	}
	return json.Marshal(resourceSchemaToolResult{Found: true, TopLevelFields: fields})
}

func deploymentSchemaFetcher() *fakeSchemaFetcher {
	return &fakeSchemaFetcher{
		connected: true,
		fields: map[string][]string{
			"apps/v1/Deployment": {"apiVersion", "kind", "metadata", "spec", "status"},
		},
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_UnknownFieldRefused is B147's
// own regression test: the exact live shape found 2026-09-06
// (breadth-campaign CHG-001) — a Deployment manifest with a top-level
// syncPolicy field that belongs to the Argo CD Application resource, not a
// Deployment — must be refused.
func TestRefuseSchemaInvalidRepositoryProposals_UnknownFieldRefused(t *testing.T) {
	gw := deploymentSchemaFetcher()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: chg001
spec:
  replicas: 1
syncPolicy:
  automated:
    selfHeal: true
`
	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "apps/chg001/deployment.yaml", Content: content}),
	}
	got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
	if got.ProposedPlan != nil {
		t.Fatal("a Deployment manifest carrying a top-level syncPolicy field (which belongs to the Application resource, not a Deployment) must be refused")
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_ValidContentSucceeds is the
// negative case: a plan whose content only uses fields the schema actually
// declares must sail through unchanged.
func TestRefuseSchemaInvalidRepositoryProposals_ValidContentSucceeds(t *testing.T) {
	gw := deploymentSchemaFetcher()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: chg001
spec:
  replicas: 3
`
	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "apps/chg001/deployment.yaml", Content: content}),
	}
	got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
	if got.ProposedPlan == nil {
		t.Fatal("a plan using only fields the schema actually declares must not be refused")
	}
	if len(gw.asked) != 1 || gw.asked[0] != "apps/v1/Deployment" {
		t.Errorf("asked = %v, want exactly one call for apps/v1/Deployment", gw.asked)
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_TemplatedContentSkipped confirms
// the documented, deliberate boundary: content that is not valid YAML at all
// (a Helm template's {{ }} syntax) is skipped, not refused — this guard only
// ever adds a refusal on top of an otherwise-valid plan, and cannot validate
// what it cannot parse into an object with a declared kind.
func TestRefuseSchemaInvalidRepositoryProposals_TemplatedContentSkipped(t *testing.T) {
	gw := deploymentSchemaFetcher()
	content := "replicas: {{ .Values.replicaCount }}\nimage: {{ .Values.image.repository }}:{{ .Values.image.tag }}\n"
	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "charts/web/values.yaml", Content: content}),
	}
	got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
	if got.ProposedPlan == nil {
		t.Fatal("templated content with no identifiable apiVersion/kind must be skipped (honest boundary), not refused")
	}
	if len(gw.asked) != 0 {
		t.Errorf("asked = %v, want no schema calls for content with no apiVersion/kind", gw.asked)
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_UnknownKindSkipped confirms the
// fail-open behavior for a kind this cluster's schema does not recognize
// (an uninstalled CRD, or a typo ARGUS cannot resolve) — skip, don't refuse,
// since this guard cannot tell "genuinely invalid" from "cannot check" here.
func TestRefuseSchemaInvalidRepositoryProposals_UnknownKindSkipped(t *testing.T) {
	gw := &fakeSchemaFetcher{connected: true, fields: map[string][]string{}}
	content := `apiVersion: example.com/v1
kind: TotallyUnknownThing
madeUpField: whatever
`
	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "apps/thing.yaml", Content: content}),
	}
	got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
	if got.ProposedPlan == nil {
		t.Fatal("an unrecognized kind must be skipped (fail open), not refused")
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_DisconnectedClusterFailsOpen is
// this guard's own documented departure from its siblings: an unreachable
// cluster must not make the whole pipeline start refusing plans it would
// have accepted before this check existed.
func TestRefuseSchemaInvalidRepositoryProposals_DisconnectedClusterFailsOpen(t *testing.T) {
	gw := &fakeSchemaFetcher{connected: false}
	content := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  replicas: 1\nsyncPolicy: {}\n"
	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "apps/x/deployment.yaml", Content: content}),
	}
	got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
	if got.ProposedPlan == nil {
		t.Fatal("a disconnected cluster must fail OPEN (skip this check), not refuse the plan")
	}
	if len(gw.asked) != 0 {
		t.Errorf("asked = %v, want no schema calls when the cluster is not connected", gw.asked)
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_DeleteIgnoresContent mirrors
// this file's other guards' own delete exemption: a delete proposes no
// content at all, so there is nothing to validate against a schema.
func TestRefuseSchemaInvalidRepositoryProposals_DeleteIgnoresContent(t *testing.T) {
	gw := deploymentSchemaFetcher()
	result := llm.Investigation{
		Status:       "complete",
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "apps/gone.yaml", Delete: true}),
	}
	got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
	if got.ProposedPlan == nil {
		t.Fatal("a delete proposal must not be refused or checked against a schema")
	}
	if len(gw.asked) != 0 {
		t.Errorf("asked = %v, want no schema calls for a delete", gw.asked)
	}
}

// TestRefuseSchemaInvalidRepositoryProposals_IgnoresNonOpenPRAndNilCases pins
// the guard's scope, mirroring the other guards' own equivalent tests.
func TestRefuseSchemaInvalidRepositoryProposals_IgnoresNonOpenPRAndNilCases(t *testing.T) {
	gw := deploymentSchemaFetcher()
	scaleDeploy := &remediation.RemediationPlan{
		ActionType: remediation.ActionScaleDeployment,
		Params:     remediation.ScaleDeploymentParams{Replicas: 2},
	}

	t.Run("nil plans", func(t *testing.T) {
		got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", llm.Investigation{})
		if got.ProposedPlan != nil || got.ProposedPairedPlan != nil {
			t.Error("nil plans must stay nil")
		}
	})
	t.Run("non-OpenPR plan is untouched", func(t *testing.T) {
		result := llm.Investigation{ProposedPlan: scaleDeploy}
		got := RefuseSchemaInvalidRepositoryProposals(context.Background(), gw, "clu_1", result)
		if got.ProposedPlan != scaleDeploy {
			t.Error("a non-OpenPR plan must be returned untouched")
		}
	})
	t.Run("nil gateway never refuses", func(t *testing.T) {
		content := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec: {}\nsyncPolicy: {}\n"
		result := llm.Investigation{ProposedPlan: openPRPlan(remediation.ProposedFile{Path: "x.yaml", Content: content})}
		got := RefuseSchemaInvalidRepositoryProposals(context.Background(), nil, "clu_1", result)
		if got.ProposedPlan == nil {
			t.Error("a nil gateway must fail open, not refuse")
		}
	})
}
