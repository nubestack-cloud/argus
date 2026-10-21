package remediation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"argus/internal/redact"
)

func TestActionType_Valid(t *testing.T) {
	cases := []struct {
		a    ActionType
		want bool
	}{
		{ActionScaleDeployment, true},
		{ActionRestartPod, true},
		{ActionPatchResourceLimits, true},
		{ActionRevertContainerImage, true},
		{ActionOpenPR, true},
		{ActionType("DeleteNamespace"), false},
		{ActionType(""), false},
	}
	for _, c := range cases {
		if got := c.a.Valid(); got != c.want {
			t.Errorf("ActionType(%q).Valid() = %v, want %v", c.a, got, c.want)
		}
	}
}

func TestRiskLevel_ValidAndOrdering(t *testing.T) {
	for _, r := range []RiskLevel{RiskLow, RiskMedium, RiskHigh} {
		if !r.Valid() {
			t.Errorf("RiskLevel(%q).Valid() = false, want true", r)
		}
	}
	if RiskLevel("critical").Valid() {
		t.Error(`RiskLevel("critical").Valid() = true, want false`)
	}

	if !RiskLow.atMost(RiskHigh) {
		t.Error("RiskLow should be at most RiskHigh")
	}
	if !RiskMedium.atMost(RiskMedium) {
		t.Error("RiskMedium should be at most RiskMedium (inclusive)")
	}
	if RiskHigh.atMost(RiskLow) {
		t.Error("RiskHigh should not be at most RiskLow")
	}
	if RiskLow.atMost(RiskLevel("bogus")) {
		t.Error("comparing against an invalid ceiling should never report true")
	}
}

func TestRemediationPlan_Validate_AcceptsOneRealisticPlanPerActionType(t *testing.T) {
	plans := []RemediationPlan{
		scaleUpPlan(),
		restartPodPlan(),
		patchResourceLimitsPlan(),
		revertContainerImagePlan(),
		openPRPlan(),
	}
	for i, p := range plans {
		if err := p.Validate(); err != nil {
			t.Errorf("plans[%d] (%s): Validate() = %v, want nil", i, p.ActionType, err)
		}
	}
}

func TestRemediationPlan_Validate_RejectsUnknownActionType(t *testing.T) {
	p := scaleUpPlan()
	p.ActionType = ActionType("DeleteNamespace")
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for an unrecognized ActionType")
	}
}

func TestRemediationPlan_Validate_RejectsNilParams(t *testing.T) {
	p := scaleUpPlan()
	p.Params = nil
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for nil Params")
	}
}

func TestRemediationPlan_Validate_RejectsMismatchedParams(t *testing.T) {
	p := scaleUpPlan()
	p.Params = OpenPRParams{Repository: "x", Files: []ProposedFile{{Path: "a.yaml", Content: "a: b\n"}}}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error when Params doesn't match ActionType")
	}
}

func TestRemediationPlan_Validate_RejectsInvalidRiskLevel(t *testing.T) {
	p := scaleUpPlan()
	p.RiskLevel = RiskLevel("critical")
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for an invalid RiskLevel")
	}
}

func TestRemediationPlan_Validate_RejectsMissingTargetName(t *testing.T) {
	p := scaleUpPlan()
	p.TargetName = ""
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for a missing target name")
	}
}

// --- PatchResourceLimitsParams bounds ---------------------------------------

func TestPatchResourceLimitsParams_Validate_AcceptsRealisticChanges(t *testing.T) {
	cases := []struct {
		name   string
		params PatchResourceLimitsParams
	}{
		{"raise only the memory limit (the OOMKill fix)", PatchResourceLimitsParams{Container: "api", MemoryLimit: "256Mi"}},
		{"raise limit and request together", PatchResourceLimitsParams{Container: "api", MemoryLimit: "1Gi", MemoryRequest: "512Mi"}},
		{"request equal to limit (Guaranteed QoS preserved)", PatchResourceLimitsParams{Container: "api", MemoryLimit: "512Mi", MemoryRequest: "512Mi"}},
		{"cpu in millicores", PatchResourceLimitsParams{Container: "api", CPULimit: "1500m", CPURequest: "250m"}},
		{"cpu in whole cores", PatchResourceLimitsParams{Container: "worker-2", CPULimit: "2"}},
		{"all four at once", PatchResourceLimitsParams{Container: "api", MemoryLimit: "1Gi", MemoryRequest: "512Mi", CPULimit: "2", CPURequest: "500m"}},
		{"exactly at the ceilings", PatchResourceLimitsParams{Container: "api", MemoryLimit: maxMemoryQuantity, CPULimit: maxCPUQuantity}},
		{"exactly at the floors", PatchResourceLimitsParams{Container: "api", MemoryLimit: minMemoryQuantity, CPULimit: minCPUQuantity}},
	}
	for _, c := range cases {
		if err := c.params.Validate(); err != nil {
			t.Errorf("%s: Validate() = %v, want nil", c.name, err)
		}
	}
}

func TestPatchResourceLimitsParams_Validate_RejectsBadParams(t *testing.T) {
	cases := []struct {
		name   string
		params PatchResourceLimitsParams
	}{
		{"no container named", PatchResourceLimitsParams{MemoryLimit: "256Mi"}},
		{"container name is not a DNS label", PatchResourceLimitsParams{Container: "My Container", MemoryLimit: "256Mi"}},
		{"nothing to change", PatchResourceLimitsParams{Container: "api"}},
		{"memory limit in the terabytes", PatchResourceLimitsParams{Container: "api", MemoryLimit: "2Ti"}},
		{"memory limit just over the ceiling", PatchResourceLimitsParams{Container: "api", MemoryLimit: "65Gi"}},
		{"memory limit below the floor", PatchResourceLimitsParams{Container: "api", MemoryLimit: "8Mi"}},
		{"memory request in the terabytes", PatchResourceLimitsParams{Container: "api", MemoryRequest: "5Ti"}},
		{"cpu limit above the ceiling", PatchResourceLimitsParams{Container: "api", CPULimit: "64"}},
		{"cpu request below the floor", PatchResourceLimitsParams{Container: "api", CPURequest: "1m"}},
		{"zero", PatchResourceLimitsParams{Container: "api", MemoryLimit: "0"}},
		{"negative", PatchResourceLimitsParams{Container: "api", CPULimit: "-500m"}},
		{"not a quantity at all", PatchResourceLimitsParams{Container: "api", MemoryLimit: "as much as it needs"}},
		{"memory request above memory limit", PatchResourceLimitsParams{Container: "api", MemoryLimit: "256Mi", MemoryRequest: "512Mi"}},
		{"cpu request above cpu limit", PatchResourceLimitsParams{Container: "api", CPULimit: "500m", CPURequest: "1"}},
	}
	for _, c := range cases {
		if err := c.params.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", c.name)
		}
	}
}

// TestPatchResourceLimitsParams_Validate_ComparesAcrossScales guards the
// specific class of bug that made using Kubernetes' own quantity parser
// non-negotiable: "1000m" and "1" are the same CPU value, and "1Gi" is larger
// than "999Mi" but SMALLER than "2G" — none of which a string comparison or a
// naive suffix table gets right.
func TestPatchResourceLimitsParams_Validate_ComparesAcrossScales(t *testing.T) {
	// request == limit expressed in different scales must be accepted, not
	// read as request > limit.
	equalAcrossScales := PatchResourceLimitsParams{Container: "api", CPULimit: "1", CPURequest: "1000m"}
	if err := equalAcrossScales.Validate(); err != nil {
		t.Errorf("cpuLimit 1 with cpuRequest 1000m: Validate() = %v, want nil (same value, different scale)", err)
	}
	// And a genuine violation across scales must still be caught.
	overAcrossScales := PatchResourceLimitsParams{Container: "api", CPULimit: "999m", CPURequest: "1"}
	if err := overAcrossScales.Validate(); err == nil {
		t.Error("cpuLimit 999m with cpuRequest 1: Validate() = nil, want an error")
	}
	// Decimal-vs-binary memory suffixes: 1G (10^9) is below 1Gi (2^30).
	memAcrossScales := PatchResourceLimitsParams{Container: "api", MemoryLimit: "1G", MemoryRequest: "1Gi"}
	if err := memAcrossScales.Validate(); err == nil {
		t.Error("memoryLimit 1G with memoryRequest 1Gi: Validate() = nil, want an error (1Gi > 1G)")
	}
}

// --- RevertContainerImageParams / RevertContainerImageExecParams ------------

func TestRevertContainerImageParams_Validate(t *testing.T) {
	ok := []string{"api", "worker-2", "a", "log-shipper"}
	for _, container := range ok {
		if err := (RevertContainerImageParams{Container: container}).Validate(); err != nil {
			t.Errorf("container %q: Validate() = %v, want nil", container, err)
		}
	}
	bad := []string{"", "My Container", "api_1", "-api", "api-", "api/1"}
	for _, container := range bad {
		if err := (RevertContainerImageParams{Container: container}).Validate(); err == nil {
			t.Errorf("container %q: Validate() = nil, want an error", container)
		}
	}
}

// TestRevertContainerImageParams_CannotCarryAnImage is the structural check
// behind this action's central safety claim: the proposable params type has no
// field an image could be decoded into, so a model (or a hand-edited
// remediation_recommendations row) that supplies one is ignored rather than
// trusted. Asserted by round-tripping the exact JSON such a caller would send.
func TestRevertContainerImageParams_CannotCarryAnImage(t *testing.T) {
	var p RevertContainerImageParams
	if err := json.Unmarshal([]byte(`{"container":"api","image":"evil.example.com/backdoor:latest"}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Container != "api" {
		t.Errorf("Container = %q, want %q", p.Container, "api")
	}
	// The whole point: whatever the sender wrote for "image" is gone, and there
	// is nowhere for it to have gone TO.
	marshaled, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(marshaled), "image") {
		t.Errorf("marshaled params = %s, want no image field at all", marshaled)
	}
}

// TestRevertContainerImageExecParams_Validate covers the execution-time form —
// the one the hub builds from live cluster state and the agent re-checks. The
// image cases are deliberately about SHAPE only: whether an image is legitimate
// is decided by its presence in the workload's ReplicaSet history, not here
// (see containerImageRE's doc comment).
func TestRevertContainerImageExecParams_Validate(t *testing.T) {
	ok := []string{
		"nginx",
		"nginx:1.27.1",
		"registry.example.com/team/app:1.2.3",
		"registry.example.com:5000/team/app:1.2.3",
		"registry.example.com/team/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"ghcr.io/org/sub/app:v1.2.3-rc.1",
	}
	for _, image := range ok {
		if err := (RevertContainerImageExecParams{Container: "api", Image: image}).Validate(); err != nil {
			t.Errorf("image %q: Validate() = %v, want nil", image, err)
		}
	}

	bad := []struct {
		name   string
		params RevertContainerImageExecParams
	}{
		{"no image at all — the un-resolved plan", RevertContainerImageExecParams{Container: "api"}},
		{"no container", RevertContainerImageExecParams{Image: "nginx:1.27.1"}},
		{"whitespace in the reference", RevertContainerImageExecParams{Container: "api", Image: "nginx:1.27 .1"}},
		{"leading space", RevertContainerImageExecParams{Container: "api", Image: " nginx:1.27.1"}},
		{"embedded newline", RevertContainerImageExecParams{Container: "api", Image: "nginx:1.27.1\nmalicious"}},
		{"shell metacharacters", RevertContainerImageExecParams{Container: "api", Image: "nginx:1.27.1;rm -rf /"}},
		{"quotes", RevertContainerImageExecParams{Container: "api", Image: `nginx:"latest"`}},
		{"absurdly long", RevertContainerImageExecParams{Container: "api", Image: strings.Repeat("a", maxContainerImageLength+1)}},
	}
	for _, c := range bad {
		if err := c.params.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", c.name)
		}
	}
}

// TestRevertContainerImageExecParamsIsNotActionParams pins the type-level
// invariant in the one way a test can: RevertContainerImageExecParams must not
// satisfy ActionParams, or an image-carrying params value would be assignable
// to RemediationPlan.Params and the "no plan can name an image" guarantee would
// become a convention.
func TestRevertContainerImageExecParamsIsNotActionParams(t *testing.T) {
	var v any = RevertContainerImageExecParams{Container: "api", Image: "nginx:1.27.1"}
	if _, ok := v.(ActionParams); ok {
		t.Error("RevertContainerImageExecParams implements ActionParams — a plan could then carry a model-supplied image")
	}
	// The proposable form, by contrast, must be assignable.
	var p any = RevertContainerImageParams{Container: "api"}
	if _, ok := p.(ActionParams); !ok {
		t.Error("RevertContainerImageParams does not implement ActionParams")
	}
}

// TestRemediationPlan_Validate_EnforcesParamsBounds is the wiring check: a
// plan carrying out-of-bounds params must fail the PLAN's own Validate, since
// that (and not the params method) is what the gate calls.
func TestRemediationPlan_Validate_EnforcesParamsBounds(t *testing.T) {
	p := patchResourceLimitsPlan()
	p.Params = PatchResourceLimitsParams{Container: "api", MemoryLimit: "4Ti"}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error — an absurd memory limit must not reach an approver")
	}

	// And the gate must classify it as Blocked (a plan-authoring problem),
	// not as something to ask a human about.
	if d := Evaluate(p, floatPtr(0.99), permissivePolicy()); d.Outcome != Blocked {
		t.Fatalf("Evaluate outcome = %v (%q), want Blocked", d.Outcome, d.Reason)
	}
}

// --- OpenPRParams: the whole-file contract --------------------------------

// TestOpenPRParams_Validate_RejectsAnUnusableFileSet replaces the old
// single-field guards (BUGS.md 110's multi-line NewValue check and its
// siblings). Those existed because the ONE mechanism that could apply an
// OpenPR plan refused a multi-line value, so a plan carrying one sailed
// through Validate, through the confidence/risk gate, and sat AwaitingApproval
// looking exactly as ready as a plan that would work — then failed identically
// on every approval attempt forever.
//
// A whole-file change cannot have that defect: multi-line content is the
// normal case now, and RUN-018's fix (one word inside a YAML block-scalar
// shell script) is expressible for the first time. What CAN still make a plan
// unapplicable is a file set that is not a file set, and those are what this
// checks — each of them at analyze time, before the plan reaches an approver.
func TestOpenPRParams_Validate_RejectsAnUnusableFileSet(t *testing.T) {
	cases := []struct {
		name    string
		params  OpenPRParams
		wantMsg string
	}{
		{
			name:    "no files at all",
			params:  OpenPRParams{Repository: "example-org/checkout-manifests"},
			wantMsg: "files is required",
		},
		{
			name: "a file with no path",
			params: OpenPRParams{Files: []ProposedFile{
				{Path: "  ", Content: "a: b\n"},
			}},
			wantMsg: "must name a path",
		},
		{
			name: "a file with no content — a deletion this channel cannot express",
			params: OpenPRParams{Files: []ProposedFile{
				{Path: "envs/prod/app.yaml", Content: "   \n"},
			}},
			wantMsg: "no content",
		},
		{
			name: "the same path twice",
			params: OpenPRParams{Files: []ProposedFile{
				{Path: "envs/prod/app.yaml", Content: "a: b\n"},
				{Path: "envs/prod/app.yaml", Content: "a: c\n"},
			}},
			wantMsg: "appears twice",
		},
		{
			name: "more files than one pull request may carry",
			params: OpenPRParams{Files: func() []ProposedFile {
				var out []ProposedFile
				for i := 0; i <= maxProposedFiles; i++ {
					out = append(out, ProposedFile{Path: fmt.Sprintf("envs/prod/f%d.yaml", i), Content: "a: b\n"})
				}
				return out
			}()},
			wantMsg: "over the",
		},
		{
			name: "a single file over the byte bound",
			params: OpenPRParams{Files: []ProposedFile{
				{Path: "envs/prod/app.yaml", Content: strings.Repeat("x", maxProposedFileBytes+1)},
			}},
			wantMsg: "over the",
		},
		{
			name: "a file marked delete that also carries content",
			params: OpenPRParams{Files: []ProposedFile{
				{Path: "envs/prod/hpa-a.yaml", Content: "a: b\n", Delete: true},
			}},
			wantMsg: "not both",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.params.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("Validate() error = %q, want it to mention %q", err.Error(), c.wantMsg)
			}
		})
	}
}

// TestOpenPRParams_Validate_AcceptsMultiLineAndMultiFile is the regression
// guard for what the rewrite exists to allow: content spanning many lines, and
// a change spanning several files, are both ordinary and must pass.
func TestOpenPRParams_Validate_AcceptsMultiLineAndMultiFile(t *testing.T) {
	p := OpenPRParams{
		Repository: "example-org/checkout-manifests",
		Files: []ProposedFile{
			{Path: "charts/checkout/values.yaml", Content: "replicaCount: 2\nresources:\n  limits:\n    memory: 512Mi\n"},
			// The exact shape BUGS.md 110's guard used to make unrepresentable:
			// a multi-line block scalar, one word of which needed changing.
			{Path: "charts/checkout/templates/deployment.yaml", Content: "spec:\n  initContainers:\n    - command:\n        - sh\n        - -c\n        - |\n          until nc -z run018-db 5432; do\n            sleep 1\n          done\n"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a multi-file, multi-line change", err)
	}
}

// TestOpenPRParams_Validate_AcceptsDelete is BACKLOG.md "still open" #2:
// AB1's finding named the correct fix for two overlapping HPAs as "delete one
// whole HPA manifest from the repo" — a file may now be proposed with
// Delete:true and no content, alone or mixed with an ordinary write to a
// DIFFERENT file in the same plan.
func TestOpenPRParams_Validate_AcceptsDelete(t *testing.T) {
	cases := []struct {
		name   string
		params OpenPRParams
	}{
		{
			name:   "a delete alone",
			params: OpenPRParams{Files: []ProposedFile{{Path: "envs/prod/hpa-a.yaml", Delete: true}}},
		},
		{
			name: "a delete mixed with a write to a different file",
			params: OpenPRParams{Files: []ProposedFile{
				{Path: "envs/prod/hpa-a.yaml", Delete: true},
				{Path: "envs/prod/hpa-b.yaml", Content: "spec:\n  maxReplicas: 5\n"},
			}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.params.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestRemediationPlan_Validate_BlocksAnEmptyOpenPRFileSet confirms the effect
// that actually matters: a structurally unusable OpenPR plan Blocks at
// RemediationPlan.Validate (and therefore at Evaluate, before any
// confidence/risk gating), not merely fails OpenPRParams.Validate in isolation.
func TestRemediationPlan_Validate_BlocksAnEmptyOpenPRFileSet(t *testing.T) {
	p := openPRPlan()
	p.Params = OpenPRParams{Repository: "example-org/checkout-manifests"}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error — an OpenPR plan naming no files must Block, not reach the confidence/risk gate")
	}
	if d := Evaluate(p, floatPtr(0.98), permissivePolicy()); d.Outcome != Blocked {
		t.Fatalf("Evaluate outcome = %v (%q), want Blocked", d.Outcome, d.Reason)
	}
}

// TestOpenPRParams_Validate_RejectsRedactionMarker is BUGS.md 112's exact live
// repro: a CFG-004-shaped fixture where the model's proposed fix ("rename
// this ConfigMap key, keep its value") required echoing a value it was
// structurally never shown (internal/redact.Marker having replaced it before
// the model ever saw the ConfigMap). Live incident inc_01m14p3awe53gd6ha49a02dvcf
// reached confidence 1.00 with a correct root cause and a plan carrying
// exactly this NewValue; approving it opened a real pull request
// (example-org/argocd-argus-test#56) writing the literal string "[REDACTED]" as
// real ConfigMap content. This must now fail Validate() instead of reaching
// AutoApprove.
func TestOpenPRParams_Validate_RejectsRedactionMarker(t *testing.T) {
	p := OpenPRParams{
		Repository: "example-org/argocd-argus-test",
		Files: []ProposedFile{{
			Path:    "envs/prod/configmap.yaml",
			Content: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\ndata:\n  RETRY_LIMIT: \"" + redact.Marker + "\"\n",
		}},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error for content that echoes redact.Marker")
	}
	if !errors.Is(err, ErrNewValueEchoesRedactionMarker) {
		t.Errorf("Validate() error = %v, want it to wrap ErrNewValueEchoesRedactionMarker", err)
	}
	if !strings.Contains(err.Error(), redact.Marker) {
		t.Errorf("Validate() error = %q, want it to name the marker", err.Error())
	}
}

// TestOpenPRParams_Validate_RejectsRedactionMarkerEmbedded confirms the check
// is a substring match, not an exact-equality one: a model padding the marker
// with surrounding text ("the value is [REDACTED]") is just as unable to have
// known the real value, and must be refused the same way.
func TestOpenPRParams_Validate_RejectsRedactionMarkerEmbedded(t *testing.T) {
	p := OpenPRParams{
		Repository: "example-org/argocd-argus-test",
		Files: []ProposedFile{{
			Path:    "envs/prod/configmap.yaml",
			Content: "data:\n  RETRY_LIMIT: \"value was " + redact.Marker + " previously\"\n",
		}},
	}
	if err := p.Validate(); !errors.Is(err, ErrNewValueEchoesRedactionMarker) {
		t.Errorf("Validate() error = %v, want ErrNewValueEchoesRedactionMarker for an embedded marker", err)
	}
}

// TestRemediationPlan_Validate_BlocksOpenPRRedactionMarker confirms the effect
// that actually matters, matching TestRemediationPlan_Validate_
// BlocksOpenPRMultilineNewValue's shape: a plan carrying a redacted-echo
// NewValue must Block at RemediationPlan.Validate()/Evaluate, before ever
// reaching the confidence/risk gate — this is the exact transition CFG-004's
// live incident needed and never got (it reached AutoApprove instead).
func TestRemediationPlan_Validate_BlocksOpenPRRedactionMarker(t *testing.T) {
	p := openPRPlan()
	p.Params = OpenPRParams{
		Repository: "example-org/argocd-argus-test",
		Files: []ProposedFile{{
			Path:    "envs/prod/configmap.yaml",
			Content: "data:\n  RETRY_LIMIT: \"" + redact.Marker + "\"\n",
		}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error — a redacted-echo OpenPR file must Block, not reach the confidence/risk gate")
	}
	if d := Evaluate(p, floatPtr(1.0), permissivePolicy()); d.Outcome != Blocked {
		t.Fatalf("Evaluate outcome = %v (%q), want Blocked — this is exactly the plan that live reached AutoApprove and opened a real pull request (PR #56) writing the marker as content", d.Outcome, d.Reason)
	}
}

// TestPatchFieldParams_Validate_RejectsRedactionMarker confirms
// PatchFieldParams carries the identical guard, even though no live
// PatchFieldPermitted allowlist entry currently reaches a redacted field
// class (see the Validate() doc comment) — the check is on the params value
// alone and does not know or care whether the allowlist can reach it.
func TestPatchFieldParams_Validate_RejectsRedactionMarker(t *testing.T) {
	p := PatchFieldParams{FieldPath: "spec.ports.0.targetPort", NewValue: redact.Marker}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error for a NewValue that echoes redact.Marker")
	}
	if !errors.Is(err, ErrNewValueEchoesRedactionMarker) {
		t.Errorf("Validate() error = %v, want it to wrap ErrNewValueEchoesRedactionMarker", err)
	}
}

// TestOpenPRParams_Validate_AcceptsOrdinaryContentMentioningRedacted is a
// regression guard in the other direction from
// TestOpenPRParams_Validate_AcceptsMultiLineAndMultiFile: ordinary content
// that happens to contain the word "redacted" (lowercase, no brackets, not
// the exact marker) must be completely unaffected — the check is a substring
// match against the exact marker string, not a fuzzy "sounds like a
// placeholder" heuristic.
func TestOpenPRParams_Validate_AcceptsOrdinaryContentMentioningRedacted(t *testing.T) {
	p := OpenPRParams{
		Repository: "example-org/checkout-manifests",
		Files: []ProposedFile{{
			Path:    "envs/prod/configmap.yaml",
			Content: "data:\n  NOTE: \"previous value was redacted by the vendor, now restored\"\n",
		}},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil — this content does not contain the exact marker string", err)
	}
}

// --- ParamsOnlyValidationFailure (BUGS.md 109 / BACKLOG.md AG1) ------------

// TestParamsOnlyValidationFailure_NilParams is BUGS.md 109's exact live
// shape: an OpenPR plan whose Params the model left nil (parseProposedPlan's
// own deliberate behaviour on an empty/unparseable wire.Params). This is
// precisely the case internal/api's analyze-time correction attempt must
// fire on.
func TestParamsOnlyValidationFailure_NilParams(t *testing.T) {
	p := openPRPlan()
	p.Params = nil
	reason, ok := p.ParamsOnlyValidationFailure()
	if !ok {
		t.Fatal("ParamsOnlyValidationFailure() = false, want true for nil Params")
	}
	if !strings.Contains(reason, "params is required") {
		t.Errorf("reason = %q, want it to name the params-required failure", reason)
	}
}

// TestParamsOnlyValidationFailure_InvalidParamsValue covers the second
// correctable shape: Params is present, of the right concrete type, but
// fails its own selfValidatingParams bounds check (here, OpenPRParams naming
// no files at all — the same "the model tried, but what it produced is no
// good" shape a post-approval dry-run rejection corrects).
func TestParamsOnlyValidationFailure_InvalidParamsValue(t *testing.T) {
	p := openPRPlan()
	p.Params = OpenPRParams{Repository: "example-org/checkout-manifests"} // no files
	reason, ok := p.ParamsOnlyValidationFailure()
	if !ok {
		t.Fatal("ParamsOnlyValidationFailure() = false, want true for a Params value that fails its own Validate()")
	}
	if reason == "" {
		t.Error("reason is empty, want the underlying Validate() failure text")
	}
}

// TestParamsOnlyValidationFailure_EmptyFileContentIsCorrectionEligible is the
// successor to BUGS.md 110 / BACKLOG.md AL1's decision, in the whole-file
// grammar: unlike the PatchField/StructuredPatch allowlist refusal (a policy
// refusal of a field PATH, independent of any value — provably unfixable by a
// corrected value), a file the model left empty is a refusal of what it
// PRODUCED, the same kind of failure TestParamsOnlyValidationFailure_
// InvalidParamsValue already exercises — so it is deliberately left
// correction-eligible rather than excluded. See ParamsOnlyValidationFailure's
// own doc comment for the full reasoning.
func TestParamsOnlyValidationFailure_EmptyFileContentIsCorrectionEligible(t *testing.T) {
	p := openPRPlan()
	p.Params = OpenPRParams{
		Repository: "example-org/checkout-manifests",
		Files:      []ProposedFile{{Path: "charts/checkout/values.yaml", Content: ""}},
	}
	reason, ok := p.ParamsOnlyValidationFailure()
	if !ok {
		t.Fatal("ParamsOnlyValidationFailure() = false, want true — an empty file body is a Params problem a corrected proposal might fix")
	}
	if !strings.Contains(reason, "no content") {
		t.Errorf("reason = %q, want it to name the empty-content failure", reason)
	}
}

// TestParamsOnlyValidationFailure_RedactionMarkerIsCorrectionIneligible is
// BUGS.md 112's explicit, documented decision, made in deliberate CONTRAST to
// TestParamsOnlyValidationFailure_MultilineNewValueIsCorrectionEligible just
// above: both are refusals of the params VALUE rather than the field PATH,
// and both would otherwise fall into the same generic selfValidatingParams
// branch, but a redaction-marker rejection is excluded anyway. Reasoning
// (spelled out in full in ParamsOnlyValidationFailure's doc comment): a
// correction attempt here would hand the exact same model the exact same
// rejection text with no new information — the real value was never shown to
// it and still is not — so success is not merely unlikely (BUGS 110's
// multi-line case) but structurally impossible, the same class of certainty
// that excludes the PatchField/StructuredPatch allowlist case, just for a
// VALUE-shaped reason instead of a PATH-shaped one.
func TestParamsOnlyValidationFailure_RedactionMarkerIsCorrectionIneligible(t *testing.T) {
	p := openPRPlan()
	p.Params = OpenPRParams{
		Repository: "example-org/argocd-argus-test",
		Files: []ProposedFile{{
			Path:    "envs/prod/configmap.yaml",
			Content: "data:\n  RETRY_LIMIT: \"" + redact.Marker + "\"\n",
		}},
	}
	if reason, ok := p.ParamsOnlyValidationFailure(); ok {
		t.Errorf("ParamsOnlyValidationFailure() = (%q, true), want (_, false) — a redaction-marker echo cannot be fixed by asking the same model again", reason)
	}
}

// TestParamsOnlyValidationFailure_RejectsEveryOtherBlockedReason is
// requirement 3 of BUGS.md 109's fix: a plan Blocked for any reason OTHER
// than nil/invalid Params must NOT be reported as correctable — an
// unrecognized ActionType, an invalid RiskLevel, a missing TargetName, a
// Params/ActionType mismatch, and a PatchField path the allowlist itself
// refuses (a policy refusal no corrected VALUE could ever satisfy) all need
// a different fix than different Params values.
func TestParamsOnlyValidationFailure_RejectsEveryOtherBlockedReason(t *testing.T) {
	cases := []struct {
		name string
		plan RemediationPlan
	}{
		{"unrecognized action type", func() RemediationPlan {
			p := scaleUpPlan()
			p.ActionType = ActionType("DeleteNamespace")
			return p
		}()},
		{"invalid risk level", func() RemediationPlan {
			p := scaleUpPlan()
			p.RiskLevel = RiskLevel("critical")
			return p
		}()},
		{"missing target name", func() RemediationPlan {
			p := scaleUpPlan()
			p.TargetName = ""
			return p
		}()},
		{"params/actionType mismatch", func() RemediationPlan {
			p := scaleUpPlan()
			p.Params = OpenPRParams{Repository: "x", Files: []ProposedFile{{Path: "a.yaml", Content: "a: b\n"}}}
			return p
		}()},
		{"PatchField path the allowlist refuses (not in the table at all)", RemediationPlan{
			ActionType:      ActionPatchField,
			TargetGVK:       "v1/Secret",
			TargetNamespace: "payments",
			TargetName:      "checkout-api",
			Params:          PatchFieldParams{FieldPath: "data.password", NewValue: "x"},
			Reversible:      true,
			RiskLevel:       RiskMedium,
		}},
		{"already valid — nothing to correct", scaleUpPlan()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if reason, ok := c.plan.ParamsOnlyValidationFailure(); ok {
				t.Errorf("ParamsOnlyValidationFailure() = (%q, true), want (_, false) — this Blocked reason is not a Params-value problem", reason)
			}
		})
	}
}

// TestHigherRisk pins the comparator WORKLOG §97's G3 fix depends on: it must
// order Low < Medium < High, and an unrecognized level must rank as SAFE
// (never higher) so a malformed value fails toward "proceed as evaluated,"
// not toward blocking every plan outright — the absolute floor is still
// enforced elsewhere (RiskFloorFor's own unrecognized-action-type case).
func TestHigherRisk(t *testing.T) {
	if !HigherRisk(RiskHigh, RiskMedium) {
		t.Error("High must rank above Medium")
	}
	if !HigherRisk(RiskMedium, RiskLow) {
		t.Error("Medium must rank above Low")
	}
	if HigherRisk(RiskLow, RiskHigh) {
		t.Error("Low must not rank above High")
	}
	if HigherRisk(RiskHigh, RiskHigh) {
		t.Error("a level must not rank above itself")
	}
	if HigherRisk(RiskLevel("bogus"), RiskLow) {
		t.Error("an unrecognized level must never compare as higher than a known one")
	}
	if HigherRisk(RiskHigh, RiskLevel("bogus")) {
		t.Error("an unrecognized level must never be beaten either — HigherRisk should decline to compare, not invent an order")
	}
}

// TestPatchResourceLimitsParams_ValidateRestore: a compensating action records
// what the live container already holds, so the absolute MINIMUMS — a rule
// about what ARGUS may propose — must not apply to it, while every other rule
// still must. Found live (T5, 2026-09-17): a 4Mi-limited container could not
// be given more memory, because the undo of that change says "4Mi" and 4Mi is
// below minMemoryQuantity.
func TestPatchResourceLimitsParams_ValidateRestore(t *testing.T) {
	belowMinimum := PatchResourceLimitsParams{Container: "web", MemoryLimit: "4Mi"}
	if err := belowMinimum.Validate(); err == nil {
		t.Error("Validate() accepted a 4Mi memory limit — the forward minimum must still hold for a proposal")
	}
	if err := belowMinimum.ValidateRestore(); err != nil {
		t.Errorf("ValidateRestore() = %v, want nil: restoring an observed 4Mi limit is describing reality, not proposing it", err)
	}

	belowCPUMinimum := PatchResourceLimitsParams{Container: "web", CPURequest: "1m"}
	if err := belowCPUMinimum.Validate(); err == nil {
		t.Error("Validate() accepted a 1m CPU request — the forward minimum must still hold")
	}
	if err := belowCPUMinimum.ValidateRestore(); err != nil {
		t.Errorf("ValidateRestore() = %v, want nil for an observed 1m CPU request", err)
	}

	// Everything else Validate checks is still checked. Each of these would be
	// a silently accepted, unusable undo if ValidateRestore had simply been
	// stubbed out instead of having one rule removed.
	for _, c := range []struct {
		name   string
		params PatchResourceLimitsParams
	}{
		{"a name that is not a container name", PatchResourceLimitsParams{Container: "Web_1", MemoryLimit: "64Mi"}},
		{"nothing to restore", PatchResourceLimitsParams{Container: "web"}},
		{"not a quantity", PatchResourceLimitsParams{Container: "web", MemoryLimit: "four megs"}},
		{"zero", PatchResourceLimitsParams{Container: "web", MemoryLimit: "0"}},
		{"negative", PatchResourceLimitsParams{Container: "web", MemoryLimit: "-64Mi"}},
		{"above the memory maximum", PatchResourceLimitsParams{Container: "web", MemoryLimit: "128Gi"}},
		{"above the cpu maximum", PatchResourceLimitsParams{Container: "web", CPULimit: "64"}},
		{"request above its own limit", PatchResourceLimitsParams{Container: "web", MemoryRequest: "128Mi", MemoryLimit: "64Mi"}},
	} {
		if err := c.params.ValidateRestore(); err == nil {
			t.Errorf("ValidateRestore() accepted %s — only the absolute minimums are dropped, not every other rule", c.name)
		}
	}
}

// TestNewVerifiedRestorePlan_MarksProvenance (PROJECT.md B171) asserts the
// one property RestoreVerified() exists for: a plan built by the constructor
// reports true, and an ordinary plan built the plain way — exactly how every
// model-authored or hand-authored plan in this codebase is built — reports
// false. If this ever drifted, a live-state check trusting RestoreVerified()
// to relax a rule would be trusting exactly the wrong plans.
func TestNewVerifiedRestorePlan_MarksProvenance(t *testing.T) {
	restoreParams := PatchResourceLimitsParams{Container: "web", MemoryLimit: "4Mi"}
	plan, err := NewVerifiedRestorePlan(ActionPatchResourceLimits, restoreParams, "apps/v1/Deployment", "prod", "web")
	if err != nil {
		t.Fatalf("NewVerifiedRestorePlan() = %v, want nil", err)
	}
	if !plan.RestoreVerified() {
		t.Error("a plan built by NewVerifiedRestorePlan must report RestoreVerified() == true")
	}
	if !plan.Reversible {
		t.Error("a restore plan is reversible by construction")
	}
	if plan.RiskLevel != RiskLow {
		t.Errorf("RiskLevel = %q, want %q", plan.RiskLevel, RiskLow)
	}
	if plan.TargetGVK != "apps/v1/Deployment" || plan.TargetNamespace != "prod" || plan.TargetName != "web" {
		t.Errorf("target not carried through: got %s %s/%s", plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
	}

	// The ordinary construction path every proposed (forward) plan in this
	// codebase actually uses — a literal RemediationPlan{...}, exactly the
	// shape a model's proposal or an approval retry builds. This must NEVER
	// report RestoreVerified() == true: there is no field on the literal a
	// caller could set to make it so, which is the whole point, but this
	// pins the zero-value behaviour so a future field reordering or an
	// exported alias could not silently flip the default.
	ordinary := RemediationPlan{
		ActionType:      ActionPatchResourceLimits,
		Params:          restoreParams,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "prod",
		TargetName:      "web",
		Reversible:      true,
		RiskLevel:       RiskLow,
	}
	if ordinary.RestoreVerified() {
		t.Error("an ordinarily-constructed RemediationPlan must never report RestoreVerified() == true")
	}
}

// TestNewVerifiedRestorePlan_RejectsMismatchedParams: the constructor asserts
// params.actionType() against the actionType argument, so a caller cannot
// mismatch the two and — more to the point for B171 — cannot mint a verified
// plan for an action type the params were never decoded for.
func TestNewVerifiedRestorePlan_RejectsMismatchedParams(t *testing.T) {
	scaleParams := ScaleDeploymentParams{Replicas: 3}
	if _, err := NewVerifiedRestorePlan(ActionPatchResourceLimits, scaleParams, "apps/v1/Deployment", "prod", "web"); err == nil {
		t.Error("NewVerifiedRestorePlan() accepted params whose actionType() does not match the requested action type")
	}
	if _, err := NewVerifiedRestorePlan(ActionScaleDeployment, nil, "apps/v1/Deployment", "prod", "web"); err == nil {
		t.Error("NewVerifiedRestorePlan() accepted nil params")
	}
}

// TestRemediationPlan_Validate_DoesNotRequireRestoreVerified guards against a
// tempting but wrong "simplification": RestoreVerified() must not become a
// way to skip RemediationPlan.Validate()'s own structural checks (container
// name shape, request<=limit, the maxima) — B171's fix is narrowly about the
// live-state "may only raise" rule (checkResourceLimitsBound rule 2 in
// internal/api), never about the params-level bounds this package owns.
// ValidateRestore already drops only the absolute minimums (see
// TestPatchResourceLimitsParams_ValidateRestore); this test pins that a
// verified restore plan still goes through exactly that same, narrow
// relaxation and nothing broader.
func TestRemediationPlan_Validate_DoesNotRequireRestoreVerified(t *testing.T) {
	// A restore plan whose params violate a rule ValidateRestore does NOT
	// drop (request above its own limit) must still fail RemediationPlan's
	// own Validate(), because Params for a PatchResourceLimits plan is still
	// the ordinary PatchResourceLimitsParams — RestoreVerified() carries the
	// provenance fact on the PLAN, it does not change which Validate the
	// params type itself runs through RemediationPlan.Validate()'s
	// selfValidatingParams call.
	badRestore := PatchResourceLimitsParams{Container: "web", MemoryRequest: "128Mi", MemoryLimit: "64Mi"}
	plan, err := NewVerifiedRestorePlan(ActionPatchResourceLimits, badRestore, "apps/v1/Deployment", "prod", "web")
	if err != nil {
		t.Fatalf("NewVerifiedRestorePlan() = %v, want nil", err)
	}
	if !plan.RestoreVerified() {
		t.Fatal("sanity: plan should report RestoreVerified() == true")
	}
	if err := plan.Validate(); err == nil {
		t.Error("RemediationPlan.Validate() accepted a restore-verified plan whose request exceeds its own limit — RestoreVerified() must not bypass this package's own params bounds")
	}

	// The one rule ValidateRestore DOES drop (the absolute minimum) is a
	// statement about proposing, not about executing against live state, and
	// RemediationPlan.Validate() calls the params type's OWN Validate() —
	// PatchResourceLimitsParams.Validate(), not ValidateRestore() — so a
	// sub-minimum value still fails here regardless of RestoreVerified().
	// This is deliberate and documents the actual seam: today,
	// RestoreVerified() is consulted only by the live-state check this
	// package cannot reach (internal/execution's
	// checkResourceLimitsBound), not by RemediationPlan.Validate() itself.
	subMinimum := PatchResourceLimitsParams{Container: "web", MemoryLimit: "4Mi"}
	restorePlan, err := NewVerifiedRestorePlan(ActionPatchResourceLimits, subMinimum, "apps/v1/Deployment", "prod", "web")
	if err != nil {
		t.Fatalf("NewVerifiedRestorePlan() = %v, want nil", err)
	}
	if err := restorePlan.Validate(); err == nil {
		t.Error("RemediationPlan.Validate() unexpectedly accepted a sub-minimum memory limit — PatchResourceLimitsParams.Validate() (not ValidateRestore) is what RemediationPlan.Validate() calls, so this is expected to fail until/unless that wiring changes")
	}
}
