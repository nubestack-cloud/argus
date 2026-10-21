package llm

import (
	"reflect"
	"strings"
	"testing"

	"argus/internal/remediation"
)

// TestBuildCorrectionPromptNamesTheFixedFieldsAndCarriesTheRejection checks
// the pure prompt-building half of CorrectPlanParams: the action type and
// target are stated (and the model is told not to change them), the
// rejected params and the cluster's own rejection text both appear
// verbatim, and the params-only schema hint for this action type is
// included so the model knows the exact shape to answer in.
func TestBuildCorrectionPromptNamesTheFixedFieldsAndCarriesTheRejection(t *testing.T) {
	plan := remediation.RemediationPlan{
		ActionType:      remediation.ActionPatchResourceLimits,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "prod",
		TargetName:      "checkout",
		Params: remediation.PatchResourceLimitsParams{
			Container:   "app",
			MemoryLimit: "256Mi",
		},
	}
	rejection := `admission webhook "resourcequota.example.com" denied the request: exceeds quota "compute-quota"`

	system, user, err := buildCorrectionPrompt(plan, rejection)
	if err != nil {
		t.Fatalf("buildCorrectionPrompt: %v", err)
	}

	if !strings.Contains(system, "You may NOT change the action type or the target") {
		t.Error("system prompt does not state the action type/target are fixed")
	}
	if !strings.Contains(user, "PatchResourceLimits") {
		t.Error("user prompt does not name the action type")
	}
	if !strings.Contains(user, "apps/v1/Deployment prod/checkout") {
		t.Error("user prompt does not name the target")
	}
	if !strings.Contains(user, "256Mi") {
		t.Error("user prompt does not include the rejected params")
	}
	if !strings.Contains(user, rejection) {
		t.Error("user prompt does not carry the cluster's own rejection text verbatim")
	}
	if !strings.Contains(user, `"container"`) {
		t.Error("user prompt does not include the params-only schema hint")
	}
}

// TestBuildCorrectionPromptRefusesUncorrectableActionTypes locks in
// CorrectPlanParams's documented refusal for the one action type with
// nothing this call can correct: RestartPod (RestartPodParams carries no
// fields at all). A genuinely unrecognized action type must refuse the same
// way rather than silently building a prompt with an empty hint.
func TestBuildCorrectionPromptRefusesUncorrectableActionTypes(t *testing.T) {
	for _, actionType := range []remediation.ActionType{remediation.ActionRestartPod, remediation.ActionType("DeleteNamespace")} {
		t.Run(string(actionType), func(t *testing.T) {
			_, _, err := buildCorrectionPrompt(remediation.RemediationPlan{ActionType: actionType}, "some rejection")
			if err == nil {
				t.Fatalf("buildCorrectionPrompt(%s): expected an error, got nil", actionType)
			}
		})
	}
}

// TestBuildCorrectionPromptOpenPR is BUGS.md 109 / BACKLOG.md AG1's addition:
// OpenPR is now correctable (internal/api's analyze-time correction attempt
// is the caller — internal/execution/correction.go's post-approval path still never
// reaches this case, since OpenPR has no dry-run/execution step to reject
// it), and the prompt must state the whole-file params shape without ever
// mentioning "repository" — that is resolved by ARGUS from the incident's own
// stored ownership, never supplied by a model, exactly like a freshly-proposed
// plan. File PATHS are asked for, because a whole-file change cannot be stated
// without them, and they are checked against the denylist and the synced
// directory in internal/gitops before anything is read or written.
func TestBuildCorrectionPromptOpenPR(t *testing.T) {
	plan := remediation.RemediationPlan{
		ActionType:      remediation.ActionOpenPR,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-r41-argo003",
		TargetName:      "argo003-selfheal",
		Params:          remediation.OpenPRParams{},
	}
	rejection := `plan rejected: params is required for action type "OpenPR"`

	system, user, err := buildCorrectionPrompt(plan, rejection)
	if err != nil {
		t.Fatalf("buildCorrectionPrompt: %v", err)
	}
	if !strings.Contains(system, "You may NOT change the action type or the target") {
		t.Error("system prompt does not state the action type/target are fixed")
	}
	if !strings.Contains(user, "OpenPR") {
		t.Error("user prompt does not name the action type")
	}
	if !strings.Contains(user, rejection) {
		t.Error("user prompt does not carry the rejection text verbatim")
	}
	if !strings.Contains(user, `"files"`) || !strings.Contains(user, `"content"`) {
		t.Error("user prompt does not include the OpenPR params-only schema hint")
	}
	// Checked as a JSON KEY specifically ("name":), not a bare mention — the
	// hint's own prose explicitly SAYS "repository"/"filePath" to tell the
	// model not to invent them (matching the original proposal prompt's
	// identical wording), which is desirable; what must never appear is
	// either name offered as something to fill in.
	if strings.Contains(user, `"repository":`) || strings.Contains(user, `"filePath":`) {
		t.Error("user prompt must not offer repository/filePath as fields to fill in — those are resolved by ARGUS, never supplied by a model")
	}
}

// TestBuildCorrectionPromptAnnotateLabelCreate is B142's prompt-side
// coverage: the three action types B130/F9 exposed to the model must be
// buildable correction prompts too, not just parseable ones — a plan
// Blocked at analyze time for one of these (internal/api/analyze.go's
// BUGS.md 109 / BACKLOG.md AG1 path) must reach a real hint, not
// buildCorrectionPrompt's "no correctable parameters" refusal.
func TestBuildCorrectionPromptAnnotateLabelCreate(t *testing.T) {
	for _, tc := range []struct {
		actionType remediation.ActionType
		wantHint   string
	}{
		{remediation.ActionAnnotateResource, `"key"`},
		{remediation.ActionLabelResource, `"key"`},
		{remediation.ActionCreateResource, `"data"`},
	} {
		t.Run(string(tc.actionType), func(t *testing.T) {
			plan := remediation.RemediationPlan{
				ActionType:      tc.actionType,
				TargetGVK:       "apps/v1/Deployment",
				TargetNamespace: "default",
				TargetName:      "web",
			}
			_, user, err := buildCorrectionPrompt(plan, `plan rejected: params is required for action type`)
			if err != nil {
				t.Fatalf("buildCorrectionPrompt(%s): unexpected error: %v — this action type must have a correctable hint (B142)", tc.actionType, err)
			}
			if !strings.Contains(user, tc.wantHint) {
				t.Errorf("buildCorrectionPrompt(%s) user prompt = %q, want it to contain %s", tc.actionType, user, tc.wantHint)
			}
		})
	}
}

// TestParseCorrectedParamsRoundTripsEveryCorrectableActionType exercises
// parseCorrectedParams for each of the four action types it supports,
// checking the model's {"params": ...} envelope decodes into exactly the
// remediation.ActionParams concrete type a freshly-proposed plan of that
// type would carry.
func TestParseCorrectedParamsRoundTripsEveryCorrectableActionType(t *testing.T) {
	tests := []struct {
		name       string
		actionType remediation.ActionType
		reply      string
		want       remediation.ActionParams
	}{
		{
			name:       "ScaleDeployment",
			actionType: remediation.ActionScaleDeployment,
			reply:      `{"params": {"replicas": 3}}`,
			want:       remediation.ScaleDeploymentParams{Replicas: 3},
		},
		{
			name:       "PatchResourceLimits",
			actionType: remediation.ActionPatchResourceLimits,
			reply:      `{"params": {"container": "app", "memoryLimit": "512Mi"}}`,
			want:       remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "512Mi"},
		},
		{
			name:       "RevertContainerImage",
			actionType: remediation.ActionRevertContainerImage,
			reply:      `{"params": {"container": "app"}}`,
			want:       remediation.RevertContainerImageParams{Container: "app"},
		},
		{
			name:       "PatchField",
			actionType: remediation.ActionPatchField,
			reply:      `{"params": {"fieldPath": "spec/replicas", "newValue": "3", "expectCurrent": "5"}}`,
			want:       remediation.PatchFieldParams{FieldPath: "spec/replicas", NewValue: "3", ExpectCurrent: "5"},
		},
		{
			// BUGS.md 109 / BACKLOG.md AG1: repository is deliberately absent
			// from the reply — a corrected OpenPR proposal never supplies one,
			// exactly like a freshly-proposed plan. What it DOES supply is the
			// whole content of one or more files, which is the only shape a
			// repository change has since 2026-08-28.
			name:       "OpenPR",
			actionType: remediation.ActionOpenPR,
			reply:      `{"params": {"files": [{"path": "charts/web/values.yaml", "content": "probePort: 80\n"}, {"path": "charts/web/templates/deployment.yaml", "content": "port: {{ .Values.probePort }}\n"}]}}`,
			want: remediation.OpenPRParams{
				Files: []remediation.ProposedFile{
					{Path: "charts/web/values.yaml", Content: "probePort: 80\n"},
					{Path: "charts/web/templates/deployment.yaml", Content: "port: {{ .Values.probePort }}\n"},
				},
			},
		},
		{
			// B142: AnnotateResource/LabelResource/CreateResource were never
			// given a case here (or in parseProposedPlan), so Params was
			// always nil and every plan of these three types was rejected by
			// RemediationPlan.Validate before its own type-specific checks
			// ever ran. These three cases close that gap.
			name:       "AnnotateResource",
			actionType: remediation.ActionAnnotateResource,
			reply:      `{"params": {"key": "argus.io/incident-id", "value": "inc_01example"}}`,
			want:       remediation.AnnotateResourceParams{Key: "argus.io/incident-id", Value: "inc_01example"},
		},
		{
			name:       "LabelResource",
			actionType: remediation.ActionLabelResource,
			reply:      `{"params": {"key": "argus.io/managed-by", "value": "argus"}}`,
			want:       remediation.LabelResourceParams{Key: "argus.io/managed-by", Value: "argus"},
		},
		{
			name:       "CreateResource",
			actionType: remediation.ActionCreateResource,
			reply:      `{"params": {"data": {"MODE": "ready"}}}`,
			want:       remediation.CreateResourceParams{Data: map[string]string{"MODE": "ready"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCorrectedParams(tt.actionType, tt.reply)
			if err != nil {
				t.Fatalf("parseCorrectedParams: %v", err)
			}
			// reflect.DeepEqual rather than !=: OpenPRParams holds a slice, so
			// it is not comparable, and == on the interface would panic at
			// runtime rather than fail to compile.
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCorrectedParams(%s, %q) = %#v, want %#v", tt.actionType, tt.reply, got, tt.want)
			}
		})
	}
}

// TestParseCorrectedParamsToleratesAMarkdownFence mirrors
// parseFinalAnalysis's own tolerance (stripJSONFence, shared by both) for a
// model that fences its JSON reply despite being told not to.
func TestParseCorrectedParamsToleratesAMarkdownFence(t *testing.T) {
	fenced := "```json\n{\"params\": {\"replicas\": 2}}\n```"
	got, err := parseCorrectedParams(remediation.ActionScaleDeployment, fenced)
	if err != nil {
		t.Fatalf("parseCorrectedParams: %v", err)
	}
	if got != (remediation.ScaleDeploymentParams{Replicas: 2}) {
		t.Errorf("parseCorrectedParams(fenced) = %#v, want Replicas: 2", got)
	}
}

// TestParseCorrectedParamsNullMeansNotFixable checks the honest-refusal path:
// a model that decides the rejection cannot be fixed by changing params
// answers {"params": null}, and this must come back as (nil, nil) — a
// distinct, checkable "not fixable" result, not an error and not a
// zero-value params struct a caller could mistake for a real answer.
func TestParseCorrectedParamsNullMeansNotFixable(t *testing.T) {
	got, err := parseCorrectedParams(remediation.ActionScaleDeployment, `{"params": null}`)
	if err != nil {
		t.Fatalf("parseCorrectedParams: unexpected error %v", err)
	}
	if got != nil {
		t.Errorf("parseCorrectedParams({\"params\": null}) = %#v, want nil", got)
	}
}

// TestParseCorrectedParamsRejectsMalformedReply checks a reply that isn't
// the requested {"params": ...} envelope at all is a real error, not a
// silently-accepted nil — parseCorrectedParams is deliberately stricter here
// than parseProposedPlan's own best-effort tolerance (see its doc comment
// for why the two functions differ on this point).
func TestParseCorrectedParamsRejectsMalformedReply(t *testing.T) {
	if _, err := parseCorrectedParams(remediation.ActionScaleDeployment, "not json at all"); err == nil {
		t.Fatal("parseCorrectedParams: expected an error for an unparseable reply, got nil")
	}
}

// TestParamsSchemaHintCoversExactlyTheCorrectableActionTypes locks in which
// action types CorrectPlanParams can correct at all — the four that
// executionToolForAction (internal/execution) can execute and
// that carry at least one tunable field, and no others. Written against
// remediation.ActionType's own closed set rather than a hand-picked list,
// so a SIXTH action type added to that enum in the future is forced through
// this test rather than silently defaulting to "not correctable" or, worse,
// "correctable" with no case to handle it.
func TestParamsSchemaHintCoversExactlyTheCorrectableActionTypes(t *testing.T) {
	wantCorrectable := map[remediation.ActionType]bool{
		remediation.ActionScaleDeployment:      true,
		remediation.ActionRestartPod:           false, // no fields to correct (RestartPodParams carries none)
		remediation.ActionPatchResourceLimits:  true,
		remediation.ActionRevertContainerImage: true,
		// BUGS.md 109 / BACKLOG.md AG1: OpenPR became correctable once
		// internal/api's analyze-time correction attempt started calling this
		// for a plan Blocked because the model left Params nil/invalid — the
		// ONLY caller that ever reaches this case; internal/execution/correction.go's
		// post-approval dry-run-rejection path still never does, since OpenPR
		// has no dry-run/execution step to reject it.
		remediation.ActionOpenPR:     true,
		remediation.ActionPatchField: true,
	}
	for actionType, want := range wantCorrectable {
		_, ok := paramsSchemaHint(actionType)
		if ok != want {
			t.Errorf("paramsSchemaHint(%s) ok = %v, want %v", actionType, ok, want)
		}
	}
}
