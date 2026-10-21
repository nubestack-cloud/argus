package gitops

import "testing"

// TestParseAdmissionRejectionObject_RealMessages pins the parser against the
// exact messages this codebase has actually observed and quoted
// (internal/agent/syncfailure.go's header) plus the DEPL-003 shape this fix
// targets, so a future refactor of the regex is caught against real evidence
// rather than an invented example.
func TestParseAdmissionRejectionObject_RealMessages(t *testing.T) {
	cases := []struct {
		name, message, wantKind, wantName string
	}{
		{
			name:     "CronJob invalid schedule, observed live",
			message:  `CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`,
			wantKind: "CronJob", wantName: "s1-syncfail",
		},
		{
			name:     "Job immutable template, observed live",
			message:  `Job.batch "immut-job" is invalid: spec.template: Invalid value: ...: field is immutable`,
			wantKind: "Job", wantName: "immut-job",
		},
		{
			name:     "Deployment maxSurge/maxUnavailable, DEPL-003's own scenario",
			message:  `Deployment.apps "web" is invalid: [spec.strategy.rollingUpdate.maxUnavailable: Invalid value: 0, spec.strategy.rollingUpdate.maxSurge: Invalid value: 0: may not both be zero]`,
			wantKind: "Deployment", wantName: "web",
		},
		{
			name:     "core-group kind carries no dotted group segment",
			message:  `Pod "web" is invalid: spec.containers[0].image: Required value`,
			wantKind: "Pod", wantName: "web",
		},
		{
			name:     "wrapped in the sweep check's own sentence (checkArgoSyncFailed)",
			message:  `Argo CD cannot apply this Application's manifests (phase Failed, 5 retries, revision abc123): CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`,
			wantKind: "CronJob", wantName: "s1-syncfail",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, name, ok := ParseAdmissionRejectionObject(tc.message)
			if !ok {
				t.Fatalf("ParseAdmissionRejectionObject(%q) = ok false, want true", tc.message)
			}
			if kind != tc.wantKind || name != tc.wantName {
				t.Errorf("got (%q, %q), want (%q, %q)", kind, name, tc.wantKind, tc.wantName)
			}
		})
	}
}

// TestParseAdmissionRejectionObject_RefusesRatherThanGuesses covers the
// shapes this parser must NOT extract a kind/name from: a resource-based
// (plural, lower-cased) message from NewNotFound/NewAlreadyExists/
// NewForbidden would feed a wrong-cased, wrong-pluralised Kind into a search
// that then fails silently rather than loudly — see admissionRejectionPattern's
// own doc comment.
func TestParseAdmissionRejectionObject_RefusesRatherThanGuesses(t *testing.T) {
	for _, message := range []string{
		"",
		"a permission was denied for this operation",
		`deployments.apps "web" already exists`,
		`deployments.apps "web" not found`,
		`Application "web" is forbidden: User "argo" cannot sync`,
		"context deadline exceeded",
	} {
		if kind, name, ok := ParseAdmissionRejectionObject(message); ok {
			t.Errorf("ParseAdmissionRejectionObject(%q) = (%q, %q, true), want ok=false", message, kind, name)
		}
	}
}

func TestIsControllerObject(t *testing.T) {
	cases := []struct {
		name string
		ref  ObjectRef
		want bool
	}{
		{"Argo Application", ObjectRef{APIVersion: "argoproj.io/v1alpha1", Kind: "Application"}, true},
		{"Flux Kustomization", ObjectRef{APIVersion: "kustomize.toolkit.fluxcd.io/v1", Kind: "Kustomization"}, true},
		{"Flux HelmRelease", ObjectRef{APIVersion: "helm.toolkit.fluxcd.io/v2", Kind: "HelmRelease"}, true},
		{"ApplicationSet is deliberately excluded", ObjectRef{APIVersion: "argoproj.io/v1alpha1", Kind: "ApplicationSet"}, false},
		{"an ordinary Deployment is not a controller object", ObjectRef{APIVersion: "apps/v1", Kind: "Deployment"}, false},
		{"a same-named Kind on an unrelated group must not be mistaken for one", ObjectRef{APIVersion: "example.com/v1", Kind: "Application"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsControllerObject(tc.ref); got != tc.want {
				t.Errorf("IsControllerObject(%+v) = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

// TestLocateIn_IdentityFromParsedMessageFindsTheRightFile is this fix's core
// proof: given ONLY the kind/name ParseAdmissionRejectionObject extracted
// from a sync-failure message — no live object, nothing read off a cluster —
// LocateIn (completely unmodified) finds the manifest the API server
// rejected, scoped to the Application's own spec.source.path the same way an
// ordinary, live-object-anchored search already is.
func TestLocateIn_IdentityFromParsedMessageFindsTheRightFile(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"apps/billing/cronjob.yaml": `apiVersion: batch/v1
kind: CronJob
metadata:
  name: s1-syncfail
  namespace: billing
spec:
  schedule: "*/5 * * * *"
`,
		// A same-named CronJob in a directory the Application does NOT sync
		// from — proves the search is actually scoped to the resolved
		// spec.source.path, not the whole repository.
		"apps/other-team/cronjob.yaml": `apiVersion: batch/v1
kind: CronJob
metadata:
  name: s1-syncfail
  namespace: other-team
spec:
  schedule: "*/5 * * * *"
`,
	})

	message := `Argo CD cannot apply this Application's manifests (phase Failed, 5 retries, revision abc123): ` +
		`CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`

	kind, name, ok := ParseAdmissionRejectionObject(message)
	if !ok {
		t.Fatalf("ParseAdmissionRejectionObject(%q) = ok false", message)
	}

	res, err := LocateIn(root, "apps/billing", ObjectRef{Kind: kind, Name: name})
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	if len(res.Locations) != 1 || res.Locations[0].Path != "apps/billing/cronjob.yaml" {
		t.Fatalf("Locations = %+v, want exactly apps/billing/cronjob.yaml", res.Locations)
	}
}

// TestLocateIn_IdentityFromParsedMessageHonestlyNotFound is the same
// mechanism's "refuse rather than guess" half: a kind/name this fallback
// cannot find anywhere under the resolved path must come back as ZERO
// matches, not an error and not a wrong file from elsewhere in the tree —
// the same discipline TestLocateIn_MissingPathIsReportedNotWidened and
// TestLocate_ReportsEveryMatch already hold LocateIn to for the
// live-object-anchored case.
func TestLocateIn_IdentityFromParsedMessageHonestlyNotFound(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"apps/billing/deployment.yaml": guestbookDeployment,
	})

	message := `CronJob.batch "does-not-exist-here" is invalid: spec.schedule: Invalid value`
	kind, name, ok := ParseAdmissionRejectionObject(message)
	if !ok {
		t.Fatalf("ParseAdmissionRejectionObject(%q) = ok false", message)
	}

	res, err := LocateIn(root, "apps/billing", ObjectRef{Kind: kind, Name: name})
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	if len(res.Locations) != 0 {
		t.Errorf("Locations = %+v, want none", res.Locations)
	}
}
