package api

import (
	"context"
	"strings"
	"testing"

	"argus/internal/gitops"
	"argus/internal/scm"
)

// TestLocateObjectFileWithFallback_NonControllerObjectNeverTouchesFindings is
// this fix's regression guard for BACKLOG.md "still open" #4: the ORDINARY,
// live-object-anchored path must be completely unaffected.
//
// tx is nil. If locateObjectFileWithFallback ever queried it for an ordinary
// (non-controller) object — an incident anchored on a Deployment, ConfigMap,
// or anything else the existing machinery already handles — calling a
// method on a nil pgx.Tx interface would panic, failing this test loudly
// rather than silently passing. The fake provider's refusal ("cannot supply
// a credential") needs no network at all (locateObjectFile's very first
// check), so this proves the whole fallback branch — and therefore the
// database read inside it — is never reached for the case that matters most:
// everything this codebase already resolved a repository change for before
// this fix existed.
func TestLocateObjectFileWithFallback_NonControllerObjectNeverTouchesFindings(t *testing.T) {
	provider := &fakeNoCredentialProvider{}
	object := gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "web", Name: "api"}

	_, err := locateObjectFileWithFallback(context.Background(), nil, "inc_test", "apps/v1/Deployment",
		provider, scm.Binding{Host: "github.com"}, "https://github.com/org/repo.git", "abc123", "apps/web", object)
	if err == nil {
		t.Fatal("expected an error from a provider with no clone credential")
	}
	if !strings.Contains(err.Error(), "cannot supply a credential") {
		t.Errorf("err = %v, want the ordinary locateObjectFile refusal, unwrapped", err)
	}
}

// TestIdentityFromMessages is findAdmissionRejectionIdentity's pure half:
// the actual decision of which message (if any) names a parseable identity,
// tested without a database connection.
func TestIdentityFromMessages(t *testing.T) {
	t.Run("skips unparseable messages and returns the first that parses", func(t *testing.T) {
		kind, name, ok := identityFromMessages([]string{
			"a permission was denied for this operation",
			`CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value`,
			`Job.batch "immut-job" is invalid: spec.template: field is immutable`,
		})
		if !ok || kind != "CronJob" || name != "s1-syncfail" {
			t.Errorf("got (%q, %q, %v), want (CronJob, s1-syncfail, true)", kind, name, ok)
		}
	})

	t.Run("no messages at all is an honest not-found, not a crash", func(t *testing.T) {
		if _, _, ok := identityFromMessages(nil); ok {
			t.Error("identityFromMessages(nil) = ok true, want false")
		}
	})

	t.Run("every message unparseable is an honest not-found", func(t *testing.T) {
		if _, _, ok := identityFromMessages([]string{
			"a permission was denied for this operation",
			"context deadline exceeded",
		}); ok {
			t.Error("expected ok = false when nothing parses")
		}
	})
}
