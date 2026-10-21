package gitopsinsight

import (
	"strings"
	"testing"
)

// Each recognised class, from a message shaped like the one Argo writes, plus
// the ordering cases: the narrower reading must win.
func TestParseArgoOperationErrorClasses(t *testing.T) {
	for msg, want := range map[string]FailureClass{
		`one or more objects failed to apply: namespaces "payments-staging" not found`:                                                                                                                     FailureClassNamespaceNotFound,
		`error when patching "/tmp/m.yaml": CustomResourceDefinition.apiextensions.k8s.io "prometheuses.monitoring.coreos.com" is invalid: metadata.annotations: Too long: must have at most 262144 bytes`: FailureClassAnnotationsTooLong,
		`ConfigMap "settings" is invalid: metadata.labels: Too long: must be no more than 63 characters`:                                                                                                   FailureClassLabelsTooLong,
		`Internal error occurred: failed calling webhook "mpod.elbv2.k8s.aws": Post "https://aws-lb-webhook.kube-system.svc:443/mutate": no endpoints available`:                                           FailureClassWebhookUnreachable,
		`failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/validate": context deadline exceeded`:                                                                             FailureClassWebhookUnreachable,
		`PostSync phase failed: hook "smoke-test" exited 2`:                                                                                                                                                FailureClassHookFailed,
		`hook "flush-cdn" failed: BackoffLimitExceeded`:                                                                                                                                                    FailureClassHookFailed,
		`admission webhook "validate.kyverno.svc-fail" denied the request: require-requests: CPU request missing`:                                                                                          FailureClassAdmissionDenied,
		`StatefulSet.apps "kafka" is forbidden: User "system:serviceaccount:argocd:argocd-application-controller" cannot patch resource "statefulsets"`:                                                    FailureClassRBACForbidden,
		`ServiceAccount "builder" already exists`:                                                                                                                                                          FailureClassAlreadyExists,
		`resource mapping not found: no matches for kind "Certificate" in version "cert-manager.io/v1"`:                                                                                                    FailureClassNoMatchesForKind,
		`Get "https://172.20.0.4:6443/version": dial tcp 172.20.0.4:6443: connect: no route to host`:                                                                                                       FailureClassClusterUnreachable,
		`Job.batch "schema-migrate" is invalid: spec.template: Invalid value: field is immutable`:                                                                                                          FailureClassFieldImmutable,
		`unable to recognize "kustomization.yaml": the server could not find the requested resource`:                                                                                                       FailureClassUnableToRecognize,
		`Operation cannot be fulfilled on configmaps "feature-flags": the object has been modified; please apply your changes to the latest version and try again`:                                         FailureClassConcurrentModification,
		`the moon is in the wrong phase`: FailureClassUnrecognized,
		``:                               "",
	} {
		got := ParseArgoOperationError(msg)
		if got.Class != want {
			t.Errorf("%q: class %q, want %q", msg, got.Class, want)
		}
		if (got.Cause == "") != (want == FailureClassUnrecognized || want == "") {
			t.Errorf("%q: cause %q", msg, got.Cause)
		}
	}
}

func TestParseArgoOperationErrorFacts(t *testing.T) {
	cases := []struct {
		msg        string
		kind, name string
		retries    int
		stuck      bool
		missingNS  string
	}{
		// Group dropped from the kind; retry suffix read; five is stuck.
		{`error when patching: CustomResourceDefinition.apiextensions.k8s.io "kafkas.kafka.strimzi.io" is invalid: metadata.annotations: Too long (retried 5 times)`,
			"CustomResourceDefinition", "kafkas.kafka.strimzi.io", 5, true, ""},
		{`Deployment.apps "checkout" is forbidden: User "system:serviceaccount:argocd:argocd-application-controller" cannot update`, "Deployment", "checkout", 0, false, ""},
		{`something odd (retried 2 times)`, "", "", 2, false, ""},
		{`something odd (retried 1 time)`, "", "", 1, false, ""},
		// A request line is not an object.
		{`PATCH "https://10.0.0.1/apis/apps/v1": unexpected EOF`, "", "", 0, false, ""},
		{`namespaces "ledger" not found`, "", "", 0, false, "ledger"},
	}
	for _, c := range cases {
		got := ParseArgoOperationError(c.msg)
		if got.AffectedKind != c.kind || got.AffectedName != c.name || got.RetryCount != c.retries || got.Stuck != c.stuck || got.MissingNamespace != c.missingNS {
			t.Errorf("%q:\n got  %s %q retries=%d stuck=%v ns=%q", c.msg, got.AffectedKind, got.AffectedName, got.RetryCount, got.Stuck, got.MissingNamespace)
		}
	}
}

func TestCleanArgoControllerMessage(t *testing.T) {
	for in, want := range map[string]string{
		"rpc error: code = Unknown desc = repository not found":                                                                             "repository not found",
		"rpc error: code = Unavailable desc = connection error: rpc error: code = DeadlineExceeded desc = context deadline exceeded":        "connection error: context deadline exceeded",
		"ComparisonError: rpc error: code = Unknown desc = kustomize build failed: rpc error: code = Unknown desc = accumulating resources": "ComparisonError: kustomize build failed: accumulating resources",
		"path does not exist":                "path does not exist",
		"rpc error: code = Unknown desc =  ": "rpc error: code = Unknown desc =",
		"  ":                                 "",
	} {
		if got := CleanArgoControllerMessage(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if c, raw := CleanArgoControllerMessageWithRaw(" rpc error: code = NotFound desc = app missing "); c != "app missing" || raw != "rpc error: code = NotFound desc = app missing" {
		t.Errorf("with raw = %q, %q", c, raw)
	}
	if c, raw := CleanArgoControllerMessageWithRaw("app missing"); c != "app missing" || raw != "" {
		t.Errorf("unchanged = %q, %q", c, raw)
	}
}

func TestConditionSeverityAndActions(t *testing.T) {
	for typ, want := range map[string]string{
		"ComparisonError": "critical/true", "SyncError": "critical/true",
		"SharedResourceWarning": "warning/true", "OrphanedResourceWarning": "warning/true",
		"SomethingInformational": "info/false", "": "info/false",
	} {
		tok, ok := SeverityForConditionType(typ)
		if got := tok + "/" + map[bool]string{true: "true", false: "false"}[ok]; got != want {
			t.Errorf("%q: %s, want %s", typ, got, want)
		}
	}
	for _, typ := range []string{"ComparisonError", "InvalidSpecError", "SyncError", "OrphanedResourceWarning", "RepeatedResourceWarning", "ExcludedResourceWarning", "SharedResourceWarning"} {
		if ActionForCondition(typ) == "" {
			t.Errorf("%s has no action", typ)
		}
	}
	if a := ActionForCondition("NewInArgo3"); a != "" {
		t.Errorf("unknown condition = %q", a)
	}
	if a, b := ActionForFluxReason("BuildFailed"), ActionForFluxReason("NeverHeardOfIt"); a == "" || b == "" || a == b || !strings.Contains(b, "reconcile") {
		t.Errorf("flux actions = %q / %q", a, b)
	}
}
