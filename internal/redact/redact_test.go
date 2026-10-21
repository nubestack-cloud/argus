package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// The canary values every test below hides in cluster data. Distinct per field
// class so a failure names which rule leaked rather than just "something did".
const (
	canaryEnvValue    = "SUPERSECRET-env-literal-value"
	canaryConfigMap   = "SUPERSECRET-configmap-payload"
	canaryLastApplied = "SUPERSECRET-in-last-applied"
	canaryTemplateEnv = "SUPERSECRET-deployment-template-env"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test fixture: %v", err)
	}
	return b
}

// assertGone is the assertion that matters: the canary must not survive
// anywhere in the output, at any nesting depth, in any encoding.
func assertGone(t *testing.T, out json.RawMessage, canary string) {
	t.Helper()
	if strings.Contains(string(out), canary) {
		t.Errorf("canary %q survived redaction.\noutput: %s", canary, out)
	}
}

// TestEnvValueDroppedKeepingShape is the primary structural rule: the literal
// value goes, name and valueFrom stay. The valueFrom half is not incidental —
// it is the reason the accepted diagnostic cost is as small as it is, so a
// change that started dropping it too would be a real regression.
func TestEnvValueDroppedKeepingShape(t *testing.T) {
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name": "app",
					"env": []any{
						map[string]any{"name": "DB_PASSWORD", "value": canaryEnvValue},
						map[string]any{"name": "FROM_SECRET", "valueFrom": map[string]any{
							"secretKeyRef": map[string]any{"name": "db-creds", "key": "password"},
						}},
					},
				},
			},
		},
	}
	out := Object(mustJSON(t, pod))
	assertGone(t, out, canaryEnvValue)

	s := string(out)
	// Shape checks: the diagnostic signal has to survive the redaction.
	for _, want := range []string{"DB_PASSWORD", "FROM_SECRET", "secretKeyRef", "db-creds", Marker} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q to survive redaction, output: %s", want, s)
		}
	}
}

// TestEnvValueDroppedInPodTemplates is the case that would have made this fix
// fail open. A Deployment's env values live at
// spec.template.spec.containers[*].env[*].value, and a CronJob's at
// spec.jobTemplate.spec.template.spec.containers[*].env[*].value — an
// implementation keyed on the Pod path alone passes TestEnvValueDropped... and
// still leaks every Deployment in the cluster.
func TestEnvValueDroppedInPodTemplates(t *testing.T) {
	envList := []any{map[string]any{"name": "TOKEN", "value": canaryTemplateEnv}}
	container := func() []any {
		return []any{map[string]any{"name": "app", "env": envList}}
	}

	cases := map[string]map[string]any{
		"Deployment": {
			"kind": "Deployment",
			"spec": map[string]any{"template": map[string]any{
				"spec": map[string]any{"containers": container()},
			}},
		},
		"CronJob": {
			"kind": "CronJob",
			"spec": map[string]any{"jobTemplate": map[string]any{
				"spec": map[string]any{"template": map[string]any{
					"spec": map[string]any{"containers": container()},
				}},
			}},
		},
		"initContainers": {
			"kind": "Pod",
			"spec": map[string]any{"initContainers": container()},
		},
		"ephemeralContainers": {
			"kind": "Pod",
			"spec": map[string]any{"ephemeralContainers": container()},
		},
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			out := Object(mustJSON(t, obj))
			assertGone(t, out, canaryTemplateEnv)
			if !strings.Contains(string(out), "TOKEN") {
				t.Errorf("env var NAME should survive, output: %s", out)
			}
		})
	}
}

// TestLastAppliedConfigurationDropped covers the annotation that is a complete
// second copy of the object. Redacting the live spec while forwarding this
// would defeat the whole exercise, which is why BUGS.md 84 names it.
func TestLastAppliedConfigurationDropped(t *testing.T) {
	inner := mustJSON(t, map[string]any{
		"spec": map[string]any{"containers": []any{map[string]any{
			"env": []any{map[string]any{"name": "PW", "value": canaryLastApplied}},
		}}},
	})
	obj := map[string]any{
		"kind": "Deployment",
		"metadata": map[string]any{
			"name": "payments",
			"annotations": map[string]any{
				"kubectl.kubernetes.io/last-applied-configuration": string(inner),
				"argus.io/keep-me": "diagnostic annotation",
			},
		},
	}
	out := Object(mustJSON(t, obj))
	assertGone(t, out, canaryLastApplied)
	if strings.Contains(string(out), "last-applied-configuration") {
		t.Errorf("the annotation key itself should be gone, output: %s", out)
	}
	// Other annotations are ordinary evidence and must not be collateral.
	if !strings.Contains(string(out), "argus.io/keep-me") {
		t.Errorf("unrelated annotations must survive, output: %s", out)
	}
}

// TestDataAndStringDataValuesDropped covers ConfigMap payloads — the class
// that routinely holds credentials nobody classified as such. Keys survive
// because "there is no database.url key" and "there is one we won't show you"
// are different diagnoses.
func TestDataAndStringDataValuesDropped(t *testing.T) {
	for _, key := range []string{"data", "stringData"} {
		t.Run(key, func(t *testing.T) {
			obj := map[string]any{
				"kind": "ConfigMap",
				key:    map[string]any{"database.url": canaryConfigMap, "log.level": "debug"},
			}
			out := Object(mustJSON(t, obj))
			assertGone(t, out, canaryConfigMap)
			// Even a value that looks harmless goes: the rule is the class,
			// not a judgement about the contents.
			assertGone(t, out, "debug")
			if !strings.Contains(string(out), "database.url") {
				t.Errorf("keys must survive, output: %s", out)
			}
		})
	}
}

// TestObjectFailsClosed is the property that keeps a future reviewer's
// "just pass it through, it's probably fine" instinct from reintroducing the
// defect. Unparseable input must not come back as itself.
func TestObjectFailsClosed(t *testing.T) {
	notJSON := json.RawMessage(`{"truncated at the byte level": "` + canaryEnvValue)
	out := Object(notJSON)
	assertGone(t, out, canaryEnvValue)
	if !ContainsMarker(string(out)) {
		t.Errorf("expected a self-describing marker payload, got: %s", out)
	}
	// Must still be valid JSON, since callers hand it straight to the tunnel
	// as a tool result body.
	var probe any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Errorf("fail-closed output must still be valid JSON: %v (%s)", err, out)
	}
}

// TestDeepNestingFailsClosed — a hostile CustomResource must not get a free
// pass by being nested past the walk's bound.
func TestDeepNestingFailsClosed(t *testing.T) {
	deep := any(map[string]any{"env": []any{
		map[string]any{"name": "X", "value": canaryEnvValue},
	}})
	for i := 0; i < maxDepth+20; i++ {
		deep = map[string]any{"nest": deep}
	}
	assertGone(t, Object(mustJSON(t, deep)), canaryEnvValue)
}

func TestTextPatternLayer(t *testing.T) {
	cases := []struct {
		name, in, mustNotContain string
	}{
		{"jwt", `auth failed for eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`, "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		{"url userinfo", `dial postgres://app:hunter2@db.internal:5432/payments failed`, "hunter2"},
		{"aws key", `using credentials AKIAIOSFODNN7EXAMPLE for upload`, "AKIAIOSFODNN7EXAMPLE"},
		{"bearer", `Authorization: Bearer sk-abcdef0123456789abcdef`, "sk-abcdef0123456789abcdef"},
		{"key=value", `starting with --db-password=hunter2 --verbose`, "hunter2"},
		{"key: value", `config: apiKey: aabbccddee112233`, "aabbccddee112233"},
		{"pem", "loaded -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY----- ok", "MIIEowIBAAKCAQEA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Text(tc.in)
			if strings.Contains(got, tc.mustNotContain) {
				t.Errorf("Text(%q) = %q, still contains %q", tc.in, got, tc.mustNotContain)
			}
			if !ContainsMarker(got) {
				t.Errorf("Text(%q) = %q, expected a marker", tc.in, got)
			}
		})
	}
}

// TestTextPreservesDiagnosticContext guards the other direction. An
// over-eager pattern layer that mangles image digests, resource versions or
// resource names makes the tool useless in a way that is harder to notice than
// a leak, because nothing fails — the model just reasons from corrupted
// evidence. This is why generic high-entropy matching was left out.
func TestTextPreservesDiagnosticContext(t *testing.T) {
	keep := []string{
		"Failed to pull image \"registry.io/app@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"",
		"pod restarted 7 times, resourceVersion 88431125",
		"--secret-name=payments-db was not found in namespace prod",
		"container app exited with code 137 (OOMKilled)",
		"0/12 nodes are available: 12 Insufficient memory",
	}
	for _, s := range keep {
		if got := Text(s); got != s {
			t.Errorf("Text() altered diagnostic text.\n in: %q\nout: %q", s, got)
		}
	}
}

// TestLogLinesRedactedThroughObject — get_logs returns {"lines":[...]}, and
// those lines reach the model, the database and the browser. The walk must
// reach string values inside arrays, not just object fields.
func TestLogLinesRedactedThroughObject(t *testing.T) {
	payload := map[string]any{"lines": []any{
		"starting up",
		"connecting to postgres://app:hunter2@db:5432/payments",
	}}
	out := Object(mustJSON(t, payload))
	assertGone(t, out, "hunter2")
	if !strings.Contains(string(out), "starting up") {
		t.Errorf("ordinary log lines must survive, output: %s", out)
	}
}

// TestContainerArgsGetPatternLayer — args are freeform strings, so they get
// the same second layer as log lines. Recorded as a deliberate addition beyond
// the letter of the G8 decision (which named three structural classes) rather
// than a substitution for it: BUGS.md 84 lists container args as a leak
// vector, and applying the existing bounded pattern set to them costs nothing.
// It is explicitly NOT a claim that args are fully protected — a credential in
// an arg with no recognisable key name still gets through, which is the
// known-and-accepted limit of any pattern layer.
func TestContainerArgsGetPatternLayer(t *testing.T) {
	pod := map[string]any{"spec": map[string]any{"containers": []any{map[string]any{
		"name": "app",
		"args": []any{"--listen=:8080", "--db-password=hunter2"},
	}}}}
	out := Object(mustJSON(t, pod))
	assertGone(t, out, "hunter2")
	if !strings.Contains(string(out), "--listen=:8080") {
		t.Errorf("benign args must survive, output: %s", out)
	}
}

// TestEmptyAndNonObjectInputs — the walk runs on every tool result, including
// the small ones, so its edge cases are hot paths rather than curiosities.
func TestEmptyAndNonObjectInputs(t *testing.T) {
	if got := Object(nil); got != nil {
		t.Errorf("Object(nil) = %s, want nil passthrough", got)
	}
	if got := Text(""); got != "" {
		t.Errorf("Text(\"\") = %q", got)
	}
	// A bare JSON array (list_resources-shaped) must walk, not fail closed.
	out := Object(json.RawMessage(`[{"name":"a"},{"name":"b"}]`))
	for _, want := range []string{`"a"`, `"b"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("array payload mangled: %s", out)
		}
	}
}

// TestEnvKeyUsedForSomethingElse — "env" is a common key name. If a CRD uses
// it for a string map rather than a container env list, the walk must still
// redact what it can and must not panic or pass the subtree through unwalked.
func TestEnvKeyUsedForSomethingElse(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{
		"env": map[string]any{"note": "postgres://app:hunter2@db:5432/x"},
	}}
	out := Object(mustJSON(t, obj))
	assertGone(t, out, "hunter2")
}

// --- AggressiveObject (BACKLOG.md E13) ---

const canaryUnreviewedCredential = "SUPERSECRET-unreviewed-crd-credential"

// TestAggressiveObject_DropsAnArbitrarilyNamedNestedCredential is the test
// E13's own brief names directly: a fixture CRD whose credential-shaped
// value sits at a field path nothing in this package (or in
// internal/agent/tools.go) has ever heard of. Object's structural rules
// would not catch this at all — there is no "env" key and no "data"/
// "stringData" key here — which is exactly the gap AggressiveObject exists
// to close for a kind found only via discovery.
func TestAggressiveObject_DropsAnArbitrarilyNamedNestedCredential(t *testing.T) {
	crd := map[string]any{
		"apiVersion": "widgets.example.com/v1",
		"kind":       "WidgetSource",
		"metadata": map[string]any{
			"name":      "prod-source",
			"namespace": "widgets",
		},
		"spec": map[string]any{
			"connection": map[string]any{
				"upstream": map[string]any{
					"apiToken": canaryUnreviewedCredential,
				},
			},
			"replicas": 3,
		},
	}
	out := AggressiveObject(mustJSON(t, crd))
	assertGone(t, out, canaryUnreviewedCredential)
	// The shape must survive: the field NAMES are still there to tell an
	// investigator "this object has a spec.connection.upstream.apiToken",
	// even though its value does not.
	for _, want := range []string{"apiToken", "connection", "upstream", "spec", "replicas"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("expected key %q to survive (shape, not value) — output: %s", want, out)
		}
	}
	// The numeric replicas value must also be gone — this pass does not
	// special-case "obviously not a string", it drops every leaf uniformly.
	if strings.Contains(string(out), "3") {
		t.Errorf("expected the numeric leaf value to be dropped too, output: %s", out)
	}
}

// TestAggressiveObject_KeepsIdentityFieldsAndTopLevelKindInfo pins the
// allowlist: apiVersion/kind and the fixed-shape metadata identity fields
// survive with their real values, because AggressiveObject would be useless
// for investigation if it also hid which object this was.
func TestAggressiveObject_KeepsIdentityFieldsAndTopLevelKindInfo(t *testing.T) {
	crd := map[string]any{
		"apiVersion": "widgets.example.com/v1",
		"kind":       "WidgetSource",
		"metadata": map[string]any{
			"name":              "prod-source",
			"namespace":         "widgets",
			"uid":               "11111111-1111-1111-1111-111111111111",
			"resourceVersion":   "12345",
			"generation":        float64(2),
			"creationTimestamp": "2026-09-01T00:00:00Z",
		},
	}
	var decoded map[string]any
	if err := json.Unmarshal(AggressiveObject(mustJSON(t, crd)), &decoded); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if decoded["apiVersion"] != "widgets.example.com/v1" || decoded["kind"] != "WidgetSource" {
		t.Errorf("expected apiVersion/kind to survive verbatim, got %+v", decoded)
	}
	metadata, _ := decoded["metadata"].(map[string]any)
	if metadata == nil {
		t.Fatalf("expected a metadata block, got %+v", decoded)
	}
	for key, want := range map[string]any{
		"name":              "prod-source",
		"namespace":         "widgets",
		"uid":               "11111111-1111-1111-1111-111111111111",
		"resourceVersion":   "12345",
		"generation":        float64(2),
		"creationTimestamp": "2026-09-01T00:00:00Z",
	} {
		if metadata[key] != want {
			t.Errorf("metadata.%s = %v, want %v (identity field must survive verbatim)", key, metadata[key], want)
		}
	}
}

// TestAggressiveObject_LabelsAndAnnotationsKeepKeysDropValues is the live-
// verification scenario's own shape: an annotation is exactly as free-form
// as a spec field, and the brief specifically calls out "an annotation ...
// holding an obviously-sensitive-looking value" as a case this must catch.
func TestAggressiveObject_LabelsAndAnnotationsKeepKeysDropValues(t *testing.T) {
	crd := map[string]any{
		"apiVersion": "widgets.example.com/v1",
		"kind":       "WidgetSource",
		"metadata": map[string]any{
			"name": "prod-source",
			"labels": map[string]any{
				"team": "payments",
			},
			"annotations": map[string]any{
				"widgets.example.com/api-credential": canaryUnreviewedCredential,
			},
		},
	}
	out := AggressiveObject(mustJSON(t, crd))
	assertGone(t, out, canaryUnreviewedCredential)
	assertGone(t, out, "payments") // label VALUE must also be dropped
	for _, want := range []string{"team", "widgets.example.com/api-credential", "labels", "annotations"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("expected key %q (shape) to survive, output: %s", want, out)
		}
	}
}

// TestAggressiveObject_FailsClosedOnUnparseableInput matches Object's own
// contract (see TestEmptyAndNonObjectInputs' sibling assertions on Object):
// input that will not decode never passes through verbatim.
func TestAggressiveObject_FailsClosedOnUnparseableInput(t *testing.T) {
	out := AggressiveObject(json.RawMessage(`{not valid json`))
	if !ContainsMarker(string(out)) {
		t.Errorf("expected a redaction marker for unparseable input, got: %s", out)
	}
}

// TestAggressiveObject_EmptyInputPassesThrough matches Object(nil)'s own
// contract: there is nothing to redact, so nothing is fabricated either.
func TestAggressiveObject_EmptyInputPassesThrough(t *testing.T) {
	if got := AggressiveObject(nil); got != nil {
		t.Errorf("AggressiveObject(nil) = %s, want nil passthrough", got)
	}
}

// TestAggressiveObject_ArrayLeavesDroppedStructureKept proves the "shape not
// values" promise extends into arrays, not just maps — a CRD's spec is just
// as likely to hold a list of connection strings as a single nested one.
func TestAggressiveObject_ArrayLeavesDroppedStructureKept(t *testing.T) {
	crd := map[string]any{
		"apiVersion": "widgets.example.com/v1",
		"kind":       "WidgetSource",
		"metadata":   map[string]any{"name": "prod-source"},
		"spec": map[string]any{
			"endpoints": []any{
				canaryUnreviewedCredential + "-1",
				canaryUnreviewedCredential + "-2",
			},
		},
	}
	out := AggressiveObject(mustJSON(t, crd))
	assertGone(t, out, canaryUnreviewedCredential)
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	spec, _ := decoded["spec"].(map[string]any)
	endpoints, _ := spec["endpoints"].([]any)
	if len(endpoints) != 2 {
		t.Errorf("expected the array's LENGTH to survive (2 elements), got %+v", endpoints)
	}
}

// TestTextIsIdempotent is PROJECT.md B182: Text(Text(s)) must equal Text(s).
//
// A caller cannot know whether the string it holds has already been through
// this package, and two already do not: internal/logging's slog handler runs
// Text over hub log text that may carry a Marker applied in the agent, and
// internal/api's diagnostics bundle substitutes known secret values with the
// Marker and then runs Text over the result. Before the fix the generic
// key=value rule matched `[REDACTED` out of an already-marked value — its
// character class excludes `]` — and left the bracket behind, so every extra
// pass appended another `]`. internal/agent worked around it by requeueing the
// PRE-redaction copy of a finding; nothing else should have to.
//
// The table is keyed by the `reason` string of the pattern it exercises, and
// the coverage check below fails when freeformPatterns gains an entry with no
// case here — so the guarantee is asserted across the whole pattern set rather
// than across whichever patterns someone remembered.
func TestTextIsIdempotent(t *testing.T) {
	cases := []struct {
		reason string
		in     string
	}{
		{"PEM private key block", "loaded -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY----- ok"},
		{"PEM private key block", "private-key=-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n-----END EC PRIVATE KEY-----"},
		{"bearer credential", "Bearer sk-abcdef0123456789abcdef rejected"},
		{"bearer credential", "Authorization: Bearer sk-abcdef0123456789abcdef"},
		{"JWT", "auth failed for eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		{"JWT", "id_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		{"AWS access key ID", "using credentials AKIAIOSFODNN7EXAMPLE for upload"},
		{"AWS access key ID", "access_key=AKIAIOSFODNN7EXAMPLE"},
		{"credential in URL userinfo", "dial postgres://app:hunter2@db.internal:5432/payments failed"},
		{"credential in URL userinfo", "dsn=postgres://app:hunter2@db.internal:5432/payments"},
		{"value of a credential-implying key", "starting with --db-password=hunter2 --verbose"},
		{"value of a credential-implying key", `config: apiKey: aabbccddee112233`},
		{"value of a credential-implying key", `run --apiKey="aabbccddee112233" --replicas=3`},
		{"value of a credential-implying key", "--secret-name=payments-db and db-password=topsecret1"},
		{"value of a credential-implying key", "connection_string=Server=db;Password=x1"},
	}

	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.reason] = true
		t.Run(tc.reason+"/"+tc.in[:min(len(tc.in), 28)], func(t *testing.T) {
			once := Text(tc.in)
			twice := Text(once)
			if twice != once {
				t.Errorf("Text is not idempotent.\n  in:    %q\n  once:  %q\n  twice: %q", tc.in, once, twice)
			}
			// A third pass costs nothing to assert and catches a fix that
			// merely moved the corruption one round further out.
			if thrice := Text(twice); thrice != once {
				t.Errorf("Text is not stable at the third pass.\n  once:   %q\n  thrice: %q", once, thrice)
			}
			if !ContainsMarker(once) {
				t.Errorf("Text(%q) = %q, expected a marker — this case no longer exercises its pattern", tc.in, once)
			}
		})
	}

	for _, p := range freeformPatterns {
		if !covered[p.reason] {
			t.Errorf("freeformPatterns has an entry %q with no idempotence case — add one to this table", p.reason)
		}
	}
}

// TestTextDoesNotCorruptItsOwnMarkerInOnePass is the half of B182 that was not
// latent. freeformPatterns runs the specific rules first and the generic
// key=value rule LAST, over their output — so a marker inserted by the bearer
// or JWT rule was being re-matched and mangled inside a SINGLE call, on the
// agent's live egress path, with no second caller involved.
func TestTextDoesNotCorruptItsOwnMarkerInOnePass(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Authorization: Bearer sk-abcdef0123456789abcdef", "Authorization: " + Marker},
		{"id_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", "id_token=" + Marker},
		{"access_key=AKIAIOSFODNN7EXAMPLE", "access_key=" + Marker},
	}
	for _, tc := range cases {
		if got := Text(tc.in); got != tc.want {
			t.Errorf("Text(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
		}
	}
}

// TestTextMarkerEchoDoesNotShieldTrailingBytes pins why the value alternation
// is quantified rather than a plain prefix. Cluster and repository text is
// untrusted input (non-negotiable 10), so a line can arrive already containing
// the marker; matching only the marker and stopping would let the bytes after
// it ride through unredacted.
func TestTextMarkerEchoDoesNotShieldTrailingBytes(t *testing.T) {
	const canary = "SUPERSECRET-after-an-echoed-marker"
	got := Text("password=" + Marker + canary)
	if strings.Contains(got, canary) {
		t.Errorf("an echoed marker shielded the value after it: Text(...) = %q", got)
	}
	if second := Text(got); second != got {
		t.Errorf("not idempotent after a marker echo.\n once: %q\n twice: %q", got, second)
	}
}
