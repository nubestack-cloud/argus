package gitopsinsight

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// applied is a live object of kind whose last-applied annotation is manifest
// and whose spec is liveSpec, both written as JSON.
func applied(kind, manifest, liveSpec string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	if liveSpec != "" {
		var spec map[string]any
		if err := json.Unmarshal([]byte(liveSpec), &spec); err != nil {
			panic(err)
		}
		obj.Object["spec"] = spec
	}
	obj.SetKind(kind)
	obj.SetNamespace("shop")
	obj.SetName("web")
	obj.SetAnnotations(map[string]string{LastAppliedAnnotation: manifest})
	return obj
}

// lines renders entries as "op path desired→live", one per entry.
func lines(entries []DriftEntry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%s %s %s→%s\n", e.Op, e.Path, e.Desired, e.Live)
	}
	return b.String()
}

func TestLastAppliedDriftAvailability(t *testing.T) {
	if _, _, err := LastAppliedDrift(nil); !errors.Is(err, ErrNoLastApplied) {
		t.Errorf("nil object: %v", err)
	}
	bare := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"replicas": int64(2)}}}
	if got, err := DriftFromLastApplied(bare); !errors.Is(err, ErrNoLastApplied) || got != nil {
		t.Errorf("no annotation: %v %v", got, err)
	}
	if got, err := DriftFromLastApplied(applied("Widget", "{oops", `{"a":1}`)); err == nil || errors.Is(err, ErrNoLastApplied) || got != nil {
		t.Errorf("bad JSON: %v %v", got, err)
	}
	// Compared and equal is an answer of its own: nothing, and no error.
	if got, err := DriftFromLastApplied(applied("Widget", `{"spec":{"size":3,"color":"teal"}}`, `{"size":3,"color":"teal"}`)); err != nil || got != nil {
		t.Errorf("no drift: %v %v", got, err)
	}
	// Neither side has a spec (a ConfigMap): nothing to compare.
	if got, err := DriftFromLastApplied(applied("ConfigMap", `{"data":{"k":"v"}}`, "")); err != nil || got != nil {
		t.Errorf("no spec: %v %v", got, err)
	}
}

func TestLastAppliedDriftShapes(t *testing.T) {
	cases := []struct {
		why            string
		manifest, live string
		want           string
	}{
		{"a changed scalar", `{"spec":{"replicas":2}}`, `{"replicas":6}`, "changed spec.replicas 2→6\n"},
		// One field inside one list element is that field, not the list.
		{"a field in a list element",
			`{"spec":{"containers":[{"name":"app","resources":{"limits":{"cpu":"500m"}}}]}}`,
			`{"containers":[{"name":"app","resources":{"limits":{"cpu":"2"}}}]}`,
			"changed spec.containers.[0].resources.limits.cpu \"500m\"→\"2\"\n"},
		{"an element appended", `{"spec":{"args":["--port=80"]}}`, `{"args":["--port=80","--debug"]}`, "added spec.args.[1] →\"--debug\"\n"},
		{"an element dropped", `{"spec":{"args":["--port=80","--debug"]}}`, `{"args":["--port=80"]}`, "removed spec.args.[1] \"--debug\"→\n"},
		// Empty and missing are the same nothing.
		{"empty versus missing", `{"spec":{"tolerations":[],"nodeSelector":{},"note":"","size":1}}`, `{"size":1,"labels":null}`, ""},
		// A subtree on one side only is one entry at its root.
		{"a whole block added", `{"spec":{"size":1}}`, `{"size":1,"affinity":{"nodeAffinity":{"required":true}}}`, "added spec.affinity →{\"nodeAffinity\":{\"required\":true}}\n"},
		{"a whole block removed", `{"spec":{"affinity":{"podAntiAffinity":{"x":1}}}}`, `{"affinity":{}}`, "removed spec.affinity {\"podAntiAffinity\":{\"x\":1}}→\n"},
		// A field that moved between versions of a CRD's schema shows as gone
		// in one place and new in the other.
		{"a field moved by a schema change",
			`{"spec":{"disruption":{"expireAfter":"720h"},"template":{"spec":{"limits":{"cpu":"100"}}}}}`,
			`{"disruption":{"budgets":[{"nodes":"10%"}]},"template":{"spec":{"limits":{"cpu":"100"},"expireAfter":"720h"}}}`,
			"added spec.disruption.budgets →[{\"nodes\":\"10%\"}]\nremoved spec.disruption.expireAfter \"720h\"→\nadded spec.template.spec.expireAfter →\"720h\"\n"},
		// A string and a bool are different values.
		{"string versus bool", `{"spec":{"enabled":"true"}}`, `{"enabled":true}`, "changed spec.enabled \"true\"→true\n"},
	}
	for _, c := range cases {
		got, err := DriftFromLastApplied(applied("Widget", c.manifest, c.live))
		if err != nil || lines(got) != c.want {
			t.Errorf("%s:\n got  %q (%v)\n want %q", c.why, lines(got), err, c.want)
		}
	}
}

// Values are copied as they are; the caller redacts by path, so an env
// value's path must be the stable, recognisable one.
func TestLastAppliedDriftEnvPathForRedaction(t *testing.T) {
	got, _ := DriftFromLastApplied(applied("Widget",
		`{"spec":{"containers":[{"name":"app","env":[{"name":"DB_PASSWORD","value":"before"}]}]}}`,
		`{"containers":[{"name":"app","env":[{"name":"DB_PASSWORD","value":"after"}]}]}`))
	if len(got) != 1 || got[0].Path != "spec.containers.[0].env.[0].value" {
		t.Fatalf("entries = %v", got)
	}
}

func TestLastAppliedDriftCap(t *testing.T) {
	var want, have []string
	for i := range DriftEntryCap + 7 {
		want = append(want, fmt.Sprintf(`"k%03d":"a"`, i))
		have = append(have, fmt.Sprintf(`"k%03d":"b"`, i))
	}
	entries, truncated, err := LastAppliedDrift(applied("Widget", `{"spec":{`+strings.Join(want, ",")+`}}`, `{`+strings.Join(have, ",")+`}`))
	if err != nil || !truncated || len(entries) != DriftEntryCap || entries[0].Path != "spec.k000" {
		t.Fatalf("%d entries, truncated=%v, first %v, err %v", len(entries), truncated, entries[0], err)
	}
}

// A short manifest against the object as the API server returns it: every
// difference is a default or a runtime-assigned field, so none is drift. A
// mistyped default fails its kind's case.
func TestLastAppliedDriftIgnoresServerDefaults(t *testing.T) {
	const container = `{"name":"app","image":"ghcr.io/acme/app:2.4.1","imagePullPolicy":"IfNotPresent","terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","resources":{},"ports":[{"containerPort":8080,"protocol":"TCP"}]}`
	pod := func(restart string) string {
		return `{"containers":[` + container + `],"dnsPolicy":"ClusterFirst","restartPolicy":"` + restart + `","schedulerName":"default-scheduler","securityContext":{},"terminationGracePeriodSeconds":30}`
	}
	const manifestPod = `{"containers":[{"name":"app","image":"ghcr.io/acme/app:2.4.1","ports":[{"containerPort":8080}]}]}`
	tmpl := func(p string) string { return `"template":{"metadata":{"labels":{"app":"web"}},"spec":` + p + `}` }
	cases := []struct{ kind, manifest, live string }{
		{"Deployment",
			`{"kind":"Deployment","spec":{"selector":{"matchLabels":{"app":"web"}},` + tmpl(manifestPod) + `}}`,
			`{"replicas":1,"progressDeadlineSeconds":600,"revisionHistoryLimit":10,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":"25%","maxUnavailable":"25%"}},"selector":{"matchLabels":{"app":"web"}},` + tmpl(pod("Always")) + `}`},
		{"StatefulSet",
			`{"kind":"StatefulSet","spec":{"serviceName":"web",` + tmpl(manifestPod) + `}}`,
			`{"replicas":1,"revisionHistoryLimit":10,"podManagementPolicy":"OrderedReady","updateStrategy":{"type":"RollingUpdate"},"serviceName":"web",` + tmpl(pod("Always")) + `}`},
		{"DaemonSet",
			`{"kind":"DaemonSet","spec":{` + tmpl(manifestPod) + `}}`,
			`{"revisionHistoryLimit":10,"updateStrategy":{"type":"RollingUpdate","rollingUpdate":{"maxUnavailable":1}},` + tmpl(pod("Always")) + `}`},
		{"ReplicaSet",
			`{"kind":"ReplicaSet","spec":{` + tmpl(manifestPod) + `}}`,
			`{"replicas":1,` + tmpl(pod("Always")) + `}`},
		{"Job",
			`{"kind":"Job","spec":{` + tmpl(manifestPod) + `}}`,
			`{"backoffLimit":6,"completionMode":"NonIndexed",` + tmpl(pod("Never")) + `}`},
		{"CronJob",
			`{"kind":"CronJob","spec":{"schedule":"0 3 * * *","jobTemplate":{"spec":{` + tmpl(manifestPod) + `}}}}`,
			`{"schedule":"0 3 * * *","concurrencyPolicy":"Allow","failedJobsHistoryLimit":1,"successfulJobsHistoryLimit":3,"suspend":false,"jobTemplate":{"spec":{"backoffLimit":6,"completionMode":"NonIndexed",` + tmpl(pod("Never")) + `}}}`},
		// nodeName is assigned by the scheduler.
		{"Pod", `{"kind":"Pod","spec":` + manifestPod + `}`, strings.TrimSuffix(pod("Always"), "}") + `,"nodeName":"worker-2"}`},
		{"Service",
			`{"kind":"Service","spec":{"selector":{"app":"web"},"ports":[{"port":80,"targetPort":8080}]}}`,
			`{"type":"ClusterIP","sessionAffinity":"None","ipFamilyPolicy":"SingleStack","clusterIP":"10.43.12.7","clusterIPs":["10.43.12.7"],"ipFamilies":["IPv4"],"internalTrafficPolicy":"Cluster","selector":{"app":"web"},"ports":[{"port":80,"targetPort":8080,"protocol":"TCP"}]}`},
		{"PersistentVolumeClaim",
			`{"kind":"PersistentVolumeClaim","spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"5Gi"}}}}`,
			`{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"5Gi"}},"volumeName":"pvc-1f2e3d4c"}`},
	}
	for _, c := range cases {
		if got, err := DriftFromLastApplied(applied(c.kind, c.manifest, c.live)); err != nil || got != nil {
			t.Errorf("%s:\n%s(%v)", c.kind, lines(got), err)
		}
	}
	// A default never overrides a value that was written.
	got, _ := DriftFromLastApplied(applied("Deployment", `{"kind":"Deployment","spec":{"replicas":4}}`,
		`{"replicas":1,"progressDeadlineSeconds":600,"revisionHistoryLimit":10,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":"25%","maxUnavailable":"25%"}}}`))
	if lines(got) != "changed spec.replicas 4→1\n" {
		t.Errorf("written replicas:\n%s", lines(got))
	}
}

func TestDefaultImagePullPolicy(t *testing.T) {
	for image, want := range map[string]string{
		"redis":                                  "Always",
		"redis:latest":                           "Always",
		"redis:7.2":                              "IfNotPresent",
		"harbor.internal:8443/team/api":          "Always",
		"harbor.internal:8443/team/api:1.9":      "IfNotPresent",
		"redis@sha256:6b8f":                      "IfNotPresent",
		"redis:7.2@sha256:6b8f":                  "IfNotPresent",
		"harbor.internal:8443/team/api@sha256:1": "IfNotPresent",
	} {
		if got := defaultImagePullPolicy(image); got != want {
			t.Errorf("%s: %s, want %s", image, got, want)
		}
	}
}

func TestArgoResourceSync(t *testing.T) {
	app := map[string]any{
		"metadata": map[string]any{"namespace": "argocd", "name": "storefront"},
		"status": map[string]any{"resources": []any{
			map[string]any{"group": "apps", "kind": "Deployment", "namespace": "shop", "name": "web", "status": "OutOfSync", "health": map[string]any{"status": "Progressing"}},
			map[string]any{"kind": "Service", "namespace": "shop", "name": "web"},
		}},
	}
	if got, ok := ArgoResourceSync(app, "apps", "Deployment", "shop", "web"); !ok || got != (ControllerSync{"Argo CD", "argocd/storefront", "OutOfSync", "Progressing"}) {
		t.Errorf("deployment = %+v %v", got, ok)
	}
	if got, ok := ArgoResourceSync(app, "", "Service", "shop", "web"); !ok || got.Status != "Unknown" || got.Health != "" {
		t.Errorf("service without a verdict = %+v %v", got, ok)
	}
	for _, miss := range [][4]string{{"apps", "Deployment", "staging", "web"}, {"", "Deployment", "shop", "web"}} {
		if _, ok := ArgoResourceSync(app, miss[0], miss[1], miss[2], miss[3]); ok {
			t.Errorf("%v matched", miss)
		}
	}
}
