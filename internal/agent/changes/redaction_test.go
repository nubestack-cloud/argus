package changes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

const (
	hashA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConfigMapHashCompareEmitsKeyOnlyChanges(t *testing.T) {
	oldCM := &corev1.ConfigMap{
		Data:       map[string]string{"app.yaml": hashA, "flags.json": hashB, "gone": hashC},
		BinaryData: map[string][]byte{"cert.der": []byte(hashA)},
	}
	newCM := &corev1.ConfigMap{
		Data:       map[string]string{"app.yaml": hashA, "flags.json": hashC, "new-key": hashB},
		BinaryData: map[string][]byte{"cert.der": []byte(hashB)},
	}

	diff := ComputeDiff("ConfigMap", oldCM, newCM)
	if diff == nil {
		t.Fatal("ComputeDiff returned nil")
	}
	want := map[string]string{
		"data.flags.json":     ValueModified,
		"data.gone":           ValueRemoved,
		"data.new-key":        ValueAdded,
		"binaryData.cert.der": ValueModified,
	}
	if len(diff.Fields) != len(want) {
		t.Fatalf("fields = %+v, want %v", diff.Fields, want)
	}
	for path, word := range want {
		change, ok := changeAt(diff.Fields, path)
		if !ok {
			t.Fatalf("missing %s in %+v", path, diff.Fields)
		}
		if change.OldValue != nil || change.NewValue != word {
			t.Fatalf("%s = %#v→%#v, want nil→%q", path, change.OldValue, change.NewValue, word)
		}
	}
	if hasPath(diff.Fields, "data.app.yaml") {
		t.Fatal("unchanged key reported")
	}
	if !strings.Contains(diff.Summary, "data.flags.json modified") {
		t.Fatalf("summary = %q", diff.Summary)
	}
	rendered := mustJSON(t, diff)
	for _, h := range []string{hashA, hashB, hashC, "sha256:"} {
		if strings.Contains(rendered, h) {
			t.Fatalf("value digest %q leaked into the diff: %s", h, rendered)
		}
	}
}

func TestConfigMapUnchangedHashesProduceNoDiff(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1"}, Data: map[string]string{"k": hashA}}
	updated := cm.DeepCopy()
	updated.ResourceVersion = "2"
	if diff := ComputeDiff("ConfigMap", cm, updated); diff != nil {
		t.Fatalf("unchanged ConfigMap produced a diff: %+v", diff)
	}
}

func TestConfigMapSummaryCollapsesManyKeys(t *testing.T) {
	oldCM := &corev1.ConfigMap{Data: map[string]string{}}
	newCM := &corev1.ConfigMap{Data: map[string]string{}}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		newCM.Data[k] = hashA
	}
	diff := ComputeDiff("ConfigMap", oldCM, newCM)
	if len(diff.Fields) != 7 || !strings.Contains(diff.Summary, "2 more keys changed") {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestConfigMapUnstructuredInputConverts(t *testing.T) {
	mk := func(v string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "cm", "namespace": "ns"},
			"data":     map[string]any{"k": v},
		}}
	}
	diff := ComputeDiffFromUnstructured("ConfigMap", mk(hashA), mk(hashB))
	if change, ok := changeAt(diff.Fields, "data.k"); !ok || change.NewValue != ValueModified {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestEnvValueChangeNeverCarriesValue(t *testing.T) {
	mk := func(env ...corev1.EnvVar) *appsv1.Deployment {
		return &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "app:v1", Env: env}},
		}}}}
	}
	oldDep := mk(
		corev1.EnvVar{Name: "DB_PASSWORD", Value: hashA},
		corev1.EnvVar{Name: "MODE", Value: hashB},
		corev1.EnvVar{Name: "OLD", Value: hashC},
		corev1.EnvVar{Name: "REF", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "pw"}}},
	)
	newDep := mk(
		corev1.EnvVar{Name: "DB_PASSWORD", Value: hashC},
		corev1.EnvVar{Name: "MODE", Value: hashB},
		corev1.EnvVar{Name: "NEW", Value: hashA},
		corev1.EnvVar{Name: "REF", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "pw2"}}},
	)

	diff := ComputeDiff("Deployment", oldDep, newDep)
	want := map[string]string{
		"spec.template.spec.containers[app].env.DB_PASSWORD": ValueModified,
		"spec.template.spec.containers[app].env.OLD":         ValueRemoved,
		"spec.template.spec.containers[app].env.NEW":         ValueAdded,
		"spec.template.spec.containers[app].env.REF":         ValueModified,
	}
	for path, word := range want {
		change, ok := changeAt(diff.Fields, path)
		if !ok {
			t.Fatalf("missing %s in %+v", path, diff.Fields)
		}
		if change.OldValue != nil || change.NewValue != word {
			t.Fatalf("%s = %#v→%#v, want nil→%q", path, change.OldValue, change.NewValue, word)
		}
	}
	if hasPath(diff.Fields, "spec.template.spec.containers[app].env.MODE") {
		t.Fatal("unchanged env var reported")
	}
	if !strings.Contains(diff.Summary, "env(app/DB_PASSWORD) changed") {
		t.Fatalf("summary = %q", diff.Summary)
	}
	rendered := mustJSON(t, diff)
	for _, leaked := range []string{"sha256:", "pw2", "secretKeyRef"} {
		if strings.Contains(rendered, leaked) {
			t.Fatalf("env content %q leaked: %s", leaked, rendered)
		}
	}
}

func TestValueStringsAreTruncated(t *testing.T) {
	long := strings.Repeat("x", 1000)
	oldSvc := &corev1.Service{Spec: corev1.ServiceSpec{ExternalIPs: []string{"1.1.1.1"}}}
	newSvc := &corev1.Service{Spec: corev1.ServiceSpec{ExternalIPs: []string{long}}}
	diff := ComputeDiff("Service", oldSvc, newSvc)
	change, ok := changeAt(diff.Fields, "spec.externalIPs")
	if !ok {
		t.Fatalf("diff = %+v", diff)
	}
	got := change.NewValue.([]string)[0]
	if utf8.RuneCountInString(got) != MaxValueLen || !strings.HasSuffix(got, TruncationMarker) {
		t.Fatalf("value not truncated to %d runes with marker: len=%d", MaxValueLen, utf8.RuneCountInString(got))
	}

	oldDep := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}}}}}
	newDep := oldDep.DeepCopy()
	newDep.Spec.Template.Spec.Containers[0].Image = "registry.example/" + long + ":v2"
	diff = ComputeDiff("Deployment", oldDep, newDep)
	image, _ := changeAt(diff.Fields, "spec.template.spec.containers[app].image")
	if s := image.NewValue.(string); utf8.RuneCountInString(s) != MaxValueLen || !strings.HasSuffix(s, TruncationMarker) {
		t.Fatalf("image value not truncated: %d runes", utf8.RuneCountInString(s))
	}

	if s := truncateValue(strings.Repeat("é", MaxValueLen)); s != strings.Repeat("é", MaxValueLen) {
		t.Fatal("string at the limit must be untouched")
	}
	nested := capValue(map[string]any{"a": []any{long}}).(map[string]any)["a"].([]any)[0].(string)
	if utf8.RuneCountInString(nested) != MaxValueLen {
		t.Fatal("nested value not truncated")
	}
}

func TestSecretsAreNeverDiffedOrTracked(t *testing.T) {
	oldU := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret", "data": map[string]any{"k": "YQ=="}}}
	newU := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret", "data": map[string]any{"k": "Yg=="}}}
	if diff := ComputeDiff("Secret", oldU, newU); diff != nil {
		t.Fatalf("Secret diffed: %+v", diff)
	}
	if diff := ComputeDiff("SealedSecret", oldU, newU); diff != nil {
		t.Fatalf("SealedSecret diffed: %+v", diff)
	}
	for _, k := range [][2]string{{"Secret", ""}, {"SealedSecret", "bitnami.com"}} {
		if Classify(k[0], k[1]) {
			t.Fatalf("Classify(%q, %q) = true", k[0], k[1])
		}
	}
	if KindHasDiffer("Secret") || KindHasDiffer("SealedSecret") {
		t.Fatal("Secret kinds must have no differ")
	}
}

func TestClassify(t *testing.T) {
	for _, tt := range []struct {
		kind, group string
		want        bool
	}{
		{"Deployment", "apps", true},
		{"Pod", "", true},
		{"ConfigMap", "", true},
		{"Application", "argoproj.io", true},
		{"HTTPRoute", "gateway.networking.k8s.io", true},
		{"ValidatingWebhookConfiguration", "admissionregistration.k8s.io", true},
		{"Job", "batch.volcano.sh", false},
		{"Gateway", "networking.istio.io", false},
		{"Event", "", false},
		{"Lease", "coordination.k8s.io", false},
		{"Rollout", "argoproj.io", false},
	} {
		if got := Classify(tt.kind, tt.group); got != tt.want {
			t.Errorf("Classify(%q, %q) = %v, want %v", tt.kind, tt.group, got, tt.want)
		}
	}
}

func TestBuildEvent(t *testing.T) {
	at := time.Date(2026, 10, 10, 14, 2, 0, 0, time.FixedZone("x", 3600))
	isController := true
	mkDep := func(image string, gen int64) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "shop", Name: "payments", UID: "uid-1", Generation: gen,
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "Other", Name: "first"},
					{Kind: "Application", Name: "payments-app", Controller: &isController},
				},
			},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}}},
		}
	}

	ev, ok := BuildEvent("Deployment", "apps", OpUpdate, mkDep("app:v1.4", 1), mkDep("app:v1.5", 2), at)
	if !ok {
		t.Fatal("image change dropped")
	}
	if ev.Namespace != "shop" || ev.Name != "payments" || ev.UID != "uid-1" || ev.Op != OpUpdate {
		t.Fatalf("identity = %+v", ev)
	}
	if ev.OwnerKind != "Application" || ev.OwnerName != "payments-app" {
		t.Fatalf("owner should be the controller ref: %+v", ev)
	}
	if !ev.ObservedAt.Equal(at) || ev.ObservedAt.Location() != time.UTC {
		t.Fatalf("observedAt = %v", ev.ObservedAt)
	}
	if !hasPath(ev.Fields, "spec.template.spec.containers[app].image") || !strings.Contains(ev.Summary, "app:v1.4→app:v1.5") {
		t.Fatalf("event = %+v", ev)
	}

	// Status-only churn on a tracked kind is dropped.
	if _, ok := BuildEvent("Deployment", "apps", OpUpdate, mkDep("app:v1", 1), mkDep("app:v1", 1), at); ok {
		t.Fatal("no-change update was kept")
	}

	// Untracked spec edits surface through the generation fallback…
	untracked := mkDep("app:v1", 2)
	untracked.Spec.MinReadySeconds = 5
	ev, ok = BuildEvent("Deployment", "apps", OpUpdate, mkDep("app:v1", 1), untracked, at)
	if !ok || len(ev.Fields) != 1 || ev.Fields[0].Path != "metadata.generation" {
		t.Fatalf("generation fallback = %+v ok=%v", ev, ok)
	}
	// …but a Deployment annotation-only generation bump does not.
	annotated := mkDep("app:v1", 2)
	annotated.Annotations = map[string]string{"example.com/revision": "2"}
	if _, ok := BuildEvent("Deployment", "apps", OpUpdate, mkDep("app:v1", 1), annotated, at); ok {
		t.Fatal("annotation-only generation bump was kept")
	}

	// Adds and deletes, including a tombstone.
	if ev, ok := BuildEvent("Deployment", "apps", OpAdd, nil, mkDep("app:v1", 1), at); !ok || ev.Summary != "created" || ev.Fields != nil {
		t.Fatalf("add = %+v ok=%v", ev, ok)
	}
	tomb := cache.DeletedFinalStateUnknown{Key: "shop/payments", Obj: mkDep("app:v1", 1)}
	if ev, ok := BuildEvent("Deployment", "apps", OpDelete, tomb, nil, at); !ok || ev.Summary != "deleted" || ev.Name != "payments" {
		t.Fatalf("tombstone delete = %+v ok=%v", ev, ok)
	}

	// Untracked kinds and Secrets never produce events.
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s"}}
	if _, ok := BuildEvent("Secret", "", OpAdd, nil, secret, at); ok {
		t.Fatal("Secret produced an event")
	}
	if _, ok := BuildEvent("Event", "", OpAdd, nil, &corev1.Event{}, at); ok {
		t.Fatal("untracked kind produced an event")
	}

	// Pods have no generation fallback.
	p1 := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Generation: 1}}
	p2 := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Generation: 2}}
	if _, ok := BuildEvent("Pod", "", OpUpdate, p1, p2, at); ok {
		t.Fatal("pod generation bump produced an event")
	}

	// JSON shape.
	ev, _ = BuildEvent("Deployment", "apps", OpUpdate, mkDep("app:v1.4", 1), mkDep("app:v1.5", 2), at)
	rendered := mustJSON(t, ev)
	for _, key := range []string{`"observedAt"`, `"kind":"Deployment"`, `"apiGroup":"apps"`, `"ownerKind":"Application"`, `"op":"update"`, `"fields"`, `"summary"`} {
		if !strings.Contains(rendered, key) {
			t.Fatalf("JSON missing %s: %s", key, rendered)
		}
	}
}

func hasPath(changes []FieldChange, path string) bool {
	_, ok := changeAt(changes, path)
	return ok
}
