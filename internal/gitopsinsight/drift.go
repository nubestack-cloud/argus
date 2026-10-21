package gitopsinsight

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// LastAppliedAnnotation is where kubectl's client-side apply (and Argo CD's
// client-side sync) keeps a JSON copy of the object as applied. Server-side
// apply and Helm do not write it, so an object without it may still have
// drifted.
const LastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// ErrNoLastApplied: the object has no last-applied annotation, so its drift
// from it is unknown — not "none".
var ErrNoLastApplied = errors.New("object has no last-applied-configuration annotation")

// DriftFromLastApplied is LastAppliedDrift without the truncation flag.
func DriftFromLastApplied(obj *unstructured.Unstructured) ([]DriftEntry, error) {
	entries, _, err := LastAppliedDrift(obj)
	return entries, err
}

// LastAppliedDrift compares the live spec with the spec recorded in the
// last-applied annotation: at most DriftEntryCap entries, sorted by path, and
// whether the cap cut any. ErrNoLastApplied or a parse error mean drift is
// unknown; no entries and no error mean it was compared and nothing differs.
//
// Only spec is compared, so a kind without one (a ConfigMap) never drifts
// here. Before comparing, the desired side gets the API server's defaults for
// the common built-in kinds, and fields the cluster assigns at runtime (a
// Service's clusterIP, a Pod's nodeName, a claim's volumeName) are dropped;
// neither is drift. A change another controller made after the apply is, and
// shows.
//
// Values are copied as found, and the annotation holds whatever was applied,
// container env values included. Entries under ...env.[N].value, and any other
// field a redaction class covers, must be redacted by the caller before they
// leave — and this must run before the object's env values are swapped for
// hashes, or every env value reads as changed.
func LastAppliedDrift(obj *unstructured.Unstructured) (entries []DriftEntry, truncated bool, err error) {
	if obj == nil {
		return nil, false, ErrNoLastApplied
	}
	raw := obj.GetAnnotations()[LastAppliedAnnotation]
	if raw == "" {
		return nil, false, ErrNoLastApplied
	}
	var applied map[string]any
	if err := json.Unmarshal([]byte(raw), &applied); err != nil {
		return nil, false, fmt.Errorf("parse last-applied-configuration: %w", err)
	}
	want, _ := applied["spec"].(map[string]any)
	if want != nil {
		kind, _ := applied["kind"].(string)
		withDefaults(kind, want)
	}
	have, _, _ := unstructured.NestedMap(obj.Object, "spec")
	if want == nil && have == nil {
		return nil, false, nil
	}
	var d differ
	d.walk("spec", want, have)
	found := filterIgnoredPaths(d.found, runtimeAssigned[obj.GetKind()])
	if len(found) == 0 {
		return nil, false, nil
	}
	entries, truncated = capped(found)
	return entries, truncated, nil
}

// runtimeAssigned are fields the API server or a controller fills with values
// nobody could have written in the manifest, as JSON pointers. They are never
// drift, whatever the manifest says.
var runtimeAssigned = map[string][]string{
	// internalTrafficPolicy can be set, but in practice is left to default.
	"Service":               {"/spec/clusterIP", "/spec/clusterIPs", "/spec/ipFamilies", "/spec/ipFamilyPolicy", "/spec/internalTrafficPolicy"},
	"Pod":                   {"/spec/nodeName"},
	"PersistentVolumeClaim": {"/spec/volumeName"},
}

// Kubernetes' own defaulting code lives in k8s.io/kubernetes, which is not an
// importable dependency, so the stable defaults of the common built-in kinds
// are written down here. The annotation holds only what the author wrote; a
// short Deployment manifest would otherwise show a dozen "added" fields the
// API server filled in. Kinds not listed are compared as they are.
//
// A kind is matched by name alone, so a custom resource that reuses a
// built-in kind's name would get its defaults.
type kindDefaults struct {
	spec map[string]any
	// podSpec is the path below spec to the pod spec, when the kind has one,
	// and restart is that pod's default restartPolicy.
	podSpec []string
	restart string
}

var defaultsByKind = map[string]kindDefaults{
	"Deployment": {spec: map[string]any{
		"replicas": int64(1), "progressDeadlineSeconds": int64(600), "revisionHistoryLimit": int64(10),
		"strategy": map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxSurge": "25%", "maxUnavailable": "25%"}},
	}, podSpec: []string{"template", "spec"}, restart: "Always"},
	"StatefulSet": {spec: map[string]any{
		"replicas": int64(1), "revisionHistoryLimit": int64(10), "podManagementPolicy": "OrderedReady",
		"updateStrategy": map[string]any{"type": "RollingUpdate"},
	}, podSpec: []string{"template", "spec"}, restart: "Always"},
	"DaemonSet": {spec: map[string]any{
		"revisionHistoryLimit": int64(10),
		"updateStrategy":       map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxUnavailable": int64(1)}},
	}, podSpec: []string{"template", "spec"}, restart: "Always"},
	"ReplicaSet": {spec: map[string]any{"replicas": int64(1)}, podSpec: []string{"template", "spec"}, restart: "Always"},
	// A Job's pods may not restart Always, so a manifest that left
	// restartPolicy out can only have meant Never.
	"Job": {spec: jobDefaults, podSpec: []string{"template", "spec"}, restart: "Never"},
	"CronJob": {spec: map[string]any{
		"concurrencyPolicy": "Allow", "failedJobsHistoryLimit": int64(1), "successfulJobsHistoryLimit": int64(3), "suspend": false,
	}, podSpec: []string{"jobTemplate", "spec", "template", "spec"}, restart: "Never"},
	"Pod":     {podSpec: []string{}, restart: "Always"},
	"Service": {spec: map[string]any{"type": "ClusterIP", "sessionAffinity": "None", "ipFamilyPolicy": "SingleStack"}},
}

var jobDefaults = map[string]any{"backoffLimit": int64(6), "completionMode": "NonIndexed"}

var podDefaults = map[string]any{
	"dnsPolicy": "ClusterFirst", "schedulerName": "default-scheduler",
	"securityContext": map[string]any{}, "terminationGracePeriodSeconds": int64(30),
}

var containerDefaults = map[string]any{
	"terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "resources": map[string]any{},
}

// withDefaults fills kind's defaults into spec wherever spec leaves a field
// absent or empty — as the API server does for most fields — and never over
// a value that was written.
func withDefaults(kind string, spec map[string]any) {
	k, ok := defaultsByKind[kind]
	if !ok {
		return
	}
	fill(spec, k.spec)
	if kind == "CronJob" {
		if job, ok := nested(spec, "jobTemplate", "spec"); ok {
			fill(job, jobDefaults)
		}
	}
	if kind == "Service" {
		// targetPort defaults too (to port), but only shows as drift when it
		// was written, so it is left alone.
		eachMap(spec["ports"], func(p map[string]any) { fill(p, map[string]any{"protocol": "TCP"}) })
	}
	if k.podSpec == nil {
		return
	}
	pod, ok := nested(spec, k.podSpec...)
	if !ok {
		return
	}
	fill(pod, podDefaults)
	fill(pod, map[string]any{"restartPolicy": k.restart})
	for _, field := range []string{"containers", "initContainers"} {
		eachMap(pod[field], func(c map[string]any) {
			image, _ := c["image"].(string)
			fill(c, containerDefaults)
			fill(c, map[string]any{"imagePullPolicy": defaultImagePullPolicy(image)})
			eachMap(c["ports"], func(p map[string]any) { fill(p, map[string]any{"protocol": "TCP"}) })
		})
	}
}

// fill copies each default into m where m's own value is absent.
func fill(m, defaults map[string]any) {
	for key, v := range defaults {
		if absent(m[key]) {
			m[key] = runtime.DeepCopyJSONValue(v)
		}
	}
}

func nested(m map[string]any, path ...string) (map[string]any, bool) {
	for _, key := range path {
		next, ok := m[key].(map[string]any)
		if !ok {
			return nil, false
		}
		m = next
	}
	return m, true
}

func eachMap(list any, do func(map[string]any)) {
	items, _ := list.([]any)
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			do(m)
		}
	}
}

// defaultImagePullPolicy is Kubernetes' rule: Always when the image's tag is
// latest, or when it has neither a tag nor a digest (which means latest);
// IfNotPresent otherwise — a digest-only reference included, since a digest
// cannot change underneath a node.
func defaultImagePullPolicy(image string) string {
	name, digest, _ := strings.Cut(strings.TrimSpace(image), "@")
	tag := ""
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		tag = name[i+1:]
	}
	if tag == "latest" || tag == "" && digest == "" {
		return "Always"
	}
	return "IfNotPresent"
}
