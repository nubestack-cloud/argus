package changes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// count records an integer that moved, summarised "label: a→b" unless quiet.
func (d *delta) count(path, label string, a, b int32, quiet bool) {
	if a == b {
		return
	}
	d.add(path, a, b)
	if !quiet {
		d.note(fmt.Sprintf("%s: %d→%d", label, a, b))
	}
}

// conditionFlip records a condition whose status moved, "Type: a→b".
func (d *delta) conditionFlip(typ, a, b string) {
	if a != b {
		d.add("status.conditions["+typ+"]", a, b, fmt.Sprintf("%s: %s→%s", typ, a, b))
	}
}

// statusOf is the status of the condition of type t in conds, "" if absent.
func statusOf[C any, T comparable](conds []C, t T, read func(C) (T, string)) string {
	for _, c := range conds {
		if typ, st := read(c); typ == t {
			return st
		}
	}
	return ""
}

func diffDeployment(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[appsv1.Deployment](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.count("spec.replicas", "replicas", replicasOrDefault(was.Spec.Replicas), replicasOrDefault(is.Spec.Replicas), false)
	d.merge(diffPodTemplate(was.Spec.Template.Spec, is.Spec.Template.Spec))
	if a, b := was.Spec.Paused, is.Spec.Paused; a != b {
		d.add("spec.paused", a, b, map[bool]string{true: "rollout paused", false: "rollout resumed"}[b])
	}
	readyMoved := was.Status.ReadyReplicas != is.Status.ReadyReplicas
	d.count("status.readyReplicas", "ready", was.Status.ReadyReplicas, is.Status.ReadyReplicas, false)
	d.count("status.updatedReplicas", "updated", was.Status.UpdatedReplicas, is.Status.UpdatedReplicas, readyMoved)
	// Available=False: the rollout missed its availability check.
	// Progressing=False: it stalled past its deadline. Neither shows in the
	// replica counts.
	read := func(c appsv1.DeploymentCondition) (appsv1.DeploymentConditionType, string) {
		return c.Type, string(c.Status)
	}
	for _, t := range []appsv1.DeploymentConditionType{appsv1.DeploymentAvailable, appsv1.DeploymentProgressing} {
		d.conditionFlip(string(t), statusOf(was.Status.Conditions, t, read), statusOf(is.Status.Conditions, t, read))
	}
	return d.result()
}

func diffReplicaSet(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[appsv1.ReplicaSet](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.count("spec.replicas", "replicas", replicasOrDefault(was.Spec.Replicas), replicasOrDefault(is.Spec.Replicas), false)
	readyMoved := was.Status.ReadyReplicas != is.Status.ReadyReplicas
	d.count("status.readyReplicas", "ready", was.Status.ReadyReplicas, is.Status.ReadyReplicas, false)
	d.count("status.availableReplicas", "available", was.Status.AvailableReplicas, is.Status.AvailableReplicas, readyMoved)
	// ReplicaFailure=True is where a failure to create pods (quota,
	// admission) shows on a ReplicaSet.
	read := func(c appsv1.ReplicaSetCondition) (appsv1.ReplicaSetConditionType, string) {
		return c.Type, string(c.Status)
	}
	t := appsv1.ReplicaSetReplicaFailure
	d.conditionFlip(string(t), statusOf(was.Status.Conditions, t, read), statusOf(is.Status.Conditions, t, read))
	return d.result()
}

func diffDaemonSet(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[appsv1.DaemonSet](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.merge(diffPodTemplate(was.Spec.Template.Spec, is.Spec.Template.Spec))
	a, b := was.Status, is.Status
	d.count("status.desiredNumberScheduled", "desired", a.DesiredNumberScheduled, b.DesiredNumberScheduled, false)
	d.count("status.numberReady", "ready", a.NumberReady, b.NumberReady, false)
	if a.UpdatedNumberScheduled != b.UpdatedNumberScheduled {
		d.add("status.updatedNumberScheduled", a.UpdatedNumberScheduled, b.UpdatedNumberScheduled,
			fmt.Sprintf("updated: %d→%d nodes", a.UpdatedNumberScheduled, b.UpdatedNumberScheduled))
	}
	// A misscheduled pod runs on a node the selector or tolerations now rule
	// out — how a taint or selector change shows.
	for _, c := range []struct {
		path, label string
		a, b        int32
	}{
		{"status.numberUnavailable", "unavailable", a.NumberUnavailable, b.NumberUnavailable},
		{"status.numberMisscheduled", "misscheduled", a.NumberMisscheduled, b.NumberMisscheduled},
	} {
		if c.a != c.b {
			d.add(c.path, c.a, c.b)
			if c.b > 0 {
				d.note(fmt.Sprintf("%s: %d", c.label, c.b))
			}
		}
	}
	return d.result()
}

func diffStatefulSet(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[appsv1.StatefulSet](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.count("spec.replicas", "replicas", replicasOrDefault(was.Spec.Replicas), replicasOrDefault(is.Spec.Replicas), false)
	d.merge(diffPodTemplate(was.Spec.Template.Spec, is.Spec.Template.Spec))
	a, b := was.Status, is.Status
	readyMoved := a.ReadyReplicas != b.ReadyReplicas
	d.count("status.readyReplicas", "ready", a.ReadyReplicas, b.ReadyReplicas, false)
	d.count("status.updatedReplicas", "updated", a.UpdatedReplicas, b.UpdatedReplicas, readyMoved)
	if a.CurrentRevision != b.CurrentRevision {
		d.add("status.currentRevision", a.CurrentRevision, b.CurrentRevision, "revision updated")
	}
	d.count("status.availableReplicas", "available", a.AvailableReplicas, b.AvailableReplicas, readyMoved)
	return d.result()
}

func diffHPA(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[autoscalingv2.HorizontalPodAutoscaler](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.count("spec.minReplicas", "minReplicas", replicasOrDefault(was.Spec.MinReplicas), replicasOrDefault(is.Spec.MinReplicas), false)
	d.count("spec.maxReplicas", "maxReplicas", was.Spec.MaxReplicas, is.Spec.MaxReplicas, false)
	cur, next := was.Status.CurrentReplicas, is.Status.CurrentReplicas
	if cur != next {
		dir := "scaled up"
		if next < cur {
			dir = "scaled down"
		}
		d.add("status.currentReplicas", cur, next, fmt.Sprintf("%s: %d→%d", dir, cur, next))
	}
	if a, b := was.Status.DesiredReplicas, is.Status.DesiredReplicas; a != b {
		d.add("status.desiredReplicas", a, b)
		if cur == next {
			d.note(fmt.Sprintf("target: %d→%d replicas", a, b))
		}
	}
	// ScalingActive=False: no metrics. AbleToScale=False: backing off, or a
	// spec error. ScalingLimited=True: the bounds overrode the decision. None
	// shows anywhere else.
	read := func(c autoscalingv2.HorizontalPodAutoscalerCondition) (autoscalingv2.HorizontalPodAutoscalerConditionType, string) {
		return c.Type, string(c.Status)
	}
	for _, t := range []autoscalingv2.HorizontalPodAutoscalerConditionType{autoscalingv2.ScalingActive, autoscalingv2.AbleToScale, autoscalingv2.ScalingLimited} {
		d.conditionFlip(string(t), statusOf(was.Status.Conditions, t, read), statusOf(is.Status.Conditions, t, read))
	}
	return d.result()
}

// jobConditionWords names each terminal Job condition for a summary.
var jobConditionWords = map[batchv1.JobConditionType]string{
	batchv1.JobComplete: "completed", batchv1.JobFailed: "failed", batchv1.JobSuspended: "suspended", batchv1.JobFailureTarget: "failure target",
}

func diffJob(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[batchv1.Job](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	d.count("status.active", "active", was.Status.Active, is.Status.Active, false)
	d.count("status.succeeded", "succeeded", was.Status.Succeeded, is.Status.Succeeded, false)
	d.count("status.failed", "failed", was.Status.Failed, is.Status.Failed, false)
	// The conditions, because a completion time alone misses a failed Job
	// (which never sets one) and the FailureTarget signal.
	read := func(c batchv1.JobCondition) (batchv1.JobConditionType, string) { return c.Type, string(c.Status) }
	for _, t := range []batchv1.JobConditionType{batchv1.JobComplete, batchv1.JobFailed, batchv1.JobSuspended, batchv1.JobFailureTarget} {
		a, b := statusOf(was.Status.Conditions, t, read), statusOf(is.Status.Conditions, t, read)
		if a == b {
			continue
		}
		text := fmt.Sprintf("%s: %s→%s", t, a, b)
		switch {
		case b == "True":
			text = jobConditionWords[t]
		case b == "False" && a == "True":
			text = "no longer " + jobConditionWords[t]
		}
		d.add("status.conditions["+string(t)+"]", a, b, text)
	}
	if was.Status.StartTime == nil && is.Status.StartTime != nil {
		d.add("status.startTime", nil, is.Status.StartTime.UTC().Format("2006-01-02T15:04:05Z"), "started")
	}
	if a, b := flag(was.Spec.Suspend), flag(is.Spec.Suspend); a != b {
		d.add("spec.suspend", a, b, map[bool]string{true: "suspended", false: "resumed"}[b])
	}
	return d.result()
}

// diffPod follows only where a pod is scheduled, its phase, and restarts
// going up. Pods churn without end; everything else about them is covered
// by their owner's differ or by the agent's detectors.
func diffPod(oldObj, newObj any) ([]FieldChange, []string) {
	was, is, ok := both[corev1.Pod](oldObj, newObj)
	if !ok {
		return nil, nil
	}
	var d delta
	if a, b := was.Status.Phase, is.Status.Phase; a != b {
		d.add("status.phase", string(a), string(b), fmt.Sprintf("phase: %s→%s", a, b))
	}
	// Within one pod UID restarts only climb; a drop is a cache artefact.
	if a, b := totalRestarts(was.Status.ContainerStatuses), totalRestarts(is.Status.ContainerStatuses); b > a {
		d.add("status.containerStatuses[*].restartCount", a, b, fmt.Sprintf("restarts: %d→%d", a, b))
	}
	if a, b := was.Spec.NodeName, is.Spec.NodeName; a != b && b != "" {
		d.add("spec.nodeName", a, b, "scheduled to "+b)
	}
	return d.result()
}

// diffPodTemplate covers the pod template Deployments, StatefulSets and
// DaemonSets share: images, resources, env (by hash) and the rest of the
// container and pod configuration. Anything that may hold a credential
// (env, command, args, exec probes) is reported as changed, never shown.
func diffPodTemplate(was, is corev1.PodSpec) ([]FieldChange, []string) {
	var d delta
	d.merge(diffContainerImages(was, is))
	if a, b := containerResources(was), containerResources(is); !reflect.DeepEqual(a, b) {
		d.add("spec.template.spec.containers[*].resources", a, b, "resources changed")
	}
	d.merge(diffPodTemplateConfig(was, is))
	return d.result()
}

// containerResources is each container's requests and limits by name, as
// "limits.cpu" → "500m".
func containerResources(spec corev1.PodSpec) map[string]any {
	out := map[string]any{}
	for _, c := range slices.Concat(spec.InitContainers, spec.Containers) {
		res := map[string]any{}
		for n, q := range c.Resources.Limits {
			res["limits."+string(n)] = q.String()
		}
		for n, q := range c.Resources.Requests {
			res["requests."+string(n)] = q.String()
		}
		out[c.Name] = res
	}
	return out
}

func diffContainerImages(was, is corev1.PodSpec) ([]FieldChange, []string) {
	before, after := containerIndex(was), containerIndex(is)
	var d delta
	for _, name := range slices.Sorted(maps.Keys(before)) {
		a, b := before[name], after[name]
		if b == nil || a.pathPrefix != b.pathPrefix || a.Image == b.Image {
			continue
		}
		d.add(b.fieldPath(name, "image"), a.Image, b.Image, fmt.Sprintf("image(%s): %s→%s", name, truncateImage(a.Image), truncateImage(b.Image)))
	}
	return d.result()
}

func diffPodTemplateConfig(was, is corev1.PodSpec) ([]FieldChange, []string) {
	before, after := containerIndex(was), containerIndex(is)
	all := maps.Clone(before)
	maps.Copy(all, after)
	var d delta
	for _, name := range slices.Sorted(maps.Keys(all)) {
		a, b := before[name], after[name]
		// A container added or removed is one entry naming it, not each of
		// its fields compared with nothing. One that moved between the init
		// and the main list is both.
		if a != nil && (b == nil || a.pathPrefix != b.pathPrefix) {
			d.add(a.fieldPath(name, ""), a.Image, nil, a.summaryKind()+" "+name+" removed")
		}
		if b != nil && (a == nil || a.pathPrefix != b.pathPrefix) {
			d.add(b.fieldPath(name, ""), nil, b.Image, fmt.Sprintf("%s %s added (%s)", b.summaryKind(), name, truncateImage(b.Image)))
		}
		if a == nil || b == nil || a.pathPrefix != b.pathPrefix {
			continue
		}
		d.containerConfig(name, a, b)
	}

	// Pod-level fields: volumes by their source, tolerations as short
	// strings, affinity only as "changed" — its tree is too big to compare
	// usefully.
	const pod = "spec.template.spec."
	if x, y := normalizedDNSPolicy(was.DNSPolicy), normalizedDNSPolicy(is.DNSPolicy); x != y {
		d.add(pod+"dnsPolicy", x, y, fmt.Sprintf("dnsPolicy: %s→%s", x, y))
	}
	ns1, se1, op1 := dnsConfigValues(was.DNSConfig)
	ns2, se2, op2 := dnsConfigValues(is.DNSConfig)
	for _, c := range []struct {
		field string
		x, y  []string
	}{{"nameservers", ns1, ns2}, {"searches", se1, se2}, {"options", op1, op2}} {
		if !slices.Equal(c.x, c.y) {
			d.add(pod+"dnsConfig."+c.field, c.x, c.y, "dnsConfig."+c.field+" changed")
		}
	}
	if x, y := volumeSourceRefs(was.Volumes), volumeSourceRefs(is.Volumes); !slices.Equal(x, y) {
		d.add(pod+"volumes", x, y, "volumes changed")
	}
	if x, y := was.ServiceAccountName, is.ServiceAccountName; x != y {
		d.add(pod+"serviceAccountName", x, y, fmt.Sprintf("serviceAccountName: %s→%s", emptyAsNone(x), emptyAsNone(y)))
	}
	if !maps.Equal(was.NodeSelector, is.NodeSelector) {
		d.add(pod+"nodeSelector", was.NodeSelector, is.NodeSelector, "nodeSelector changed")
	}
	if x, y := tolerationRefs(was.Tolerations), tolerationRefs(is.Tolerations); !slices.Equal(x, y) {
		d.add(pod+"tolerations", x, y, "tolerations changed")
	}
	if !reflect.DeepEqual(was.Affinity, is.Affinity) {
		d.add(pod+"affinity", "changed", "changed", "affinity changed")
	}
	if !reflect.DeepEqual(was.SecurityContext, is.SecurityContext) {
		d.add(pod+"securityContext", "changed", "changed", "pod securityContext changed")
	}
	return d.result()
}

// containerConfig compares one container present on both sides.
func (d *delta) containerConfig(name string, a, b *podTemplateContainer) {
	at := func(field string) string { return b.fieldPath(name, field) }
	for _, c := range diffContainerEnv(at(""), a.Env, b.Env) {
		d.add(c.Path, c.OldValue, c.NewValue, envChangeSummary(c, name))
	}
	if x, y := envFromRefs(a.EnvFrom), envFromRefs(b.EnvFrom); !slices.Equal(x, y) {
		d.add(at("envFrom"), x, y, "envFrom("+name+") changed")
	}
	if x, y := a.ImagePullPolicy, b.ImagePullPolicy; x != y {
		d.add(at("imagePullPolicy"), string(x), string(y), fmt.Sprintf("imagePullPolicy(%s): %s→%s", name, x, y))
	}
	for _, probe := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
		x, y := normalizedProbe(probeForName(a.Container, probe)), normalizedProbe(probeForName(b.Container, probe))
		if !reflect.DeepEqual(x, y) {
			d.add(at(probe), x, y, probe+"("+name+") changed")
		}
	}
	// Command lines often carry tokens and passwords; only that they changed
	// leaves the agent.
	if !slices.Equal(a.Command, b.Command) {
		d.add(at("command"), "changed", "changed", "command("+name+") changed")
	}
	if !slices.Equal(a.Args, b.Args) {
		d.add(at("args"), "changed", "changed", "args("+name+") changed")
	}
	if x, y := volumeMountRefs(a.VolumeMounts), volumeMountRefs(b.VolumeMounts); !slices.Equal(x, y) {
		d.add(at("volumeMounts"), x, y, "volumeMounts("+name+") changed")
	}
	if x, y := containerPortRefs(a.Ports), containerPortRefs(b.Ports); !slices.Equal(x, y) {
		d.add(at("ports"), x, y, "ports("+name+") changed")
	}
	// A deep structure whose detail rarely matters in triage; that it
	// changed does.
	if !reflect.DeepEqual(a.SecurityContext, b.SecurityContext) {
		d.add(at("securityContext"), "changed", "changed", "securityContext("+name+") changed")
	}
}

// podTemplateContainer is a container and which list it is in.
type podTemplateContainer struct {
	corev1.Container
	pathPrefix string
}

const (
	initContainersPath = "spec.template.spec.initContainers"
	containersPath     = "spec.template.spec.containers"
)

// fieldPath is "<list>[<name>]" and the field beneath it, if any.
func (c podTemplateContainer) fieldPath(name, field string) string {
	p := c.pathPrefix + "[" + name + "]"
	if field == "" {
		return p
	}
	return p + "." + field
}

func (c podTemplateContainer) summaryKind() string {
	if c.pathPrefix == initContainersPath {
		return "init container"
	}
	return "container"
}

// containerIndex is every container by name; a main container shadows an
// init container of the same name.
func containerIndex(spec corev1.PodSpec) map[string]*podTemplateContainer {
	out := map[string]*podTemplateContainer{}
	for _, list := range []struct {
		path string
		cs   []corev1.Container
	}{{initContainersPath, spec.InitContainers}, {containersPath, spec.Containers}} {
		for _, c := range list.cs {
			out[c.Name] = &podTemplateContainer{Container: c, pathPrefix: list.path}
		}
	}
	return out
}

// diffContainerEnv compares env vars by name. A literal value arrives as
// its "sha256:<hex>" digest, so comparing strings finds a change without
// the value; a valueFrom compares by what it refers to. Each change carries
// only the word added, removed or modified.
func diffContainerEnv(containerPath string, before, after []corev1.EnvVar) []FieldChange {
	return keyLevelChanges(containerPath+".env", envFingerprints(before), envFingerprints(after), func(a, b string) bool { return a == b })
}

func envFingerprints(env []corev1.EnvVar) map[string]string {
	out := make(map[string]string, len(env))
	for _, e := range env {
		if e.ValueFrom != nil {
			out[e.Name] = "from:" + envValueFromRef(e.ValueFrom)
		} else {
			out[e.Name] = "value:" + e.Value
		}
	}
	return out
}

// envValueFromRef names what a valueFrom reads, never its value.
func envValueFromRef(from *corev1.EnvVarSource) string {
	switch {
	case from.ConfigMapKeyRef != nil:
		return "configMapKeyRef:" + from.ConfigMapKeyRef.Name + "/" + from.ConfigMapKeyRef.Key
	case from.SecretKeyRef != nil:
		return "secretKeyRef:" + from.SecretKeyRef.Name + "/" + from.SecretKeyRef.Key
	case from.FieldRef != nil:
		return "fieldRef:" + from.FieldRef.FieldPath
	case from.ResourceFieldRef != nil:
		r := from.ResourceFieldRef
		return "resourceFieldRef:" + r.ContainerName + "/" + r.Resource + "/" + r.Divisor.String()
	}
	return "valueFrom"
}

// envChangeSummary is "env(container/NAME) added|removed|changed".
func envChangeSummary(change FieldChange, container string) string {
	name := change.Path
	if i := strings.LastIndex(name, ".env."); i >= 0 {
		name = name[i+len(".env."):]
	}
	word, _ := change.NewValue.(string)
	if word == ValueModified {
		word = "changed"
	}
	return "env(" + container + "/" + name + ") " + word
}

func envFromRefs(refs []corev1.EnvFromSource) []string {
	out := []string{}
	for _, r := range refs {
		switch {
		case r.ConfigMapRef != nil:
			out = append(out, "configMap:"+r.ConfigMapRef.Name+" prefix="+r.Prefix)
		case r.SecretRef != nil:
			out = append(out, "secret:"+r.SecretRef.Name+" prefix="+r.Prefix)
		}
	}
	slices.Sort(out)
	return out
}

func probeForName(c corev1.Container, name string) *corev1.Probe {
	return map[string]*corev1.Probe{"readinessProbe": c.ReadinessProbe, "livenessProbe": c.LivenessProbe, "startupProbe": c.StartupProbe}[name]
}

// normalizedProbe is a probe's timing and handler. Ports are written with
// Port.String(), so named ports stay apart (IntVal turns every name into 0);
// an exec handler is a short digest of its command, which can hold a
// credential.
func normalizedProbe(p *corev1.Probe) any {
	if p == nil {
		return nil
	}
	out := map[string]any{
		"initialDelaySeconds": p.InitialDelaySeconds, "timeoutSeconds": p.TimeoutSeconds, "periodSeconds": p.PeriodSeconds,
		"successThreshold": p.SuccessThreshold, "failureThreshold": p.FailureThreshold,
	}
	h := p.ProbeHandler
	switch {
	case h.HTTPGet != nil:
		out["handler"] = "httpGet:" + string(h.HTTPGet.Scheme) + ":" + h.HTTPGet.Port.String() + h.HTTPGet.Path
	case h.TCPSocket != nil:
		out["handler"] = "tcpSocket:" + h.TCPSocket.Port.String()
	case h.GRPC != nil:
		svc := ""
		if h.GRPC.Service != nil {
			svc = *h.GRPC.Service
		}
		out["handler"] = "grpc:" + strconv.Itoa(int(h.GRPC.Port)) + "/" + svc
	case h.Exec != nil:
		sum := sha256.Sum256([]byte(strings.Join(h.Exec.Command, "\x00")))
		out["handler"] = "exec:sha256:" + hex.EncodeToString(sum[:6])
	}
	return out
}

// normalizedDNSPolicy is the policy, ClusterFirst when left unset.
func normalizedDNSPolicy(p corev1.DNSPolicy) string {
	if p == "" {
		p = corev1.DNSClusterFirst
	}
	return string(p)
}

// dnsConfigValues is a pod's custom DNS settings, each list non-nil so an
// absent config equals an empty one; options are "name" or "name=value".
func dnsConfigValues(c *corev1.PodDNSConfig) (nameservers, searches, options []string) {
	nameservers, searches, options = []string{}, []string{}, []string{}
	if c == nil {
		return
	}
	nameservers = append(nameservers, c.Nameservers...)
	searches = append(searches, c.Searches...)
	for _, o := range c.Options {
		v := o.Name
		if o.Value != nil {
			v += "=" + *o.Value
		}
		options = append(options, v)
	}
	return
}

// volumeSourceRefs writes each volume as "name:kind/source" — what it comes
// from, never what it holds — sorted.
func volumeSourceRefs(vols []corev1.Volume) []string {
	out := make([]string, 0, len(vols))
	for _, v := range vols {
		s := v.VolumeSource
		src := "other"
		switch {
		case s.ConfigMap != nil:
			src = "configMap/" + s.ConfigMap.Name
		case s.Secret != nil:
			src = "secret/" + s.Secret.SecretName
		case s.PersistentVolumeClaim != nil:
			src = "pvc/" + s.PersistentVolumeClaim.ClaimName
		case s.EmptyDir != nil:
			src = "emptyDir"
		case s.HostPath != nil:
			src = "hostPath/" + s.HostPath.Path
		case s.Projected != nil:
			src = "projected"
		case s.DownwardAPI != nil:
			src = "downwardAPI"
		case s.CSI != nil:
			src = "csi/" + s.CSI.Driver
		}
		out = append(out, v.Name+":"+src)
	}
	slices.Sort(out)
	return out
}

// volumeMountRefs writes each mount as "volume→path[/subPath][(ro)]", sorted.
func volumeMountRefs(mounts []corev1.VolumeMount) []string {
	out := make([]string, 0, len(mounts))
	for _, m := range mounts {
		s := m.Name + "→" + m.MountPath
		if m.SubPath != "" {
			s += "/" + m.SubPath
		}
		if m.ReadOnly {
			s += "(ro)"
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// containerPortRefs writes each port as "number/protocol[(name)]", sorted.
func containerPortRefs(ports []corev1.ContainerPort) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		s := strconv.Itoa(int(p.ContainerPort)) + "/" + string(corev1.ProtocolTCP)
		if p.Protocol != "" {
			s = strconv.Itoa(int(p.ContainerPort)) + "/" + string(p.Protocol)
		}
		if p.Name != "" {
			s += "(" + p.Name + ")"
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// tolerationRefs writes each toleration as "key exists" or "key=value", then
// ":effect", sorted.
func tolerationRefs(tols []corev1.Toleration) []string {
	out := make([]string, 0, len(tols))
	for _, t := range tols {
		s := t.Key
		switch {
		case t.Operator == corev1.TolerationOpExists:
			s += " exists"
		case t.Value != "":
			s += "=" + t.Value
		}
		if t.Effect != "" {
			s += ":" + string(t.Effect)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// replicasOrDefault is a replica count, 1 when unset as the API defaults it.
func replicasOrDefault(p *int32) int32 {
	if p == nil {
		return 1
	}
	return *p
}

func totalRestarts(statuses []corev1.ContainerStatus) int32 {
	var n int32
	for _, s := range statuses {
		n += s.RestartCount
	}
	return n
}
