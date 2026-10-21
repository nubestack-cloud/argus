package upgradeready

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// proxyContainer is the kube-proxy container in a DaemonSet: the one named
// kube-proxy, or the only container there is.
func proxyContainer(ds *appsv1.DaemonSet) *corev1.Container {
	cs := ds.Spec.Template.Spec.Containers
	if i := slices.IndexFunc(cs, func(c corev1.Container) bool { return c.Name == "kube-proxy" }); i >= 0 {
		return &cs[i]
	}
	if len(cs) == 1 {
		return &cs[0]
	}
	return nil
}

func osOf(spec *corev1.PodSpec) string {
	if spec.OS != nil {
		return strings.ToLower(string(spec.OS.Name))
	}
	return strings.ToLower(spec.NodeSelector[corev1.LabelOSStable])
}

// mode is one kube-proxy's mode as configured, and where it was read.
type mode struct {
	value, path string
}

// kubeProxyMode: Kubernetes 1.37 warns when the Linux mode is left implicit,
// because 1.40 changes the implicit default from iptables to nftables, and
// IPVS is on its way out.
func (s *scan) kubeProxyMode() Check {
	r := newReport("kube-proxy-mode-transition", "Networking", "kube-proxy mode transition",
		"kube-proxy DaemonSet or mirror Pod configuration", "Every readable kube-proxy names a supported mode explicitly.").
		since("1.37").citing(docIPVS, docNftables)
	in := s.in
	if in.DaemonSets == nil {
		return r.unknown("DaemonSets could not be read, so kube-proxy's mode was not looked at.")
	}
	managed := in.managedControlPlane()
	found, undecided := 0, 0
	for _, ds := range in.DaemonSets {
		if ds == nil || !isKubeProxy(ds) {
			continue
		}
		found++
		r.Inspected++
		c := proxyContainer(ds)
		if c == nil {
			undecided++
			r.caveat(fmt.Sprintf("%s/%s has several containers and none is named kube-proxy.", ds.Namespace, ds.Name))
			continue
		}
		m, err := s.daemonSetMode(ds, c)
		at := &ResourceRef{Group: "apps", Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name}
		if err != nil {
			undecided++
			r.caveat(fmt.Sprintf("%s/%s: %v.", ds.Namespace, ds.Name, err))
		} else if !judgeMode(r, at, m, osOf(&ds.Spec.Template.Spec), managed) {
			undecided++
		}
	}
	if found == 0 {
		if in.Pods == nil {
			return r.unknown("There is no kube-proxy DaemonSet, and Pods could not be read to look for a static kube-proxy.")
		}
		for _, p := range in.mirrorPods() {
			if p.Namespace != "kube-system" {
				continue
			}
			i := slices.IndexFunc(p.Spec.Containers, func(c corev1.Container) bool { return c.Name == "kube-proxy" })
			if i < 0 {
				continue
			}
			found++
			r.Inspected++
			args := commandLine(p.Spec.Containers[i])
			if cfg, ok := args.first("--config"); ok {
				undecided++
				r.caveat(fmt.Sprintf("%s/%s: a static kube-proxy's --config=%s cannot be read through the Kubernetes API.", p.Namespace, p.Name, cfg.value))
				continue
			}
			m := mode{path: "spec.containers[kube-proxy].command/args[--proxy-mode]"}
			if set, ok := args.first("--proxy-mode"); ok {
				m = mode{set.value, "spec.containers[kube-proxy]." + set.field + "[--proxy-mode]"}
			}
			if !judgeMode(r, podRef(p.Namespace, p.Name), m, osOf(&p.Spec), managed) {
				undecided++
			}
		}
	}
	if found == 0 {
		return r.unknown("No kube-proxy DaemonSet or mirror Pod was found; kube-proxy may run as a host process, or the provider's dataplane may replace it.")
	}
	incomplete := ""
	if undecided > 0 {
		incomplete = "kube-proxy was found, but its effective mode could not be worked out."
	}
	return r.finish(func(n int) string {
		return count(n, "kube-proxy mode needs", "kube-proxy modes need") + " a migration decision."
	}, incomplete)
}

// daemonSetMode reads the mode a kube-proxy DaemonSet configures: from the
// file --config names when there is one, else from --proxy-mode, else none.
func (s *scan) daemonSetMode(ds *appsv1.DaemonSet, c *corev1.Container) (mode, error) {
	args := commandLine(*c)
	cfg, ok := args.first("--config")
	if !ok {
		if set, ok := args.first("--proxy-mode"); ok {
			return mode{set.value, "spec.template.spec.containers[" + c.Name + "]." + set.field + "[--proxy-mode]"}, nil
		}
		return mode{path: "spec.template.spec.containers[" + c.Name + "].command/args[--proxy-mode]"}, nil
	}
	content, where, err := configFile(s.in.ConfigMaps, ds, c, cfg.value)
	if err != nil {
		return mode{}, err
	}
	var doc map[string]any
	if err := k8syaml.NewYAMLOrJSONDecoder(strings.NewReader(content), 4096).Decode(&doc); err != nil {
		return mode{}, fmt.Errorf("its kube-proxy configuration could not be parsed: %v", err)
	}
	v, _, err := unstructured.NestedString(doc, "mode")
	if err != nil {
		return mode{}, errors.New("its kube-proxy configuration has a mode that is not a string")
	}
	return mode{v, where + ".mode"}, nil
}

// configFile finds the ConfigMap key a mounted file path resolves to and
// returns its content and an evidence path for it.
func configFile(cms []*corev1.ConfigMap, ds *appsv1.DaemonSet, c *corev1.Container, file string) (string, string, error) {
	if cms == nil {
		return "", "", fmt.Errorf("ConfigMaps could not be read, so --config=%s was not followed", file)
	}
	file = path.Clean(file)
	for _, m := range c.VolumeMounts {
		dir := strings.TrimSuffix(path.Clean(m.MountPath), "/")
		rel, under := strings.CutPrefix(file, dir+"/")
		if file != dir && !under {
			continue
		}
		vi := slices.IndexFunc(ds.Spec.Template.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == m.Name })
		if vi < 0 || ds.Spec.Template.Spec.Volumes[vi].ConfigMap == nil {
			continue
		}
		src := ds.Spec.Template.Spec.Volumes[vi].ConfigMap
		key := cmpOr(m.SubPath, rel)
		if j := slices.IndexFunc(src.Items, func(it corev1.KeyToPath) bool { return path.Clean(it.Path) == key }); j >= 0 {
			key = src.Items[j].Key
		}
		ci := slices.IndexFunc(cms, func(cm *corev1.ConfigMap) bool {
			return cm != nil && cm.Namespace == ds.Namespace && cm.Name == src.Name
		})
		if ci < 0 {
			return "", "", fmt.Errorf("ConfigMap %s/%s could not be read", ds.Namespace, src.Name)
		}
		cm := cms[ci]
		value, inData := cm.Data[key]
		where := fmt.Sprintf("ConfigMap/%s/%s.data.%s", cm.Namespace, cm.Name, key)
		if !inData {
			b, inBinary := cm.BinaryData[key]
			if !inBinary {
				return "", "", fmt.Errorf("ConfigMap %s/%s has no key %q", cm.Namespace, cm.Name, key)
			}
			value, where = string(b), fmt.Sprintf("ConfigMap/%s/%s.binaryData.%s", cm.Namespace, cm.Name, key)
		}
		if hashedAtCapture(value) {
			return "", "", fmt.Errorf("ConfigMap %s/%s key %q is hashed when the agent captures it, so the content of --config=%s is not collected", cm.Namespace, cm.Name, key, file)
		}
		return value, where, nil
	}
	return "", "", fmt.Errorf("--config=%s is not a file from a mounted ConfigMap", file)
}

// judgeMode records what one kube-proxy's mode means for the upgrade and
// reports whether the mode could be judged at all.
func judgeMode(r *report, at *ResourceRef, m mode, osName string, managed bool) bool {
	value := strings.ToLower(strings.TrimSpace(m.value))
	if value == "" && osName == "windows" {
		value = "kernelspace" // Windows has one mode
	}
	via := "Change"
	if managed {
		via = "Through the provider's add-on or cluster configuration (not by editing the reconciled kube-proxy), change"
	}
	switch value {
	case "iptables", "nftables", "kernelspace":
		return true
	case "ipvs":
		f := r.flag(LevelReview, "IPVS mode is deprecated", at, live(m.path, "ipvs"),
			"IPVS is set to be off by default in Kubernetes 1.40 and removed in 1.43.",
			via+" kube-proxy to nftables or iptables, and validate it, before IPVS is turned off.")
		f.References = refs(docIPVS)
	case "":
		f := r.flag(LevelReview, "Linux proxy mode left implicit", at, live(m.path, "unspecified"),
			"Kubernetes 1.37 warns about an implicit mode because the Linux default moves from iptables to nftables in 1.40.",
			via+" kube-proxy to name iptables or nftables explicitly, after validating the one chosen.")
		f.References = refs(docNftables)
	default:
		r.caveat(fmt.Sprintf("%s %s/%s uses kube-proxy mode %q, which this check does not recognise.", at.Kind, at.Namespace, at.Name, value))
		return false
	}
	return true
}
