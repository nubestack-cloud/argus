package argusagentchart

// PROJECT.md K2: hub.caBundle / hub.caSecretRef let the agent trust a private
// CA for HTTPS to hub.apiUrl. These render the chart and check that both
// agent Deployments get the env var, the mount and a volume of the right
// source — and that nothing CA-related renders when neither is set.

import (
	"strings"
	"testing"
)

type caDeployment struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				Containers []struct {
					Env []struct {
						Name  string `yaml:"name"`
						Value string `yaml:"value"`
					} `yaml:"env"`
					VolumeMounts []struct {
						Name      string `yaml:"name"`
						MountPath string `yaml:"mountPath"`
						ReadOnly  bool   `yaml:"readOnly"`
					} `yaml:"volumeMounts"`
				} `yaml:"containers"`
				Volumes []struct {
					Name      string `yaml:"name"`
					ConfigMap *struct {
						Name string `yaml:"name"`
					} `yaml:"configMap"`
					Secret *struct {
						SecretName string `yaml:"secretName"`
						Items      []struct {
							Key  string `yaml:"key"`
							Path string `yaml:"path"`
						} `yaml:"items"`
					} `yaml:"secret"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type caConfigMap struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
}

const testPEM = "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----"

// withRemediate renders both Deployments, so each check covers the
// investigation agent and the remediation agent.
var withRemediate = []string{"--set", "remediate.enabled=true", "--set", "remediate.namespaces={default}"}

func renderCA(t *testing.T, extraSet ...string) ([]caDeployment, []caConfigMap) {
	t.Helper()
	out, err := helmTemplateRaw(t, append(append([]string{}, withRemediate...), extraSet...)...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	deps := decodeYAMLDocs[caDeployment](t, out, func(k string) bool { return k == "Deployment" })
	if len(deps) != 2 {
		t.Fatalf("rendered %d Deployments, want 2 (investigation + remediation)", len(deps))
	}
	cms := decodeYAMLDocs[caConfigMap](t, out, func(k string) bool { return k == "ConfigMap" })
	return deps, cms
}

func caEnv(d caDeployment) string {
	for _, e := range d.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "ARGUS_HUB_CA_FILE" {
			return e.Value
		}
	}
	return ""
}

func TestHubCANotRenderedByDefault(t *testing.T) {
	deps, cms := renderCA(t)
	for _, d := range deps {
		if v := caEnv(d); v != "" {
			t.Errorf("%s: ARGUS_HUB_CA_FILE=%q with no CA configured", d.Metadata.Name, v)
		}
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Name == "hub-ca" {
				t.Errorf("%s: hub-ca volume rendered with no CA configured", d.Metadata.Name)
			}
		}
	}
	for _, cm := range cms {
		if cm.Metadata.Name == "argus-agent-hub-ca" {
			t.Errorf("hub-ca ConfigMap rendered with no CA configured")
		}
	}
}

func assertCAMounted(t *testing.T, d caDeployment) {
	t.Helper()
	if v := caEnv(d); v != "/etc/argus/hub-ca/ca.crt" {
		t.Errorf("%s: ARGUS_HUB_CA_FILE = %q, want /etc/argus/hub-ca/ca.crt", d.Metadata.Name, v)
	}
	found := false
	for _, m := range d.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "hub-ca" {
			found = true
			if m.MountPath != "/etc/argus/hub-ca" || !m.ReadOnly {
				t.Errorf("%s: hub-ca mount = %+v, want read-only at /etc/argus/hub-ca", d.Metadata.Name, m)
			}
		}
	}
	if !found {
		t.Errorf("%s: no hub-ca volumeMount", d.Metadata.Name)
	}
}

func TestHubCABundleRendersConfigMapAndMount(t *testing.T) {
	deps, cms := renderCA(t, "--set", "hub.caBundle="+testPEM)
	var cm *caConfigMap
	for i := range cms {
		if cms[i].Metadata.Name == "argus-agent-hub-ca" {
			cm = &cms[i]
		}
	}
	if cm == nil {
		t.Fatal("no argus-agent-hub-ca ConfigMap rendered for hub.caBundle")
	}
	if cm.Metadata.Namespace != "argus-system" {
		t.Errorf("ConfigMap namespace = %q, want argus-system", cm.Metadata.Namespace)
	}
	if !strings.Contains(cm.Data["ca.crt"], "BEGIN CERTIFICATE") {
		t.Errorf("ConfigMap ca.crt = %q, want the PEM bundle", cm.Data["ca.crt"])
	}
	for _, d := range deps {
		assertCAMounted(t, d)
		ok := false
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Name == "hub-ca" && v.ConfigMap != nil && v.ConfigMap.Name == "argus-agent-hub-ca" && v.Secret == nil {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: hub-ca volume is not the argus-agent-hub-ca ConfigMap", d.Metadata.Name)
		}
	}
}

func TestHubCASecretRefMountsExistingSecret(t *testing.T) {
	deps, cms := renderCA(t, "--set", "hub.caSecretRef.name=corp-ca", "--set", "hub.caSecretRef.key=root.pem")
	for _, cm := range cms {
		if cm.Metadata.Name == "argus-agent-hub-ca" {
			t.Errorf("hub-ca ConfigMap rendered for caSecretRef; the Secret is the source")
		}
	}
	for _, d := range deps {
		assertCAMounted(t, d)
		ok := false
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Name == "hub-ca" && v.Secret != nil && v.Secret.SecretName == "corp-ca" &&
				len(v.Secret.Items) == 1 && v.Secret.Items[0].Key == "root.pem" && v.Secret.Items[0].Path == "ca.crt" {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: hub-ca volume does not project Secret corp-ca key root.pem to ca.crt", d.Metadata.Name)
		}
	}
}

func TestHubCABothSourcesFailRender(t *testing.T) {
	out, err := helmTemplateRaw(t, "--set", "hub.caBundle="+testPEM, "--set", "hub.caSecretRef.name=corp-ca")
	if err == nil {
		t.Fatal("helm template succeeded with both hub.caBundle and hub.caSecretRef.name set; want a render error")
	}
	if !strings.Contains(string(out), "not both") {
		t.Errorf("render error does not say why:\n%s", out)
	}
}
