package upgradeready

import "strconv"

// ReviewedThrough is the newest Kubernetes minor whose upgrade notes these
// checks have been written against. A target beyond it can never be called
// free of known blockers.
const ReviewedThrough = "1.37"

const (
	k8sSite = "https://kubernetes.io/"
	k8sRepo = "https://github.com/kubernetes/kubernetes/"
	keps    = "https://github.com/kubernetes/enhancements/tree/master/keps/"
)

func ref(title, url string) Reference { return Reference{Title: title, URL: url} }

// pr cites a change in the kubernetes/kubernetes repository.
func pr(number int, title string) Reference {
	return ref(title, k8sRepo+"pull/"+strconv.Itoa(number))
}

// refs copies a reference list, so no finding shares a backing array with
// a check or with another finding.
func refs(lists ...[]Reference) []Reference {
	var out []Reference
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

var (
	release137Notes = ref("Kubernetes 1.37 changelog", k8sRepo+"blob/release-1.37/CHANGELOG/CHANGELOG-1.37.md")
	kubeletMetrics  = ref("Kubernetes metrics reference", k8sSite+"docs/reference/instrumentation/metrics/")
	webhookPractice = k8sSite + "docs/concepts/cluster-administration/admission-webhooks-good-practices/"
	dynamicAdmit    = k8sSite + "docs/reference/access-authn-authz/extensible-admission-controllers/"

	docSkew          = []Reference{ref("Version skew policy", k8sSite+"releases/version-skew-policy/")}
	docAPIMigration  = []Reference{ref("Deprecated API migration guide", k8sSite+"docs/reference/using-api/deprecation-guide/")}
	docNotes136      = []Reference{ref("Kubernetes 1.36 urgent upgrade notes", k8sRepo+"blob/master/CHANGELOG/CHANGELOG-1.36.md#urgent-upgrade-notes")}
	docNotes137      = []Reference{ref("Kubernetes 1.37 release notes", release137Notes.URL)}
	docExternalIPs   = []Reference{ref("Deprecating Service externalIPs", k8sSite+"blog/2026/05/14/kubernetes-v1-36-deprecation-and-removal-of-service-externalips/")}
	docGKEExecProbes = []Reference{ref("GKE: exec probe timeouts", "https://cloud.google.com/kubernetes-engine/docs/deprecations/exec-probe-timeouts")}
	docStrictIP      = []Reference{ref("KEP-4858: IP and CIDR validation", keps+"sig-network/4858-ip-cidr-validation")}
	docCRDConversion = []Reference{ref("CRD versioning: webhook conversion", k8sSite+"docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion")}
	docScheduling137 = []Reference{pr(140184, "Workload and PodGroup APIs promoted to v1beta1")}
	docKubeadm137    = []Reference{pr(136016, "kubeadm drops v1beta3 and PublicKeysECDSA")}
	docFlags137      = []Reference{pr(138002, "No-op cloud provider controller registrations removed")}
	docPodGroupAdmit = []Reference{pr(139008, "PodGroupWorkloadExists admission plugin removed"), release137Notes}
	docCAdvisor137   = []Reference{pr(139870, "Deprecated cAdvisor flags and metrics removed"), release137Notes}
	docGitRepo       = []Reference{
		ref("Volumes: gitRepo", k8sSite+"docs/concepts/storage/volumes/#gitrepo"),
		ref("Kubernetes 1.36: gitRepo volume driver removed", k8sSite+"blog/2026/04/22/kubernetes-v1-36-release/#removal-of-the-gitrepo-volume-driver"),
	}
	docCgroup = []Reference{
		kubeletMetrics,
		ref("Kubernetes 1.35 changelog: cgroup v1", k8sRepo+"blob/master/CHANGELOG/CHANGELOG-1.35.md#deprecation"),
		ref("KEP-4569: cgroup v1 maintenance mode", keps+"sig-node/4569-cgroup-v1-maintenance-mode"),
		ref("KEP-5573: removing cgroup v1", keps+"sig-node/5573-remove-cgroup-v1"),
	}
	docRuntime = []Reference{kubeletMetrics, ref("CRI cgroup driver lookup is GA", k8sSite+"blog/2025/09/12/kubernetes-v1-34-cri-cgroup-driver-lookup-now-ga/")}
	docDrain   = []Reference{
		ref("Safely drain a node", k8sSite+"docs/tasks/administer-cluster/safely-drain-node/"),
		ref("Specifying a disruption budget", k8sSite+"docs/tasks/run-application/configure-pdb/"),
		ref("PodDisruptionBudget API", k8sSite+"docs/reference/kubernetes-api/policy-resources/pod-disruption-budget-v1/"),
	}
	docAdmission       = []Reference{ref("Admission webhook good practices", webhookPractice), ref("Dynamic admission control", dynamicAdmit)}
	docMatchPolicy     = []Reference{ref("Matching every API version", webhookPractice+"#match-all-versions")}
	docWebhookBackends = []Reference{ref("Webhook failure policy", dynamicAdmit+"#failure-policy"), ref("Highly available webhooks", webhookPractice+"#ha-deployment")}
	docWebhookScope    = []Reference{ref("Limiting webhook scope", webhookPractice+"#webhook-limit-scope")}
	docAPIServices     = []Reference{
		ref("API aggregation layer", k8sSite+"docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/"),
		ref("APIService API", k8sSite+"docs/reference/kubernetes-api/apiregistration/api-service-v1/"),
	}
	docEventQPS = []Reference{
		pr(117119, "eventRecordQPS of zero means unlimited"),
		ref("Kubelet 1.36 hands eventRecordQPS to client-go", k8sRepo+"blob/v1.36.0/cmd/kubelet/app/server.go#L726-L730"),
		ref("client-go 1.36 default QPS", k8sRepo+"blob/v1.36.0/staging/src/k8s.io/client-go/rest/config.go#L46-L49"),
		ref("client-go 1.36 replaces a zero QPS with its default", k8sRepo+"blob/v1.36.0/staging/src/k8s.io/client-go/rest/config.go#L370-L375"),
	}
	docIPVS = []Reference{
		ref("KEP-5495: deprecating kube-proxy IPVS mode", keps+"sig-network/5495-deprecate-ipvs-mode-in-kube-proxy"),
		pr(139397, "KubeProxyIPVS feature gate added"),
	}
	docNftables = []Reference{
		ref("KEP-5343: nftables as kube-proxy's default", keps+"sig-network/5343-nftables-to-default"),
		pr(139957, "Warning for an implicit kube-proxy mode"),
	}
	docSELinux = []Reference{
		ref("Breaking changes in SELinux volume labeling", k8sSite+"blog/2026/04/22/breaking-changes-in-selinux-volume-labeling/"),
		pr(139956, "SELinuxMount graduates to GA"),
	}
	docGateLifecycle = []Reference{
		ref("Kubernetes 1.36 feature lifecycle", k8sRepo+"blob/release-1.36/test/compatibility_lifecycle/reference/versioned_feature_list.yaml"),
		ref("Kubernetes 1.37 feature lifecycle", k8sRepo+"blob/release-1.37/test/compatibility_lifecycle/reference/versioned_feature_list.yaml"),
	}
	docDRAMetrics = []Reference{pr(138542, "DRA ResourceClaim creation metrics harmonised")}
)
