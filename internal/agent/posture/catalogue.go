package posture

// CheckMeta is a check's catalogue entry. The hub serves the catalogue with
// every scan, so the UI never carries its own copy of the wording.
type CheckMeta struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category,omitempty"`
	// DefaultSeverity is what the check reports with no operator override:
	// "high" or "medium". A check that emits both shows its worse one.
	DefaultSeverity string      `json:"defaultSeverity,omitempty"`
	Description     string      `json:"description"`
	Remediation     string      `json:"remediation"`
	Frameworks      []string    `json:"frameworks,omitempty"`
	References      []Reference `json:"references,omitempty"`
}

// Reference is a link to the documentation behind a check.
type Reference struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// The framework labels a check can carry. The UI filters on these strings.
const (
	FrameworkNSACISA = "NSA/CISA"
	FrameworkCIS     = "CIS"
)

// framework is a set of the labels above.
type framework uint8

const (
	nsa framework = 1 << iota
	cis
	noFramework framework = 0
)

func (f framework) labels() []string {
	var out []string
	if f&nsa != 0 {
		out = append(out, FrameworkNSACISA)
	}
	if f&cis != 0 {
		out = append(out, FrameworkCIS)
	}
	return out
}

// The reported severity ladder for DefaultSeverity.
const (
	high   = "high"
	medium = "medium"
)

func doc(label, url string) Reference { return Reference{Label: label, URL: url} }

const k8sDocs = "https://kubernetes.io/docs/"

var (
	docSecurityContext = doc("Kubernetes: configure a security context", k8sDocs+"tasks/configure-pod-container/security-context/")
	docPodSecurity     = doc("Kubernetes: Pod Security Standards", k8sDocs+"concepts/security/pod-security-standards/")
	docHardening       = doc("NSA/CISA Kubernetes Hardening Guidance", "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF")
	docResources       = doc("Kubernetes: resource management for containers", k8sDocs+"concepts/configuration/manage-resources-containers/")
	docProbes          = doc("Kubernetes: liveness, readiness and startup probes", k8sDocs+"tasks/configure-pod-container/configure-liveness-readiness-startup-probes/")
	docImages          = doc("Kubernetes: images", k8sDocs+"concepts/containers/images/")
	docDeployments     = doc("Kubernetes: Deployments", k8sDocs+"concepts/workloads/controllers/deployment/")
	docDisruptions     = doc("Kubernetes: disruptions and PodDisruptionBudgets", k8sDocs+"concepts/workloads/pods/disruptions/")
	docSpread          = doc("Kubernetes: topology spread constraints", k8sDocs+"concepts/scheduling-eviction/topology-spread-constraints/")
	docAffinity        = doc("Kubernetes: affinity and anti-affinity", k8sDocs+"concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity")
	docTokens          = doc("Kubernetes: service accounts", k8sDocs+"concepts/security/service-accounts/")
	docSecrets         = doc("Kubernetes: Secrets", k8sDocs+"concepts/configuration/secret/")
	docConfigMaps      = doc("Kubernetes: ConfigMaps", k8sDocs+"concepts/configuration/configmap/")
	docHostPath        = doc("Kubernetes: hostPath volumes", k8sDocs+"concepts/storage/volumes/#hostpath")
	docDeprecations    = doc("Kubernetes: deprecated API migration guide", k8sDocs+"reference/using-api/deprecation-guide/")
	docServices        = doc("Kubernetes: Services", k8sDocs+"concepts/services-networking/service/")
	docIngress         = doc("Kubernetes: Ingress", k8sDocs+"concepts/services-networking/ingress/")
	docFinalizers      = doc("Kubernetes: finalizers", k8sDocs+"concepts/overview/working-with-objects/finalizers/")
	docVolumes         = doc("Kubernetes: persistent volumes", k8sDocs+"concepts/storage/persistent-volumes/")
	docOpenGitOps      = doc("OpenGitOps principles", "https://opengitops.dev/")
	docArgoCD          = doc("Argo CD documentation", "https://argo-cd.readthedocs.io/en/stable/")
	docHelm            = doc("Helm: charts", "https://helm.sh/docs/topics/charts/")
	docCertificate     = doc("cert-manager: the Certificate resource", "https://cert-manager.io/docs/usage/certificate/")
	docTraefikCRD      = doc("Traefik: Kubernetes CRD routing", "https://doc.traefik.io/traefik/routing/providers/kubernetes-crd/")
	docTraefikMW       = doc("Traefik: middlewares", "https://doc.traefik.io/traefik/middlewares/overview/")
	docCrossplane      = doc("Crossplane: composite resources", "https://docs.crossplane.io/latest/concepts/composite-resources/")
)

// check declares one catalogue entry; section fills in its category.
func check(id, title, severity string, fw framework, description, remediation string, refs ...Reference) CheckMeta {
	return CheckMeta{
		ID: id, Title: title, DefaultSeverity: severity,
		Description: description, Remediation: remediation,
		Frameworks: fw.labels(), References: refs,
	}
}

func section(category string, entries ...CheckMeta) []CheckMeta {
	for i := range entries {
		entries[i].Category = category
	}
	return entries
}

func catalogue(sections ...[]CheckMeta) map[string]CheckMeta {
	out := map[string]CheckMeta{}
	for _, s := range sections {
		for _, m := range s {
			out[m.ID] = m
		}
	}
	return out
}

// CheckRegistry is every check a scan can report, by ID. The IDs are stored
// in operators' settings and exceptions, so they never change. A finding's
// category is read from here, so the settings page files each check under
// the section its findings appear in.
var CheckRegistry = catalogue(
	section(CategorySecurity,
		check("runAsRoot", "Runs as root", medium, nsa|cis,
			"Neither the container nor its pod promises a non-root user, so the process may run as UID 0. A breakout from a root process starts with root on the node.",
			"Set runAsNonRoot: true, or a non-zero runAsUser, in the container's or the pod's securityContext.",
			docSecurityContext, docPodSecurity, docHardening),
		check("privileged", "Privileged container", high, nsa|cis,
			"A privileged container sees the node's devices and holds every capability; container isolation no longer stands between it and the host.",
			"Remove privileged: true from the container's securityContext.",
			docSecurityContext, docPodSecurity, docHardening),
		check("privilegeEscalation", "Privilege escalation allowed", high, nsa|cis,
			"Unless allowPrivilegeEscalation is false, a process can gain more privilege than the one that started it, through setuid binaries for example.",
			"Set allowPrivilegeEscalation: false in the container's securityContext.",
			docSecurityContext, docPodSecurity),
		check("readOnlyRootFs", "Writable root filesystem", medium, nsa,
			"An intruder who can write to the image's filesystem can replace binaries or drop tools into it.",
			"Set readOnlyRootFilesystem: true and mount an emptyDir wherever the application has to write.",
			docSecurityContext, docHardening),
		check("dangerousCapabilities", "Dangerous capability added", high, nsa|cis,
			"SYS_ADMIN, NET_ADMIN and ALL are close to root on the node and are common routes out of a container.",
			"Take the capability out of capabilities.add; drop ALL and add back only what the process needs.",
			docSecurityContext, docPodSecurity),
		check("insecureCapabilities", "Risky capability added", medium, nsa|cis,
			"NET_RAW, SYS_PTRACE, MKNOD and DAC_OVERRIDE allow forged packets, tracing other processes, creating device nodes and ignoring file permissions.",
			"Take the capability out of capabilities.add; drop ALL and add back only what the process needs.",
			docSecurityContext, docPodSecurity),
		check("dockerSocketMount", "Container runtime socket mounted", high, nsa|cis,
			"With the Docker, containerd or CRI-O socket mounted, the container can start any container on the node, which amounts to root on it.",
			"Remove the hostPath volume for the socket. Build images with a daemonless builder such as Kaniko or BuildKit rootless rather than the node's runtime.",
			docHostPath, docHardening),
		check("sensitiveHostPath", "Sensitive host path mounted", high, nsa|cis,
			"The pod mounts a host directory such as /etc, /proc, /sys, /var/run, /var/log or /root, or the whole host filesystem, exposing node configuration, credentials or other workloads' state.",
			"Drop the hostPath volume, or narrow it to one directory that holds nothing sensitive; use emptyDir or a PersistentVolumeClaim for storage.",
			docHostPath, docPodSecurity),
		check("hostNetwork", "Host network", medium, nsa|cis,
			"The pod shares the node's network namespace: it can bind the node's ports and reach services listening only on the node.",
			"Remove hostNetwork: true unless the workload is node networking infrastructure.",
			docPodSecurity, docHardening),
		check("hostPID", "Host process namespace", high, nsa|cis,
			"The pod can see, and with enough privilege signal or trace, every process on the node.",
			"Remove hostPID: true.",
			docPodSecurity, docHardening),
		check("hostIPC", "Host IPC namespace", high, nsa|cis,
			"The pod shares the node's shared memory and IPC objects with every host process.",
			"Remove hostIPC: true.",
			docPodSecurity, docHardening),
		check("automountServiceAccountToken", "Service account token mounted", medium, nsa,
			"An API token is mounted into the pod. Anything that compromises the pod can call the Kubernetes API with that service account's permissions.",
			"Set automountServiceAccountToken: false on the pod or its service account, and turn it on only for pods that call the API.",
			docTokens, docHardening),
		check("secretInConfigMap", "Credential-like key in a ConfigMap", medium, nsa,
			"A key name suggests a password, private key, access key or client secret. ConfigMaps are not encrypted at rest and are readable far more widely than Secrets. Only key names are inspected; values never reach this check.",
			"Move the value into a Secret and keep the ConfigMap for settings that are safe to read.",
			docSecrets),
	),
	section(CategoryReliability,
		check("readinessProbeMissing", "No readiness probe", medium, noFramework,
			"Without a readiness probe a container receives traffic as soon as it starts, before it can serve it.",
			"Add a readinessProbe (HTTP, TCP, gRPC or exec) that passes only once the container can serve.",
			docProbes),
		check("livenessProbeMissing", "No liveness probe", medium, noFramework,
			"Without a liveness probe a container that hangs while its process stays up is never restarted.",
			"Add a livenessProbe that fails when the container stops making progress.",
			docProbes),
		check("imageTagLatest", "Image not pinned", high, noFramework,
			"The image is tagged latest or not tagged at all, so what runs depends on when each node pulled it, and rolling back means nothing.",
			"Pin a version tag such as nginx:1.27.2, or a digest.",
			docImages),
		check("pullPolicyNotAlways", "Mutable tag without imagePullPolicy: Always", medium, noFramework,
			"A mutable tag and a pull policy other than Always let each node keep whatever it cached, so replicas can run different code.",
			"Pin the image, or set imagePullPolicy: Always while the tag stays mutable.",
			docImages),
		check("singleReplica", "Single replica", medium, noFramework,
			"With one replica any drain, eviction or crash is an outage.",
			"Run two or more replicas, or let a HorizontalPodAutoscaler manage the count.",
			docDeployments, docDisruptions),
		check("rolloutAvailabilityRisk", "Rollout can drop to zero available", medium, noFramework,
			"The rolling update allows every replica to be unavailable and allows no surge, so the controller may take down all old pods before any new one is ready. A rollout that must not overlap old and new versions says so better with the Recreate strategy.",
			"Give maxSurge at least 1 (or a positive percentage), or keep maxUnavailable below the replica count; choose strategy.type: Recreate only when full replacement is intended.",
			docDeployments),
		check("missingPDB", "No PodDisruptionBudget", medium, noFramework,
			"Nothing limits how many replicas a drain or upgrade may evict at once, so all of them can go together.",
			"Add a PodDisruptionBudget selecting these pods, with minAvailable or maxUnavailable set to what the service can lose.",
			docDisruptions),
		check("missingTopologySpread", "No topology spread constraints", medium, noFramework,
			"Nothing asks the scheduler to keep the replicas apart, so they can all land on one node or zone and fail together.",
			"Add topologySpreadConstraints over kubernetes.io/hostname or topology.kubernetes.io/zone.",
			docSpread),
		check("podHARisk", "All replicas on one node", medium, noFramework,
			"Every running pod of this Deployment (two or more of them, counting old and new ReplicaSets during a rollout) is on the same node. Only placement is judged, not readiness; pending, finished and terminating pods are left out. When some pods' owners cannot be resolved the check is skipped, unless the pods it can resolve already span more than one node.",
			"Spread the replicas with pod anti-affinity or topology spread constraints.",
			docAffinity, docSpread),
		check("deprecatedAPIVersion", "Deprecated API version served", high, noFramework,
			"The cluster still serves an API version that a later Kubernetes release removes; anything written against it stops working after that upgrade.",
			"Move manifests and clients to the replacement version before upgrading.",
			docDeprecations),
		check("serviceNoMatchingPods", "Service selects no pods", medium, noFramework,
			"No pod carries the labels this Service selects, so it has no endpoints and connections to it fail.",
			"Make the selector match the labels on the workload's pod template.",
			docServices),
		check("ingressNoMatchingService", "Ingress backend Service missing", medium, noFramework,
			"An Ingress path sends traffic to a Service that does not exist; requests for it get an error from the controller.",
			"Correct the backend Service name, or create the Service.",
			docIngress),
		check("stuckTerminating", "Stuck terminating", high, noFramework,
			"The object was deleted but is still here. Finalizers normally clear within seconds; minutes usually mean the controller owning a finalizer is down, crash-looping, or cannot reach something its cleanup needs, such as a webhook or an external API.",
			"Look up the controller behind each finalizer in metadata.finalizers (for Argo CD the application controller, for Flux the kustomize, helm or source controller) and get it healthy; deletion then completes by itself. Clearing finalizers by hand abandons their cleanup and is a last resort.",
			docFinalizers),
		check(checkGitOpsUnmanaged, "Workload outside GitOps", medium, noFramework,
			"This cluster uses GitOps, but nothing marks this workload as managed by Argo CD, Flux or Helm; it was most likely applied by hand. There is no reviewed source for its desired state, no drift detection and no declarative rollback.",
			"Commit its manifests to a repository Argo CD or Flux reconciles, or adopt it into an existing Application or Kustomization.",
			docOpenGitOps, docArgoCD),
		check(checkGitOpsHelmOnly, "Helm release outside GitOps", medium, noFramework,
			"This workload belongs to a Helm release installed with the helm CLI. Upgrades made that way skip pull-request review and the GitOps rollback path.",
			"Drive the release from Git with a Flux HelmRelease or an Argo CD Application pointing at the chart.",
			docOpenGitOps, docHelm),
		check("pvcPending", "PersistentVolumeClaim stuck Pending", high, noFramework,
			"The claim has been Pending far longer than binding takes. Usually no volume fits its class, size or access mode, or the provisioner is not working.",
			"Read the claim's events and the CSI provisioner's logs, and check its StorageClass exists.",
			docVolumes),
		check("pvReleasedOrFailed", "PersistentVolume Released or Failed", high, noFramework,
			"Released: the volume's claim was deleted, and under the Retain policy the volume and its data wait for someone to decide. Failed: provisioning or reclaim went wrong.",
			"For Released, delete the volume once its data is not needed, or bind it again. For Failed, read the provisioner's logs for the error.",
			docVolumes),
		check("certificateExpiry", "Certificate expiring", high, noFramework,
			"A cert-manager Certificate expires within 30 days. cert-manager normally renews well before that, so a renewal has likely stalled. The certificate-expiry-imminent rule opens an incident only at 7 days; this is the earlier warning.",
			"Read the Certificate's Ready and Issuing conditions and its newest CertificateRequest to see why renewal has not happened.",
			docCertificate),
		check("traefikIngressRouteMissingService", "IngressRoute Service missing", high, noFramework,
			"A route in this Traefik IngressRoute names a Service that does not exist, so requests it matches fail.",
			"Fix the Service name under routes[].services, or create the Service.",
			docTraefikCRD),
		check("traefikIngressRouteMissingMiddleware", "IngressRoute Middleware missing", high, noFramework,
			"A route in this Traefik IngressRoute names a Middleware that does not exist, and Traefik will not serve a route with a missing middleware.",
			"Fix the name under routes[].middlewares, or create the Middleware.",
			docTraefikCRD, docTraefikMW),
		check("traefikErrorsMiddlewareMissingService", "Error-page Service missing", high, noFramework,
			"This errors Middleware sends error pages to a Service that does not exist, so clients get Traefik's default page instead.",
			"Fix spec.errors.service, or create the Service.",
			docTraefikMW),
		check("traefikMiddlewareChainMissingMember", "Middleware chain member missing", high, noFramework,
			"This chain Middleware includes a Middleware that does not exist, which makes the whole chain unusable.",
			"Fix spec.chain.middlewares, or create the missing Middleware.",
			docTraefikMW),
		check("crossplaneNotReady", "Crossplane resource not Ready", high, noFramework,
			"The claim or composite reports Ready=False: what it manages is not provisioned, or has drifted from its desired state.",
			"Describe it for events and conditions, then follow the composed managed resources and the provider's logs.",
			docCrossplane),
	),
	section(CategoryEfficiency,
		check("cpuRequestMissing", "No CPU request", medium, cis,
			"The scheduler treats a container with no CPU request as needing none, so nodes get overcommitted and the container is first to be starved.",
			"Set resources.requests.cpu, for example 100m.",
			docResources),
		check("memoryRequestMissing", "No memory request", medium, cis,
			"The scheduler treats a container with no memory request as needing none and may place it where memory runs out.",
			"Set resources.requests.memory, for example 128Mi.",
			docResources),
		check("cpuLimitMissing", "No CPU limit", medium, cis,
			"Nothing caps the container's CPU, so it can take a node's spare capacity from its neighbours.",
			"Set resources.limits.cpu, for example 500m.",
			docResources),
		check("memoryLimitMissing", "No memory limit", medium, cis,
			"Nothing caps the container's memory, so it can grow until the node's kernel starts killing processes.",
			"Set resources.limits.memory, for example 512Mi.",
			docResources),
		check("orphanConfigMapSecret", "Unused ConfigMap", medium, noFramework,
			"No workload, Ingress or supported controller configuration refers to this ConfigMap. Only ConfigMaps are judged, because the agent does not list Secrets, and only references this check understands are counted: something that reads the ConfigMap by name from its own code is invisible to it.",
			"Make sure nothing outside the references checked still uses it, then reference it from whatever should consume it, or delete it.",
			docConfigMaps),
		check("orphanPVC", "Unused PersistentVolumeClaim", medium, noFramework,
			"The claim is Bound but no pod mounts it; its workload was probably deleted or scaled away, and the storage stays allocated.",
			"Once its data is not needed, delete the claim, and its volume too if that is Retained.",
			docVolumes),
	),
)
